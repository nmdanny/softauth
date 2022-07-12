use anyhow::anyhow;
use bytes::BytesMut;
use thiserror::Error;
use tokio::sync::mpsc::UnboundedSender;
use futures::{StreamExt, SinkExt};
use tower::Service;
use tracing::{debug_span, error, trace, warn};
use super::{packet_processing::{PacketProcessing, PacketProcessingResult}};

use crate::{
    authenticator::{api::{CTAP2Request, CTAP2Response, AuthServiceError, AuthenticatorError}, transport::CTAP2ServerTransport},
};

use super::{
    command::{ErrorCode},
    packet::{
        Message, MessageDecodeError, MessageEncoder,
        Packet, HID_REPORT_SIZE,
    },
    transport::HIDTransport,
};

/// An error that occurs during processing of a CTAP-HID packet/transaction.
#[derive(Debug, Error)]
pub enum ServerError {
    /// A decoding error
    #[error(transparent)]
    MessageDecodeError(#[from] MessageDecodeError),

    #[error("[chan {new_chan}] Server is busy on channel {busy_chan}")]
    ChannelBusy { busy_chan: u32, new_chan: u32 },

    #[error("[chan {chan}] Invalid channel")]
    InvalidChannel { chan: u32 },

    #[error("[chan {chan}] Misc error")]
    Other { chan: u32, reason: String },
}

impl ServerError {
    /// Gets the channel of the 
    pub fn get_channel(&self) -> u32 {
        match self {
            ServerError::MessageDecodeError(err) => err.get_channel(),
            ServerError::ChannelBusy { new_chan, .. } => *new_chan,
            ServerError::InvalidChannel { chan } => *chan,
            ServerError::Other { chan, .. } => *chan,
        }
    }
}

impl From<ServerError> for ErrorCode {
    fn from(err: ServerError) -> Self {
        match err {
            ServerError::MessageDecodeError(err) => err.into(),
            ServerError::ChannelBusy { .. } => ErrorCode::ChannelBusy,
            ServerError::InvalidChannel { .. } => ErrorCode::InvalidChannel,
            ServerError::Other { .. } => ErrorCode::Other,
        }
    }
}

impl From<ServerError> for Message {
    fn from(err: ServerError) -> Self {
        match err {
            ServerError::MessageDecodeError(err) => err.into(),
            ServerError::ChannelBusy { new_chan, .. } => {
                ErrorCode::ChannelBusy.to_message(new_chan)
            }
            ServerError::InvalidChannel { chan } => ErrorCode::InvalidChannel.to_message(chan),
            ServerError::Other { chan, .. } => ErrorCode::Other.to_message(chan),
        }
    }
}

/// Entry point to the authenticator daemon
pub struct CTAPServer<T> {
    transport: T,
    logic: PacketProcessing,
    encoder: MessageEncoder,
}


impl<T> CTAPServer<T>
where
    T: HIDTransport + Unpin,
{
    /// Creates a handler given a transport for CTAP-HID reports,
    /// and an authenticator
    pub fn new(transport: T) -> Self {
        CTAPServer {
            transport,
            logic: PacketProcessing::new(),
            encoder: MessageEncoder::new(),
        }
    }

    /// Runs forever, processing CTAP-HID packets. May return early in case of a transport errors.
    pub async fn run<A>(&mut self, service: A) -> anyhow::Result<()>
    where A: Service<CTAP2Request, Response = CTAP2Response, Error = AuthServiceError> + Send + 'static,
          A::Future: 'static
    {
        let (ctap2_transport, req_send, mut res_recv) = CTAP2ServerTransport::new();
        let server = tokio_tower::pipeline::Server::new(ctap2_transport, service);
        let ls = tokio::task::LocalSet::new();
        let mut server_jh = ls.spawn_local(server);

        ls.run_until(async move {
            loop {
            tokio::select! {
                server_res = &mut server_jh => {
                    match server_res {
                        Ok(Ok(())) => return Ok(()),
                        Ok(Err(e)) => {
                            error!("There was an error in the CTAP2 server requiring it to shut down: {:?}", e);
                            return Err(e.into());
                        }
                        Err(e) => { 
                            error!("There was a panic in the CTAP2 server requiring it to shut down: {:?}", e);
                            return Err(e.into()) 
                        },
                    }
                }
                res = res_recv.recv() => {
                    let span = debug_span!("CTAP2 Response");
                    let _enter = span.enter();
                    if let Some(res) = res {
                        trace!(?res, "Writing CTAP2 Response message");
                        self.write_message(res.into()).await?;
                    } else {
                        return Ok(())
                    }
                },
                report = self.transport.next() => {
                    if let Some(report) = report {
                        let report = report?;
                        self.handle_report(&req_send, report).await?;
                    } else {
                        return Ok(());
                    }
                },
            };
            }
        }).await
    }

    async fn handle_report(&mut self, req_send: &UnboundedSender<CTAP2Request>, report: Vec<u8>) -> anyhow::Result<()> {
        let packet = Packet::from_report(report.as_ref());

        let channel = packet.get_channel();
        let span = debug_span!("Packet", ?channel);
        let _enter = span.enter();
        match self.logic.handle_packet(packet) {
            Ok(PacketProcessingResult::WaitingForMorePackets) => {},
            Ok(PacketProcessingResult::ResponseReady(message)) => {
                trace!(?message, "Writing a CTAP HID response message");
                self.write_message(message).await?;
            },
            Ok(PacketProcessingResult::CTAP2Request(message)) => {
                let ctap_req = CTAP2Request::try_from(&message);
                match ctap_req {
                    Ok(req) => {
                        req_send.send(req).map_err(|_| anyhow!("CTAP2 service crashe,d can't send request"))?;
                    } 
                    Err(auth_err) => { 
                        assert!(matches!(auth_err, AuthenticatorError::DeserializationError(_)));
                        error!("Error deserializing CBOR request: {:?}, bytes: {}", 
                                auth_err, hex::encode(&message.payload[1..]));
                        let err_msg = Message::from(&AuthServiceError::new(auth_err, message.channel_identifier));
                        self.write_message(err_msg).await?;
                    },
                };
            },
            Ok(PacketProcessingResult::Aborted) => {
                warn!("Aborted current CTAP-HID transaction");
            },
            Err(error) => {
                error!(?error, "Error while processing a CTAP-HID packet");
                let error_message = Message::from(error);
                self.write_message(error_message).await?;
            },
        };

        Ok(())

    }

    async fn write_message(&mut self, message: Message) -> anyhow::Result<()> {
        let mut buf = BytesMut::new();
        self.encoder.encode_message(&message, &mut buf)?;
        for chunk in buf.chunks_exact(HID_REPORT_SIZE as usize) {
            self.transport.send(chunk.to_owned()).await?;
        }
        trace!("Sent message");
        Ok(())
    }
}

