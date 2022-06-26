use thiserror::Error;
use bytes::BytesMut;
use tracing::{info, trace, debug_span, error, warn, instrument, debug, trace_span};

use crate::hid::command::{InvalidCommandType, CommandType};

use super::{transport::{HIDTransport}, channel::{ChannelAllocator, BROADCAST_CHANNEL}, packet::{Message, MessageDecodeError, ChannelParseState, Packet, MessageEncoder, HID_REPORT_SIZE, InitializationPacket}, command::ErrorCode};

#[derive(Debug, Error)]
pub enum ServerError {
    #[error(transparent)]
    MessageDecodeError (#[from] MessageDecodeError),

    #[error("Channel {busy_chan} is busy")]
    ChannelBusy { busy_chan: u32, new_chan: u32}
}

impl Into<Message> for ServerError {
    fn into(self) -> Message {
        match self {
            ServerError::MessageDecodeError(err) => err.into(),
            ServerError::ChannelBusy { new_chan, .. } => ErrorCode::ChannelBusy.to_message(new_chan)
        }
    }
}

#[derive(Debug)]
enum ServerState {
    Idle,
    Busy {
        chan: u32,
        decoder: ChannelParseState
    }
}


/// Handles logic of CTAP-HID packet processing, does not include
/// IO nor keepalive messages.
pub struct ServerLogic {
    chan_alloc: ChannelAllocator,
    state: ServerState
}

/// Entry point to the program
pub struct CTAPServer {
    transport: Box<dyn HIDTransport>,
    logic: ServerLogic,
    encoder: MessageEncoder,
}

impl CTAPServer {
    /// Creates a handler given a transport for CTAP-HID reports.
    pub fn new<T: HIDTransport + 'static>(transport: T) -> Self {
        CTAPServer { transport: Box::new(transport), 
                     logic: ServerLogic::new() ,
                     encoder: MessageEncoder::new()
                    }
    }

    /// Runs forever, processing CTAP-HID packets. May return early in case of a transport errors.
    pub fn run(&mut self) -> anyhow::Result<()> {
        let mut bytes = BytesMut::new();
        loop {
            let report = self.transport.receive_report()?;
            let packet = Packet::from_report(report.as_ref());
            let maybe_message = match self.logic.handle_packet(packet) {
                Ok(maybe_message) => maybe_message,
                Err(error) => Some(error.into())
            };
            if let Some(message) = maybe_message {
                self.write_message(message)?;
            }
        }
    }

    fn write_message(&mut self, message: Message) -> anyhow::Result<()> {
        let mut buf = BytesMut::new();
        self.encoder.encode_message(&message, &mut buf)?;
        for chunk in buf.chunks_exact(HID_REPORT_SIZE as usize) {
            self.transport.send_report(chunk)?;
        }
        Ok(())
    }
}


/// The result of a packet handler method - may return a message or an error
pub type HandlerResult = Result<Option<Message>, ServerError>;

impl ServerLogic {
    pub fn new() -> Self {
        ServerLogic { chan_alloc:  ChannelAllocator::new(), state: ServerState::Idle }
    }
    pub fn is_busy(&self) -> bool {
        if let ServerState::Busy { .. } = self.state {
            true
        } else {
            false
        }
    }


    pub fn abort_transaction(&mut self) {
        if let ServerState::Busy { chan, .. } = &self.state {
            warn!(?chan, "Aborted transaction");
        } else {
            warn!("Tried to abort a transaction while server is already idle")
        }
        self.state = ServerState::Idle;
    }

    pub fn begin_transaction(&mut self, init_packet: &InitializationPacket) -> HandlerResult {
        assert!(!self.is_busy(), "Cannot begin transaction while busy");
        let chan = init_packet.channel_identifier.get();
        match ChannelParseState::new(init_packet) {
            Ok(mut decoder) => {
                if decoder.is_finished() {
                    let message = decoder.try_finish().unwrap();
                    self.state = ServerState::Busy { chan, decoder };
                    return self.process_message(&message);
                } else {
                    trace!("Got an initialization packet, waiting for more");
                    self.state = ServerState::Busy { chan, decoder };
                    return Ok(None)
                }
            },
            Err(decode_err) => {
                error!(?decode_err, "Decode error while parsing initialization packet");
                return Err(decode_err.into())
            },
        };
    }

    #[instrument(skip(self), level = "debug")]
    pub fn process_message(&mut self, message: &Message) -> HandlerResult {
        debug!("Processing message");
        Ok(None)
    }

    /// Handles a packet, may return a message to be written in response to the packet.
    pub fn handle_packet(&mut self, packet: Packet<&[u8]>) -> HandlerResult {
        let span = trace_span!("Packet", ?self.state);
        let _enter = span.enter();
        trace!(?packet, chan=packet.get_channel(), "Received a CTAP-HID packet");

        match (packet.get_channel(), &mut self.state, packet) {
            (new_chan, ServerState::Busy { chan, .. }, _) if new_chan != *chan => {
                error!(?new_chan, cur_chan=chan, "Got packet from a conflicting channel");
                return Err(ServerError::ChannelBusy { busy_chan: *chan, new_chan });
            },
            (new_chan, ServerState::Busy { chan, decoder}, Packet::InitializationPacket(init)) => {
                assert_eq!(new_chan, *chan, "Impossible");
                if init.get_command_type() == Ok(CommandType::INIT) {
                    self.abort_transaction();
                    return Ok(None)
                } else if init.get_command_type() ==  Ok(CommandType::CANCEL) {
                    // TODO: difference between abort and init
                    self.abort_transaction();
                    return Ok(None)
                }
                else { 
                    error!(?decoder, "Received initialization packet that isn't INIT or CANCEL while busy, ignoring packet");
                    return Err(ServerError::ChannelBusy { busy_chan: *chan, new_chan });
                }
            },
            (new_chan, ServerState::Busy { chan, ref mut decoder}, Packet::ContinuationPacket(cont)) => {
                assert_eq!(new_chan, *chan, "Impossible");
                match decoder.add_continuation_packet(&cont) {
                    Ok(()) if decoder.is_finished() => { 
                        let message = decoder.try_finish().unwrap();
                        return self.process_message(&message);
                    },
                    Ok(()) => {
                        trace!(?decoder, "Got a continuation packet, waiting for more");
                        return Ok(None)
                    },
                    Err(error) => {
                        error!(?error, ?decoder, "Error while processing continuation packet, aborting transaction");
                        self.abort_transaction();
                        return Err(error.into())
                    },
                }

            },
            (new_chan, ServerState::Idle, Packet::ContinuationPacket(_)) => {
                error!("Received a continuation packet while an initialization packet was expected");
                return Err(MessageDecodeError::UnexpectedCont { chan: new_chan }.into());
            },
            (_, ServerState::Idle, Packet::InitializationPacket(init)) => {
                trace!("Received an initialization packet while idle, beginning new transaction");
                return self.begin_transaction(&*init);
            }
            _ => panic!("Impossible/missing branches")
        };
    }

    

}