use thiserror::Error;
use bytes::BytesMut;
use tracing::{trace, debug_span, error, warn, instrument};
use zerocopy::{LayoutVerified, AsBytes};

use crate::hid::{command::{InvalidCommandType, CommandType}, channel::RESERVED_CHANNEL};

use super::{transport::{HIDTransport}, channel::{ChannelAllocator, BROADCAST_CHANNEL}, packet::{Message, MessageDecodeError, ChannelParseState, Packet, MessageEncoder, HID_REPORT_SIZE, InitializationPacket}, command::{ErrorCode, InitCommand, InitCommandResponse}};


/// An error that occurs during processing of a CTAP-HID packet/transaction. 
#[derive(Debug, Error)]
pub enum ServerError {
    #[error(transparent)]
    MessageDecodeError (#[from] MessageDecodeError),

    #[error("[chan {new_chan}] Server is busy on channel {busy_chan}")]
    ChannelBusy { busy_chan: u32, new_chan: u32},

    #[error("[chan {chan}] Invalid channel")]
    InvalidChannel { chan: u32 },

    #[error("[chan {chan}] Misc error")]
    Other { chan: u32, reason: String}
}

impl From<ServerError> for ErrorCode {
    fn from(err: ServerError) -> Self {
        match err {
            ServerError::MessageDecodeError(err) => err.into(),
            ServerError::ChannelBusy { .. } => ErrorCode::ChannelBusy,
            ServerError::InvalidChannel { .. } => ErrorCode::InvalidChannel,
            ServerError::Other { .. } => ErrorCode::Other
        }
    }
}

impl From<ServerError> for Message {
    fn from(err: ServerError) -> Self {
        match err {
            ServerError::MessageDecodeError(err) => err.into(),
            ServerError::ChannelBusy { new_chan, .. } => ErrorCode::ChannelBusy.to_message(new_chan),
            ServerError::InvalidChannel { chan } => ErrorCode::InvalidChannel.to_message(chan),
            ServerError::Other { chan, .. } => ErrorCode::Other.to_message(chan)
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
/// IO, keepalive messages or timeouts.
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
        loop {
            let report = self.transport.receive_report()?;
            let packet = Packet::from_report(report.as_ref());

            let span = debug_span!("Packet");
            let _enter = span.enter();
            let maybe_message = match self.logic.handle_packet(packet) {
                Ok(maybe_message) => maybe_message,
                Err(error) => Some(error.into())
            };
            if let Some(message) = maybe_message {
                trace!(?message, "Writing a message");
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
        matches!(self.state, ServerState::Busy {..})
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
                if let Some(message) = decoder.try_finish() {
                    self.state = ServerState::Busy { chan, decoder };
                    let result = self.process_message(&message);
                    self.state = ServerState::Idle;
                    result
                } else {
                    trace!("Got an initialization packet, waiting for more");
                    assert!(chan != RESERVED_CHANNEL && chan != BROADCAST_CHANNEL, "Must not be broadcast");
                    self.state = ServerState::Busy { chan, decoder };
                    Ok(None)
                }
            },
            Err(decode_err) => {
                error!(?decode_err, "Decode error while parsing initialization packet");
                Err(decode_err.into())
            },
        }
    }

    fn handle_init(&mut self, message: &Message) -> HandlerResult {
        let chan = message.channel_identifier;
        let msg = LayoutVerified::<_, InitCommand>::new_unaligned(message.payload.as_ref())
            .ok_or(MessageDecodeError::InvalidPayloadLength { chan, invalid_len: message.payload.len() as u16})?;
        
        let mut ret_msg = Message {
            channel_identifier: chan,
            command: message.command,
            payload: Vec::new()
        };
        if chan == BROADCAST_CHANNEL {
            let new_cid = self.chan_alloc.allocate().ok_or_else(|| {
                error!("Could not allocate a channel, server full");
                ServerError::Other { chan, reason: "Could not allocate a channel".into() }
            })?;
            ret_msg.payload.extend_from_slice(InitCommandResponse::new(msg.nonce, new_cid).as_bytes());
            trace!(?new_cid, "Allocated new channel");
            Ok(Some(ret_msg))
        } else {
            ret_msg.payload.extend_from_slice(InitCommandResponse::new(msg.nonce, chan).as_bytes());
            self.abort_transaction();
            Ok(Some(ret_msg))
        }
    }

    #[instrument(skip(self), level = "debug")]
    pub fn process_message(&mut self, message: &Message) -> HandlerResult {
        let chan = message.channel_identifier;
        let command = message.command.map_err(|reason| MessageDecodeError::InvalidCommand { chan, reason })?;
        trace!("Processing message");
        match command {
            CommandType::Msg => error!("TODO U2F message"),
            CommandType::Cbor => error!("TODO CBOR"),
            CommandType::Init => return self.handle_init(message),
            CommandType::Ping => return Ok(Some(message.clone())),
            CommandType::Cancel => error!("TODO cancel"),
            CommandType::Error => error!("Impossible - authenticator received an error message"),
            CommandType::Keepalive => error!("Impossible - authenticator received a keepalive message"),
            CommandType::Wink => error!("TODO wink"),
            CommandType::Lock => error!("LOCK unsupported"),
        }
        Err(MessageDecodeError::InvalidCommand { chan, reason: InvalidCommandType::InvalidCommand(command.into()) }
            .into())
    }

    /// Handles a packet, may return a message to be written in response to the packet.
    pub fn handle_packet(&mut self, packet: Packet<&[u8]>) -> HandlerResult {
        trace!(?packet, chan=packet.get_channel(), "Received a CTAP-HID packet");
        let new_chan = packet.get_channel();

        if new_chan == RESERVED_CHANNEL {
            error!("Received invalid CID - reserved channel");
            return Err(ServerError::InvalidChannel { chan: new_chan })
        };

        if new_chan != BROADCAST_CHANNEL && !self.chan_alloc.is_allocated(new_chan) {
            error!(?new_chan, "Received a non-allocated channel");
            return Err(ServerError::InvalidChannel { chan: new_chan })
        }

        match (&mut self.state, packet) {
            (ServerState::Busy { chan, .. }, _) if new_chan != *chan => {
                error!(?new_chan, cur_chan=chan, "Got packet from a conflicting channel");
                Err(ServerError::ChannelBusy { busy_chan: *chan, new_chan })
            },
            (ServerState::Busy { chan, decoder}, Packet::InitializationPacket(init)) => {
                assert_eq!(new_chan, *chan, "Impossible");
                if [Ok(CommandType::Init), Ok(CommandType::Cancel)].contains(&init.get_command_type()) {
                    // TODO: difference between abort and init
                    self.abort_transaction();
                    Ok(None)
                }
                else { 
                    error!(?decoder, "Received initialization packet that isn't INIT or CANCEL while busy, ignoring packet");
                    Err(ServerError::ChannelBusy { busy_chan: *chan, new_chan })
                }
            },
            (ServerState::Busy { chan, ref mut decoder}, Packet::ContinuationPacket(cont)) => {
                assert_eq!(new_chan, *chan, "Impossible");
                match decoder.add_continuation_packet(&cont) {
                    Ok(()) if decoder.is_finished() => { 
                        let message = decoder.try_finish().unwrap();
                        self.process_message(&message)
                    },
                    Ok(()) => {
                        trace!(?decoder, "Got a continuation packet, waiting for more");
                        Ok(None)
                    },
                    Err(error) => {
                        error!(?error, ?decoder, "Error while processing continuation packet, aborting transaction");
                        self.abort_transaction();
                        Err(error.into())
                    },
                }

            },
            (ServerState::Idle, Packet::ContinuationPacket(_)) => {
                error!("Received a continuation packet while an initialization packet was expected");
                Err(MessageDecodeError::UnexpectedCont { chan: new_chan }.into())
            },
            (ServerState::Idle, Packet::InitializationPacket(init)) => {
                trace!("Received an initialization packet while idle, beginning new transaction");
                self.begin_transaction(&*init)
            }
        }
    }

    

}