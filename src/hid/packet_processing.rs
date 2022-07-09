use tracing::{warn, trace, error, instrument, debug_span};
use zerocopy::{LayoutVerified, AsBytes};

use crate::hid::{channel::{BROADCAST_CHANNEL, RESERVED_CHANNEL}, server::ServerError, command::{InitCommandResponse, CommandType, InvalidCommandType}};

use super::{channel::ChannelAllocator, packet::{Message, ChannelParseState, InitializationPacket, MessageDecodeError, Packet}, command::InitCommand};


/// Handles logic of CTAP-HID packet processing in a synchronous manner: 
/// - Allocating channels upon beginning a new transaction
/// - Tracking packet parse state
/// - Returning errors when given the wrong packet (unexpected or busy channel)
/// 
/// Does not handle timeouts, IO (includnig writing responses) or the actual logic of CTAP commands.
pub struct PacketProcessing {
    chan_alloc: ChannelAllocator,
    state: PacketProcessingState,
}


#[derive(Debug)]
enum PacketProcessingState {
    Idle,
    Busy {
        chan: u32,
        decoder: ChannelParseState,
    },
}


/// The result of processing a valid packet
#[derive(Debug, Clone)]
pub enum PacketProcessingResult {
    /// Waiting for continuation packets
    WaitingForMorePackets,

    /// An immediate response message is available. This is the case
    /// for simple commands (like CTAPHID_INIT)
    ResponseReady(Message),

    /// A CBOR request has been received, its handling
    /// should be delegated to another component.
    CTAP2Request(Message),

    /// The current transaction has been aborted (no response
    /// message is to be sent)
    Aborted
}

/// The result of a packet handler method in response to receiving a packet.
pub type HandlerResult = Result<PacketProcessingResult, ServerError>;

impl PacketProcessing {
    pub fn new() -> Self {
        PacketProcessing {
            chan_alloc: ChannelAllocator::new(),
            state: PacketProcessingState::Idle,
        }
    }

    pub fn is_busy(&self) -> bool {
        matches!(self.state, PacketProcessingState::Busy { .. })
    }

    pub fn abort_transaction(&mut self) {
        if let PacketProcessingState::Busy { chan, .. } = &self.state {
            warn!(?chan, "Aborted transaction");
        } else {
            warn!("Tried to abort a transaction while server is already idle")
        }
        self.state = PacketProcessingState::Idle;
    }

    pub fn begin_transaction(&mut self, init_packet: &InitializationPacket) -> HandlerResult {
        assert!(!self.is_busy(), "Cannot begin transaction while busy");
        let chan = init_packet.channel_identifier.get();
        match ChannelParseState::new(init_packet) {
            Ok(mut decoder) => {
                if let Some(message) = decoder.try_finish() {
                    self.state = PacketProcessingState::Busy { chan, decoder };
                    let result = self.process_message(message);
                    self.state = PacketProcessingState::Idle;
                    result
                } else {
                    trace!("Got an initialization packet, waiting for more");
                    assert!(
                        chan != RESERVED_CHANNEL && chan != BROADCAST_CHANNEL,
                        "Must not be broadcast"
                    );
                    self.state = PacketProcessingState::Busy { chan, decoder };
                    Ok(PacketProcessingResult::WaitingForMorePackets)
                }
            }
            Err(decode_err) => {
                error!(
                    ?decode_err,
                    "Decode error while parsing initialization packet"
                );
                Err(decode_err.into())
            }
        }
    }

    fn handle_init(&mut self, message: &Message) -> HandlerResult {
        let chan = message.channel_identifier;
        let msg = LayoutVerified::<_, InitCommand>::new_unaligned(message.payload.as_ref()).ok_or(
            MessageDecodeError::InvalidPayloadLength {
                chan,
                invalid_len: message.payload.len() as u16,
            },
        )?;

        let mut ret_msg = Message {
            channel_identifier: chan,
            command: message.command,
            payload: Vec::new(),
        };
        if chan == BROADCAST_CHANNEL {
            let new_cid = self.chan_alloc.allocate().ok_or_else(|| {
                error!("Could not allocate a channel, server full");
                ServerError::Other {
                    chan,
                    reason: "Could not allocate a channel".into(),
                }
            })?;
            ret_msg
                .payload
                .extend_from_slice(InitCommandResponse::new(msg.nonce, new_cid).as_bytes());
            trace!(?new_cid, "Allocated new channel");
            Ok(PacketProcessingResult::ResponseReady(ret_msg))
        } else {
            ret_msg
                .payload
                .extend_from_slice(InitCommandResponse::new(msg.nonce, chan).as_bytes());
            self.abort_transaction();
            Ok(PacketProcessingResult::ResponseReady(ret_msg))
        }
    }

    #[instrument(skip(self, message), level = "debug")]
    pub fn process_message(&mut self, message: Message) -> HandlerResult {
        let chan = message.channel_identifier;
        let command = message
            .command
            .map_err(|reason| MessageDecodeError::InvalidCommand { chan, reason })?;
        let span = debug_span!("Message", ?command);
        let _enter = span.enter();
        trace!(?command, "Processing message");
        match command {
            CommandType::Msg => error!("TODO U2F message"),
            CommandType::Cbor => return Ok(PacketProcessingResult::CTAP2Request(message)),
            CommandType::Init => return self.handle_init(&message),
            CommandType::Ping => return Ok(PacketProcessingResult::ResponseReady(message.clone())),
            CommandType::Cancel => error!("TODO cancel"),
            CommandType::Error => error!("Impossible - authenticator received an error message"),
            CommandType::Keepalive => {
                error!("Impossible - authenticator received a keepalive message")
            }
            CommandType::Wink => error!("TODO wink"),
            CommandType::Lock => error!("LOCK unsupported"),
        }
        Err(MessageDecodeError::InvalidCommand {
            chan,
            reason: InvalidCommandType::InvalidCommand(command.into()),
        }
        .into())
    }

    /// Handles a packet, may return a message to be written in response to the packet.
    pub fn handle_packet(&mut self, packet: Packet<&[u8]>) -> HandlerResult {
        trace!(
            ?packet,
            chan = packet.get_channel(),
            "Received a CTAP-HID packet"
        );
        let new_chan = packet.get_channel();

        if new_chan == RESERVED_CHANNEL {
            error!("Received invalid CID - reserved channel");
            return Err(ServerError::InvalidChannel { chan: new_chan });
        };

        if new_chan != BROADCAST_CHANNEL && !self.chan_alloc.is_allocated(new_chan) {
            error!(?new_chan, "Received a non-allocated channel");
            return Err(ServerError::InvalidChannel { chan: new_chan });
        }

        match (&mut self.state, packet) {
            (PacketProcessingState::Busy { chan, .. }, _) if new_chan != *chan => {
                error!(
                    ?new_chan,
                    cur_chan = chan,
                    "Got packet from a conflicting channel"
                );
                Err(ServerError::ChannelBusy {
                    busy_chan: *chan,
                    new_chan,
                })
            }
            (PacketProcessingState::Busy { chan, decoder }, Packet::InitializationPacket(init)) => {
                assert_eq!(new_chan, *chan, "Impossible");
                if [Ok(CommandType::Init), Ok(CommandType::Cancel)]
                    .contains(&init.get_command_type())
                {
                    // TODO: difference between abort and init
                    self.abort_transaction();
                    Ok(PacketProcessingResult::Aborted)
                } else {
                    error!(?decoder, "Received initialization packet that isn't INIT or CANCEL while busy, ignoring packet");
                    Err(ServerError::ChannelBusy {
                        busy_chan: *chan,
                        new_chan,
                    })
                }
            }
            (
                PacketProcessingState::Busy {
                    chan,
                    ref mut decoder,
                },
                Packet::ContinuationPacket(cont),
            ) => {
                assert_eq!(new_chan, *chan, "Impossible");
                match decoder.add_continuation_packet(&cont) {
                    Ok(()) if decoder.is_finished() => {
                        let message = decoder.try_finish().unwrap();
                        self.process_message(message)
                    }
                    Ok(()) => {
                        trace!(?decoder, "Got a continuation packet, waiting for more");
                        Ok(PacketProcessingResult::WaitingForMorePackets)
                    }
                    Err(error) => {
                        error!(
                            ?error,
                            ?decoder,
                            "Error while processing continuation packet, aborting transaction"
                        );
                        self.abort_transaction();
                        Err(error.into())
                    }
                }
            }
            (PacketProcessingState::Idle, Packet::ContinuationPacket(_)) => {
                error!(
                    "Received a continuation packet while an initialization packet was expected"
                );
                Err(MessageDecodeError::UnexpectedCont { chan: new_chan }.into())
            }
            (PacketProcessingState::Idle, Packet::InitializationPacket(init)) => {
                trace!("Received an initialization packet while idle, beginning new transaction");
                self.begin_transaction(&*init)
            }
        }
    }
}


