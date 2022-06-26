use tracing::{info, trace};

use crate::hid::command::InvalidCommandType;

use super::{transport::{HIDTransport}, channel::{ChannelAllocator, BROADCAST_CHANNEL}, packet::{Message, MessageDecodeError, ChannelParseState, Packet}, command::ErrorCode};


#[derive(Debug)]
enum ServerState {
    Idle,
    Busy {
        chan: u32,
        decoder: ChannelParseState
    }
}

/// Handles CTAP-HID commands
pub struct CTAPServer {
    transport: Box<dyn HIDTransport>,
    chan_alloc: ChannelAllocator,
    state: ServerState
}

impl CTAPServer {
    /// Creates a handler given a transport for CTAP-HID messages.
    pub fn new<T: HIDTransport + 'static>(transport: T) -> Self {
        CTAPServer { transport: Box::new(transport), chan_alloc: ChannelAllocator::new(), state: ServerState::Idle }
    }

    /// Runs forever, processing CTAP-HID packets. May return early in case of a transport error.
    pub fn run(&mut self) -> anyhow::Result<()> {
        loop {
            let report = self.transport.receive_report()?;
            let packet = Packet::from_report(report.as_ref());
            trace!(?packet, "Received a CTAP-HID packet");
        }
    }
    

}