use num_enum::{IntoPrimitive, TryFromPrimitive};
use thiserror::Error;

/// A CTAP-HID command (note that the MSB isn't set, unlike in the wire protocol)
/// See https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-commands
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
pub enum CommandType {
    MSG = 0x03,
    CBOR = 0x10,
    INIT = 0x06,
    PING = 0x01,
    CANCEL = 0x11,
    ERROR = 0x3F,
    KEEPALIVE = 0x3B,
    // optional:
    WINK = 0x08,
    LOCK = 0x04,
}

const CTAPHID_VENDOR_FIRST: u8 = 0x40;
const CTAPHID_VENDOR_LAST: u8 = 0x7F;


#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum InvalidCommandType {
    #[error("'{0}' is a vendor command identifier, and thus unsupported")]
    UnsupportedVendor(u8),

    #[error("'{0}' is not a valid CTAP-HID command identifier")]
    InvalidCommand(u8)
}

impl CommandType {
    /// Parses a command identifier from CTAP-HID packet
    pub fn from_packet_command_identifier(mut command_identifier: u8) -> Result<CommandType, InvalidCommandType> {
        assert!(command_identifier & 0x80 != 0, "Command identifier MSB must be set");
        command_identifier &= 0x7F;
        if command_identifier >= CTAPHID_VENDOR_FIRST && command_identifier <= CTAPHID_VENDOR_LAST {
            return Err(InvalidCommandType::UnsupportedVendor(command_identifier));
        }
        return CommandType::try_from(command_identifier)
            .map_err(|_| InvalidCommandType::InvalidCommand(command_identifier))
    }
}