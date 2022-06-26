use num_enum::{IntoPrimitive, TryFromPrimitive};
use thiserror::Error;
use zerocopy::{FromBytes, AsBytes, Unaligned, U32, BigEndian, U64};

use super::packet::Message;

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

/// Error codes that may be sent as part of a response message, see 
/// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#usb-hid-error
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
pub enum ErrorCode {
    InvalidCmd = 0x01, 	// The command in the request is invalid
    InvalidPar = 0x02, 	// The parameter(s) in the request is invalid
    InvalidLen = 0x03, 	// The length field (BCNT) is invalid for the request
    InvalidSeq = 0x04, 	// The sequence does not match expected value
    MsgTimeout = 0x05, 	// The message has timed out
    ChannelBusy = 0x06, 	// The device is busy for the requesting channel. The client SHOULD retry the request after a short delay. Note that the client MAY abort the transaction if the command is no longer relevant.
    LockRequired = 0x0A, 	// Command requires channel lock
    InvalidChannel = 0x0B, 	// CID is not valid.
    Other = 0x7F 	// Unspecified error 
}

impl ErrorCode {
    pub fn to_message(self, channel_identifier: u32) -> Message {
        Message { channel_identifier, command: Ok(CommandType::ERROR), payload: vec![self.into() ] }
    }
}

#[repr(C)]
#[derive(FromBytes, AsBytes, Unaligned, Debug)]
pub struct InitCommand {
    pub nonce: [u8; 8]
}

#[repr(C)]
#[derive(FromBytes, AsBytes, Unaligned, Debug)]
pub struct InitCommandResponse {
    pub nonce: [u8; 8],
    pub channel_id: U32<BigEndian>,
    pub ctaphid_version: u8,
    pub major_device_version: u8,
    pub minor_device_version: u8,
    pub build_device_version: u8,
    pub capabilities_flag: u8
}

const CAPABILITY_WINK: u8 = 0x01;
const CAPABILITY_CBOR: u8 = 0x04;
const CAPABILITY_NMSG: u8 = 0x08;

impl InitCommandResponse {
    pub fn new(nonce: [u8; 8], channel_id: u32) -> Self {
        InitCommandResponse { 
            nonce: nonce, 
            channel_id: channel_id.into(),
            ctaphid_version: 2,
            major_device_version: 0, 
            minor_device_version: 0, 
            build_device_version: 0, 
            capabilities_flag: CAPABILITY_CBOR | CAPABILITY_NMSG
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
pub enum KeepaliveStatus {
    Processing = 1,
    Upneeded = 2,
}
