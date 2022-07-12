use std::collections::{hash_map::Entry, HashMap};

use super::{
    channel::BROADCAST_CHANNEL,
    command::{CommandType, ErrorCode, InvalidCommandType},
};
use bytes::BufMut;

use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

use zerocopy::{AsBytes, BigEndian, ByteSlice, FromBytes, LayoutVerified, Unaligned, U16, U32};

/// Size of an input or output HID report in bytes,
/// equal to the size of a CTAP-HID packet.
pub const HID_REPORT_SIZE: u8 = 64;

/// Payload size(bytes) of a CTAP-HID initialization packet
const INIT_PACKET_PAYLOAD_SIZE: usize = HID_REPORT_SIZE as usize - 7;

/// Payload size(bytes) of a CTAP-HID continuation packet
const CONT_PACKET_PAYLOAD_SIZE: usize = HID_REPORT_SIZE as usize - 5;

/// Maximal payload size(bytes) of a CTAP-HID message
const MAX_MESSAGE_PAYLOAD_SIZE: usize =
    INIT_PACKET_PAYLOAD_SIZE + CONT_PACKET_PAYLOAD_SIZE * (MAX_SEQ_NUM as usize + 1);

/// The max amount of packets belonging to a single CTAP-HID message.
const MAX_SEQ_NUM: u8 = 0x7f;

#[repr(C)]
#[derive(FromBytes, AsBytes, Unaligned, Debug)]
pub struct InitializationPacket {
    pub channel_identifier: U32<BigEndian>,
    pub command_identifier: u8,
    pub payload_length: U16<BigEndian>,
    pub data: [u8; INIT_PACKET_PAYLOAD_SIZE],
}

impl InitializationPacket {
    pub fn get_command_type(&self) -> Result<CommandType, InvalidCommandType> {
        CommandType::from_packet_command_identifier(self.command_identifier)
    }
}

#[repr(C)]
#[derive(FromBytes, AsBytes, Unaligned, Debug)]
pub struct ContinuationPacket {
    pub channel_identifier: U32<BigEndian>,
    pub packet_sequence: u8,
    pub data: [u8; CONT_PACKET_PAYLOAD_SIZE],
}

/// A CTAP-HID packet
#[derive(Debug)]
pub enum Packet<B: ByteSlice> {
    InitializationPacket(LayoutVerified<B, InitializationPacket>),
    ContinuationPacket(LayoutVerified<B, ContinuationPacket>),
}

impl<B: ByteSlice> Packet<B> {
    /// Creates a packet from a HID report whose size is assumed to be [HID_REPORT_SIZE]
    pub fn from_report(report: B) -> Self {
        assert_eq!(
            report.len(),
            HID_REPORT_SIZE as usize,
            "Packet size must match HID_REPORT_SIZE"
        );
        if report[4] & 0x80 != 0 {
            Packet::InitializationPacket(LayoutVerified::new_unaligned(report).unwrap())
        } else {
            Packet::ContinuationPacket(LayoutVerified::new_unaligned(report).unwrap())
        }
    }

    pub fn get_channel(&self) -> u32 {
        match self {
            Packet::InitializationPacket(init) => init.channel_identifier.get(),
            Packet::ContinuationPacket(cont) => cont.channel_identifier.get(),
        }
    }
}

/// A message re-assembled from one or more CTAP-HID packets, but yet to have
/// its payload decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub channel_identifier: u32,
    pub command: Result<CommandType, InvalidCommandType>,
    pub payload: Vec<u8>,
}

/// State used for parsing a single CTAP-HID message.
#[derive(Debug)]
pub struct ChannelParseState {
    wip_message: Option<Message>,
    channel_identifier: u32,
    remaining_payload_length: usize,
    next_seq_num: u8,
}

impl ChannelParseState {
    /// Initializes the parse state with an initialization packet. Returns an
    /// error if the packet is malformed.
    pub fn new(init: &InitializationPacket) -> Result<Self, MessageDecodeError> {
        let channel_identifier = init.channel_identifier.get();
        let command = CommandType::from_packet_command_identifier(init.command_identifier);
        if init.payload_length.get() as usize > MAX_MESSAGE_PAYLOAD_SIZE {
            return Err(MessageDecodeError::InvalidPayloadLength {
                chan: channel_identifier,
                invalid_len: init.payload_length.get(),
            });
        }

        let total_payload_length = init.payload_length.get() as usize;
        let mut payload = Vec::new();
        payload.reserve_exact(total_payload_length);

        let bytes_to_take = init.data.len().min(total_payload_length);
        payload.extend_from_slice(&init.data[..bytes_to_take]);
        let remaining_payload_length = total_payload_length - bytes_to_take;

        let wip_message = Message {
            channel_identifier,
            command,
            payload,
        };
        Ok(ChannelParseState {
            channel_identifier: wip_message.channel_identifier,
            wip_message: Some(wip_message),
            remaining_payload_length,
            next_seq_num: 0,
        })
    }

    pub fn is_finished(&self) -> bool {
        self.remaining_payload_length == 0
    }

    /// Tries to finish parsing and return the finally assembled message.
    pub fn try_finish(&mut self) -> Option<Message> {
        if !self.is_finished() {
            return None;
        }
        self.wip_message.take()
    }

    /// Advances the parser by adding a continuation packet, assumed to
    /// belong to the same channel as the initialization packet. An error
    /// is returned if the continuation packet is malformed or unexpected.
    pub fn add_continuation_packet(
        &mut self,
        cont: &ContinuationPacket,
    ) -> Result<(), MessageDecodeError> {
        assert_eq!(
            cont.channel_identifier.get(),
            self.channel_identifier,
            "Got ContinuationPacket with wrong channel ID"
        );
        if self.is_finished() || self.wip_message.is_none() {
            return Err(MessageDecodeError::UnexpectedCont {
                chan: self.channel_identifier,
            });
        }
        if cont.packet_sequence != self.next_seq_num {
            return Err(MessageDecodeError::UnexpectedSeq {
                expected: self.next_seq_num,
                gotten: cont.packet_sequence,
                chan: self.channel_identifier,
            });
        }
        if cont.packet_sequence > MAX_SEQ_NUM {
            // impossible because if seq is at 0x80 or above,
            // we would've parsed an initialization packet instead.
            panic!("Impossible state - got too many continuation packets");
        }
        let bytes_to_take = self.remaining_payload_length.min(cont.data.len());
        self.wip_message
            .as_mut()
            .unwrap()
            .payload
            .extend_from_slice(&cont.data[..bytes_to_take]);
        self.remaining_payload_length -= bytes_to_take;
        self.next_seq_num += 1;
        Ok(())
    }
}

/// Responsible for decoding HID packets. Packets might arrive from multiple
/// channels and will be parsed independently of each other(no channel locking is required yet),
/// but are assumed to arrive in-order within each channel.
pub struct MessageDecoder {
    // maps each channel id to state of message being parsed at that channel.
    chan_packets: HashMap<u32, ChannelParseState>,
}

impl MessageDecoder {
    pub fn new() -> Self {
        MessageDecoder {
            chan_packets: HashMap::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum MessageDecodeError {
    #[error("[chan {chan}] Expected a continuation packet with seq {expected}, got {gotten}")]
    UnexpectedSeq { expected: u8, gotten: u8, chan: u32 },

    #[error("[chan {chan}] Expected a continuation packet with seq {expected_seq}, got initialization instead.")]
    UnexpectedInit { expected_seq: u8, chan: u32 },

    #[error("[chan {chan}] Expected an initialization packet, got a continuation packet instead.")]
    UnexpectedCont { chan: u32 },

    #[error("[chan {chan}] Got a packet whose payload length {invalid_len} is invalid.")]
    InvalidPayloadLength { chan: u32, invalid_len: u16 },

    #[error("[chan {chan}] Got an invalid command: {reason}")]
    InvalidCommand {
        chan: u32,
        reason: InvalidCommandType,
    },

    #[error("[chan {chan}] Got an invalid parameter: {reason}")]
    InvalidParameter { chan: u32, reason: String },

    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

impl MessageDecodeError {
    pub fn get_channel(&self) -> u32 {
        match self {
            MessageDecodeError::UnexpectedSeq { chan, .. } => *chan,
            MessageDecodeError::UnexpectedInit { chan, .. } => *chan,
            MessageDecodeError::UnexpectedCont { chan } => *chan,
            MessageDecodeError::InvalidPayloadLength { chan, .. } => *chan,
            MessageDecodeError::InvalidParameter { chan, .. } => *chan,
            MessageDecodeError::InvalidCommand { chan, .. } => *chan,
            MessageDecodeError::IoError(..) => BROADCAST_CHANNEL,
        }
    }
}

impl From<MessageDecodeError> for ErrorCode {
    fn from(err: MessageDecodeError) -> Self {
        match err {
            MessageDecodeError::UnexpectedSeq { .. } => ErrorCode::InvalidSeq,
            MessageDecodeError::UnexpectedInit { .. } => ErrorCode::Other,
            MessageDecodeError::UnexpectedCont { .. } => ErrorCode::Other,
            MessageDecodeError::InvalidPayloadLength { .. } => ErrorCode::InvalidLen,
            MessageDecodeError::InvalidCommand { .. } => ErrorCode::InvalidCmd,
            MessageDecodeError::InvalidParameter { .. } => ErrorCode::InvalidPar,
            MessageDecodeError::IoError(..) => ErrorCode::Other,
        }
    }
}

impl From<MessageDecodeError> for Message {
    fn from(err: MessageDecodeError) -> Self {
        let channel = err.get_channel();
        let err_code: ErrorCode = err.into();
        err_code.to_message(channel)
    }
}

impl MessageDecoder {
    /// Resets a channel's parse state, must be invoked after encountering a decode error belonging to a channel.
    pub fn reset_channel(&mut self, chan: u32) {
        self.chan_packets.remove(&chan);
    }

    /// Decodes a new CTAP HID report, updating the state of the decoder, and may also return the final
    /// decoded message if this was the last packet for said message.
    pub fn decode_packet<B: AsRef<[u8]>>(
        &mut self,
        report: B,
    ) -> Result<Option<Message>, MessageDecodeError> {
        let report = report.as_ref();
        assert_eq!(
            report.len(),
            HID_REPORT_SIZE as usize,
            "Buffer size doesn't match expected HID REPORT SIZE"
        );
        if report[4] & 0x80 != 0 {
            self.decode_initialization_packet(report)
        } else {
            self.decode_continuation_packet(report)
        }
    }

    /// Tries decoding a new initialization packet. On decode success, might
    /// return the message if it was entirely contained in the packet's payload.
    fn decode_initialization_packet<B: AsRef<[u8]>>(
        &mut self,
        report: B,
    ) -> Result<Option<Message>, MessageDecodeError> {
        let report = report.as_ref();
        assert_eq!(
            report.len(),
            HID_REPORT_SIZE as usize,
            "Buffer size doesn't match expected HID REPORT SIZE"
        );
        assert_ne!(
            report[4] & 0x80,
            0,
            "MSB of 4th byte must be set in an initialization packet"
        );
        let packet = LayoutVerified::<&[u8], InitializationPacket>::new_unaligned(report).unwrap();
        match self.chan_packets.entry(packet.channel_identifier.get()) {
            Entry::Occupied(ent) => {
                return Err(MessageDecodeError::UnexpectedInit {
                    expected_seq: ent.get().next_seq_num,
                    chan: packet.channel_identifier.get(),
                })
            }
            Entry::Vacant(ent) => {
                let mut parse_state = ChannelParseState::new(&packet)?;
                match parse_state.try_finish() {
                    Some(message) => return Ok(Some(message)),
                    None => {
                        ent.insert(parse_state);
                    }
                }
            }
        }
        Ok(None)
    }

    /// Tries decoding a continuation packet. On decode success, if it was
    /// the final packet of a message - returns that message.
    fn decode_continuation_packet<B: AsRef<[u8]>>(
        &mut self,
        report: B,
    ) -> Result<Option<Message>, MessageDecodeError> {
        let report = report.as_ref();
        assert_eq!(
            report.len(),
            HID_REPORT_SIZE as usize,
            "Buffer size doesn't match expected HID REPORT SIZE"
        );
        assert_eq!(
            report[4] & 0x80,
            0,
            "MSB of 4th byte must not be set in a continuation packet"
        );
        let packet = LayoutVerified::<&[u8], ContinuationPacket>::new_unaligned(report).unwrap();
        match self.chan_packets.entry(packet.channel_identifier.get()) {
            Entry::Occupied(mut ent) => {
                let parse_state = ent.get_mut();
                parse_state.add_continuation_packet(&packet)?;
                if parse_state.is_finished() {
                    let (_, mut parse_state) = ent.remove_entry();
                    return Ok(Some(parse_state.try_finish().unwrap()));
                }
            }
            Entry::Vacant(_) => {
                return Err(MessageDecodeError::UnexpectedCont {
                    chan: packet.channel_identifier.get(),
                })
            }
        }
        Ok(None)
    }
}

impl Decoder for MessageDecoder {
    type Item = Message;

    type Error = MessageDecodeError;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < HID_REPORT_SIZE as usize {
            return Ok(None);
        }
        // Try to decode as many packets as possible in the buffer,
        // stopping once we get at least one complete message or
        // run out of input.
        while src.len() >= HID_REPORT_SIZE as usize {
            let report = src.split_to(HID_REPORT_SIZE as usize);
            let maybe_message = self.decode_packet(report)?;
            if maybe_message.is_some() {
                return Ok(maybe_message);
            }
        }
        Ok(None)
    }
}

#[derive(Debug, Error)]
pub enum MessageEncoderError {
    #[error("Got IO error while encoding message: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Got message payload of {got} bytes, but maximum is {max} bytes")]
    PayloadTooLarge { got: usize, max: usize },
}

pub struct MessageEncoder {}
impl MessageEncoder {
    pub fn new() -> Self {
        MessageEncoder {}
    }

    pub fn encode_message(
        &self,
        message: &Message,
        dest: &mut bytes::BytesMut,
    ) -> Result<(), MessageEncoderError> {
        if message.payload.len() > MAX_MESSAGE_PAYLOAD_SIZE {
            return Err(MessageEncoderError::PayloadTooLarge {
                got: message.payload.len(),
                max: MAX_MESSAGE_PAYLOAD_SIZE,
            });
        }
        assert_eq!(dest.len(), 0, "Initial write buffer wasn't empty");

        let (init_payload, other_payloads) = split_to_packet_payloads(&message.payload);

        let init_packet = InitializationPacket {
            channel_identifier: message.channel_identifier.into(),
            payload_length: (message.payload.len() as u16).into(),
            command_identifier: u8::from(
                message
                    .command
                    .expect("Cannot encode message with unsupported command"),
            ) | 0x80,
            data: init_payload,
        };
        dest.put(init_packet.as_bytes());

        for (seq, payload) in other_payloads.enumerate() {
            assert!(seq < 0x80, "Impossible, tried writing too many packets");
            let cont_payload = ContinuationPacket {
                channel_identifier: message.channel_identifier.into(),
                packet_sequence: (seq as u8),
                data: payload,
            };
            dest.put(cont_payload.as_bytes());
        }

        assert_eq!(
            dest.len() % HID_REPORT_SIZE as usize,
            0,
            "Encoded message bytes must be divisible by HID_REPORT_SIZE"
        );
        Ok(())
    }
}

fn split_to_packet_payloads(
    payload: &[u8],
) -> (
    [u8; INIT_PACKET_PAYLOAD_SIZE],
    impl Iterator<Item = [u8; CONT_PACKET_PAYLOAD_SIZE]> + '_,
) {
    let mut init_payload = [0u8; INIT_PACKET_PAYLOAD_SIZE];
    let init_payload_size = INIT_PACKET_PAYLOAD_SIZE.min(payload.len());
    init_payload[..init_payload_size].copy_from_slice(&payload[..init_payload_size]);

    let payload = &payload[init_payload_size..];
    let it = payload.chunks(CONT_PACKET_PAYLOAD_SIZE).map(|chunk| {
        let mut cont_payload = [0u8; CONT_PACKET_PAYLOAD_SIZE];
        let cont_payload_size = CONT_PACKET_PAYLOAD_SIZE.min(chunk.len());
        cont_payload[..cont_payload_size].copy_from_slice(&chunk[..cont_payload_size]);
        cont_payload
    });

    (init_payload, it)
}

impl Encoder<Message> for MessageEncoder {
    type Error = MessageEncoderError;

    fn encode(&mut self, item: Message, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        self.encode_message(&item, dst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split_to_vecs(d: &[u8]) -> Vec<Vec<u8>> {
        let (first, rest) = split_to_packet_payloads(d);
        let mut vecs = vec![first.to_vec()];
        for chunk in rest {
            vecs.push(chunk.to_vec())
        }
        vecs
    }

    #[test]
    fn test_split_to_packet_payloads_short() {
        let short = [1, 2, 3];
        let short_res = split_to_vecs(&short);
        let expected = {
            let mut vec = vec![0; INIT_PACKET_PAYLOAD_SIZE];
            vec[..3].copy_from_slice(&[1, 2, 3]);
            vec![vec]
        };
        assert_eq!(short_res, expected);
    }

    #[test]
    fn test_split_to_packet_payloads_full_init() {
        let full = vec![1u8; INIT_PACKET_PAYLOAD_SIZE];
        let expected = vec![vec![1u8; INIT_PACKET_PAYLOAD_SIZE]];
        assert_eq!(split_to_vecs(&full), expected);
    }

    #[test]
    fn test_split_to_packet_payloads_two_full() {
        let expected = vec![
            vec![1u8; INIT_PACKET_PAYLOAD_SIZE],
            vec![2u8; CONT_PACKET_PAYLOAD_SIZE],
        ];
        let raw = expected.iter().flatten().cloned().collect::<Vec<_>>();
        assert_eq!(split_to_vecs(&raw), expected);
    }

    #[test]
    fn test_split_to_packet_full_init_partial_cont() {
        let raw = vec![1u8; INIT_PACKET_PAYLOAD_SIZE + 3];
        let mut expected = vec![
            vec![1u8; INIT_PACKET_PAYLOAD_SIZE],
            vec![0u8; CONT_PACKET_PAYLOAD_SIZE],
        ];
        expected[1][..3].copy_from_slice(&[1, 1, 1]);

        assert_eq!(split_to_vecs(&raw), expected);

        let raw = vec![1u8; INIT_PACKET_PAYLOAD_SIZE + CONT_PACKET_PAYLOAD_SIZE + 5];
        let mut expected = vec![
            vec![1u8; INIT_PACKET_PAYLOAD_SIZE],
            vec![1u8; CONT_PACKET_PAYLOAD_SIZE],
            vec![0u8; CONT_PACKET_PAYLOAD_SIZE],
        ];
        expected[2][..5].copy_from_slice(&[1, 1, 1, 1, 1]);
        assert_eq!(split_to_vecs(&raw), expected);
    }

    #[test]
    fn test_encode_decode_short_msg() {
        let msg = Message {
            channel_identifier: 1337,
            command: Ok(CommandType::Msg),
            payload: vec![1, 3, 3, 7],
        };

        let mut buf = bytes::BytesMut::new();
        let mut encoder = MessageEncoder::new();
        let mut decoder = MessageDecoder::new();

        encoder.encode(msg.clone(), &mut buf).unwrap();
        assert_eq!(buf.len(), HID_REPORT_SIZE as usize);

        let res = decoder.decode(&mut buf).unwrap();

        assert_eq!(res, Some(msg));

        let res_2 = decoder.decode(&mut buf).unwrap();
        assert_eq!(res_2, None);
    }

    #[test]
    pub fn test_encode_decode_longer_msg() {
        let msg = Message {
            channel_identifier: 1337,
            command: Ok(CommandType::Msg),
            payload: vec![1u8; INIT_PACKET_PAYLOAD_SIZE + CONT_PACKET_PAYLOAD_SIZE * 2 + 5],
        };

        let mut buf = bytes::BytesMut::new();
        let mut encoder = MessageEncoder::new();
        let mut decoder = MessageDecoder::new();

        encoder.encode(msg.clone(), &mut buf).unwrap();
        assert_eq!(buf.len(), HID_REPORT_SIZE as usize * 4);

        let res = decoder.decode(&mut buf).unwrap();

        assert_eq!(res, Some(msg));

        let res_2 = decoder.decode(&mut buf).unwrap();
        assert_eq!(res_2, None);
    }
}
