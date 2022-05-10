use std::collections::{
    self,
    hash_map::{self, Entry},
    HashMap,
};

use super::{
    command::{CommandType, InvalidCommandType},
    device::HID_REPORT_SIZE,
};
use bytes::{Buf, BufMut};
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};
use tracing::{event, Level};
use zerocopy::{AsBytes, BigEndian, ByteSlice, FromBytes, LayoutVerified, Unaligned, U16, U32};

/// A 'Packet' is the PDU of the CTAP-HID protocol. It has a fixed size which equals to
/// the size of a single HID report (as defined in [HID_REPORT_SIZE])
///
/// See https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-message-and-packet-structure
///
#[derive(Debug)]
pub enum Packet<B: ByteSlice> {
    Initialization(LayoutVerified<B, InitializationPacket>),
    Continuation(LayoutVerified<B, ContinuationPacket>),
}

impl<B: ByteSlice> Packet<B> {
    pub fn get_channel_identifier(&self) -> u32 {
        match self {
            Packet::Initialization(init) => init.channel_identifier.into(),
            Packet::Continuation(cont) => cont.channel_identifier.into(),
        }
    }

    pub fn get_data(&self) -> &[u8] {
        match self {
            Packet::Initialization(init) => &init.data,
            Packet::Continuation(cont) => &cont.data,
        }
    }
}

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
    channel_identifier: U32<BigEndian>,
    command_identifier: u8,
    payload_length: U16<BigEndian>,
    data: [u8; INIT_PACKET_PAYLOAD_SIZE],
}

#[repr(C)]
#[derive(FromBytes, AsBytes, Unaligned, Debug)]
pub struct ContinuationPacket {
    channel_identifier: U32<BigEndian>,
    packet_sequence: u8,
    data: [u8; CONT_PACKET_PAYLOAD_SIZE],
}

/// A message re-assembled from one or more CTAP-HID packets, but yet to have
/// its payload decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    channel_identifier: u32,
    command: Result<CommandType, InvalidCommandType>,
    payload: Vec<u8>,
}

struct ChannelParseState {
    wip_message: Message,
    remaining_payload_length: usize,
    next_seq_num: u8,
}

impl ChannelParseState {
    fn new(init: &InitializationPacket) -> Result<Self, MessageDecodeError> {
        if init.payload_length.get() as usize > MAX_MESSAGE_PAYLOAD_SIZE {
            return Err(MessageDecodeError::MalformedPacket(format!(
                "Got a packet with payload length of {}, max is {}",
                init.payload_length.get(),
                MAX_MESSAGE_PAYLOAD_SIZE
            )));
        }

        let command = CommandType::from_packet_command_identifier(init.command_identifier);
        let channel_identifier = init.channel_identifier.get();

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
            wip_message,
            remaining_payload_length,
            next_seq_num: 0,
        })
    }

    fn finished(&self) -> bool {
        return self.remaining_payload_length == 0;
    }

    fn finish(self) -> Message {
        if !self.finished() {
            panic!("Tried to finish a message with missing packets");
        }
        return self.wip_message;
    }

    fn add_continuation_packet(
        &mut self,
        cont: &ContinuationPacket,
    ) -> Result<(), MessageDecodeError> {
        assert_eq!(
            cont.channel_identifier.get(),
            self.wip_message.channel_identifier
        );
        if self.finished() {
            return Err(MessageDecodeError::UnexpectedCont);
        }
        if cont.packet_sequence != self.next_seq_num {
            return Err(MessageDecodeError::UnexpectedSeq {
                expected: self.next_seq_num,
                gotten: cont.packet_sequence,
            });
        }
        if cont.packet_sequence > MAX_SEQ_NUM {
            // impossible because if seq is at 0x80 or above,
            // we would've parsed an initialization packet instead.
            panic!("Impossible state - got too many continuation packets");
        }
        let bytes_to_take = self.remaining_payload_length.min(cont.data.len());
        self.wip_message
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
    #[error("Got IO error while decoding message packets: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Expected a continuation packet with seq {expected}, got {gotten}")]
    UnexpectedSeq { expected: u8, gotten: u8 },

    #[error("Expected a continuation packet with seq {expected_seq}, got initialization instead.")]
    UnexpectedInit { expected_seq: u8 },

    #[error("Expected an initialization packet, got a continuation packet instead.")]
    UnexpectedCont,

    #[error("Got a malformed packet: {0}")]
    MalformedPacket(String),
}

impl MessageDecoder {
    fn decode_initialization_packet(&mut self, report: &bytes::BytesMut) -> Result<Option<Message>, MessageDecodeError> {
        assert_eq!(report.len(), HID_REPORT_SIZE as usize);
        assert_ne!(report[4] & 0x80, 0);
        let packet =
            LayoutVerified::<&[u8], InitializationPacket>::new_unaligned(report.as_ref())
                .unwrap();
        match self.chan_packets.entry(packet.channel_identifier.get()) {
            Entry::Occupied(ent) => {
                return Err(MessageDecodeError::UnexpectedInit {
                    expected_seq: ent.get().next_seq_num,
                })
            }
            Entry::Vacant(ent) => {
                let parse_state = ChannelParseState::new(&packet)?;
                if parse_state.finished() {
                    return Ok(Some(parse_state.finish()));
                } else {
                    ent.insert(parse_state);
                }
            }
        }
        Ok(None)
    }

    fn decode_continuation_packet(&mut self, report: &bytes::BytesMut) -> Result<Option<Message>, MessageDecodeError> {
        assert_eq!(report.len(), HID_REPORT_SIZE as usize);
        assert_eq!(report[4] & 0x80, 0);
        let packet =
            LayoutVerified::<&[u8], ContinuationPacket>::new_unaligned(report.as_ref())
                .unwrap();
        match self.chan_packets.entry(packet.channel_identifier.get()) {
            Entry::Occupied(mut ent) => {
                let parse_state = ent.get_mut();
                parse_state.add_continuation_packet(&packet)?;
                if parse_state.finished() {
                    let (_, parse_state) = ent.remove_entry();
                    return Ok(Some(parse_state.finish()));
                }
            }
            Entry::Vacant(_) => return Err(MessageDecodeError::UnexpectedCont),
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
            let maybe_message = if report[4] & 0x80 != 0 {
                self.decode_initialization_packet(&report)?
            } else {
                self.decode_continuation_packet(&report)?
            };
            if maybe_message.is_some() {
                return Ok(maybe_message)
            }
        }
        return Ok(None);
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
        MessageEncoder {  }
    }
}

fn split_to_packet_payloads<'a>(
    payload: &'a [u8],
) -> (
    [u8; INIT_PACKET_PAYLOAD_SIZE],
    impl Iterator<Item = [u8; CONT_PACKET_PAYLOAD_SIZE]> + 'a,
) {
    let mut init_payload = [0u8; INIT_PACKET_PAYLOAD_SIZE];
    let init_payload_size = INIT_PACKET_PAYLOAD_SIZE.min(payload.len());
    init_payload[..init_payload_size].copy_from_slice(&payload[..init_payload_size]);

    let payload = &payload[init_payload_size..];
    let it = payload.chunks(CONT_PACKET_PAYLOAD_SIZE).map(|chunk| {
        let mut cont_payload = [0u8; CONT_PACKET_PAYLOAD_SIZE];
        let cont_payload_size = CONT_PACKET_PAYLOAD_SIZE.min(chunk.len());
        cont_payload[..cont_payload_size].copy_from_slice(&chunk[..cont_payload_size]);
        return cont_payload;
    });

    return (init_payload, it);
}

impl Encoder<Message> for MessageEncoder {
    type Error = MessageEncoderError;

    fn encode(&mut self, item: Message, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        if item.payload.len() > MAX_MESSAGE_PAYLOAD_SIZE {
            return Err(MessageEncoderError::PayloadTooLarge {
                got: item.payload.len(),
                max: MAX_MESSAGE_PAYLOAD_SIZE,
            });
        }
        assert_eq!(dst.len(), 0, "Initial write buffer wasn't empty");

        let (init_payload, other_payloads) = split_to_packet_payloads(&item.payload);

        let init_packet = InitializationPacket {
            channel_identifier: item.channel_identifier.into(),
            payload_length: (item.payload.len() as u16).into(),
            command_identifier: u8::from(
                item.command
                    .expect("Cannot encode message with unsupported command"),
            ) | 0x80,
            data: init_payload,
        };
        dst.put(init_packet.as_bytes());

        for (seq, payload) in other_payloads.enumerate() {
            assert!(seq < 0x80, "Impossible, tried writing too many packets");
            let cont_payload = ContinuationPacket {
                channel_identifier: item.channel_identifier.into(),
                packet_sequence: (seq as u8).into(),
                data: payload,
            };
            dst.put(cont_payload.as_bytes());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tokio_util::codec::{FramedWrite, FramedRead};

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
        let raw = expected
            .iter()
            .map(|v| v.clone())
            .flatten()
            .collect::<Vec<_>>();
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
            command: Ok(CommandType::MSG),
            payload: vec![1, 3, 3, 7]
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
            command: Ok(CommandType::MSG),
            payload: vec![1u8; INIT_PACKET_PAYLOAD_SIZE + CONT_PACKET_PAYLOAD_SIZE * 2 + 5]
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
