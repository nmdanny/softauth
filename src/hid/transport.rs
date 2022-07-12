#[allow(unused)]
use super::packet::HID_REPORT_SIZE;
use futures::{Future, Sink, Stream};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("IO error during HID transport: {0}")]
    IoError(#[from] std::io::Error),

    #[error(transparent)]
    OtherError(#[from] anyhow::Error),
}

/// A HID transport is a sink and stream of CTAP HID input/output reports respectively, each
/// with a fixed size of [HID_REPORT_SIZE] bytes.
pub trait HIDTransport:
    Sink<Vec<u8>, Error = TransportError> + Stream<Item = Result<Vec<u8>, TransportError>>
{
}
