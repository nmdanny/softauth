use thiserror::Error;

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("IO error during HID transport: {0}")]
    IoError(#[from] std::io::Error),

    #[error(transparent)]
    OtherError(#[from] anyhow::Error),
}

/// An abstraction for sending or receiving CTAP HID input/output reports, with a fixed size of 
/// [HID_REPORT_SIZE] bytes. 
pub trait HIDTransport {
    fn send_report(&mut self, data: &[u8]) -> Result<(), TransportError>;

    fn receive_report(&mut self) -> Result<Vec<u8>, TransportError>;
}