use std::convert::TryFrom;
use std::fs::{File, OpenOptions};
use std::io::{self, prelude::*};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::codec::*;


pub trait UHIDRead {
    /// Reads a queued output event. No reaction is required to an output event, but you should handle them according to your needs.
   fn read_output_event(&mut self) -> Result<OutputEvent, StreamError>;
}

impl <T: Read> UHIDRead for T {
    fn read_output_event(&mut self) -> Result<OutputEvent, StreamError> {
        let mut event = [0u8; UHID_EVENT_SIZE];
        self.read_exact(&mut event)
            .map_err(StreamError::Io)?;
        OutputEvent::try_from(event)
    }
}

pub trait UHIDWrite {
    /// The data parameter should contain a data-payload. This is the raw data that you read from your device. The kernel will parse the HID reports.
    fn write_input_event(&mut self, data: &[u8]) -> io::Result<()>;


    /// This destroys the internal HID device. No further I/O will be accepted. There may still be pending output events that you can receive but no further input events can be sent to the kernel.
    fn write_destroy_event(&mut self) -> io::Result<()>;
}

impl <T: Write> UHIDWrite for T {
    fn write_input_event(&mut self, data: &[u8]) -> io::Result<()> {
        let event: [u8; UHID_EVENT_SIZE] = InputEvent::Input { data }.into();
        self.write_all(&event)
    }

    fn write_destroy_event(&mut self) -> io::Result<()> {
        let event: [u8; UHID_EVENT_SIZE] = InputEvent::Destroy.into();
        self.write_all(&event)
    }
}

/// Contains information about your HID device, sent when UHIDDevice is created
#[derive(Debug, Clone, PartialEq)]
pub struct CreateParams {
    pub name: String,
    pub phys: String,
    pub uniq: String,
    pub bus: Bus,
    pub vendor: u32,
    pub product: u32,
    pub version: u32,
    pub country: u32,
    pub rd_data: Vec<u8>,
}

/// Opens a UHID character device at given path, or /dev/uhid if no path is provided.
pub fn create_uhid_device_file(params: CreateParams, path: Option<&Path>) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    options.write(true);
    if cfg!(unix) {
        options.custom_flags(libc::O_RDWR | libc::O_CLOEXEC);
    }
    let path = path.unwrap_or(Path::new("/dev/uhid"));
    let mut handle = options.open(path)?;
    let event: [u8; UHID_EVENT_SIZE] = InputEvent::Create(params).into();
    handle.write_all(&event)?;
    Ok(handle)
}
