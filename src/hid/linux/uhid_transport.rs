use tracing::{error, debug};
use uhid_virt::{UHIDWrite, UHIDRead, OutputEvent};

use crate::hid::transport::{HIDTransport, TransportError};

use super::device::create_ctaphid_device;

pub struct LinuxUHIDTransport {
    file: std::fs::File
}

impl LinuxUHIDTransport {
    pub fn new() -> std::io::Result<Self> {
        let file = create_ctaphid_device()?;
        Ok(Self { file })
    }
}

impl Drop for LinuxUHIDTransport {
    fn drop(&mut self) {
        if let Err(e) =  self.file.write_destroy_event() {
            error!("Couldn't write UHID destroy event for linux UHID file: {:?}", e);
            return;
        }
        debug!("UHID destroy event written");
    }
}

impl HIDTransport for LinuxUHIDTransport {
    fn send_report(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.file.write_input_event(data)
            .map_err(TransportError::IoError)
    }

    fn receive_report(&mut self) -> Result<Vec<u8>, TransportError> {
        loop {
            let res = self.file.read_output_event()
                .map_err(anyhow::Error::new)?;
            match res {
                OutputEvent::Output { mut data } => { 
                    // TODO: BUG: why do UHID output event come with an extra byte in the front?
                    data.remove(0);    
                    return Ok(data) 
                },
                event => {
                    debug!(?event, "Got an OutputEvent which isn't Output, ignoring.");
                }
            }
        }

    }
}