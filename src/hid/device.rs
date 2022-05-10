use std::fs::File;

use std::io;
use uhid_virt::{Bus, CreateParams, UHIDDevice};
use tracing::{Level, event};

/// Size of an input or output HID report in bytes,
/// equal to the size of a CTAP-HID packet.
pub const HID_REPORT_SIZE: u8 = 40;


static CTAP_REPORT_DESCRIPTOR: &'static [u8] = &[
    0x06, 0xD0, 0xF1, // HID_UsagePage ( FIDO_USAGE_PAGE ),
    0x09, 0x01, // HID_Usage ( FIDO_USAGE_CTAPHID ),
    0xA1, 0x01, // HID_Collection ( HID_Application ),
    0x09, 0x20, // HID_Usage ( FIDO_USAGE_DATA_IN ),
    0x15, 0x00, // HID_LogicalMin ( 0 ),
    0x26, 0xFF, 0x00, // HID_LogicalMaxS ( 0xff ),
    0x75, 0x08, // HID_ReportSize ( 8 ),
    0x95, HID_REPORT_SIZE, // HID_ReportCount ( HID_INPUT_REPORT_BYTES ),
    0x81, 0x02, // HID_Input ( HID_Data | HID_Absolute | HID_Variable ),
    0x09, 0x21, // HID_Usage ( FIDO_USAGE_DATA_OUT ),
    0x15, 0x00, // HID_LogicalMin ( 0 ),
    0x26, 0xFF, 0x00, // HID_LogicalMaxS ( 0xff ),
    0x75, 0x08, // HID_ReportSize ( 8 ),
    0x95, HID_REPORT_SIZE, // HID_ReportCount ( HID_OUTPUT_REPORT_BYTES ),
    0x91, 0x02, // HID_Output ( HID_Data | HID_Absolute | HID_Variable ),
    0xC0, // HID_EndCollection
];

/// Encapsulates access to a CTAP HID device
pub struct CTAPHIDDevice {
    dev: UHIDDevice<File>,
}


impl CTAPHIDDevice {
    pub fn new() -> io::Result<Self> {
        let params = CreateParams {
            name: "Software CTAP2".to_owned(),
            phys: "Phys".to_owned(),
            uniq: "Uniq".to_owned(),
            bus: Bus::USB,
            vendor: 0,
            product: 0,
            country: 0,
            version: 0,
            rd_data: CTAP_REPORT_DESCRIPTOR.to_owned(),
        };
        let dev = UHIDDevice::create(params)?;
        Ok(CTAPHIDDevice { dev })
    }
}

impl Drop for CTAPHIDDevice {
    fn drop(&mut self) {
        let res = self.dev.destroy();
        if let Err(e) = res {
            event!(Level::ERROR, "Couldn't destroy uhid device: {:?}", e);
        }
    }
}
