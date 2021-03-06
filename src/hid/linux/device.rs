use std::fs::File;

use std::io;
use uhid_virt::{create_uhid_device_file, Bus, CreateParams};

use crate::hid::packet::HID_REPORT_SIZE;

#[rustfmt::skip]
static CTAP_REPORT_DESCRIPTOR: &[u8] = &[
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

pub fn create_ctaphid_device() -> io::Result<File> {
    let params = CreateParams {
        name: "Software CTAP2".to_owned(),
        phys: "Phys".to_owned(),
        uniq: "Uniq".to_owned(),
        // TODO: somehow Bus::USB is ignored by hidapi 'hid_enumerate' (used by google ctap2 test tool),
        // but Bluetooth works
        bus: Bus::BLUETOOTH,
        vendor: 1337,
        product: 1337,
        country: 1337,
        version: 1,
        rd_data: CTAP_REPORT_DESCRIPTOR.to_owned(),
    };
    create_uhid_device_file(params, None)
}
