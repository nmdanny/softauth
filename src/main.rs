mod hid;
mod authenticator;

use anyhow::Context;
use tracing::{info, debug};
use uhid_virt::UHIDWrite;

use crate::hid::{server::CTAPServer, linux::uhid_transport::LinuxUHIDTransport};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    info!("Creating UHID transport");
    let transport = LinuxUHIDTransport::new()?;
    debug!("Created UHID transport");
    let mut server = CTAPServer::new(transport);
    server.run();
    Ok(())
}
