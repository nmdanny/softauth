mod authenticator;
mod cbor;
mod hid;

use tracing::{debug, info};

use crate::{
    authenticator::api::CTAP2Service,
    hid::{linux::uhid_transport::LinuxUHIDTransport, server::CTAPServer},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    info!("Creating UHID transport");
    let transport = LinuxUHIDTransport::new().await?;
    debug!("Created UHID transport");
    let authenticator = CTAP2Service::new();
    let mut server = CTAPServer::new(transport);
    server.run(authenticator).await?;
    info!("Daemon is stopping");
    Ok(())
}
