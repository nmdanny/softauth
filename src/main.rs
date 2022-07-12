mod hid;
mod authenticator;
mod cbor;


use tracing::{info, debug};


use crate::{hid::{server::CTAPServer, linux::uhid_transport::LinuxUHIDTransport}, authenticator::api::CTAP2Service};

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
