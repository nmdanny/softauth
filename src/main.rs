mod hid;

use anyhow::Context;
use tokio::signal::ctrl_c;
use tracing::{event, span, Level};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    event!(Level::INFO, "Creating UHID device");
    let mut dev = hid::device::CTAPHIDDevice::new();
    event!(Level::INFO, "Created UHID device");
    event!(Level::INFO, "Destroyed UHID device");
    Ok(())
}
