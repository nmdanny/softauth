use std::{pin::Pin, sync::Arc, task::Poll};

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tracing::{debug, error};
use uhid_virt::InputEvent;
use uhid_virt::StreamError;
use uhid_virt::UHID_EVENT_SIZE;
use uhid_virt::{OutputEvent, UHIDRead, UHIDWrite};

use crate::hid::{
    packet::HID_REPORT_SIZE,
    transport::{HIDTransport, TransportError},
};

use super::device::create_ctaphid_device;

pub struct LinuxUHIDTransport {
    recv_read: UnboundedReceiver<Result<Vec<u8>, TransportError>>,
    send_write: UnboundedSender<Vec<u8>>,
}

impl LinuxUHIDTransport {
    pub async fn new() -> anyhow::Result<Self> {
        let (send_read, recv_read) = unbounded_channel::<Result<Vec<u8>, TransportError>>();
        let (send_write, mut recv_write) = unbounded_channel::<Vec<u8>>();
        let mut file_rh = create_ctaphid_device()?;
        let mut file_wh = file_rh.try_clone()?;
        let read_jh = tokio::task::spawn_blocking(move || {
            loop {
                let event = file_rh
                    .read_output_event();
                match event {
                    Ok(OutputEvent::Output { mut data }) => {
                        // TODO: BUG: why do UHID output event come with an extra byte in the front?
                        data.remove(0);
                        if let Err(e) = send_read.send(Ok(data)) {
                            error!("UHID reader is closing due to send error: {:?}", e);
                            break;
                        }
                    }
                    Ok(event) => {
                        debug!(?event, "Got an OutputEvent which isn't Output, ignoring.");
                    },
                    Err(StreamError::Io(e)) => {
                        send_read.send(Err(TransportError::IoError(e)))
                            .unwrap_or_else(|_| error!("Couldn't send IO error to server"));
                        break;
                    },
                    Err(StreamError::UnknownEventType(e)) => {
                        error!("Received event of unknown type '{}', ignoring", e);
                    }
                }
            }
        });
        let write_jh = tokio::task::spawn_blocking(move || {
            while let Some(data) = recv_write.blocking_recv() {
                assert_eq!(data.len(), HID_REPORT_SIZE as usize, "Payload must fit HID Report size");
                file_wh
                    .write_input_event(&data)
                    .expect("Write task couldn't write input event");
            }
            file_wh
                .write_destroy_event()
                .expect("Write task couldn't write destroy event");
        });
        Ok(Self {
            recv_read,
            send_write,
        })
    }
}

impl futures::Stream for LinuxUHIDTransport {
    type Item = Result<Vec<u8>, TransportError>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.recv_read.poll_recv(cx)
    }
}

impl futures::Sink<Vec<u8>> for LinuxUHIDTransport {
    type Error = TransportError;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        self.send_write.send(item).map_err(|_| {
            TransportError::OtherError(anyhow::anyhow!("Couldn't queue message to be sent"))
        })?;
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl HIDTransport for LinuxUHIDTransport {}
