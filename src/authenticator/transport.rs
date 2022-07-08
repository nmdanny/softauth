use super::api::{AuthenticatorError, CTAP2Request, CTAP2Response};
use std::task::Poll;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// A stream of CTAP2 requests and sink of CTAP2 responses,
/// for use with [tokio_tower]
pub struct CTAP2ServerTransport {
    recv_req: UnboundedReceiver<CTAP2Request>,
    send_res: UnboundedSender<CTAP2Response>,
}

impl futures::sink::Sink<CTAP2Response> for CTAP2ServerTransport {
    type Error = AuthenticatorError;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: CTAP2Response) -> Result<(), Self::Error> {
        self.send_res
            .send(item)
            .map_err(|_| AuthenticatorError::ResponseSinkClosed)?;
        Ok(())
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl futures::stream::Stream for CTAP2ServerTransport {
    type Item = Result<CTAP2Request, AuthenticatorError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.recv_req.poll_recv(cx).map(|s| s.map(Ok))
    }
}

impl CTAP2ServerTransport {
    pub fn new() -> (
        Self,
        UnboundedSender<CTAP2Request>,
        UnboundedReceiver<CTAP2Response>,
    ) {
        let (send_req, recv_req) = tokio::sync::mpsc::unbounded_channel();
        let (send_res, recv_res) = tokio::sync::mpsc::unbounded_channel();
        (Self { recv_req, send_res }, send_req, recv_res)
    }
}
