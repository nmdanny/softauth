use std::{pin::Pin, task::Poll, sync::Arc};

use futures::Future;
use tokio::sync::Mutex;
use thiserror::Error;
use tower::Service;
use tracing::trace;

use crate::{hid::{packet::Message, command::CommandType}, cbor::{key_mapped::KeymappedStruct, ordered_ser::make_ordered}};

use super::{command::{StatusCode, CTAPCommand}, types::AuthenticatorGetInfoResponse};

#[derive(Error, Debug)]
pub enum AuthenticatorError {
    #[error(transparent)]
    CTAPErrorStatus(#[from] StatusCode),

    #[error("Cannot send CTAP response as HID server is closed")]
    ResponseSinkClosed,

    #[error("Cannot receive CTAP requests as HID server is closed")]
    RequestSinkClosed
}

#[derive(Debug)]
pub struct CTAP2Request {
    pub channel_identifier: u32,
    pub command: CTAP2Command
}

#[derive(Debug)]
pub enum CTAP2Command {
    GetInfo,
    Reset
}

impl CTAP2Command {
    pub fn from_ctap_cbor(command_byte: u8, payload: &[u8]) -> Result<Self, AuthenticatorError> {
        let cmd = CTAPCommand::try_from(command_byte)
            .map_err(|_| StatusCode::Ctap1ErrInvalidCommand)?;
        
        Ok(match cmd {
            CTAPCommand::MakeCredential => todo!(),
            CTAPCommand::GetAssertion => todo!(),
            CTAPCommand::GetNextAssertion => todo!(),
            CTAPCommand::GetInfo => CTAP2Command::GetInfo,
            CTAPCommand::GetClientPin => todo!(),
            CTAPCommand::Reset => CTAP2Command::Reset,
            CTAPCommand::BioEnrollment => todo!(),
            CTAPCommand::Selection => todo!(),
            CTAPCommand::LargeBlobs => todo!(),
            CTAPCommand::Config => todo!(),
        })
    }
}

impl TryFrom<&Message> for CTAP2Request {
    type Error = AuthenticatorError;

    fn try_from(value: &Message) -> Result<Self, Self::Error> {
        assert_eq!(value.command, Ok(CommandType::Cbor), "Message passed must be a CBOR message");
        if value.payload.is_empty() {
            return Err(StatusCode::Ctap1ErrInvalidLength.into());
        }
        let channel_identifier = value.channel_identifier;
        let command_byte = value.payload[0];
        let payload = &value.payload[1..];
        let command = CTAP2Command::from_ctap_cbor(command_byte, payload)?;
        Ok(CTAP2Request { command, channel_identifier })
        
    }
}

#[derive(Debug)]
pub struct CTAP2Response {
    pub channel_identifier: u32,
    pub data: CTAP2ResponseData
}

impl From<CTAP2Response> for Message {
    fn from(res: CTAP2Response) -> Self {
        let channel_identifier = res.channel_identifier;
        let command = Ok(CommandType::Cbor);
        let payload: Vec<u8> = res.data.into();
        Message { channel_identifier, command, payload } 
    }
}

#[derive(Debug)]
pub enum CTAP2ResponseData {
    GetInfo(AuthenticatorGetInfoResponse),
    ResetOK
}

impl From<CTAP2ResponseData> for Vec<u8> {
    fn from(data: CTAP2ResponseData) -> Self {
        let mut buf = vec![StatusCode::Ctap1ErrSuccess as u8];
        match data {
            CTAP2ResponseData::GetInfo(res) => {
                let km = KeymappedStruct::from(res);
                let mut value = ciborium::value::Value::serialized(&km).unwrap();
                make_ordered(&mut value);
                ciborium::ser::into_writer(&value, &mut buf).unwrap();
            },
            CTAP2ResponseData::ResetOK => {}
        }
        trace!("CTAP2 Response CBOR bytes: {}", hex::encode(&buf[1..]));
        buf
    }
}

pub struct CTAP2Service {
    imp: Arc<Mutex<CTAP2ServiceImpl>>
}



impl Service<CTAP2Request> for CTAP2Service {
    type Response = CTAP2Response;

    type Error = AuthenticatorError;

    type Future = Pin<Box<dyn 'static + Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: CTAP2Request) -> Self::Future {
        let imp = self.imp.clone();
        Box::pin(async move {
            let channel_identifier = req.channel_identifier;
            let mut imp = imp.lock().await;
            let data = imp.handle_command(req.command).await?;
            Ok(CTAP2Response { data, channel_identifier })
        })
    }
}



impl CTAP2Service {
    pub fn new() -> Self {
        CTAP2Service { imp: Arc::new(Mutex::new(CTAP2ServiceImpl::new())) }
    }

}

struct CTAP2ServiceImpl {}

impl CTAP2ServiceImpl {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn handle_command(&mut self, command: CTAP2Command) -> Result<CTAP2ResponseData, AuthenticatorError> {
        match command {
            CTAP2Command::GetInfo => Ok(CTAP2ResponseData::GetInfo(AuthenticatorGetInfoResponse::default())),
            CTAP2Command::Reset => {
                self.reset_device().await
            }
        }

    }

    pub async fn reset_device(&mut self) -> Result<CTAP2ResponseData, AuthenticatorError> {
        // TODO: resetting a device
        Ok(CTAP2ResponseData::ResetOK)
    }
}
