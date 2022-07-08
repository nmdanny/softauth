use std::{pin::Pin, task::Poll};

use futures::{Future, FutureExt};
use thiserror::Error;
use tower::Service;

use crate::{hid::{packet::Message, command::CommandType}, cbor::key_mapped::KeymappedStruct};

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
    GetInfo
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
            CTAPCommand::Reset => todo!(),
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

#[derive(Debug)]
pub enum CTAP2ResponseData {
    GetInfo(AuthenticatorGetInfoResponse)
}

impl Into<Vec<u8>> for CTAP2ResponseData {

    fn into(self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            CTAP2ResponseData::GetInfo(res) => {
                let km = KeymappedStruct::from(res);
                ciborium::ser::into_writer(&km, &mut buf).unwrap();
            },
        }
        buf
    }
}

pub struct CTAP2Service {

}

impl Service<CTAP2Request> for CTAP2Service {
    type Response = CTAP2Response;

    type Error = AuthenticatorError;

    type Future = Pin<Box<dyn Send + Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: CTAP2Request) -> Self::Future {
        Box::pin(async move {
            let channel_identifier = req.channel_identifier;
            let data = match req.command {
                CTAP2Command::GetInfo => CTAP2ResponseData::GetInfo(AuthenticatorGetInfoResponse::default()),
            };
            Ok(CTAP2Response { data, channel_identifier })
        })
    }
}


impl CTAP2Service {
    pub fn new() -> Self {
        Self {}
    }
}
