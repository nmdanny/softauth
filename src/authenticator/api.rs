use std::{pin::Pin, task::Poll, sync::Arc};

use futures::Future;
use serde::Deserialize;
use tokio::sync::Mutex;
use thiserror::Error;
use tower::Service;
use tracing::trace;

use crate::{hid::{packet::Message, command::CommandType}, cbor::{key_mapped::{KeymappedStruct, Keymappable}, ordered_ser::make_ordered}};

use super::{command::{StatusCode, CTAPCommand}, types::{AuthenticatorGetInfoResponse, AuthenticatorMakeCredentialParams, AuthenticatorMakeCredentialResponse}, auth_impl::CTAP2ServiceImpl};



#[derive(Error, Debug)]
pub enum AuthenticatorError {
    #[error(transparent)]
    CTAPErrorStatus(#[from] StatusCode),

    #[error("Deserialization error: {0}")]
    DeserializationError(ciborium::de::Error<std::io::Error>),

    #[error("Cannot send response (response sink is closed)")]
    CannotSendResponse

}

/// Error message type retuned from the Service
#[derive(Error, Debug)]
#[error("Authenticator error on channel {channel_identifier}: {inner}")]
pub struct AuthServiceError {
    #[source]
    inner: AuthenticatorError,
    channel_identifier: u32,
}

impl AuthServiceError {
    pub fn new(inner: AuthenticatorError, channel_identifier: u32) -> Self {
        Self { inner, channel_identifier }
    }
}

impl From<&AuthServiceError> for Message {
    fn from(err: &AuthServiceError) -> Self {
        let status_code = match err.inner {
            AuthenticatorError::CTAPErrorStatus(status) => status,
            AuthenticatorError::DeserializationError(_) => StatusCode::Ctap2ErrInvalidCbor,
            AuthenticatorError::CannotSendResponse => StatusCode::Ctap1ErrOther,
        };
        Message { 
            channel_identifier:err.channel_identifier, 
            command: Ok(CommandType::Cbor), 
            payload: vec![status_code as u8] }
    }
}

#[derive(Debug)]
pub struct CTAP2Request {
    pub channel_identifier: u32,
    pub command: CTAP2Command
}

#[derive(Debug)]
pub enum CTAP2Command {
    GetInfo,
    MakeCredential(Box<AuthenticatorMakeCredentialParams>),
    Reset
}

impl CTAP2Command {
    pub fn from_ctap_cbor(command_byte: u8, payload: &[u8]) -> Result<Self, AuthenticatorError> {
        let cmd = CTAPCommand::try_from(command_byte)
            .map_err(|_| StatusCode::Ctap1ErrInvalidCommand)?;
        
        Ok(match cmd {
            CTAPCommand::MakeCredential => {
                let data: KeymappedStruct<_, u8> = ciborium::de::from_reader(payload)
                    .map_err(AuthenticatorError::DeserializationError)?;
                CTAP2Command::MakeCredential(Box::new(data.into_inner()))
            },
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
    MakeCredential(AuthenticatorMakeCredentialResponse),
    ResetOK
}

impl From<CTAP2ResponseData> for Vec<u8> {
    fn from(data: CTAP2ResponseData) -> Self {
        let mut buf = vec![StatusCode::Ctap1ErrSuccess as u8];
        let mut value = match data {
            CTAP2ResponseData::GetInfo(res) => {
                let km = KeymappedStruct::from(res);
                ciborium::value::Value::serialized(&km).unwrap()
            },
            CTAP2ResponseData::MakeCredential(res) => {
                let km = KeymappedStruct::from(res);
                ciborium::value::Value::serialized(&km).unwrap()
            },
            CTAP2ResponseData::ResetOK => { return buf }
        };
        make_ordered(&mut value);
        ciborium::ser::into_writer(&value, &mut buf).unwrap();
        trace!("CTAP2 Response CBOR bytes: {}", hex::encode(&buf[1..]));
        buf
    }
}

pub struct CTAP2Service {
    imp: Arc<Mutex<CTAP2ServiceImpl>>
}



impl Service<CTAP2Request> for CTAP2Service {
    type Response = CTAP2Response;

    type Error = AuthServiceError;

    type Future = Pin<Box<dyn 'static + Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: CTAP2Request) -> Self::Future {
        let imp = self.imp.clone();
        Box::pin(async move {
            let channel_identifier = req.channel_identifier;
            let mut imp = imp.lock().await;
            let data = imp.handle_command(req.command).await
                .map_err(|inner| AuthServiceError {
                    inner, channel_identifier
                })?;
            Ok(CTAP2Response { data, channel_identifier })
        })
    }
}



impl CTAP2Service {
    pub fn new() -> Self {
        CTAP2Service { imp: Arc::new(Mutex::new(CTAP2ServiceImpl::new())) }
    }

}
