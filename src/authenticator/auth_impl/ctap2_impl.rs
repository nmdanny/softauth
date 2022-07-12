use crate::authenticator::{
    api::{AuthenticatorError, CTAP2Command, CTAP2ResponseData},
    types::AuthenticatorGetInfoResponse,
};

pub struct CTAP2ServiceImpl {}

impl CTAP2ServiceImpl {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn handle_command(
        &mut self,
        command: CTAP2Command,
    ) -> Result<CTAP2ResponseData, AuthenticatorError> {
        match command {
            CTAP2Command::GetInfo => Ok(CTAP2ResponseData::GetInfo(
                AuthenticatorGetInfoResponse::default(),
            )),
            CTAP2Command::MakeCredential(params) => self.handle_make_credential(*params).await,
            CTAP2Command::Reset => self.reset_device().await,
        }
    }

    pub async fn reset_device(&mut self) -> Result<CTAP2ResponseData, AuthenticatorError> {
        // TODO: resetting a device
        Ok(CTAP2ResponseData::ResetOK)
    }
}
