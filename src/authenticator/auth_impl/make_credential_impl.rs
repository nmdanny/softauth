use crate::authenticator::{
    api::{AuthenticatorError, CTAP2ResponseData},
    types::AuthenticatorMakeCredentialParams,
};

use super::CTAP2ServiceImpl;

impl CTAP2ServiceImpl {
    pub async fn handle_make_credential(
        &mut self,
        params: AuthenticatorMakeCredentialParams,
    ) -> Result<CTAP2ResponseData, AuthenticatorError> {
        todo!()
    }
}
