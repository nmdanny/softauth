use async_trait::async_trait;
use futures::Future;

use super::types::{PublicKeyCredentialDescriptor, CredentialId, RpId};




#[async_trait]
pub trait Storage {
    type Error : std::error::Error;


    async fn get_credential_by_id(&self, cred_id: CredentialId) -> Result<Option<PublicKeyCredentialDescriptor>, Self::Error>;

    async fn get_credentials_for_rp(&self, rp_id: RpId) -> Result<Vec<PublicKeyCredentialDescriptor>, Self::Error>;
}