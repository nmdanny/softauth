use std::collections::HashSet;

use super::COSEAlgorithmIdentifier;
use coset::CoseKey;
use serde::{de::DeserializeOwned, Serialize};

pub trait CryptoKeyPair: Sized + Serialize + DeserializeOwned {
    fn to_public_cose_key(&self) -> CoseKey;
}

/// This trait encompasses the asymetric cryptographic operations required for the authenticator - creating key pairs and signing data with them,
/// supporting a variable number of algorithms according to the COSE specification
pub trait CryptoSystem {
    type Error: std::error::Error;
    type KeyPair: CryptoKeyPair;

    fn supported_algs(&self) -> Result<&HashSet<COSEAlgorithmIdentifier>, Self::Error>;

    fn is_supported_alg(&self, alg: COSEAlgorithmIdentifier) -> Result<bool, Self::Error> {
        Ok(self.supported_algs()?.contains(&alg))
    }

    fn generate_credential_keypair(
        &self,
        alg: COSEAlgorithmIdentifier,
    ) -> Result<Self::KeyPair, Self::Error>;

    fn sign_data(&self, keypair: &Self::KeyPair, data: &[u8]) -> Result<Vec<u8>, Self::Error>;
}
