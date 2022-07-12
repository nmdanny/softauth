use super::{COSEAlgorithmIdentifier, CoseKey};


pub struct KeyPair {
    private: CoseKey,
    public: CoseKey
}


/// This trait encompasses the asymetric cryptographic operations required for the authenticator - creating key pairs and signing data with them,
/// supporting a variable number of algorithms according to the COSE specification
trait CryptoSystem {
    type Error: std::error::Error;

    fn supported_algs(&self) -> Result<&[COSEAlgorithmIdentifier], Self::Error>;

    fn is_supported_alg(&self, alg: COSEAlgorithmIdentifier) -> Result<bool, Self::Error> {
        Ok(self.supported_algs()?.contains(&alg))
    }
    
    fn generate_credential_keypair(&self, alg: COSEAlgorithmIdentifier) -> Result<KeyPair, Self::Error>;

    fn sign_data(&self, private_key: &CoseKey, data: &[u8]) -> Result<Vec<u8>, Self::Error>;
}