use modular_bitfield::{bitfield, prelude::B3};
use serde::{Deserialize, Serialize, ser::SerializeTuple};

use crate::authenticator::crypto::COSEAlgorithmIdentifier;

use super::{Aaguid, Extension};

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialPrivateKey(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialPublicKey(pub Vec<u8>);

/// Identifies the relying party(RP) of a credential.
/// [See more](https://w3c.github.io/webauthn/#rp-id)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpId(pub String);

/// Identifies a credential.
/// [See more](https://w3c.github.io/webauthn/#credential-id)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialId(pub Vec<u8>);

/// Identifies a user's account within a particular RP.
/// [See more](https://w3c.github.io/webauthn/#dom-publickeycredentialuserentity-id)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserHandle(#[serde(with = "serde_bytes")] pub Vec<u8>);

/// Used by the authenticator to create assertions. This is essentially
/// the entire data
/// [See more](https://www.w3.org/TR/webauthn/#public-key-credential-source)
#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialSource {
    #[serde(rename = "type")]
    pub _type: PublicKeyType,
    pub id: CredentialId,
    pub rp_id: RpId,
    pub private_key: CredentialPrivateKey,
    pub user_handle: Option<UserHandle>,
}

/// Currently there's only 1 source type (public key)
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyType {
    #[serde(rename = "public-key")]
    PublicKey,
}

/// Note, in an attestation signature(after 'authenticatorMakeCredentials'), the 'attested_cred_data' must be set
/// - it contains the public key which the RP stores.
/// In an assertion signature(after 'authenticatorGetAssertion'), it mustn't be set.
/// [See more](https://www.w3.org/TR/webauthn/#authenticator-data)
#[derive(Debug)]
pub struct AuthenticatorData {
    pub rp_id_hash: u32,
    pub flags: AuthenticatorDataFlags,
    pub counter: u32,
    pub attested_cred_data: Option<AttestedCredData>,
    pub extensions: Option<Vec<Extension>>,
}

impl Serialize for AuthenticatorData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        let n_fields = 3 + (self.attested_cred_data.is_some() as u8) + (self.extensions.is_some() as u8);
        let mut tup = serializer.serialize_tuple(n_fields as usize)?;
        tup.serialize_element(&self.rp_id_hash)?;
        assert_eq!(self.flags.bytes.len(), 1, "AuthenticatorDataFlags must be 1 byte");
        tup.serialize_element(&self.flags.bytes[0])?;
        tup.serialize_element(&self.counter)?;
        if let Some(attested_cred_data) = &self.attested_cred_data {
            tup.serialize_element(attested_cred_data)?;
        }
        if let Some(extensions) = &self.extensions {
            tup.serialize_element(extensions)?;
        }
        tup.end()
    }
}

#[bitfield]
#[derive(Debug, Serialize, Deserialize)]
/// [See more](https://www.w3.org/TR/webauthn/#authenticator-data)
pub struct AuthenticatorDataFlags {
    pub user_present: bool,
    pub rfu_1: bool,
    pub user_verified: bool,
    pub rfu_2: B3,
    pub attested_data_included: bool,
    pub extension_data_included: bool,
}

/// [See more](https://www.w3.org/TR/webauthn/#attested-credential-data)
#[derive(Debug)]
pub struct AttestedCredData {
    pub aaguid: Aaguid,
    pub credential_id_length: u16,
    pub credential_id: CredentialId,
    pub credential_public_key: CredentialPublicKey,
}

impl Serialize for AttestedCredData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        let mut tup = serializer.serialize_tuple(4)?;
        tup.serialize_element(&self.aaguid)?;
        tup.serialize_element(&self.credential_id_length)?;
        tup.serialize_element(&self.credential_id)?;
        tup.serialize_element(&self.credential_public_key)?;
        tup.end()
    }
}

/// [See more](https://www.w3.org/TR/webauthn/#attestation-object)
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "fmt")]
pub enum AttestationStatement {
    #[serde(rename = "packed")]
    Packed {
        #[serde(rename = "attStmt")]
        att_stmt: PackedAttestationStatement,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PackedAttestationStatement {
    pub alg: COSEAlgorithmIdentifier,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
    pub x5c: Vec<X5cElement>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum X5cElement {
    AttestationCert(AttestationCert),
    CaCert(CaCert),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationCert(#[serde(with = "serde_bytes")] pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize)]
pub struct CaCert(#[serde(with = "serde_bytes")] pub Vec<u8>);


#[cfg(test)]
mod tests {
    use crate::authenticator::types::APP_AAGUID;

    use super::*;
    #[test]
    fn test_auth_data() {
        let auth_data = AuthenticatorData {
            counter: 0,
            extensions: None,
            flags: AuthenticatorDataFlags::new(),
            rp_id_hash: 0x1337,
            attested_cred_data: Some(AttestedCredData {
                aaguid: APP_AAGUID,
                credential_id: CredentialId(vec![1,3,3,7]),
                credential_id_length: 4,
                credential_public_key: CredentialPublicKey(vec![5, 5, 5, 5])
            })
        };
        let mut vec = vec![];
        ciborium::ser::into_writer(&auth_data, &mut vec).unwrap();
        // TODO: this test doesn't check the proper structure yet
    }
}