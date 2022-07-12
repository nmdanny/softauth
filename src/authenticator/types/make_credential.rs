use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{authenticator::crypto::COSEAlgorithmIdentifier, cbor::key_mapped::VecKeymappable};

use super::{
    AttestationStatement, AuthenticatorData, CredentialId, PublicKeyType, RpId, UserHandle,
};

/// Used when creating a credential, contains attributes related to the RP.
/// [See more](https://w3c.github.io/webauthn/#dictdef-publickeycredentialrpentity)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    id: RpId,
    name: Option<String>,
}

/// Used when creating a credential, contains attributes related to the user account.
/// [See more](https://w3c.github.io/webauthn/#dictdef-publickeycredentialuserentity)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialUserEntity {
    id: UserHandle,
    name: Option<String>,

    #[serde(rename = "displayName")]
    display_name: Option<String>,
}

/// Identifies a crypto algorithm supported by the RP.
/// [See more](https://w3c.github.io/webauthn/#dictdef-publickeycredentialparameters)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    _type: PublicKeyType,
    alg: COSEAlgorithmIdentifier,
}

/// Identifies a credential (similar to [CredentialId]) along with the transports it can be used on.
/// [See more](https://w3c.github.io/webauthn/#dictdef-publickeycredentialdescriptor)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    _type: PublicKeyType,
    id: CredentialId,
    transports: Option<Vec<String>>,
}

/// https://www.w3.org/TR/webauthn-2#sctn-extension-id
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionIdentifier(String);

/// https://www.w3.org/TR/webauthn-2/#authenticator-extension-input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extension {}

/// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#makecred-option-key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorOptions {
    rk: Option<bool>,
    up: Option<bool>,
    // Depracated in CTAP2.1
    uv: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ClientDataHash(#[serde(with = "serde_bytes")] Vec<u8>);

/// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorMakeCredential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorMakeCredentialParams {
    client_data_hash: ClientDataHash,
    rp: PublicKeyCredentialRpEntity,
    user: PublicKeyCredentialUserEntity,
    pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    exclude_list: Option<Vec<PublicKeyCredentialDescriptor>>,
    extensions: Option<BTreeMap<String, Extension>>,
    options: Option<AuthenticatorOptions>,
    pin_uv_auth_param: Option<Vec<u8>>,
    pin_uv_auth_protocol: Option<u64>,
    enterprise_attestation: Option<u64>,
}

impl VecKeymappable<u8> for AuthenticatorMakeCredentialParams {
    fn field_mappings() -> Vec<(&'static str, u8)> {
        return vec![
            ("client_data_hash", 0x01),
            ("rp", 0x02),
            ("user", 0x03),
            ("pub_key_cred_params", 0x04),
            ("exclude_list", 0x05),
            ("extensions", 0x06),
            ("options", 0x07),
            ("pin_uv_auth_param", 0x08),
            ("pin_uv_auth_protocol", 0x09),
            ("enterprise_attestation", 0x0A),
        ];
    }
}

#[derive(Debug, Serialize)]
pub struct AuthenticatorMakeCredentialResponse {
    fmt: String,
    auth_data: AuthenticatorData,
    att_stmt: AttestationStatement,
}

impl VecKeymappable<u8> for AuthenticatorMakeCredentialResponse {
    fn field_mappings() -> Vec<(&'static str, u8)> {
        vec![("fmt", 0x01), ("auth_data", 0x02), ("att_stmt", 0x03)]
    }
}

#[cfg(test)]
mod tests {
    use crate::cbor::key_mapped::KeymappedStruct;

    use super::AuthenticatorMakeCredentialParams;

    #[test]
    fn can_parse_chromium_make_credentials() {
        let cbor = hex::decode("a5015820a830e6419cd1e40a074b78365370c64a8796c2fe8cbb70903c8cf60dd534045b02a26269646b776562617574686e2e696f646e616d656b776562617574686e2e696f03a36269644a8a893e00000000000000646e616d656273666b646973706c61794e616d65627366048aa263616c672664747970656a7075626c69632d6b6579a263616c67382264747970656a7075626c69632d6b6579a263616c67382364747970656a7075626c69632d6b6579a263616c6739010064747970656a7075626c69632d6b6579a263616c6739010164747970656a7075626c69632d6b6579a263616c6739010264747970656a7075626c69632d6b6579a263616c67382464747970656a7075626c69632d6b6579a263616c67382564747970656a7075626c69632d6b6579a263616c67382664747970656a7075626c69632d6b6579a263616c672764747970656a7075626c69632d6b657907a1627576f5").unwrap();
        let val: KeymappedStruct<AuthenticatorMakeCredentialParams, u8> =
            ciborium::de::from_reader(&*cbor).unwrap();
        let val = val.into_inner();
        assert_eq!(
            val.client_data_hash.0,
            hex::decode("A830E6419CD1E40A074B78365370C64A8796C2FE8CBB70903C8CF60DD534045B")
                .unwrap()
        );
        assert_eq!(val.rp.id.0, "webauthn.io");
        assert_eq!(val.rp.name, Some("webauthn.io".to_owned()));
        assert_eq!(val.user.id.0, hex::decode("8A893E00000000000000").unwrap());
        assert_eq!(val.user.name, Some("sf".to_string()));
        assert_eq!(val.user.display_name, Some("sf".to_string()));
    }
}
