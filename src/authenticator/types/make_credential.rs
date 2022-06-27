use std::collections::BTreeMap;

use serde::{Serialize, Deserialize};

/// https://w3c.github.io/webauthn/#rp-id
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpId(String);

/// https://w3c.github.io/webauthn/#dom-publickeycredentialuserentity-id
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserId(Vec<u8>);

/// https://w3c.github.io/webauthn/#credential-id
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialId(Vec<u8>);

/// https://w3c.github.io/webauthn/#dictdef-publickeycredentialrpentity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    id: RpId,
    name: Option<String>
}

/// https://w3c.github.io/webauthn/#dictdef-publickeycredentialuserentity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialUserEntity {
    id: UserId,
    name: Option<String>,

    #[serde(rename = "displayName")]
    display_name: Option<String>
}

/// https://w3c.github.io/webauthn/#typedefdef-cosealgorithmidentifier
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct COSEAlgorithmIdentifier(i32);


/// https://w3c.github.io/webauthn/#dictdef-publickeycredentialparameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    _type: String,
    alg: COSEAlgorithmIdentifier

}

/// https://w3c.github.io/webauthn/#dictdef-publickeycredentialdescriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    _type: String,
    id: CredentialId,
    transports: Option<Vec<String>>
}


/// https://www.w3.org/TR/webauthn-2#sctn-extension-id
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionIdentifier(String);


/// https://www.w3.org/TR/webauthn-2/#authenticator-extension-input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extension {

}

/// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#makecred-option-key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorOptions {
    rk: bool,
    up: bool,
    // Depracated in CTAP2.1
    uv: bool
}


/// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorMakeCredential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorMakeCredentialParams {
    client_data_hash: Vec<u8>,
    rp: PublicKeyCredentialRpEntity,
    user: PublicKeyCredentialRpEntity,
    pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    exclude_list: Option<Vec<PublicKeyCredentialDescriptor>>,
    extensions: Option<BTreeMap<String, Extension>>,
    options: Option<AuthenticatorOptions>,
    pin_uv_auth_param: Option<Vec<u8>>,
    pin_uv_auth_protocol: Option<u64>,
    enterprise_attestation: Option<u64>


}