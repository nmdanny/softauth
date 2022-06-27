/// This module defines the various features and options supported by the authenticator

use serde::{Deserialize, Serialize};

/// https://www.w3.org/TR/webauthn-2/#aaguid
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AAGUID([u8; 16]);

const APP_AAGUID: AAGUID = AAGUID([1, 3, 3, 7, 1, 1, 2, 3, 5, 8, 13, 21, 1, 3, 3, 7]);

/// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#option-id
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorGetInfoOptions {
    plot: bool,
    rk: bool,
    client_pin: bool,
    up: bool,
    uv: bool,
    pin_uv_auth_token: bool,
}

impl Default for AuthenticatorGetInfoOptions {
    fn default() -> Self {
        Self {
            plot: Default::default(),
            rk: Default::default(),
            client_pin: Default::default(),
            up: Default::default(),
            uv: Default::default(),
            pin_uv_auth_token: Default::default(),
        }
    }
}

/// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorGetInfoResponse {
    versions: Vec<String>,
    extensions: Vec<String>,
    aaguid: AAGUID,
    options: AuthenticatorGetInfoOptions,
}

impl Default for AuthenticatorGetInfoResponse {
    fn default() -> Self {
        Self {
            versions: vec!["FIDO_2_0".into()],
            extensions: Default::default(),
            aaguid: APP_AAGUID,
            options: Default::default(),
        }
    }
}
