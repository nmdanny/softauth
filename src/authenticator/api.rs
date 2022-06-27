use thiserror::Error;

use super::command::StatusCode;

#[derive(Error, Debug)]
pub enum AuthenticatorError {
    #[error(transparent)]
    CTAPErrorStatus(StatusCode),

    #[error("Custom error: {0}")]
    OtherError(String)
}

pub struct Authenticator {

}


pub type AuthenticatorResult<T> = Result<T, AuthenticatorError>;

impl Authenticator {
    pub fn new() -> Self {
        Self {}
    }


}
