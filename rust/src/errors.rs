use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum Error {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("invalid signature provided")]
    InvalidSignature,
    #[error("invalid payload structure when de-serialising valid payload, were you perhaps expecting the wrong payload structure or recently changed it?")]
    InvalidPayload,
    #[error("invalid token provided")]
    InvalidToken,
    #[error("could not expand key")]
    HkdfExpandError,
    #[error("could not fill key")]
    HkdfFillError,
    #[error("token has expired")]
    TokenExpired,
}
