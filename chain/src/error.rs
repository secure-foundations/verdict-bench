use vstd::prelude::*;

use thiserror::Error;

use parser::ParseError as X509ParseError;

verus! {

#[derive(Debug)]
pub enum ValidationError {
    IntegerOverflow,
    EmptyChain,
    ProofFailure,
    TimeParseError,
    RSAPubKeyParseError,
    UnexpectedExtParam,
}

}

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("x509 parse error: {0:?}")]
    X509ParseError(X509ParseError),

    #[error("validation error: {0:?}")]
    ValidationError(ValidationError),

    #[error("found BEGIN CERTIFICATE without matching END CERTIFICATE")]
    NoMatchingEndCertificate,

    #[error("found END CERTIFICATE without matching BEGIN CERTIFICATE")]
    NoMatchingBeginCertificate,

    #[error("base64 decode error: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error("failed to validate domain")]
    DomainValidationError,
}

impl From<X509ParseError> for Error {
    fn from(err: X509ParseError) -> Self {
        Error::X509ParseError(err)
    }
}

impl From<ValidationError> for Error {
    fn from(err: ValidationError) -> Self {
        Error::ValidationError(err)
    }
}
