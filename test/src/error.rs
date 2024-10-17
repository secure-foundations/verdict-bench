use thiserror::Error;

use parser::ParseError as X509ParseError;
use vpl::{ProofError as VPLProofError, ParseError as VPLParseError};
use chain::error::ValidationError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("x509 parse error: {0:?}")]
    X509ParseError(X509ParseError),

    #[error("base64 decode error: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error("csv error: {0}")]
    CSVError(#[from] csv::Error),

    #[error("action parse error: {0}")]
    ParseActionError(#[from] ParseActionError),

    #[error("vpl parse error: {0}")]
    VPLParseError(VPLParseError),

    #[error("vpl proof error: {0}")]
    VPLProofError(VPLProofError),

    #[error("validation error: {0:?}")]
    ChainValidationError(ValidationError),

    #[error("regex error: {0}")]
    RegexError(#[from] regex::Error),
}

#[derive(Error, Debug)]
pub enum ParseActionError {
    #[error("found BEGIN CERTIFICATE without matching END CERTIFICATE")]
    NoMatchingEndCertificate,

    #[error("found END CERTIFICATE without matching BEGIN CERTIFICATE")]
    NoMatchingBeginCertificate,
}

impl From<X509ParseError> for Error {
    fn from(err: X509ParseError) -> Self {
        Error::X509ParseError(err)
    }
}

impl From<VPLParseError> for Error {
    fn from(err: VPLParseError) -> Self {
        Error::VPLParseError(err)
    }
}

impl From<VPLProofError> for Error {
    fn from(err: VPLProofError) -> Self {
        Error::VPLProofError(err)
    }
}

impl From<ValidationError> for Error {
    fn from(err: ValidationError) -> Self {
        Error::ChainValidationError(err)
    }
}
