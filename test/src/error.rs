use thiserror::Error;

use std::sync::mpsc::{RecvError, SendError};

use parser::ParseError as X509ParseError;
use chain::error::{Error as ChainError, ValidationError};

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

    #[error("validation error: {0:?}")]
    ChainValidationError(ValidationError),

    #[error("chain error: {0}")]
    ChainError(ChainError),

    #[error("regex error: {0}")]
    RegexError(#[from] regex::Error),

    #[error("channel send error: {0}")]
    SendError(String),

    #[error("channel receive error: {0}")]
    RecvError(String),
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

impl From<ValidationError> for Error {
    fn from(err: ValidationError) -> Self {
        Error::ChainValidationError(err)
    }
}

impl From<ChainError> for Error {
    fn from(err: ChainError) -> Self {
        Error::ChainError(err)
    }
}

impl<T> From<SendError<T>> for Error {
    fn from(err: SendError<T>) -> Self {
        Error::SendError(err.to_string())
    }
}

impl<T> From<crossbeam::channel::SendError<T>> for Error {
    fn from(err: crossbeam::channel::SendError<T>) -> Self {
        Error::SendError(err.to_string())
    }
}

impl From<RecvError> for Error {
    fn from(err: RecvError) -> Self {
        Error::RecvError(err.to_string())
    }
}

impl From<crossbeam::channel::RecvError> for Error {
    fn from(err: crossbeam::channel::RecvError) -> Self {
        Error::RecvError(err.to_string())
    }
}
