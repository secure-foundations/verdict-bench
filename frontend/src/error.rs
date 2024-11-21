use thiserror::Error;

use std::sync::mpsc::{RecvError, SendError};

use parser::ParseError as X509ParseError;
use chain::error::ValidationError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("x509 parse error: {0:?}")]
    X509ParseError(X509ParseError),

    #[error("csv error: {0}")]
    CSVError(#[from] csv::Error),

    #[error("found BEGIN CERTIFICATE without matching END CERTIFICATE")]
    NoMatchingEndCertificate,

    #[error("found END CERTIFICATE without matching BEGIN CERTIFICATE")]
    NoMatchingBeginCertificate,

    #[error("validation error: {0:?}")]
    ChainValidationError(ValidationError),

    #[error("regex error: {0}")]
    RegexError(#[from] regex::Error),

    #[error("channel send error: {0}")]
    SendError(String),

    #[error("channel receive error: {0}")]
    RecvError(String),

    #[error("failed to validate domain")]
    DomainValidationError,

    #[error("repeat number must be positive")]
    ZeroRepeat,

    #[error("libfaketime.so not found at {0}")]
    LibFakeTimeNotFound(String),

    #[error("chromium not found at {0}")]
    ChromiumRepoNotFound(String),

    #[error("firefox not found at {0}")]
    FirefoxRepoNotFound(String),

    #[error("failed to get child process stdin")]
    ChildStdin,

    #[error("failed to get child process stdout")]
    ChildStdout,

    #[error("empty certificate bundle")]
    EmptyBundle,

    #[error("chromium cert bench error: {0}")]
    ChromiumBenchError(String),

    #[error("firefox cert bench error: {0}")]
    FirefoxBenchError(String),
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
