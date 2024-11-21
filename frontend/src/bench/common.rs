use crate::error::*;

#[derive(Debug)]
pub struct ValidationResult {
    pub err: Option<String>,
    /// Durations in microseconds
    pub stats: Vec<u64>,
}

pub trait X509Agent {
    type Impl: X509Impl;

    fn init(&self, roots_path: &str, timestamp: u64) -> Result<Self::Impl, Error>;
}

pub trait X509Impl {
    fn validate(&mut self, bundle: &Vec<String>, domain: &str, repeat: usize) -> Result<ValidationResult, Error>;
}
