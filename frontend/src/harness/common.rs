pub use chain::policy::ExecTask;

use crate::error::*;

#[derive(Debug)]
pub struct ValidationResult {
    pub valid: bool,
    pub err: String,
    pub stats: Vec<u64>, // Durations in microseconds
}

pub trait Harness {
    fn spawn(&self, roots_path: &str, timestamp: u64) -> Result<Box<dyn Instance>, Error>;
}

pub trait Instance: Send {
    fn validate(&mut self, bundle: &Vec<String>, task: &ExecTask, repeat: usize) -> Result<ValidationResult, Error>;
}
