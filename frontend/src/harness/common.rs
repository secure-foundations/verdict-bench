pub use chain::policy::ExecTask;

use crate::error::*;

#[derive(Debug)]
pub struct ValidationResult {
    pub err: Option<String>,
    /// Durations in microseconds
    pub stats: Vec<u64>,
}

pub trait Harness {
    fn spawn(&self, roots_path: &str, timestamp: u64) -> Result<Box<dyn Instance>, Error>;
}

pub trait Instance {
    fn validate(&mut self, bundle: &Vec<String>, task: &ExecTask, repeat: usize) -> Result<ValidationResult, Error>;
}
