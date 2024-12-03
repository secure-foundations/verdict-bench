use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout};

use chain::policy::{ExecTask, ExecPurpose};

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

/// A common protocol used by the test harnesses of Chrome, Firefox, etc.
/// Basically the frontend sends benchmarking task (leaf, intermediates, repeat, etc.)
/// and the server implementing the benchmark performs the task in its native language
pub struct CommonBenchInstance {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl CommonBenchInstance {
    pub fn new(mut child: Child) -> Result<CommonBenchInstance, Error> {
        let stdin = child.stdin.take().ok_or(Error::ChildStdin)?;
        let stdout = child.stdout.take().ok_or(Error::ChildStdout)?;
        Ok(CommonBenchInstance { child, stdin, stdout: BufReader::new(stdout) })
    }
}

impl Instance for CommonBenchInstance {
    fn validate(&mut self, bundle: &Vec<String>, task: &ExecTask, repeat: usize) -> Result<ValidationResult, Error> {
        if bundle.len() == 0 {
            return Err(Error::EmptyBundle);
        }

        if repeat == 0 {
            return Err(Error::ZeroRepeat);
        }

        let task_str = match task {
            ExecTask::DomainValidation(domain) => {
                if domain.trim().is_empty() {
                    // Abort if the domain is empty
                    return Ok(ValidationResult {
                        valid: false,
                        err: "empty domain name".to_string(),
                        stats: vec![0; repeat],
                    });
                }
                format!("domain: {}", domain)
            },
            ExecTask::ChainValidation(ExecPurpose::ServerAuth) => "validate".to_string(),
            // _ => return Err(Error::UnsupportedTask)
        };

        writeln!(self.stdin, "repeat: {}", repeat)?;
        writeln!(self.stdin, "leaf: {}", bundle[0])?;
        for cert in bundle.iter().skip(1) {
            writeln!(self.stdin, "interm: {}", cert)?;
        }
        writeln!(self.stdin, "{}", task_str)?;

        let mut line = String::new();

        if self.stdout.read_line(&mut line)? == 0 {
            return Err(Error::CommonBenchError("failed to read stdout".to_string()));
        }

        // Wait for the bench server to send back the result in the form of
        // `result: <OK or err msg> <sample 1 time> <sample 2 time> ...`
        if line.starts_with("result:") {
            let mut res = line["result:".len()..].trim().split_ascii_whitespace();
            let res_fst = res.next().ok_or(Error::CommonBenchError("no results".to_string()))?;

            Ok(ValidationResult {
                valid: res_fst == "OK",
                err: if res_fst == "OK" { "".to_string() } else { res_fst.to_string() },

                // Parse the rest as a space separated list of integers (time in microseconds)
                stats: res.map(|s| s.parse().unwrap()).collect(),
            })
        } else if line.starts_with("error:") {
            Err(Error::CommonBenchError(line["error:".len()..].trim().to_string()))
        } else {
            Err(Error::CommonBenchError(format!("unexpected output: {}", line)))
        }
    }
}

impl Drop for CommonBenchInstance {
    fn drop(&mut self) {
        if let Some(status) = self.child.try_wait().unwrap() {
            eprintln!("cert bench failed with: {}", status);
        }

        // We expect the process to be still running
        // so no need to consume the status here
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}
