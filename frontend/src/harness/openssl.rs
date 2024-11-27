use std::path::PathBuf;
use std::io::{BufRead, BufReader, Write};
use std::process::{self, Child, ChildStdin, ChildStdout};

use chain::policy::ExecPurpose;

use super::common::*;
use crate::error::*;

pub struct OpenSSLHarness {
    pub repo: String,
    pub debug: bool,
}

pub struct OpenSSLInstance {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Harness for OpenSSLHarness {
    /// Spawns a child process to run cert_bench
    fn spawn(&self, roots_path: &str, timestamp: u64) -> Result<Box<dyn Instance>, Error> {
        let mut bin_path = PathBuf::from(&self.repo);
        bin_path.push("cert_bench");

        if !bin_path.exists() {
            return Err(Error::OpenSSLRepoNotFound(bin_path.display().to_string()));
        }

        let mut cmd = process::Command::new(bin_path);
        cmd.arg(roots_path)
            // Use libfaketime to change the validation time
            .arg(timestamp.to_string())
            .stdin(process::Stdio::piped())
            .stdout(process::Stdio::piped());

        if !self.debug {
            cmd.stderr(process::Stdio::null());
        };

        let mut child = cmd.spawn()?;

        let stdin = child.stdin.take().ok_or(Error::ChildStdin)?;
        let stdout = child.stdout.take().ok_or(Error::ChildStdout)?;

        Ok(Box::new(OpenSSLInstance { child, stdin, stdout: BufReader::new(stdout) }))
    }
}

impl Instance for OpenSSLInstance {
    /// Send one validation job, and then read the results from stdout
    fn validate(&mut self, bundle: &Vec<String>, task: &ExecTask, repeat: usize) -> Result<ValidationResult, Error> {
        if bundle.len() == 0 {
            return Err(Error::EmptyBundle);
        }

        if repeat == 0 {
            return Err(Error::ZeroRepeat);
        }

        if let ExecTask::ChainValidation(ExecPurpose::ServerAuth) = task {} else {
            return Err(Error::UnsupportedTask);
        }

        writeln!(self.stdin, "repeat: {}", repeat)?;
        writeln!(self.stdin, "leaf: {}", bundle[0])?;

        for cert in bundle.iter().skip(1) {
            writeln!(self.stdin, "interm: {}", cert)?;
        }
        writeln!(self.stdin, "validate")?;

        let mut line = String::new();

        if self.stdout.read_line(&mut line)? == 0 {
            return Err(Error::OpenSSLBenchError("failed to read stdout".to_string()));
        }

        if line.starts_with("result:") {
            let mut res = line["result:".len()..].trim().split_ascii_whitespace();
            let res_fst = res.next().ok_or(Error::OpenSSLBenchError("no results".to_string()))?;

            Ok(ValidationResult {
                valid: res_fst == "OK",
                err: if res_fst == "OK" { "".to_string() } else { res_fst.to_string() },

                // Parse the rest as a space separated list of integers (time in microseconds)
                stats: res.map(|s| s.parse().unwrap()).collect(),
            })
        } else if line.starts_with("error:") {
            Err(Error::OpenSSLBenchError(line["error:".len()..].trim().to_string()))
        } else {
            Err(Error::OpenSSLBenchError(format!("unexpected output: {}", line)))
        }
    }
}

impl Drop for OpenSSLInstance {
    fn drop(&mut self) {
        if let Some(status) = self.child.try_wait().unwrap() {
            eprintln!("openssl cert bench failed with: {}", status);
        }

        // We expect the process to be still running
        // so no need to consume the status here
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}
