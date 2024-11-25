use std::path::PathBuf;
use std::io::{BufRead, BufReader, Write};
use std::process::{self, Child, ChildStdin, ChildStdout};

use chrono::{TimeZone, Utc};

use super::common::*;
use crate::error::*;

pub struct ChromeHarness {
    pub repo: String,
    pub faketime_lib: String,
    pub debug: bool,
}

pub struct ChromeInstance {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Harness for ChromeHarness {
    /// Spawns a child process to run cert_bench
    fn spawn(&self, roots_path: &str, timestamp: u64) -> Result<Box<dyn Instance>, Error> {
        let mut bin_path = PathBuf::from(&self.repo);
        bin_path.extend([ "src", "out", "Release", "cert_bench" ]);

        let fake_time = Utc.timestamp_opt(timestamp as i64, 0).unwrap()
            .format("%Y-%m-%d %H:%M:%S").to_string();

        // Check `args.faketime_lib` exists
        if !PathBuf::from(&self.faketime_lib).exists() {
            return Err(Error::LibFakeTimeNotFound(self.faketime_lib.clone()));
        }

        if !bin_path.exists() {
            return Err(Error::ChromeRepoNotFound(bin_path.display().to_string()));
        }

        let mut cmd = process::Command::new(bin_path);
        cmd.arg(roots_path)
            // Use libfaketime to change the validation time
            .env("LD_PRELOAD", &self.faketime_lib)
            .env("FAKETIME", &format!("@{}", fake_time))
            .stdin(process::Stdio::piped())
            .stdout(process::Stdio::piped());

        if !self.debug {
            cmd.stderr(process::Stdio::null());
        };

        let mut child = cmd.spawn()?;

        let stdin = child.stdin.take().ok_or(Error::ChildStdin)?;
        let stdout = child.stdout.take().ok_or(Error::ChildStdout)?;

        Ok(Box::new(ChromeInstance { child, stdin, stdout: BufReader::new(stdout) }))
    }
}

impl Instance for ChromeInstance {
    /// Send one validation job, and then read the results from stdout
    fn validate(&mut self, bundle: &Vec<String>, task: &ExecTask, repeat: usize) -> Result<ValidationResult, Error> {
        if bundle.len() == 0 {
            return Err(Error::EmptyBundle);
        }

        if repeat == 0 {
            return Err(Error::ZeroRepeat);
        }

        let domain = match task {
            ExecTask::DomainValidation(domain) => domain,
            _ => return Err(Error::UnsupportedTask),
        };

        if domain.trim().is_empty() {
            // Chrome would abort if the domain is empty
            return Ok(ValidationResult {
                valid: false,
                err: "empty domain name".to_string(),
                stats: vec![0; repeat],
            });
        }

        writeln!(self.stdin, "repeat: {}", repeat)?;
        writeln!(&mut self.stdin, "leaf: {}", bundle[0])?;

        for cert in bundle.iter().skip(1) {
            writeln!(&mut self.stdin, "interm: {}", cert)?;
        }
        writeln!(&mut self.stdin, "domain: {}", domain)?;

        let mut line = String::new();

        if self.stdout.read_line(&mut line)? == 0 {
            return Err(Error::ChromeBenchError("failed to read stdout".to_string()));
        }

        if line.starts_with("result:") {
            let mut res = line["result:".len()..].trim().split_ascii_whitespace();
            let res_fst = res.next().ok_or(Error::ChromeBenchError("no results".to_string()))?;

            Ok(ValidationResult {
                valid: res_fst == "OK",
                err: if res_fst == "OK" { "".to_string() } else { res_fst.to_string() },

                // Parse the rest as a space separated list of integers (time in microseconds)
                stats: res.map(|s| s.parse().unwrap()).collect(),
            })
        } else if line.starts_with("error:") {
            Err(Error::ChromeBenchError(line["error:".len()..].trim().to_string()))
        } else {
            Err(Error::ChromeBenchError(format!("unexpected output: {}", line)))
        }
    }
}

impl Drop for ChromeInstance {
    fn drop(&mut self) {
        if let Some(status) = self.child.try_wait().unwrap() {
            eprintln!("chrome cert bench failed with: {}", status);
        }

        // We expect the process to be still running
        // so no need to consume the status here
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}
