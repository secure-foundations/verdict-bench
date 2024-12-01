use std::time::Instant;
use std::path::PathBuf;
use std::io::{BufRead, BufReader, Write};
use std::process::{self, Child, ChildStdin, ChildStdout};

use chrono::{TimeZone, Utc};
use tempfile::NamedTempFile;
use chain::policy::ExecPurpose;

use super::common::*;
use crate::error::*;

#[derive(Clone)]
pub struct ArmorHarness {
    pub repo: String,
    pub faketime_lib: String,
    pub debug: bool,
}

pub struct ArmorInstance {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Harness for ArmorHarness {
    fn spawn(&self, roots_path: &str, timestamp: u64) -> Result<Box<dyn Instance>, Error> {
        let mut driver_path = PathBuf::from(&self.repo);
        driver_path.extend([ "src", "armor-driver", "driver.py" ]);

        let fake_time = Utc.timestamp_opt(timestamp as i64, 0).unwrap()
            .format("%Y-%m-%d %H:%M:%S").to_string();

        // Check `args.faketime_lib` exists
        if !PathBuf::from(&self.faketime_lib).exists() {
            return Err(Error::LibFakeTimeNotFound(self.faketime_lib.clone()));
        }

        if !driver_path.exists() {
            return Err(Error::ArmorRepoNotFound(driver_path.display().to_string()));
        }

        let mut cmd = process::Command::new("python3");
        cmd // Use libfaketime to change the validation time
            .env("LD_PRELOAD", &self.faketime_lib)
            .env("FAKETIME", &format!("@{}", fake_time))
            .arg(std::fs::canonicalize(driver_path)?)
            .arg("--trust_store").arg(std::fs::canonicalize(roots_path)?)
            .arg("--purpose").arg("serverAuth")
            .stdin(process::Stdio::piped())
            .stdout(process::Stdio::piped());

        if !self.debug {
            cmd.stderr(process::Stdio::null());
        };

        let mut child = cmd.spawn()?;

        let stdin = child.stdin.take().ok_or(Error::ChildStdin)?;
        let stdout = child.stdout.take().ok_or(Error::ChildStdout)?;

        Ok(Box::new(ArmorInstance { child, stdin, stdout: BufReader::new(stdout) }))
    }
}

impl Instance for ArmorInstance {
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
            return Err(Error::ArmorBenchError("failed to read stdout".to_string()));
        }

        if line.starts_with("result:") {
            let mut res = line["result:".len()..].trim().split_ascii_whitespace();
            let res_fst = res.next().ok_or(Error::ArmorBenchError("no results".to_string()))?;

            Ok(ValidationResult {
                valid: res_fst == "true",
                err: "".to_string(),

                // Parse the rest as a space separated list of integers (time in microseconds)
                stats: res.map(|s| s.parse().unwrap()).collect(),
            })
        } else if line.starts_with("error:") {
            Err(Error::ArmorBenchError(line["error:".len()..].trim().to_string()))
        } else {
            Err(Error::ArmorBenchError(format!("unexpected output: {}", line)))
        }
    }
}
