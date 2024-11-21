use std::path::PathBuf;
use std::io::{BufRead, BufReader, Write};
use std::process::{self, Child, ChildStdin, ChildStdout};

use chrono::{TimeZone, Utc};

use super::common::*;
use crate::error::*;

pub struct ChromiumAgent {
    pub repo: String,
    pub faketime_lib: String,
    pub debug: bool,
}

pub struct ChromiumImpl {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl X509Agent for ChromiumAgent {
    type Impl = ChromiumImpl;

    /// Spawns a child process to run cert_bench
    fn init(&self, roots_path: &str, timestamp: u64) -> Result<Self::Impl, Error> {
        let mut bin_path = PathBuf::from(&self.repo);
        bin_path.extend([ "src", "out", "Release", "cert_bench" ]);

        let fake_time = Utc.timestamp_opt(timestamp as i64, 0).unwrap()
            .format("%Y-%m-%d %H:%M:%S").to_string();

        // Check `args.faketime_lib` exists
        if !PathBuf::from(&self.faketime_lib).exists() {
            return Err(Error::LibFakeTimeNotFound(self.faketime_lib.clone()));
        }

        if !bin_path.exists() {
            return Err(Error::ChromiumRepoNotFound(bin_path.display().to_string()));
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

        Ok(ChromiumImpl { child, stdin, stdout: BufReader::new(stdout) })
    }
}

impl X509Impl for ChromiumImpl {
    /// Send one validation job, and then read the results from stdout
    fn validate(&mut self, bundle: &Vec<String>, domain: &str, repeat: usize) -> Result<ValidationResult, Error> {
        if bundle.len() == 0 {
            return Err(Error::EmptyBundle);
        }

        if repeat == 0 {
            return Err(Error::ZeroRepeat);
        }

        if domain.trim().is_empty() {
            // Chrome would abort if the domain is empty
            return Ok(ValidationResult {
                err: Some("empty_domain_name".to_string()),
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
            return Err(Error::ChromiumBenchError("failed to read stdout".to_string()));
        }

        if line.starts_with("result:") {
            let mut res = line["result:".len()..].trim().split_ascii_whitespace();
            let res_fst = res.next().ok_or(Error::ChromiumBenchError("no results".to_string()))?;

            Ok(ValidationResult {
                err: if res_fst == "OK" { None } else { Some(res_fst.to_string()) },

                // Parse the rest as a space separated list of integers (time in microseconds)
                stats: res.map(|s| s.parse().unwrap()).collect(),
            })
        } else if line.starts_with("error:") {
            Err(Error::ChromiumBenchError(line["error:".len()..].trim().to_string()))
        } else {
            Err(Error::ChromiumBenchError(format!("unexpected output: {}", line)))
        }
    }
}

impl Drop for ChromiumImpl {
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
