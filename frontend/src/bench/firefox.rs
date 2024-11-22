use std::path::PathBuf;
use std::io::{BufRead, BufReader, Write};
use std::process::{self, Child, ChildStdin, ChildStdout};

use super::common::*;
use crate::error::*;

const RESET_COUNT: usize = 100;

pub struct FirefoxAgent {
    pub repo: String,
    pub debug: bool,
}

pub struct FirefoxImpl {
    bin_path: PathBuf,
    roots_path: String,
    timestamp: u64,
    debug: bool,

    /// Number of jobs processed
    count: usize,

    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl X509Agent for FirefoxAgent {
    type Impl = FirefoxImpl;

    /// Spawns a child process to run cert_bench
    fn init(&self, roots_path: &str, timestamp: u64) -> Result<Self::Impl, Error> {
        let mut bin_path = PathBuf::from(&self.repo);
        bin_path.extend([ "cert_bench.sh" ]);

        if !bin_path.exists() {
            return Err(Error::FirefoxRepoNotFound(bin_path.display().to_string()));
        }

        let mut cmd = process::Command::new(bin_path.clone());
        cmd.arg(roots_path)
            .arg(timestamp.to_string())
            .stdin(process::Stdio::piped())
            .stdout(process::Stdio::piped());

        if !self.debug {
            cmd.stderr(process::Stdio::null());
        };

        let mut child = cmd.spawn()?;

        let stdin = child.stdin.take().ok_or(Error::ChildStdin)?;
        let stdout = child.stdout.take().ok_or(Error::ChildStdout)?;

        Ok(FirefoxImpl {
            bin_path,
            roots_path: roots_path.to_string(),
            timestamp,
            debug: self.debug,

            count: 0,
            child, stdin, stdout: BufReader::new(stdout),
        })
    }
}

impl FirefoxImpl {
    /// Restart the benching process
    /// NOTE: this is currently a workaround for the degrading
    /// performance of the test harness overtime due to the
    /// use of certdb in Firefox
    fn reset(&mut self) -> Result<(), Error> {
        let mut cmd = process::Command::new(&self.bin_path);
        cmd.arg(&self.roots_path)
            .arg(self.timestamp.to_string())
            .stdin(process::Stdio::piped())
            .stdout(process::Stdio::piped());

        if !self.debug {
            cmd.stderr(process::Stdio::null());
        };

        let mut child = cmd.spawn()?;

        let stdin = child.stdin.take().ok_or(Error::ChildStdin)?;
        let stdout = child.stdout.take().ok_or(Error::ChildStdout)?;

        // Kill the previous process
        self.child.kill()?;
        self.child.wait()?;

        // Set the new one
        self.child = child;
        self.stdin = stdin;
        self.stdout = BufReader::new(stdout);

        Ok(())
    }
}

impl X509Impl for FirefoxImpl {
    /// Send one validation job, and then read the results from stdout
    fn validate(&mut self, bundle: &Vec<String>, domain: &str, repeat: usize) -> Result<ValidationResult, Error> {
        if bundle.len() == 0 {
            return Err(Error::EmptyBundle);
        }

        if repeat == 0 {
            return Err(Error::ZeroRepeat);
        }

        self.count += 1;

        if self.count >= RESET_COUNT {
            self.reset()?;
            self.count = 0;
        }

        writeln!(self.stdin, "repeat: {}", repeat)?;
        writeln!(&mut self.stdin, "leaf: {}", bundle[0])?;

        for cert in bundle.iter().skip(1) {
            writeln!(&mut self.stdin, "interm: {}", cert)?;
        }
        writeln!(&mut self.stdin, "domain: {}", domain)?;

        let mut line = String::new();

        if self.stdout.read_line(&mut line)? == 0 {
            return Err(Error::FirefoxBenchError("failed to read stdout".to_string()));
        }

        if line.starts_with("result:") {
            let mut res = line["result:".len()..].trim().split_ascii_whitespace();
            let res_fst = res.next().ok_or(Error::FirefoxBenchError("no results".to_string()))?;

            Ok(ValidationResult {
                err: if res_fst == "OK" { None } else { Some(res_fst.to_string()) },

                // Parse the rest as a space separated list of integers (time in microseconds)
                stats: res.map(|s| s.parse().map_err(|_| Error::FirefoxBenchError("result parse error".to_string())))
                    .collect::<Result<Vec<_>, _>>()?,
            })
        } else if line.starts_with("error:") {
            Err(Error::FirefoxBenchError(line["error:".len()..].trim().to_string()))
        } else {
            Err(Error::FirefoxBenchError(format!("unexpected output: {}", line)))
        }
    }
}

impl Drop for FirefoxImpl {
    fn drop(&mut self) {
        if let Some(status) = self.child.try_wait().unwrap() {
            eprintln!("firefox cert bench failed with: {}", status);
        }

        // We expect the process to be still running
        // so no need to consume the status here
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}
