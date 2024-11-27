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
    harness: ArmorHarness,

    driver_path: PathBuf,
    roots_path: String,
    fake_time: String,
}

impl Harness for ArmorHarness {
    /// Spawns a child process to run cert_bench
    fn spawn(&self, roots_path: &str, timestamp: u64) -> Result<Box<dyn Instance>, Error> {
        let mut driver_path = PathBuf::from(&self.repo);
        driver_path.extend([ "src", "armor-driver", "driver.py" ]);

        if !driver_path.exists() {
            return Err(Error::ArmorRepoNotFound(driver_path.display().to_string()));
        }

        let fake_time = Utc.timestamp_opt(timestamp as i64, 0).unwrap()
            .format("%Y-%m-%d %H:%M:%S").to_string();

        // Check `args.faketime_lib` exists
        if !PathBuf::from(&self.faketime_lib).exists() {
            return Err(Error::LibFakeTimeNotFound(self.faketime_lib.clone()));
        }

        Ok(Box::new(ArmorInstance {
            harness: self.clone(),
            driver_path,
            roots_path: roots_path.to_string(),
            fake_time: format!("@{}", fake_time),
        }))
    }
}

impl Instance for ArmorInstance {
    fn validate(&mut self, bundle: &Vec<String>, task: &ExecTask, repeat: usize) -> Result<ValidationResult, Error> {
        if let ExecTask::ChainValidation(ExecPurpose::ServerAuth) = task {} else {
            return Err(Error::ArmorBenchError(format!("unsupported task: {:?}", task)));
        }

        // Create a temporary PEM file to store the bundle
        let mut chain_file = NamedTempFile::with_suffix(".pem")?;

        for cert_base64 in bundle {
            writeln!(chain_file, "-----BEGIN CERTIFICATE-----")?;

            let len = cert_base64.len();
            for i in (0..len).step_by(64) {
                writeln!(chain_file, "{}", std::str::from_utf8(&cert_base64.as_bytes()[i..(i + 64).min(len)])?)?;
            }

            writeln!(chain_file, "-----END CERTIFICATE-----")?;
        }
        chain_file.flush()?;
        // chain_file.close()?;

        // time faketime "$(date -d @1725029869 '+%Y-%m-%d %H:%M:%S')" \
        // python3 src/armor-driver/driver.py \
        //     --chain <chain.pem> \
        //     --trust_store <roots.pem> \
        //     --purpose serverAuth
        let mut cmd = process::Command::new("python3");
        cmd.current_dir(&self.harness.repo)
            // Use libfaketime to change the validation time
            .env("LD_PRELOAD", &self.harness.faketime_lib)
            .env("FAKETIME", &self.fake_time)
            .arg(std::fs::canonicalize(&self.driver_path)?)
            .arg("--chain").arg(chain_file.path())
            .arg("--trust_store").arg(std::fs::canonicalize(&self.roots_path)?)
            .arg("--purpose").arg("serverAuth");

        let mut output = "invalid repeat".to_string();
        let mut durations = Vec::with_capacity(repeat);

        // Repeat ARMOR execution
        for i in 0..repeat {
            let start = Instant::now();

            let cmd_output = cmd.output()?;
            if self.harness.debug && i == 0 {
                std::io::stderr().write_all(&cmd_output.stderr)?;
            }
            output = String::from_utf8(cmd_output.stdout)?;

            durations.push(start.elapsed().as_micros()
                .try_into().map_err(|_| Error::DurationOverflow)?);
        }

        chain_file.close()?;

        if output.trim() == "success" {
            Ok(ValidationResult {
                valid: true,
                err: "".to_string(),
                stats: durations,
            })
        } else if output.trim() == "failed" {
            Ok(ValidationResult {
                valid: true,
                err: "".to_string(),
                stats: durations,
            })
        } else {
            Err(Error::ArmorBenchError(format!("unknown result: {}", output)))
        }
    }
}
