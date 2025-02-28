use std::path::PathBuf;
use std::process;

use super::common::*;
use crate::error::*;

pub struct OpenSSLHarness {
    pub repo: String,
    pub debug: bool,
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
        cmd.current_dir(&self.repo)
            .arg(std::fs::canonicalize(roots_path)?)
            .arg(timestamp.to_string())
            .stdin(process::Stdio::piped())
            .stdout(process::Stdio::piped());

        if !self.debug {
            cmd.stderr(process::Stdio::null());
        };

        Ok(Box::new(CommonBenchInstance::new(cmd.spawn()?, timestamp)?))
    }
}
