use std::cell::RefCell;
use std::thread;
use std::thread::JoinHandle;
use std::time::Instant;

use chain::policy;
use chain::policy::ExecPolicy;
use chain::validate::Validator;
use crossbeam::channel;
use crossbeam::channel::Receiver;
use crossbeam::channel::Sender;
use parser::{parse_x509_cert, decode_base64, VecDeep};

use crate::validator::Policy;
use crate::error::*;
use crate::utils::*;

use super::common::*;

pub struct VerdictHarness {
    pub policy: Policy,
    pub debug: bool,
}

struct Job {
    bundle: Vec<String>,
    task: ExecTask,
    repeat: usize,
}

pub struct VerdictInstance {
    tx_job: Option<Sender<Job>>,
    rx_res: Option<Receiver<ValidationResult>>,
    handle: Option<JoinHandle<Result<(), Error>>>,
}

impl VerdictInstance {
    fn worker(roots_bytes: Vec<Vec<u8>>, policy: ExecPolicy, rx_job: Receiver<Job>, tx_res: Sender<ValidationResult>) -> Result<(), Error> {
        // Parse root certificates before receiving any job
        let roots = roots_bytes.iter()
            .map(|bytes| parse_x509_cert(bytes))
            .collect::<Result<Vec<_>, _>>()?;

        let validator = Validator::new(policy, VecDeep::from_vec(roots));

        while let Ok(Job { bundle, task, repeat }) = rx_job.recv() {
            let mut durations = Vec::with_capacity(repeat);
            let mut res: Result<bool, Error> = Ok(false);

            // Errors in chain parsing should not be raised to terminate the entire worker
            let inner = || -> Result<bool, Error> {
                let chain_bytes = bundle.iter().map(|base64: &String| {
                    decode_base64(base64.as_bytes())
                }).collect::<Result<Vec<_>, _>>()?;
                let chain = chain_bytes.iter().map(|bytes| {
                    parse_x509_cert(bytes)
                }).collect::<Result<Vec<_>, _>>()?;

                let chain = VecDeep::from_vec(chain);

                Ok(validator.validate(&chain, &task)?)
            };

            for i in 0..repeat {
                let start = Instant::now();
                res = inner();
                durations.push(start.elapsed().as_micros()
                    .try_into().map_err(|_| Error::DurationOverflow)?);
            }

            tx_res.send(ValidationResult {
                valid: match res {
                    Ok(true) => true,
                    _ => false,
                },
                err: match res {
                    Err(e) => e.to_string(),
                    _ => "".to_string(),
                },
                stats: durations,
            })?;
        }

        Ok(())
    }
}

impl Harness for VerdictHarness {
    fn spawn(&self, roots_path: &str, timestamp: u64) -> Result<Box<dyn Instance>, Error> {
        let roots_bytes = read_pem_file_as_bytes(roots_path)?;

        let policy = match self.policy {
            Policy::ChromeHammurabi => policy::ExecPolicy::chrome_hammurabi(timestamp),
            Policy::FirefoxHammurabi => policy::ExecPolicy::firefox_hammurabi(timestamp),
            Policy::OpenSSL => policy::ExecPolicy::openssl(timestamp),
        };

        let (tx_job, rx_job) = channel::unbounded();
        let (tx_res, rx_res) = channel::unbounded();

        Ok(Box::new(VerdictInstance {
            tx_job: Some(tx_job),
            rx_res: Some(rx_res),
            handle: Some(thread::spawn(move || VerdictInstance::worker(roots_bytes, policy, rx_job, tx_res))),
        }))
    }
}

impl Instance for VerdictInstance {
    fn validate(&mut self, bundle: &Vec<String>, task: &ExecTask, repeat: usize) -> Result<ValidationResult, Error> {
        if repeat == 0 {
            return Err(Error::ZeroRepeat);
        }

        self.tx_job.as_ref().ok_or(
            Error::VerdictBenchError("tx_job has already been dropped".to_string())
        )?.send(Job {
            bundle: bundle.clone(),
            task: task.clone(),
            repeat,
        })?;

        Ok(self.rx_res.as_ref().ok_or(
            Error::VerdictBenchError("tx_job has already been dropped".to_string())
        )?.recv()?)
    }
}

impl Drop for VerdictInstance {
    fn drop(&mut self) {
        drop(self.tx_job.take().unwrap());
        drop(self.rx_res.take().unwrap());

        let Some(handle) = self.handle.take() else {
            eprintln!("verdict impl already joined");
            return;
        };

        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => eprintln!("verdict impl failed with: {:?}", e),
            Err(e) => eprintln!("failed to join verdict impl: {:?}", e),
        }
    }
}
