use std::cell::RefCell;
use std::thread;
use std::thread::JoinHandle;
use std::time::Instant;

use chain::policy;
use chain::validate::Validator;
use crossbeam::channel;
use crossbeam::channel::Receiver;
use crossbeam::channel::Sender;
use parser::{parse_x509_cert, decode_base64, VecDeep};

use crate::validator::Policy;
use crate::error::*;
use crate::utils::*;

use super::common::*;

pub struct VerdictAgent {
    pub policy: Policy,
    pub debug: bool,
}

struct Job {
    bundle: Vec<String>,
    domain: String,
    repeat: usize,
}

pub struct VerdictImpl {
    tx_job: Option<Sender<Job>>,
    rx_res: Option<Receiver<ValidationResult>>,
    handle: Option<JoinHandle<Result<(), Error>>>,
}

impl X509Agent for VerdictAgent {
    type Impl = VerdictImpl;

    fn init(&self, roots_path: &str, timestamp: u64) -> Result<Self::Impl, Error> {
        let roots_bytes = read_pem_file_as_bytes(roots_path)?;
        let policy = self.policy.clone();

        let (tx_job, rx_job) = channel::unbounded();
        let (tx_res, rx_res) = channel::unbounded();

        Ok(VerdictImpl {
            tx_job: Some(tx_job),
            rx_res: Some(rx_res),
            handle: Some(thread::spawn(move || -> Result<(), Error> {
                // println!("{}", roots_bytes.len());

                // Parse root certificates before receiving any job
                let roots = roots_bytes.iter()
                    .map(|bytes| parse_x509_cert(bytes))
                    .collect::<Result<Vec<_>, _>>()?;

                let policy = match policy {
                    Policy::ChromeHammurabi => policy::ExecPolicy::chrome_hammurabi(timestamp),
                    Policy::FirefoxHammurabi => policy::ExecPolicy::firefox_hammurabi(timestamp),
                    Policy::OpenSSL => policy::ExecPolicy::openssl(timestamp),
                };

                let validator = Validator::new(policy, VecDeep::from_vec(roots));

                while let Ok(Job { bundle, domain, repeat }) = rx_job.recv() {
                    let mut durations: Vec<_> = Vec::with_capacity(repeat);
                    let mut res = false;

                    for i in 0..repeat {
                        let start = Instant::now();

                        let chain_bytes = bundle.iter().map(|base64: &String| {
                            decode_base64(base64.as_bytes())
                        }).collect::<Result<Vec<_>, _>>()?;
                        let chain = chain_bytes.iter().map(|bytes| {
                            parse_x509_cert(bytes)
                        }).collect::<Result<Vec<_>, _>>()?;

                        let chain = VecDeep::from_vec(chain);

                        res = validator.validate_hostname(&chain, &domain)?;

                        durations.push(start.elapsed().as_micros()
                            .try_into().map_err(|_| Error::DurationOverflow)?);
                    }

                    tx_res.send(ValidationResult {
                        err: if res { None } else { Some("false".to_string()) },
                        stats: durations,
                    })?;
                }

                Ok(())
            })),
        })
    }
}

impl X509Impl for VerdictImpl {
    fn validate(&mut self, bundle: &Vec<String>, domain: &str, repeat: usize) -> Result<ValidationResult, Error> {
        self.tx_job.as_ref().ok_or(
            Error::VerdictBenchError("tx_job has already been dropped".to_string())
        )?.send(Job {
            bundle: bundle.clone(),
            domain: domain.to_string(),
            repeat,
        })?;

        Ok(self.rx_res.as_ref().ok_or(
            Error::VerdictBenchError("tx_job has already been dropped".to_string())
        )?.recv()?)
    }
}

impl Drop for VerdictImpl {
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
