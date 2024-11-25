use std::io;
use std::fs::File;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use chrono::Utc;
use clap::{Parser, ValueEnum};
use crossbeam::channel;
use crossbeam::channel::Receiver;
use crossbeam::channel::Sender;
use csv::{ReaderBuilder, WriterBuilder};

use crate::ct_logs::*;
use crate::error::*;
use crate::utils::*;
use crate::harness::*;
use crate::validator::Policy;

#[derive(Parser, Debug)]
pub struct Args {
    /// X509 validator used for benchmarking
    agent: BenchHarness,

    /// Path to the root certificates
    roots: String,

    /// Directory containing intermediate certificates
    interm_dir: String,

    #[clap(num_args = 1..)]
    csv_files: Vec<String>,

    /// Only test the certificate with the given hash
    #[clap(long)]
    hash: Option<String>,

    /// Store the results in the given CSV file
    #[clap(short = 'o', long)]
    out_csv: Option<String>,

    /// Number of parallel threads to run validation
    #[clap(short = 'j', long = "jobs", default_value = "1")]
    num_jobs: usize,

    /// Only validate the first <limit> certificates, if specified
    #[clap(short = 'l', long)]
    limit: Option<usize>,

    /// Path to the Chrome build repo with cert_bench
    #[clap(long)]
    chrome_repo: Option<String>,

    /// Path to the Firefox build repo
    #[clap(long)]
    firefox_repo: Option<String>,

    /// Path to the OpenSSL harness repo
    #[clap(long)]
    openssl_repo: Option<String>,

    /// Path to libfaketime.so
    #[clap(long, default_value = "/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1")]
    faketime_lib: String,

    /// Repeat validation of each certificate for benchmarking
    #[clap(short = 'n', long, default_value = "1")]
    repeat: usize,

    /// Override the current time with the given timestamp
    #[clap(short = 't', long)]
    override_time: Option<i64>,

    /// Enable debug mode
    #[arg(long, default_value_t = false)]
    debug: bool,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum BenchHarness {
    VerdictChrome,
    VerdictFirefox,
    Chrome,
    Firefox,
    OpenSSL,
}

fn get_harness(args: &Args) -> Result<Box<dyn Harness>, Error> {
    Ok(match args.agent {
        BenchHarness::Chrome =>
            Box::new(ChromeHarness {
                repo: args.chrome_repo.clone()
                    .ok_or(Error::ChromeBenchError("chrome repo not specified".to_string()))?,
                faketime_lib: args.faketime_lib.clone(),
                debug: args.debug,
            }),

        BenchHarness::Firefox =>
            Box::new(FirefoxHarness {
                repo: args.firefox_repo.clone()
                    .ok_or(Error::FirefoxBenchError("firefox repo not specified".to_string()))?,
                debug: args.debug,
            }),

        BenchHarness::OpenSSL =>
            Box::new(OpenSSLHarness {
                repo: args.openssl_repo.clone()
                    .ok_or(Error::OpenSSLBenchError("openssl repo not specified".to_string()))?,
                debug: args.debug,
            }),

        BenchHarness::VerdictChrome =>
            Box::new(VerdictHarness {
                policy: Policy::ChromeHammurabi,
                debug: args.debug,
            }),

        BenchHarness::VerdictFirefox =>
            Box::new(VerdictHarness {
                policy: Policy::FirefoxHammurabi,
                debug: args.debug,
            }),
    })
}

/// Each worker thread waits for CTLogEntry's, does the validation, and then sends back CTLogResult's
fn worker(args: &Args, mut instance: Box<dyn Instance>, rx_job: Receiver<CTLogEntry>, tx_res: Sender<CTLogResult>) -> Result<(), Error> {
    // Recv a CTLogEntry
    while let Ok(entry) = rx_job.recv() {
        let mut bundle = vec![entry.cert_base64.to_string()];

        // Look up all intermediate certificates <args.interm_dir>/<entry.interm_certs>.pem
        // `entry.interm_certs` is a comma-separated list
        for interm_cert in entry.interm_certs.split(",") {
            bundle.extend(read_pem_file_as_base64(&format!("{}/{}.pem", &args.interm_dir, interm_cert))?);
        }

        let res = instance.validate(&bundle, &ExecTask::DomainValidation(entry.domain.to_string()), args.repeat)?;

        // Send back a CTLogResult
        tx_res.send(CTLogResult {
            hash: entry.hash,
            domain: entry.domain,
            valid: res.valid,
            err: res.err,
            stats: res.stats,
        })?;
    }

    Ok(())
}

/// Collect validation results from `rx_res` and write them to a CSV file (or stdout if not specified)
fn reducer(out_csv: Option<String>, rx_res: Receiver<CTLogResult>) -> Result<(), Error> {
    // Open the output file if it exists, otherwise use stdout
    let mut handle: Box<dyn io::Write> = if let Some(out_path) = out_csv {
        Box::new(File::create(out_path)?)
    } else {
        Box::new(std::io::stdout())
    };
    let mut output_writer =
        WriterBuilder::new().has_headers(false).from_writer(handle);

    let start = Instant::now();

    while let Ok(res) = rx_res.recv() {
        output_writer.serialize(res)?;
        output_writer.flush()?;
    }

    eprintln!("total validation time: {:.3}s", start.elapsed().as_secs_f64());

    Ok(())
}

pub fn main(args: Args) -> Result<(), Error> {
    let args = Arc::new(args);

    if args.csv_files.is_empty() {
        eprintln!("no csv files given");
        return Ok(());
    }

    let timestamp = args.override_time.unwrap_or(Utc::now().timestamp()) as u64;
    let harness: Box<dyn Harness> = get_harness(&args)?;

    let mut found_hash = false;

    let (tx_job, rx_job) = channel::unbounded();
    let (tx_res, rx_res) = channel::unbounded();

    let mut workers = Vec::new();

    let inner = || {
        for _ in 0..args.num_jobs {
            let args = args.clone();
            let instance = harness.spawn(&args.roots, timestamp)?;
            let rx_job = rx_job.clone();
            let tx_res = tx_res.clone();

            workers.push(thread::spawn(move || worker(&args, instance, rx_job, tx_res)));
        }

        let out_csv = args.out_csv.clone();
        workers.push(thread::spawn(move || reducer(out_csv, rx_res)));

        // Main thread: read the input CSV files and send jobs (CTLogEntry's) to worker threads
        let mut found_hash = false;
        for path in &args.csv_files {
            let file = File::open(path)?;
            let mut reader = ReaderBuilder::new()
                .has_headers(false)
                .from_reader(file);

            for (i, entry) in reader.deserialize().enumerate() {
                let entry: CTLogEntry = entry?;

                if let Some(limit) = args.limit {
                    if i >= limit {
                        break;
                    }
                }

                // If a specific hash is specified, only check certificate with that hash
                if let Some(hash) = &args.hash {
                    if hash != &entry.hash {
                        continue;
                    } else {
                        found_hash = true;
                    }
                }

                tx_job.send(entry)?;
            }
        }

        if let Some(hash) = &args.hash {
            if !found_hash {
                eprintln!("hash {} not found in the given CSV files", hash);
            }
        }

        Ok(())
    };

    let res = inner();

    // Signal no more jobs
    drop(tx_job);
    drop(tx_res);

    // Join all workers at the end
    for (i, worker) in workers.into_iter().enumerate() {
        match worker.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                eprintln!("worker {} failed with error: {}", i, err);
            }
            Err(err) => {
                eprintln!("failed to join worker {}: {:?}", i, err);
            }
        }
    }

    res
}
