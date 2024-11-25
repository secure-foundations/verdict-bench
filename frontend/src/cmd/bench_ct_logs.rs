use std::io;
use std::fs::File;

use chrono::Utc;
use clap::{Parser, ValueEnum};
use csv::{ReaderBuilder, WriterBuilder};

use crate::ct_logs::*;
use crate::error::*;
use crate::utils::*;
use crate::harness::*;
use crate::validator::Policy;

#[derive(Parser, Debug)]
pub struct Args {
    /// X509 validator used for benchmarking
    agent: BenchAgent,

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
pub enum BenchAgent {
    VerdictChrome,
    VerdictFirefox,
    Chrome,
    Firefox,
}

fn get_harness(args: &Args) -> Result<Box<dyn Harness>, Error> {
    Ok(match args.agent {
        BenchAgent::Chrome =>
            Box::new(ChromeAgent {
                repo: args.chrome_repo.clone()
                    .ok_or(Error::ChromeBenchError("chrome repo not specified".to_string()))?,
                faketime_lib: args.faketime_lib.clone(),
                debug: args.debug,
            }),

        BenchAgent::Firefox =>
            Box::new(FirefoxAgent {
                repo: args.firefox_repo.clone()
                    .ok_or(Error::FirefoxBenchError("firefox repo not specified".to_string()))?,
                debug: args.debug,
            }),

        BenchAgent::VerdictChrome =>
            Box::new(VerdictAgent {
                policy: Policy::ChromeHammurabi,
                debug: args.debug,
            }),

        BenchAgent::VerdictFirefox =>
            Box::new(VerdictAgent {
                policy: Policy::FirefoxHammurabi,
                debug: args.debug,
            }),
    })
}

pub fn main(args: Args) -> Result<(), Error> {
    if args.csv_files.is_empty() {
        eprintln!("no csv files given");
        return Ok(());
    }

    let timestamp = args.override_time.unwrap_or(Utc::now().timestamp()) as u64;
    let harness: Box<dyn Harness> = get_harness(&args)?;
    let mut instance = harness.spawn(&args.roots, timestamp)?;

    let mut found_hash = false;

    // Open the output file if it exists, otherwise use stdout
    let mut output_handle: Box<dyn io::Write> = if let Some(out_path) = args.out_csv {
        Box::new(File::create(out_path)?)
    } else {
        Box::new(std::io::stdout())
    };
    let mut output_writer =
        WriterBuilder::new().has_headers(false).from_writer(output_handle);

    let mut inner = || -> Result<(), Error> {
        for path in &args.csv_files {
            let file = File::open(path)?;
            let mut reader = ReaderBuilder::new()
                .has_headers(false)  // If your CSV has headers
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

                let mut bundle = vec![entry.cert_base64.to_string()];

                // Look up all intermediate certificates <args.interm_dir>/<entry.interm_certs>.pem
                // `entry.interm_certs` is a comma-separated list
                for interm_cert in entry.interm_certs.split(",") {
                    bundle.extend(read_pem_file_as_base64(&format!("{}/{}.pem", &args.interm_dir, interm_cert))?);
                }

                let res = instance.validate(&bundle, &ExecTask::DomainValidation(entry.domain.to_string()), args.repeat)?;

                // println!("{}: {:?}", entry.hash, res);

                output_writer.serialize(CTLogResult {
                    hash: entry.hash,
                    domain: entry.domain,
                    result: if let Some(err) = res.err {
                        err
                    } else {
                        "true".to_string()
                    },
                    stats: res.stats,
                })?;

                output_writer.flush()?;
            }
        }

        Ok(())
    };

    if let Err(err) = inner() {
        eprintln!("failed: {}", err);
    }

    Ok(())
}
