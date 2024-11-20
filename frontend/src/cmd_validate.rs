use std::time::Instant;

use clap::{Parser, ValueEnum};

use parser::{parse_x509_cert, VecDeep};
use chain::policy;
use chain::validate::Validator;

use crate::error::*;
use crate::utils::*;

#[derive(Parser, Debug)]
pub struct Args {
    /// Policy to use
    policy: Policy,

    /// Path to the root certificates
    roots: String,

    /// The certificate chain to verify (in PEM format)
    chain: String,

    /// The target domain to be validated
    domain: String,

    /// Enable debug mode
    #[arg(long, default_value_t = false)]
    debug: bool,

    /// Override the current time with the given timestamp
    #[clap(short = 't', long)]
    override_time: Option<i64>,

    /// Generate timing stats in wall-clock time
    #[clap(short = 's', long, default_value_t = false)]
    stats: bool,

    /// Repeat the validation for benchmarking purpose
    #[clap(short = 'n', long)]
    repeat: Option<usize>,
}

#[derive(Debug, Clone, ValueEnum)]
enum Policy {
    ChromeHammurabi,
    FirefoxHammurabi,
}

pub fn main(args: Args) -> Result<(), Error> {
    // Parse roots and chain PEM files
    let roots_bytes = read_pem_file_as_bytes(&args.roots)?;
    let chain_bytes = read_pem_file_as_bytes(&args.chain)?;

    let roots = VecDeep::from_vec(roots_bytes.iter().map(|cert_bytes| {
        parse_x509_cert(cert_bytes)
    }).collect::<Result<Vec<_>, _>>()?);

    let repeat = args.repeat.unwrap_or(1);

    if repeat == 0 {
        return Err(Error::ZeroRepeat);
    }

    let timestamp = args.override_time.unwrap_or(chrono::Utc::now().timestamp()) as u64;
    let policy = match args.policy {
        Policy::ChromeHammurabi => policy::ExecPolicy::chrome_hammurabi(timestamp),
        Policy::FirefoxHammurabi => policy::ExecPolicy::firefox_hammurabi(timestamp),
    };

    let validator = Validator::new(policy, roots);

    let mut durations = Vec::with_capacity(repeat);
    let mut res = false;

    // Repeat <repeat> times
    for i in 0..repeat {
        let begin = Instant::now();

        let chain = VecDeep::from_vec(chain_bytes.iter().map(|cert_bytes| {
            parse_x509_cert(cert_bytes)
        }).collect::<Result<Vec<_>, _>>()?);

        if args.debug && i == 0 {
            print_debug_info(&validator.roots, &chain, &args.domain, timestamp as i64);
        }

        res = validator.validate(&chain, &policy::ExecTask::DomainValidation(args.domain.clone()))?;

        durations.push(begin.elapsed().as_micros());
    }

    if args.stats {
        for duration in durations {
            eprintln!("validation took {:.2}ms", duration as f64 / 1000f64);
        }
    }

    eprintln!("result: {}", res);

    if !res {
        return Err(Error::DomainValidationError);
    }

    Ok(())
}
