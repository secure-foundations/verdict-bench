mod error;
mod issue;
mod hash;
mod rsa;
mod ecdsa;
mod utils;
mod policy;
mod convert;
mod validate;

use std::process::ExitCode;
use std::time::Instant;

use clap::{command, Parser, ValueEnum};

use parser::VecDeep;
use error::Error;

#[derive(Debug, Clone, ValueEnum)]
enum Policy {
    ChromeHammurabi,
}

#[derive(Parser, Debug)]
#[command(long_about = None)]
struct Args {
    /// A Prolog source file containing the policy program
    policy: Policy,

    /// File containing the trusted root certificates
    roots: String,

    /// The certificate chain to verify
    chain: String,

    /// The target domain to be validated
    domain: String,

    /// Path to the SWI-Prolog binary
    #[clap(long, value_parser, num_args = 0.., value_delimiter = ' ', default_value = "swipl")]
    swipl_bin: String,

    /// Enable debug mode
    #[arg(long, default_value_t = false)]
    debug: bool,

    /// Override the current time with the given timestamp
    #[clap(short = 't', long)]
    override_time: Option<i64>,

    /// Generate timing stats in wall-clock time
    #[clap(short = 's', long, default_value_t = false)]
    stats: bool,
}

fn main_args(args: Args) -> Result<(), Error> {
    // Parse roots and chain PEM files
    let roots_bytes = utils::read_pem_file_as_bytes(&args.roots)?;
    let chain_bytes = utils::read_pem_file_as_bytes(&args.chain)?;

    let begin = Instant::now();

    let roots = roots_bytes.iter().map(|cert_bytes| {
        utils::parse_x509_certificate(cert_bytes)
    }).collect::<Result<Vec<_>, _>>()?;

    let chain = chain_bytes.iter().map(|cert_bytes| {
        utils::parse_x509_certificate(cert_bytes)
    }).collect::<Result<Vec<_>, _>>()?;

    let timestamp = args.override_time.unwrap_or(chrono::Utc::now().timestamp()) as u64;

    let policy = match args.policy {
        Policy::ChromeHammurabi => policy::ExecPolicy::chrome_hammurabi(timestamp),
    };

    let res = validate::valid_domain(&policy, &VecDeep::from_vec(roots), &VecDeep::from_vec(chain), &args.domain)?;

    if args.stats {
        eprintln!("parsing + validation took {}ms", begin.elapsed().as_micros() as f64 / 1000f64);
    }

    eprintln!("result: {}", res);

    if !res {
        return Err(Error::DomainValidationError);
    }

    Ok(())
}

fn main() -> ExitCode {
    match main_args(Args::parse()) {
        Ok(..) => ExitCode::from(0),
        Err(err) => {
            eprintln!("{}", err);
            ExitCode::from(1)
        }
    }
}
