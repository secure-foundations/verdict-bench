mod error;
mod specs;
mod validate;
mod hash;
mod facts;
mod rsa;
mod ecdsa;
mod utils;

use std::fs;
use std::process::ExitCode;

use clap::{command, Parser};

use parser::VecDeep;
use vpl::{parse_program, SwiplBackend};

use validate::*;
use facts::*;
use error::Error;

#[derive(Parser, Debug)]
#[command(long_about = None)]
struct Args {
    /// A Prolog source file containing the policy program
    policy: String,

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
}

fn main_args(args: Args) -> Result<(), Error> {
    // Parse roots and chain PEM files
    let roots_bytes = utils::read_pem_file_as_bytes(&args.roots)?;
    let chain_bytes = utils::read_pem_file_as_bytes(&args.chain)?;

    let roots = roots_bytes.iter().map(|cert_bytes| {
        utils::parse_x509_certificate(cert_bytes)
    }).collect::<Result<Vec<_>, _>>()?;

    let chain = chain_bytes.iter().map(|cert_bytes| {
        utils::parse_x509_certificate(cert_bytes)
    }).collect::<Result<Vec<_>, _>>()?;

    let mut swipl_backend = SwiplBackend {
        debug: args.debug,
        swipl_bin: args.swipl_bin.clone(),
    };

    // Parse the source file
    let source = fs::read_to_string(&args.policy)?;
    let (policy, _) = parse_program(source, &args.policy)?;

    let query = Query {
        roots: &VecDeep::from_vec(roots),
        chain: &VecDeep::from_vec(chain),
        domain: &args.domain.to_lowercase(),
        now: args.override_time.unwrap_or(chrono::Utc::now().timestamp()),
    };

    if args.debug {
        query.print_debug_info();
    }

    // Call the main validation routine
    let res = valid_domain::<_, Error>(
        &swipl_backend,
        policy,
        &query,
        args.debug,
    )?;
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
