use std::time::Instant;

use chain::policy::ExecPurpose;
use chain::policy::ExecTask;
use clap::Parser;

use parser::{parse_x509_cert, VecDeep};

use crate::error::*;
use crate::utils::*;
use crate::validator;

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(flatten)]
    validator: validator::Args,

    /// Path to the root certificates
    roots: String,

    /// The certificate chain to verify (in PEM format)
    chain: String,

    /// The target domain to be validated
    /// If not specified, the task will be Task::ChainValidation(Purpose::ServerAuth)
    domain: Option<String>,

    /// Generate timing stats in wall-clock time
    #[clap(short = 's', long, default_value_t = false)]
    stats: bool,

    /// Repeat the validation for benchmarking purpose
    #[clap(short = 'n', long)]
    repeat: Option<usize>,
}

pub fn main(args: Args) -> Result<(), Error> {
    // Parse roots and chain PEM files
    let roots_bytes = read_pem_file_as_bytes(&args.roots)?;
    let chain_bytes = read_pem_file_as_bytes(&args.chain)?;

    let roots = roots_bytes.iter().map(|cert_bytes| {
        parse_x509_cert(cert_bytes)
    }).collect::<Result<Vec<_>, _>>()?;

    let repeat = args.repeat.unwrap_or(1);

    if repeat == 0 {
        return Err(Error::ZeroRepeat);
    }

    let validator = validator::new_validator(&args.validator, roots)?;

    let mut durations = Vec::with_capacity(repeat);
    let mut res = false;

    let task = if let Some(domain) = &args.domain {
        ExecTask::DomainValidation(domain.to_string())
    } else {
        ExecTask::ChainValidation(ExecPurpose::ServerAuth)
    };

    // Repeat <repeat> times
    for i in 0..repeat {
        let begin = Instant::now();

        let chain = VecDeep::from_vec(chain_bytes.iter().map(|cert_bytes| {
            parse_x509_cert(cert_bytes)
        }).collect::<Result<Vec<_>, _>>()?);

        if args.validator.debug && i == 0 {
            print_debug_info(&validator.roots, &chain, &task, validator.get_validation_time());
        }

        res = validator.validate(&chain, &task)?;

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
