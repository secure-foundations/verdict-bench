use clap::{Parser, ValueEnum};

use chain::policy;
use chain::validate::Validator;
use parser::{x509, VecDeep};

use crate::error::*;

/// Common arguments for certificate validation
#[derive(Parser, Debug)]
#[group(skip)]
pub struct Args {
    /// Policy to use
    pub policy: Policy,

    /// Enable debug mode
    #[arg(long, default_value_t = false)]
    pub debug: bool,

    /// Override the current time with the given timestamp
    #[clap(short = 't', long)]
    pub override_time: Option<i64>,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum Policy {
    ChromeHammurabi,
    FirefoxHammurabi,
}

pub fn new_validator<'a>(args: &Args, roots: Vec<x509::CertificateValue<'a>>) -> Result<Validator<'a>, Error> {
    let timestamp = args.override_time.unwrap_or(chrono::Utc::now().timestamp()) as u64;
    let policy = match args.policy {
        Policy::ChromeHammurabi => policy::ExecPolicy::chrome_hammurabi(timestamp),
        Policy::FirefoxHammurabi => policy::ExecPolicy::firefox_hammurabi(timestamp),
    };

    Ok(Validator::new(policy, VecDeep::from_vec(roots)))
}
