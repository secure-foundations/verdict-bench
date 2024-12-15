use std::fs::File;
use std::io::{self, BufWriter, BufReader, Write};

use chain::policy::{ExecPurpose, ExecTask};
use chrono::Utc;
use clap::Parser;
use limbo_harness_support::models::{ExpectedResult, Testcase};
use limbo_harness_support::models::{Limbo, PeerKind, ValidationKind};
use tempfile::NamedTempFile;

use crate::error::*;
use crate::harness::*;

#[derive(Parser, Debug)]
pub struct Args {
    /// X509 validator used for testing
    #[clap(flatten)]
    harness: HarnessArgs,

    /// Path to the Limbo test cases
    path: String,

    /// Number of parallel threads to run validation
    #[clap(short = 'j', long = "jobs", default_value = "1")]
    num_jobs: usize,

    /// Test a particular test ID
    #[clap(short = 't', long = "test")]
    test_id: Option<String>,

    /// Only validate the first <limit> certificates, if specified
    #[clap(short = 'l', long)]
    limit: Option<usize>,

    /// Enable debug mode
    #[arg(long, default_value_t = false)]
    debug: bool,

    /// Do chain validation only without domain
    #[arg(long, default_value_t = false)]
    no_domain: bool,

    /// Repeat validation of each certificate for benchmarking
    #[clap(short = 'n', long, default_value = "1")]
    repeat: usize,
}

/// Strip -----BEGIN CERTIFICATE----- and -----END CERTIFICATE-----
/// and remove any whitespaces
fn strip_pem(s: &str) -> Option<String>
{
    Some(s.trim()
        .strip_prefix("-----BEGIN CERTIFICATE-----")?
        .strip_suffix("-----END CERTIFICATE-----")?
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect())
}

fn test_limbo(args: &Args, harness: &Box<dyn Harness>, testcase: &Testcase) -> Result<bool, Error>
{
    let tmp_root_file = NamedTempFile::new()?;
    let tmp_root_path = tmp_root_file.path().to_str()
        .ok_or(io::Error::other("failed to convert path to str"))?
        .to_string();

    let mut writer = BufWriter::new(&tmp_root_file);
    for cert in &testcase.trusted_certs {
        writeln!(writer, "{}", cert)?;
    }
    writer.flush()?;

    let timestamp = testcase.validation_time.unwrap_or(Utc::now()).timestamp() as u64;

    let mut instance = harness.spawn(&tmp_root_path, timestamp)?;

    let mut bundle = vec![
        strip_pem(&testcase.peer_certificate)
            .ok_or(Error::LimboError("failed to process PEM".to_string()))?
    ];

    for interm in &testcase.untrusted_intermediates {
        bundle.push(strip_pem(interm)
            .ok_or(Error::LimboError("failed to process PEM".to_string()))?);
    }

    let task = if let Some(peer_name) = &testcase.expected_peer_name {
        if args.no_domain {
            ExecTask::ChainValidation(ExecPurpose::ServerAuth)
        } else {
            ExecTask::DomainValidation(peer_name.value.clone())
        }
    } else {
        ExecTask::ChainValidation(ExecPurpose::ServerAuth)
    };

    let (valid, err) = match instance.validate(&bundle, &task, args.repeat) {
        Ok(res) => (res.valid, res.err),
        Err(e) => (false, e.to_string()),
    };

    let expected = testcase.expected_result == ExpectedResult::Success;
    println!("{} (expect {}): {}, {}", testcase.id.to_string(), expected, valid, err);

    Ok(expected == valid)
}

pub fn main(args: Args) -> Result<(), Error>
{
    let harness = get_harness_from_args(&args.harness, args.debug)?;

    let limbo: Limbo = serde_json::from_reader(BufReader::new(File::open(&args.path)?))?;
    eprintln!("loaded {} testcases", limbo.testcases.len());

    // Only perform server authentication and DNS name validation (if enabled)
    let filter = |t: &&Testcase|
        t.validation_kind == ValidationKind::Server &&
        (args.no_domain || (t.expected_peer_name.is_some() && t.expected_peer_name.as_ref().unwrap().kind == PeerKind::Dns)) &&
        if let Some(id) = &args.test_id { &t.id.to_string() == id } else { true };

    let mut total = 0;
    let mut conformant = 0;

    for (i, testcase) in limbo.testcases.iter().filter(filter).enumerate() {
        if let Some(limit) = args.limit {
            if i >= limit {
                break;
            }
        }

        total += 1;

        if test_limbo(&args, &harness, testcase)? {
            conformant += 1;
        }
    }

    eprintln!("{}/{} conformant ({} errors)", conformant, total, total - conformant);

    Ok(())
}
