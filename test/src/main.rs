mod error;

use vstd::prelude::*;

use base64::Engine;
use std::io::{self, BufRead};
use std::process::ExitCode;
use std::fs::File;

use std::collections::HashMap;

use csv::ReaderBuilder;
use serde::Deserialize;

use clap::{command, Parser, Subcommand};

use parser::{Combinator, x509};

use error::*;

#[derive(Parser, Debug)]
#[command(long_about = None)]
struct Args {
    #[clap(subcommand)]
    action: Action,
}

#[derive(Debug, Subcommand)]
enum Action {
    /// Parse PEM format X.509 certificates from stdin
    Parse(ParseArgs),

    /// Parse a specific format of certificates stored in CSVs
    ParseCTLog(ParseCTLogArgs),

    /// Validate certificates in the given CT log files
    ValidateCTLog(ValidateCTLogArgs),
}

#[derive(Parser, Debug)]
struct ParseArgs {
    /// Ignore parse errors in X.509
    #[clap(short = 'e', long, default_value_t = false)]
    ignore_parse_errors: bool,
}

#[derive(Parser, Debug)]
struct ParseCTLogArgs {
    #[clap(num_args = 1..)]
    csv_files: Vec<String>,

    #[clap(short = 'e', long, default_value_t = false)]
    ignore_parse_errors: bool,
}

#[derive(Parser, Debug)]
struct ValidateCTLogArgs {
    /// A Prolog source file containing the policy program
    policy: String,

    /// Path to the root certificates
    roots: String,

    /// Directory containing intermediate certificates
    interm_dir: String,

    #[clap(num_args = 1..)]
    csv_files: Vec<String>,

    /// Only test the certificate with the given hash
    #[clap(long)]
    hash: Option<String>,

    /// Store the results as CSV files in the given directory
    #[clap(short = 'o', long)]
    out_dir: Option<String>,

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

verus! {
    fn parse_x509_bytes<'a>(bytes: &'a [u8]) -> Result<x509::CertificateValue<'a>, parser::ParseError> {
        let (n, cert) = x509::Certificate.parse(bytes)?;
        if n != bytes.len() {
            return Err(parser::ParseError::Other("trailing bytes in certificate".to_string()));
        }
        Ok(cert)
    }
}

/// Read the given PEM file and return a vector of Vec<u8>'s
/// such that each correspond to one certificate
///
/// TODO: Merge with the same function in chain
fn read_pem_file_as_bytes(path: &str) -> Result<Vec<Vec<u8>>, Error> {
    let src = std::fs::read_to_string(path)?;
    let mut certs = vec![];

    const PREFIX: &'static str = "-----BEGIN CERTIFICATE-----";
    const SUFFIX: &'static str = "-----END CERTIFICATE-----";

    for chunk in src.split(PREFIX).skip(1) {
        let Some(cert_src) = chunk.split(SUFFIX).next() else {
            return Err(ParseActionError::NoMatchingEndCertificate)?;
        };

        let cert_base64 = cert_src.split_whitespace().collect::<String>();
        let cert_bytes = base64::prelude::BASE64_STANDARD.decode(cert_base64)?;

        certs.push(cert_bytes);
    }

    Ok(certs)
}

/// Read from stdin a sequence of PEM-encoded certificates, parse them, and print them to stdout
fn parse_cert_from_stdin(args: ParseArgs) -> Result<(), Error>
{
    const PREFIX: &'static str = "-----BEGIN CERTIFICATE-----";
    const SUFFIX: &'static str = "-----END CERTIFICATE-----";

    let mut cur_cert_base64 = None;
    let mut num_parsed = 0;

    for line in io::stdin().lock().lines() {
        let line = line?;
        let line_trimmed = line.trim();

        if line_trimmed == PREFIX {
            if cur_cert_base64.is_some() {
                Err(ParseActionError::NoMatchingEndCertificate)?;
            }

            cur_cert_base64 = Some(String::new());
        } else if line_trimmed == SUFFIX {
            match cur_cert_base64.take() {
                Some(cert_base64) => {
                    num_parsed += 1;

                    let cert_bytes = base64::prelude::BASE64_STANDARD.decode(cert_base64)?;

                    match parse_x509_bytes(&cert_bytes) {
                        Ok(cert) => {
                            println!("{:?}", cert.get().cert.get().subject_key.alg);
                            // println!("{:?}", cert);
                        }
                        Err(err) => {
                            if !args.ignore_parse_errors {
                                Err(err)?;
                            } else {
                                eprintln!("error parsing certificate {}, ignored", num_parsed);
                            }
                        }
                    }
                }
                None => {
                    Err(ParseActionError::NoMatchingBeginCertificate)?;
                }
            }
        } else if let Some(cur_cert_base64) = cur_cert_base64.as_mut() {
            cur_cert_base64.push_str(line_trimmed);
        }
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct CTLogEntry {
    cert_base64: String,
    hash: String, // SHA-256 hash of the entire certificate
    domain: String,
    interm_certs: String,
}

fn parse_cert_ct_logs(args: ParseCTLogArgs) -> Result<(), Error>
{
    eprintln!("parsing {} CT log file(s)", args.csv_files.len());

    // Count the number of certificates using each subject key algo
    let mut signature_algs = HashMap::new();
    let mut subject_keys = HashMap::new();

    let mut num_parsed_total = 0;

    for path in args.csv_files {
        let mut num_parsed = 0;

        let file = File::open(&path)?;
        let mut reader = ReaderBuilder::new()
            .has_headers(false)  // If your CSV has headers
            .from_reader(file);

        for result in reader.deserialize() {
            let result: CTLogEntry = result?;

            let cert_bytes = base64::prelude::BASE64_STANDARD.decode(result.cert_base64)?;

            match parse_x509_bytes(&cert_bytes) {
                Ok(cert) => {
                    let alg_str = format!("{:?}", cert.get().cert.get().subject_key.alg);
                    *subject_keys.entry(alg_str).or_insert(0) += 1;

                    let sig_alg_str = format!("{:?}", cert.get().sig_alg);
                    *signature_algs.entry(sig_alg_str).or_insert(0) += 1;
                }
                Err(err) => {
                    if !args.ignore_parse_errors {
                        Err(err)?;
                    } else {
                        eprintln!("error parsing certificate in {}, ignored", path);
                    }
                }
            }

            num_parsed += 1;
            num_parsed_total += 1;
        }

        eprintln!("parsed {} certificate(s) in {} (total {})", num_parsed, path, num_parsed_total);
        eprintln!("subject key algorithms found so far: {:?}", subject_keys);
        eprintln!("signature algorithms found so far: {:?}", signature_algs);
    }

    eprintln!("parsed {} certificate(s) in total", num_parsed_total);

    Ok(())
}

fn validate_ct_logs(args: ValidateCTLogArgs) -> Result<(), Error>
{
    eprintln!("validating {} CT log file(s)", args.csv_files.len());

    // Parse root certificates
    let roots_bytes = read_pem_file_as_bytes(&args.roots)?;
    let roots: Vec<parser::CachedValue<'_, parser::asn1::ASN1<x509::CertificateInner>>> =
        roots_bytes.iter().map(|bytes| parse_x509_bytes(bytes)).collect::<Result<Vec<_>, _>>()?;
    let roots = parser::VecDeep::from_vec(roots);

    // Load swipl backend parameters
    let mut swipl_backend = vpl::SwiplBackend {
        debug: args.debug,
        swipl_bin: args.swipl_bin.clone(),
    };

    // Parse the source file
    let source = std::fs::read_to_string(&args.policy)?;

    let timestamp = args.override_time.unwrap_or(chrono::Utc::now().timestamp());

    for path in args.csv_files {
        let file = File::open(&path)?;
        let mut reader = ReaderBuilder::new()
            .has_headers(false)  // If your CSV has headers
            .from_reader(file);

        for entry in reader.deserialize() {
            let entry: CTLogEntry = entry?;

            // If a specific hash is specified, only check certificate with that hash
            if let Some(hash) = &args.hash {
                if hash != &entry.hash {
                    continue;
                }
            }

            let validate = || {
                let mut chain_bytes = vec![base64::prelude::BASE64_STANDARD.decode(entry.cert_base64)?];

                // Look up all intermediate certificates <args.interm_dir>/<entry.interm_certs>.pem
                // `entry.interm_certs` is a comma-separated list
                for interm_cert in entry.interm_certs.split(",") {
                    chain_bytes.append(&mut read_pem_file_as_bytes(&format!("{}/{}.pem", args.interm_dir, interm_cert))?);
                }

                let mut chain =
                    chain_bytes.iter().map(|bytes| parse_x509_bytes(bytes)).collect::<Result<Vec<_>, _>>()?;

                let chain = parser::VecDeep::from_vec(chain);

                // TODO: move parsing outside
                let (policy, _) = vpl::parse_program(&source, &args.policy)?;

                let query = chain::facts::Query {
                    roots: &roots,
                    chain: &chain,
                    domain: &entry.domain.to_lowercase(),
                    now: timestamp,
                };

                chain::validate::valid_domain::<_, Error>(
                    &mut swipl_backend,
                    policy,
                    &query,
                    args.debug,
                )
            };

            match validate() {
                Ok(res) => {
                    println!("{},{},{}", entry.hash, entry.domain, res);
                }
                Err(err) => {
                    println!("{},{},crash: {}", entry.hash, entry.domain, err);
                }
            }
        }
    }

    Ok(())
}

fn main_args(args: Args) -> Result<(), Error> {
    match args.action {
        Action::Parse(args) => parse_cert_from_stdin(args),
        Action::ParseCTLog(args) => parse_cert_ct_logs(args),
        Action::ValidateCTLog(args) => validate_ct_logs(args),
    }
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
