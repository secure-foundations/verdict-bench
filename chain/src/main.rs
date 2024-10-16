mod error;
mod specs;
mod validate;
mod hash;
mod facts;
mod rsa;
mod ecdsa;

use vstd::prelude::*;

use std::fs;
use std::process::ExitCode;

use base64::Engine;
use clap::{command, Parser};

use parser::{x509, ParseError, Combinator, VecDeep};
use vpl::{parse_program, SwiplBackend};

use validate::*;
use facts::*;
use error::Error;

verus! {
    fn parse_x509_bytes<'a>(bytes: &'a [u8]) -> Result<x509::CertificateValue<'a>, ParseError> {
        let (n, cert) = x509::Certificate.parse(bytes)?;
        if n != bytes.len() {
            return Err(ParseError::Other("trailing bytes in certificate".to_string()));
        }
        Ok(cert)
    }
}

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

/// Read the given PEM file and return a vector of Vec<u8>'s
/// such that each correspond to one certificate
fn read_pem_file_as_bytes(path: &str) -> Result<Vec<Vec<u8>>, Error> {
    let src = std::fs::read_to_string(path)?;
    let mut certs = vec![];

    const PREFIX: &'static str = "-----BEGIN CERTIFICATE-----";
    const SUFFIX: &'static str = "-----END CERTIFICATE-----";

    for chunk in src.split(PREFIX).skip(1) {
        let Some(cert_src) = chunk.split(SUFFIX).next() else {
            return Err(Error::NoMatchingEndCertificate);
        };

        let cert_base64 = cert_src.split_whitespace().collect::<String>();
        let cert_bytes = base64::prelude::BASE64_STANDARD.decode(cert_base64)
            .map_err(|e| Error::Base64DecodeError(e))?;

        certs.push(cert_bytes);
    }

    Ok(certs)
}

fn main_args(args: Args) -> Result<(), Error> {
    // Parse roots and chain PEM files
    let roots_bytes = read_pem_file_as_bytes(&args.roots)?;
    let chain_bytes = read_pem_file_as_bytes(&args.chain)?;

    let roots = roots_bytes.iter().map(|cert_bytes| {
        parse_x509_bytes(cert_bytes)
    }).collect::<Result<Vec<_>, _>>()?;

    let chain = chain_bytes.iter().map(|cert_bytes| {
        parse_x509_bytes(cert_bytes)
    }).collect::<Result<Vec<_>, _>>()?;

    // Print some general information about the certs
    eprintln!("{} root certificate(s)", roots.len());
    eprintln!("{} certificate(s) in the chain", chain.len());

    for (i, cert) in chain.iter().enumerate() {
        eprintln!("cert {}:", i);
        eprintln!("  issuer: {}", cert.get().cert.get().issuer);
        eprintln!("  subject: {}", cert.get().cert.get().subject);
        eprintln!("  signature algorithm: {:?}", cert.get().sig_alg);
        eprintln!("  signature: {:?}", cert.get().cert.get().signature);
        eprintln!("  subject key info: {:?}", cert.get().cert.get().subject_key);
    }

    // Check that for each i, cert[i + 1] issued cert[i]
    for i in 0..chain.len() - 1 {
        if likely_issued(&chain[i + 1], &chain[i]) {
            if verify_signature(&chain[i + 1], &chain[i]) {
                eprintln!("cert {} issued cert {}", i + 1, i);
            } else {
                eprintln!("cert {} issued cert {} (but signature error)", i + 1, i);
            }
        }
    }

    // Check if root cert issued any of the chain certs
    for (i, root) in roots.iter().enumerate() {
        for (j, chain_cert) in chain.iter().enumerate() {
            if likely_issued(root, chain_cert) {
                if verify_signature(root, chain_cert) {
                    eprintln!("root cert {} issued cert {}", i, j);
                } else {
                    eprintln!("root cert {} issued cert {} (but signature error)", i, j);
                }
            }
        }
    }

    eprintln!("=================== validating domain {} ===================", &args.domain);

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
        domain: &args.domain,
        now: args.override_time.unwrap_or(chrono::Utc::now().timestamp()),
    };

    // Call the main validation routine
    let res = valid_domain::<_, Error>(
        &mut swipl_backend,
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

pub fn main() -> ExitCode {
    match main_args(Args::parse()) {
        Ok(..) => ExitCode::from(0),
        Err(err) => {
            eprintln!("{}", err);
            ExitCode::from(1)
        }
    }
}
