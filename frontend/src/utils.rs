use chrono::{DateTime, Utc};

use std::fs::File;
use std::io::{BufRead, BufReader};

use parser::{*, x509};
use chain::{policy, issue};

use crate::error::Error;

pub fn read_pem_file_as_bytes(path: &str) -> Result<Vec<Vec<u8>>, Error> {
    let file = BufReader::new(File::open(path)?);
    read_pem_as_bytes(file)
}

/// Read a PEM file (given as a BufRead) and return a vector of Vec<u8>'s
/// such that each correspond to one certificate
pub fn read_pem_as_bytes<B: BufRead>(reader: B) -> Result<Vec<Vec<u8>>, Error> {
    let mut certs = vec![];

    const PREFIX: &'static str = "-----BEGIN CERTIFICATE-----";
    const SUFFIX: &'static str = "-----END CERTIFICATE-----";

    let mut cur_cert_base64 = None;

    for line in reader.lines() {
        let line = line?;
        let line_trimmed = line.trim();

        if line_trimmed == PREFIX {
            if cur_cert_base64.is_some() {
                Err(Error::NoMatchingEndCertificate)?;
            }

            cur_cert_base64 = Some(String::new());
        } else if line_trimmed == SUFFIX {
            match cur_cert_base64.take() {
                Some(cert_base64) => {
                    let cert_bytes = decode_base64(cert_base64.as_bytes())?;
                    certs.push(cert_bytes);
                }
                None => {
                    Err(Error::NoMatchingBeginCertificate)?;
                }
            }
        } else if let Some(cur_cert_base64) = cur_cert_base64.as_mut() {
            cur_cert_base64.push_str(line_trimmed);
        }
    }

    Ok(certs)
}

pub fn print_debug_info(roots: &VecDeep<x509::CertificateValue>, chain: &VecDeep<x509::CertificateValue>, domain: &str, now: i64) {
    eprintln!("=================== query info ===================");
    // Print some general information about the certs
    eprintln!("{} root certificate(s)", roots.len());
    eprintln!("{} certificate(s) in the chain", chain.len());

    // Check that for each i, cert[i + 1] issued cert[i]
    for i in 0..chain.len() - 1 {
        if issue::likely_issued(chain.get(i + 1), chain.get(i)) {
            eprintln!("cert {} issued cert {}", i + 1, i);
        }
    }

    let mut used_roots = Vec::new();

    // Check if root cert issued any of the chain certs
    for (i, root) in roots.to_vec().iter().enumerate() {
        let mut used = false;

        for (j, chain_cert) in chain.to_vec().iter().enumerate() {
            if issue::likely_issued(root, chain_cert) {
                used = true;
                eprintln!("root cert {} issued cert {}", i, j);
            }
        }

        if used {
            used_roots.push(i);
        }
    }

    let print_cert = |cert: &x509::CertificateValue| {
        eprintln!("  subject: {}", cert.get().cert.get().subject);
        eprintln!("  issued by: {}", cert.get().cert.get().issuer);
        eprintln!("  signed with: {:?}", cert.get().sig_alg);
        eprintln!("  subject key: {:?}", cert.get().cert.get().subject_key.alg);
    };

    for (i, cert) in chain.to_vec().iter().enumerate() {
        eprintln!("cert {}:", i);
        print_cert(cert);
    }

    for i in used_roots.iter() {
        eprintln!("root cert {}:", i);
        print_cert(roots.get(*i));
    }

    eprintln!("domain to validate: {}", domain);
    eprintln!("timestamp: {} ({})", now, match DateTime::<Utc>::from_timestamp(now, 0) {
        Some(dt) => dt.to_string(),
        None => "invalid".to_string(),
    });

    for (i, cert) in chain.to_vec().iter().enumerate() {
        eprintln!("abstract cert {}:", i);
        eprintln!("  {:?}", policy::Certificate::from(cert));
    }

    for i in used_roots.iter() {
        eprintln!("abstract root cert {}:", i);
        eprintln!("  {:?}", policy::Certificate::from(roots.get(*i)));
    }

    eprintln!("=================== end query info ===================");
}
