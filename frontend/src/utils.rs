// use chain::policy::ExecTask;
// use chrono::{DateTime, Utc};

use std::fs::File;
use std::io::{BufRead, BufReader};

use parser::*;
// use parser::{*, x509};
// use chain::{policy, issue};

use crate::error::Error;

pub fn read_pem_file_as_base64(path: &str) -> Result<Vec<String>, Error> {
    let file = BufReader::new(File::open(path)?);
    read_pem_as_base64(file).collect()
}

/// Read a PEM file (given as a BufRead) and return an iterator over the decoded certificates
pub fn read_pem_as_bytes<B: BufRead>(reader: B) -> impl Iterator<Item = Result<Vec<u8>, Error>> {
    read_pem_as_base64(reader).map(|res|
        match res {
            Ok(cert_base64) => Ok(decode_base64(cert_base64.as_bytes())?),
            Err(err) => Err(err),
        }
    )
}

/// Read a PEM file and return an iteger over base64 encoded strings
pub fn read_pem_as_base64<B: BufRead>(reader: B) -> impl Iterator<Item = Result<String, Error>> {
    const PREFIX: &'static str = "-----BEGIN CERTIFICATE-----";
    const SUFFIX: &'static str = "-----END CERTIFICATE-----";

    let mut cur_cert_base64 = None;

    reader.lines().filter_map(move |line| {
        let inner = || {
            let line = line?;
            let line_trimmed = line.trim();

            if line_trimmed == PREFIX {
                if cur_cert_base64.is_some() {
                    Err(Error::NoMatchingEndCertificate)
                } else {
                    cur_cert_base64 = Some(String::new());
                    Ok(None)
                }
            } else if line_trimmed == SUFFIX {
                match cur_cert_base64.take() {
                    // Found some base64 chunk
                    Some(cert_base64) => Ok(Some(cert_base64)),
                    None => Err(Error::NoMatchingBeginCertificate),
                }
            } else if let Some(cur_cert_base64) = cur_cert_base64.as_mut() {
                cur_cert_base64.push_str(line_trimmed);
                Ok(None)
            } else {
                // Ignore lines between SUFFIX and the next PREFIX
                Ok(None)
            }
        };

        match inner() {
            Ok(Some(cert_bytes)) => Some(Ok(cert_bytes)),
            Ok(None) => None,
            Err(err) => Some(Err(err)), // Eager return on error
        }
    })
}

// pub fn print_debug_info(roots: &VecDeep<x509::CertificateValue>, chain: &VecDeep<x509::CertificateValue>, task: &ExecTask, now: u64) {
//     eprintln!("=================== task info ===================");
//     // Print some general information about the certs
//     eprintln!("{} root certificate(s)", roots.len());
//     eprintln!("{} certificate(s) in the chain", chain.len());

//     // Check that for each i, cert[i + 1] issued cert[i]
//     for i in 0..chain.len() - 1 {
//         if issue::likely_issued(chain.get(i + 1), chain.get(i)) {
//             eprintln!("cert {} issued cert {}", i + 1, i);
//         }
//     }

//     let mut used_roots = Vec::new();

//     // Check if root cert issued any of the chain certs
//     for (i, root) in roots.to_vec().iter().enumerate() {
//         let mut used = false;

//         for (j, chain_cert) in chain.to_vec().iter().enumerate() {
//             if issue::likely_issued(root, chain_cert) {
//                 used = true;
//                 eprintln!("root cert {} issued cert {}", i, j);
//             }
//         }

//         if used {
//             used_roots.push(i);
//         }
//     }

//     let print_cert = |cert: &x509::CertificateValue| {
//         eprintln!("  subject: {}", cert.get().cert.get().subject);
//         eprintln!("  issued by: {}", cert.get().cert.get().issuer);
//         eprintln!("  signed with: {:?}", cert.get().sig_alg);
//         eprintln!("  subject key: {:?}", cert.get().cert.get().subject_key.alg);
//     };

//     for (i, cert) in chain.to_vec().iter().enumerate() {
//         eprintln!("cert {}:", i);
//         print_cert(cert);
//     }

//     for i in used_roots.iter() {
//         eprintln!("root cert {}:", i);
//         print_cert(roots.get(*i));
//     }

//     eprintln!("task: {:?}", task);

//     eprintln!("timestamp: {} ({})", now, match DateTime::<Utc>::from_timestamp(now as i64, 0) {
//         Some(dt) => dt.to_string(),
//         None => "invalid".to_string(),
//     });

//     for (i, cert) in chain.to_vec().iter().enumerate() {
//         eprintln!("abstract cert {}:", i);
//         eprintln!("  {:?}", policy::Certificate::from(cert));
//     }

//     for i in used_roots.iter() {
//         eprintln!("abstract root cert {}:", i);
//         eprintln!("  {:?}", policy::Certificate::from(roots.get(*i)));
//     }

//     eprintln!("=================== end task info ===================");
// }
