use vstd::prelude::*;

use std::fs::File;
use std::io::{BufRead, BufReader};

use base64::{Engine, prelude::BASE64_STANDARD};

use parser::{x509, ParseError, Combinator};
use crate::error::Error;

verus! {
    pub fn parse_x509_certificate<'a>(bytes: &'a [u8]) -> Result<x509::CertificateValue<'a>, ParseError> {
        let (n, cert) = x509::Certificate.parse(bytes)?;
        if n != bytes.len() {
            return Err(ParseError::Other("trailing bytes in certificate".to_string()));
        }
        Ok(cert)
    }
}

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
                    let cert_bytes = BASE64_STANDARD.decode(cert_base64)?;
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
