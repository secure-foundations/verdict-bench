
use std::error::Error;
use std::fs;
use std::iter::zip;
use std::io::{self, BufRead, Write};
use std::time::Instant;

use openssl::x509::X509;
use clap::Parser;
// use tempfile::tempdir;

const HEADER: &'static str = "-----BEGIN CERTIFICATE-----";
const FOOTER: &'static str = "-----END CERTIFICATE-----";

#[derive(Parser, Debug)]
struct Args {
    /// chrome or firefox
    client: String,

    /// Path to the root certificates
    roots: String,

    /// The timestamp to validate a certificate at
    timestamp: u64,

    /// Ignore root parsing errors (skip the corresponding root)
    #[arg(long, default_value_t = false)]
    ignore_root_parse_error: bool,
}

// fn form_chain(leaf: &String, intpath: &str, ints: &String) -> String {
//     // Wrap leaf in Certificate header/Footer
//     let formatted_leaf = format!("{}\r\n{}\r\n{}\r\n", HEADER, leaf, FOOTER);
//     let split_ints: Vec<&str> = ints.split(",").collect();
//     let p = split_ints.iter().map(|f| {
//         let filename = format!("{}/{}{}", intpath, f, ".pem");
//         let int = read_disk_certificate(&filename).unwrap();
//         format!("{}", int)
//     }).collect::<String>();
//     let formatted_chain = format!("{}{}", formatted_leaf, p);
//     format!("{}", formatted_chain)
// }

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    // Parse root certificates
    let roots_content = fs::read_to_string(args.roots)?;
    let roots = X509::stack_from_pem(&roots_content.as_bytes())?;
    let roots_der: Vec<_> = roots.iter().map(|root| root.to_der().unwrap()).collect();

    let mut prolog_roots = Vec::new();

    for (i, root_der) in roots_der.iter().enumerate() {
        match acclib::cert::PrologCert::from_der(root_der) {
            Ok(cert) => prolog_roots.push(cert),
            Err(e) =>
                if args.ignore_root_parse_error {
                    eprintln!("skipping root {} due to parse error", i)
                } else {
                    Err(io::Error::other("failed to parse certificate"))?
                }
        }
    }

    let roots: Vec<_> = zip(roots, prolog_roots).collect();

    let mut leaf = None;
    let mut interm = vec![];
    let mut repeat: isize = 1;

    // let tmp_dir = tempdir()?;
    // let tmp_dir_path = tmp_dir.path().to_str()
    //     .ok_or(io::Error::other("failed to get tmp dir path"))?;

    for line in io::stdin().lock().lines() {
        let line = line?;
        let trim = line.trim();

        if trim.starts_with("leaf: ") {
            if leaf.is_some() {
                Err(io::Error::other("leaf already sent"))?
            }
            leaf = Some(trim["leaf: ".len()..].to_string());
        } else if trim.starts_with("interm: ") {
            if leaf.is_none() {
                Err(io::Error::other("leaf not sent yet"))?
            }
            interm.push(trim["interm: ".len()..].to_string());
        } else if trim.starts_with("domain: ") {
            let domain = trim["domain: ".len()..].to_lowercase();
            let pem: String = std::iter::once(leaf.take().ok_or(io::Error::other("leaf not set yet"))?)
                .chain(interm.drain(..))
                .map(|cert| format!("{}\r\n{}\r\n{}\r\n", HEADER, cert, FOOTER))
                .collect::<Vec<_>>()
                .join("\n");

            let timestamp = args.timestamp;
            let client = &args.client;

            let validate = || -> Result<(), String> {
                let mut chain = X509::stack_from_pem(&pem.as_bytes())
                    .map_err(|_| "parse_failed".to_string())?;
                let facts = acclib::get_chain_facts_with_roots(&roots, &mut chain)
                    .map_err(|_| "fact_gen_failed")?;

                let job_string = acclib::get_job_string(&domain, &facts, timestamp);

                acclib::verify_chain_with_job(&job_string, client)
                    .map_err(|_| "policy_failed")?;

                Ok(())
            };

            let mut durations = vec![];
            let mut result = Ok(());

            for _ in 0..repeat {
                let start = Instant::now();
                result = validate();
                durations.push(start.elapsed().as_micros());
            }

            println!("result: {} {}", match result {
                Ok(..) => "OK".to_string(),
                Err(err) => err,
            }, durations.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(" "));
            io::stdout().flush()?;

            // println!("tmp dir: {}", tmp_dir_path);
        } else if trim.starts_with("repeat: ") {
            repeat = trim["repeat: ".len()..].parse()?;

            if repeat < 1 {
                Err(io::Error::other("repeat should be >= 1"))?
            }
        } else if trim.is_empty() {
            continue;
        } else {
            Err(io::Error::other("unknown command"))?
        }
    }

    // loop {}
    // drop(tmp_dir);

    Ok(())
}
