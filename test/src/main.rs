mod error;

use base64::{Engine, prelude::BASE64_STANDARD};
use std::io;
use std::process::ExitCode;
use std::fs::File;
use std::collections::HashMap;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use csv::{ReaderBuilder, WriterBuilder};
use serde::{Deserialize, Serialize};

use clap::{command, Parser, Subcommand};

use regex::Regex;

use chain::utils::*;
use parser::{x509, VecDeep};
use vpl::Backend;
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

    /// Compare the results of two CT logs
    DiffResults(DiffResultsArgs),
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

    /// Store the results in the given CSV file
    #[clap(short = 'o', long)]
    out_csv: Option<String>,

    /// Path to the SWI-Prolog binary
    #[clap(long, value_parser, num_args = 0.., value_delimiter = ' ', default_value = "swipl")]
    swipl_bin: String,

    /// Enable debug mode
    #[arg(long, default_value_t = false)]
    debug: bool,

    /// Override the current time with the given timestamp
    #[clap(short = 't', long)]
    override_time: Option<i64>,

    /// Number of parallel threads to run validation
    #[clap(short = 'j', long = "jobs", default_value = "1")]
    num_jobs: usize,

    /// Only validate the first <limit> certificates, if specified
    #[clap(short = 'l', long)]
    limit: Option<usize>,
}

#[derive(Parser, Debug)]
struct DiffResultsArgs {
    /// The main CSV file to compare against
    /// All entries in file2 should have a
    /// corresponding entry in file1, but
    /// not necessarily the other way around
    file1: String,

    /// The second CSV file to compare
    /// If this is optional, we read from stdin
    file2: Option<String>,

    /// Regex expressions specifying classes of results
    /// e.g. if file1 uses OK for success, while file2 uses true, then
    /// we can add a class r"OK|true" for both of them
    ///
    /// Result strings not belong to any class are considered as a singleton
    /// class of the string itself
    #[clap(short = 'c', long = "class", value_parser, num_args = 0..)]
    classes: Vec<String>,
}

/// Read from stdin a sequence of PEM-encoded certificates, parse them, and print them to stdout
fn parse_cert_from_stdin(args: ParseArgs) -> Result<(), Error>
{
    const PREFIX: &'static str = "-----BEGIN CERTIFICATE-----";
    const SUFFIX: &'static str = "-----END CERTIFICATE-----";

    let mut num_parsed = 0;
    let mut total_time = Duration::new(0, 0);

    for cert_bytes in read_pem_as_bytes(io::stdin().lock())? {
        let begin = Instant::now();
        let parsed = parse_x509_certificate(&cert_bytes);
        total_time += begin.elapsed();

        match parsed {
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

        num_parsed += 1;
    }

    println!("time: {:.3}s", total_time.as_secs_f64());

    Ok(())
}

#[derive(Debug, Deserialize)]
struct CTLogEntry {
    cert_base64: String,
    hash: String, // SHA-256 hash of the entire certificate
    domain: String,
    interm_certs: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct CTLogResult {
    hash: String,
    domain: String,
    result: String,
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

            let cert_bytes = BASE64_STANDARD.decode(result.cert_base64)?;

            match parse_x509_certificate(&cert_bytes) {
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

struct ValidationResult {
    hash: String,
    domain: String,
    result: Result<bool, Error>,
}

type Timer = Arc<Mutex<Duration>>;

fn validate_ct_logs_job<C: vpl::Compiled>(
    args: &ValidateCTLogArgs,
    policy: &vpl::Program,
    roots: &VecDeep<x509::CertificateValue>,
    compiled: &C,
    timestamp: i64,
    entry: &CTLogEntry,
    timer: &Timer,
) -> Result<bool, Error> where
    Error: From<<C as vpl::Compiled>::Error>
{
    let mut chain_bytes = vec![BASE64_STANDARD.decode(&entry.cert_base64)?];

    // Look up all intermediate certificates <args.interm_dir>/<entry.interm_certs>.pem
    // `entry.interm_certs` is a comma-separated list
    for interm_cert in entry.interm_certs.split(",") {
        chain_bytes.append(&mut read_pem_file_as_bytes(&format!("{}/{}.pem", &args.interm_dir, interm_cert))?);
    }

    let mut chain =
        chain_bytes.iter().map(|bytes| parse_x509_certificate(bytes)).collect::<Result<Vec<_>, _>>()?;

    let chain = parser::VecDeep::from_vec(chain);

    let query = chain::facts::Query {
        roots: roots,
        chain: &chain,
        domain: &entry.domain.to_lowercase(),
        now: timestamp,
    };

    if args.debug {
        query.print_debug_info();
    }

    // use polyfill::*;
    // use parser::{*, asn1::*, x509::*};
    // use parser::OptionDeep::*;
    // use vpl::*;

    // use chain::specs::*;
    // use chain::facts::*;
    // use chain::error::*;

    // let mut facts_deep = vec_deep![];
    // QueryFacts::facts(&query, &mut facts_deep)?;
    // let facts = facts_deep.to_vec_owned();

    // let begin = ThreadTime::try_now()?;

    // let goal = TermX::app_str("certVerifiedChain", vec![ query.get_chain(0).cert() ]);

    // // Solve and validate the goal
    // let res = match solve_and_validate::<C, error::Error>(compiled, &policy, facts, &goal, args.debug, true)? {
    //     ValidationResult::Success(thm) => {
    //         Ok(true)
    //     }
    //     ValidationResult::ProofFailure => Err(ValidationError::ProofFailure)?,
    //     ValidationResult::BackendFailure => Ok(false),
    // };

    // let begin = ThreadTime::try_now()?;
    // let begin = Instant::now();

    let begin = Instant::now();

    let res = chain::validate::valid_domain::<_, Error>(
        compiled,
        &policy,
        &query,
        args.debug,
    );

    *timer.lock().unwrap() += begin.elapsed();

    res
}

fn validate_ct_logs(args: ValidateCTLogArgs) -> Result<(), Error>
{
    let args = Arc::new(args);
    // let heap_profiler = heappy::HeapProfilerGuard::new(1).unwrap();

    eprintln!("validating {} CT log file(s)", args.csv_files.len());

    // Parse the policy source file
    let policy_src = std::fs::read_to_string(&args.policy)?;
    let (policy, _) = vpl::parse_program(&policy_src, &args.policy)?;
    let policy = Arc::new(policy);

    // Load swipl backend and compile the policy
    let mut swipl_backend = vpl::SwiplCompiledBackend {
        debug: args.debug,
        swipl_bin: args.swipl_bin.clone(),
    };
    let compiled = Arc::new(swipl_backend.compile(&policy)?);

    let timestamp = args.override_time.unwrap_or(chrono::Utc::now().timestamp());

    let (tx_job, rx_job) = crossbeam::channel::unbounded::<CTLogEntry>();
    let (tx_res, rx_res) = mpsc::channel();

    let timer = Arc::new(Mutex::new(Duration::new(0, 0)));

    // Spawn <num_jobs> many worker threads
    let mut workers = (0..args.num_jobs).map(|_| {
        let rx_job = rx_job.clone();
        let tx_res = tx_res.clone();
        let args = args.clone();
        let policy = policy.clone();
        let compiled = compiled.clone();
        let timer = timer.clone();

        // Each worker thread waits for jobs, does the validation, and then sends back the result
        thread::spawn(move || -> Result<(), Error> {
            // Each thread has to parse its own copy of the root certs and policy

            // Parse root certificates
            // TODO: move this outside
            let roots_bytes = read_pem_file_as_bytes(&args.roots)?;
            let roots =
                roots_bytes.iter().map(|bytes| parse_x509_certificate(bytes)).collect::<Result<Vec<_>, _>>()?;
            let roots = parser::VecDeep::from_vec(roots);

            while let Ok(entry) = rx_job.recv() {
                tx_res.send(ValidationResult {
                    hash: entry.hash.clone(),
                    domain: entry.domain.clone(),
                    result: validate_ct_logs_job(
                        &args,
                        &policy,
                        &roots,
                        compiled.as_ref(),
                        timestamp,
                        &entry,
                        &timer,
                    ),
                })?;
            }

            Ok(())
        })
    }).collect::<Vec<_>>();

    // Spawn another thread to collect results and write to output
    let out_csv = args.out_csv.clone();
    workers.push(thread::spawn(move || -> Result<(), Error> {
        // Open the output file if it exists, otherwise use stdout
        let mut handle: Box<dyn io::Write> = if let Some(out_path) = out_csv {
            Box::new(File::create(out_path)?)
        } else {
            Box::new(std::io::stdout())
        };
        let mut output_writer =
            WriterBuilder::new().has_headers(false).from_writer(handle);

        let mut num_res = 0;

        while let Ok(res) = rx_res.recv() {
            let result_str = match res.result {
                Ok(res) => res.to_string(),
                Err(err) => format!("fail: {}", err),
            };

            output_writer.serialize(CTLogResult {
                hash: res.hash,
                domain: res.domain,
                result: result_str,
            })?;
            output_writer.flush()?;

            if num_res % 50 == 0 {
                eprint!("\r{:.7}s", timer.lock().unwrap().as_secs_f64() as f64 / num_res as f64);
            }
            num_res += 1;
        }

        eprintln!("");

        Ok(())
    }));

    let mut found_hash = false;
    for path in &args.csv_files {
        let file = File::open(path)?;
        let mut reader = ReaderBuilder::new()
            .has_headers(false)  // If your CSV has headers
            .from_reader(file);

        for (i, entry) in reader.deserialize().enumerate() {
            let entry: CTLogEntry = entry?;

            if let Some(limit) = args.limit {
                if i >= limit {
                    break;
                }
            }

            // If a specific hash is specified, only check certificate with that hash
            if let Some(hash) = &args.hash {
                if hash != &entry.hash {
                    continue;
                } else {
                    found_hash = true;
                }
            }

            tx_job.send(entry)?;
        }
    }

    if let Some(hash) = &args.hash {
        if !found_hash {
            eprintln!("hash {} not found in the given CSV files", hash);
        }
    }

    // Signal no more jobs
    drop(tx_job);
    drop(tx_res);

    // Join all workers at the end
    for (i, worker) in workers.into_iter().enumerate() {
        match worker.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                eprintln!("worker {} failed with error: {}", i, err);
            }
            Err(err) => {
                eprintln!("failed to join worker {}: {:?}", i, err);
            }
        }
    }

    // let report = heap_profiler.report();

    // let mut file = std::fs::File::create("memflame.svg").unwrap();
    // report.flamegraph(&mut file);

    // let mut file = std::fs::File::create("memflame.pb").unwrap();
    // report.write_pprof(&mut file).unwrap();

    Ok(())
}

/// Used for comparing results represented as different strings (e.g. OK vs true)
#[derive(PartialEq, Eq)]
enum DiffClass {
    Class(usize),
    Singleton(String),
}

impl DiffClass {
    fn get(classes: &[Regex], s: &str) -> DiffClass {
        // Match against each class
        for (i, class_regex) in classes.iter().enumerate() {
            if class_regex.is_match(&s) {
                return DiffClass::Class(i);
            }
        }

        return DiffClass::Singleton(s.to_string());
    }
}

fn diff_ct_log_results(args: DiffResultsArgs) -> Result<(), Error>
{
    let classes = args.classes.iter()
        .map(|pat| Regex::new(pat)).collect::<Result<Vec<_>, _>>()?;

    // Read CSV file1 into a HashMap
    let file1 = File::open(&args.file1)?;
    let mut file1_results: HashMap<String, (CTLogResult, DiffClass)> =
        ReaderBuilder::new()
            .has_headers(false)
            .from_reader(file1)
            .deserialize::<CTLogResult>()
            .map(|res| {
                let res = res?;
                let class = DiffClass::get(&classes, &res.result);
                Ok::<_, csv::Error>((
                    res.hash.clone(),
                    (res, class),
                ))
            })
            .collect::<Result<_, _>>()?;

    // Create a reader on file2 or stdin
    let file2: Box<dyn io::Read> = if let Some(file2) = args.file2 {
        Box::new(File::open(file2)?)
    } else {
        Box::new(std::io::stdin())
    };

    let mut file2_reader = ReaderBuilder::new()
        .has_headers(false)
        .from_reader(file2);

    // For each result entry in file2, check if the corresponding one exists in file1
    // Otherwise report
    for result in file2_reader.deserialize() {
        let result: CTLogResult = result?;

        if let Some((file1_result, file1_class)) = file1_results.get(&result.hash) {
            let file2_class = DiffClass::get(&classes, &result.result);

            if file1_class != &file2_class {
                println!("mismatch at {}: {} vs {}", &result.hash, &file1_result.result, &result.result);
            }
        } else {
            println!("{} does not exist in {}", &result.hash, &args.file1);
        }
    }

    Ok(())
}

fn main_args(args: Args) -> Result<(), Error> {
    match args.action {
        Action::Parse(args) => parse_cert_from_stdin(args),
        Action::ParseCTLog(args) => parse_cert_ct_logs(args),
        Action::ValidateCTLog(args) => validate_ct_logs(args),
        Action::DiffResults(args) => diff_ct_log_results(args),
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
