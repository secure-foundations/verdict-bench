mod error;
mod utils;
mod ct_logs;
mod validator;
mod cmd_parse_cert;
mod cmd_validate;
mod cmd_parse_ct_logs;
mod cmd_validate_ct_logs;
mod cmd_diff_results;
mod cmd_bench_ct_logs;

use std::process::ExitCode;
use clap::{command, Parser, Subcommand};
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
    ParseCert(cmd_parse_cert::Args),

    /// Validate a single certificate chain in PEM format
    Validate(cmd_validate::Args),

    /// Parse a specific format of certificates stored in CSVs
    ParseCTLogs(cmd_parse_ct_logs::Args),

    /// Validate certificates in the given CT log files
    ValidateCTLog(cmd_validate_ct_logs::Args),

    /// Compare the results of two CT logs
    DiffResults(cmd_diff_results::Args),

    /// Benchmark CT logs on multiple clients
    BenchCTLogs(cmd_bench_ct_logs::Args),
}

fn main_args(args: Args) -> Result<(), Error> {
    match args.action {
        Action::ParseCert(args) => cmd_parse_cert::main(args),
        Action::Validate(args) => cmd_validate::main(args),
        Action::ParseCTLogs(args) => cmd_parse_ct_logs::main(args),
        Action::ValidateCTLog(args) => cmd_validate_ct_logs::main(args),
        Action::DiffResults(args) => cmd_diff_results::main(args),
        Action::BenchCTLogs(args) => cmd_bench_ct_logs::main(args),
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
