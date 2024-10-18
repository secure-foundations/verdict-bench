mod checker;
mod containers;
mod display;
mod error;
mod matching;
mod parser;
mod proof;
mod trace;
mod view;
mod backend;
mod validate;

use std::fs;
use std::process::ExitCode;

use backend::*;
use validate::*;

use clap::{command, Parser};

use crate::error::Error;
use crate::parser::{parse_program, parse_term};

#[derive(Parser, Debug)]
#[command(long_about = None)]
struct Args {
    /// Prolog source file
    source: String,

    /// The main goal to be solved
    goal: String,

    /// Path to the SWI-Prolog binary
    #[clap(long, value_parser, num_args = 0.., value_delimiter = ' ', default_value = "swipl")]
    swipl_bin: String,

    /// Enable debug mode
    #[arg(long, default_value_t = false)]
    debug: bool,

    /// Allow unsupported builtins
    #[arg(long, default_value_t = false)]
    allow_unsupported_builtin: bool,

    /// Only print out the parsed Prolog program and the command to be run
    #[arg(long, default_value_t = false)]
    dry: bool,
}

fn main_args(mut args: Args) -> Result<(), Error> {
    // Parse the source file
    let source = fs::read_to_string(&args.source)?;
    let (program, line_map) = parse_program(source, &args.source)?;

    // Parse the goal term
    let goal = parse_term(&args.goal)?;

    if args.debug || args.dry {
        eprintln!("[debug] parsed program:");
        for rule in &program.rules {
            eprintln!("[debug]   {}", rule);
        }
    }

    let mut swipl_backend = SwiplBackend {
        debug: args.debug,
        swipl_bin: args.swipl_bin.clone(),
    };

    match solve_and_validate::<_, Error>(
        &mut swipl_backend,
        &program,
        &goal,
        args.debug,
        args.allow_unsupported_builtin,
    )? {
        ValidationResult::Success(thm) => {
            eprintln!("validated goal: {}", thm.stmt);
            Ok(())
        }
        ValidationResult::ProofFailure => {
            Err(Error::NoMatchingProof)
        }
        ValidationResult::BackendFailure => {
            Err(Error::BackendFailure)
        }
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
