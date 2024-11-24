use std::io;
use std::fs::File;
use std::collections::HashMap;

use clap::Parser;
use regex::Regex;
use csv::ReaderBuilder;

use crate::ct_logs::*;
use crate::error::*;

#[derive(Parser, Debug)]
pub struct Args {
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

pub fn main(args: Args) -> Result<(), Error>
{
    let classes = args.classes.iter()
        .map(|pat| Regex::new(pat)).collect::<Result<Vec<_>, _>>()?;

    // Read CSV file1 into a HashMap
    let file1 = File::open(&args.file1)?;
    let mut file1_results: HashMap<String, (CTLogResultWithoutStats, DiffClass)> =
        ReaderBuilder::new()
            .has_headers(false)
            .from_reader(file1)
            .deserialize::<CTLogResultWithoutStats>()
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
        let result: CTLogResultWithoutStats = result?;

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
