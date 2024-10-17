use vstd::prelude::*;

use std::process::{Child, Command, Stdio, ChildStdout};
use std::io::{self, BufRead, BufReader, Lines, Write};
use std::collections::HashMap;

use tempfile::NamedTempFile;

use crate::trace::Event;
use crate::checker::*;
use crate::parser::*;

verus! {

/// A backend is essentially an iterator over trace Events
/// NOTE: impls of this trait does not need to be verified
/// as long as the they can return a valid sequence of proof
/// events, then the result is sound
pub trait Backend {
    type Instance: Instance<Error = Self::Error>;
    type Error;

    /// Start solving the given goal in the program
    /// and return the solver instance to interact with
    fn solve(&mut self, program: &Program, goal: &Term) -> Result<Self::Instance, Self::Error>;
}

/// Used for avoiding this: https://github.com/rust-lang/rust/issues/87479
/// which currently causes a Verus issue: https://github.com/verus-lang/verus/issues/1296
pub trait InstanceSuper {
    type Iterator<'a>: EventIterator<'a, Error = Self::Error>;
    type Error;
}

pub trait Instance: InstanceSuper {
    fn events<'a>(&'a mut self) -> Result<Self::Iterator<'a>, Self::Error>;

    /// Get the final result after all events are consumed
    fn proven(&mut self) -> Result<bool, Self::Error>;
}

pub trait EventIterator<'a> {
    type Error;

    /// Get the next event, return Proven or Failure at the end
    fn next(&mut self) -> Result<Option<Event>, Self::Error>;
}

}

/// A backend that uses SWI-Prolog to solve goals
/// A meta interpreter (meta.pl) is used to extract
/// the proof events
pub struct SwiplBackend {
    pub debug: bool,
    pub swipl_bin: String,
}

pub struct SwiplInstance {
    debug: bool,
    child: Child,
    meta_file: NamedTempFile,
    src_file: NamedTempFile,
    line_map: HashMap<usize, RuleId>,
}

pub struct SwiplInstanceIterator<'a> {
    debug: bool,
    line_map: &'a HashMap<usize, RuleId>,
    lines: Lines<BufReader<&'a mut ChildStdout>>,
}

impl Backend for SwiplBackend {
    type Instance = SwiplInstance;
    type Error = io::Error;

    fn solve(&mut self, program: &Program, goal: &Term) -> Result<Self::Instance, Self::Error> {
        let mut meta_file = NamedTempFile::new()?;
        let mut src_file = NamedTempFile::new()?;

        // Load the meta interpreter
        if self.debug {
            eprintln!("[debug] writing meta.pl to {}", meta_file.path().display());
        }
        write!(meta_file, "{}", include_str!("meta.pl"))?;
        meta_file.flush()?;

        if self.debug {
            eprintln!("[debug] writing source file to {}", src_file.path().display());
        }

        // Each rule takes exactly one line, so the line map is i |-> i - 1
        let line_map = (0..program.rules.len()).map(|i| (i + 1, i)).collect();
        write!(src_file, "{}", program)?;
        src_file.flush()?;

        // Run the main goal in swipl with the meta interpreter
        let mut swipl_cmd = Command::new(&self.swipl_bin);
        swipl_cmd
            .arg("-s")
            .arg(meta_file.path())
            .arg("-s")
            .arg(src_file.path())
            .arg("-g")
            .arg(format!("prove({})", goal))
            .arg("-g")
            .arg("halt")
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        // Spawn the swipl process
        let swipl = swipl_cmd.spawn()?;

        if self.debug {
            eprintln!("[debug] running swipl command: {:?}", &swipl_cmd);
        }

        Ok(SwiplInstance {
            debug: self.debug,
            child: swipl,
            meta_file,
            src_file,
            line_map,
        })
    }
}

impl InstanceSuper for SwiplInstance {
    type Iterator<'a> = SwiplInstanceIterator<'a>;
    type Error = io::Error;
}

impl Instance for SwiplInstance {
    fn events<'a>(&'a mut self) -> Result<Self::Iterator<'a>, Self::Error> {
        let stdout = self.child.stdout.as_mut()
            .ok_or(io::Error::other("child process missing stdout"))?;

        // Return an iterator over stdout lines
        Ok(SwiplInstanceIterator {
            debug: self.debug,
            line_map: &self.line_map,
            lines: BufReader::new(stdout).lines(),
        })
    }

    fn proven(&mut self) -> Result<bool, Self::Error> {
        // Consume and throw away rest of the stdout,
        // so that swipl doesn't block
        if let Some(stdout) = self.child.stdout.as_mut() {
            io::copy(stdout, &mut io::sink())?;
        }

        // Swipl succeeds iff the exit is 0
        Ok(self.child.wait()?.success())
    }
}

impl<'a> EventIterator<'a> for SwiplInstanceIterator<'a> {
    type Error = io::Error;

    fn next(&mut self) -> Result<Option<Event>, Self::Error> {
        let Some(line) = self.lines.next() else {
            return Ok(None);
        };
        let line = line?;

        if self.debug {
            eprintln!("[debug] ==============================================================");
            eprintln!("[debug] event {}", &line);
        }

        // Parse each line as an event
        match parse_trace_event(&line, &self.line_map) {
            Ok(event) => Ok(Some(event)),
            Err(err) => Err(io::Error::other(format!(
                "failed to parse trace event \"{}\": {}",
                &line, err
            ))),
        }
    }
}
