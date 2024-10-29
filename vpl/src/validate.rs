// The main validation routine

use vstd::prelude::*;
use std::fmt;

use polyfill::*;

use crate::backend::*;
use crate::checker::*;
use crate::trace::*;
use crate::proof::*;

verus! {

pub enum ValidationResult {
    Success(Theorem),

    /// backend succeeds but fails to produce a proof
    ProofFailure,

    /// backend fails to prove it
    BackendFailure,
}

pub fn read_events<I: Instance, E: From<I::Error> + From<ProofError>>(
    instance: &mut I,
    program: &Program,
    goal: &Term,
    debug: bool,
    allow_unsupported_builtin: bool,
) -> (res: Result<Option<Theorem>, E>)
    ensures
        res matches Ok(Some(thm)) ==> {
            &&& thm@.wf(program@)
            &&& thm@.stmt == goal@
        }

{
    let mut validator = TraceValidator::new(program);
    let mut events = instance.events()?;

    // Process all events until the goal is proven or the backend terminates
    loop
        invariant validator.wf(program@)
    {
        if let Some(event) = events.next()? {
            let thm = validator.process_event(program, &event, debug, allow_unsupported_builtin)?;
            if (&thm.stmt).eq(goal) {
                return Ok(Some(thm.clone()));
            }
        } else {
            return Ok(None);
        }
    }
}

/// Solve a goal and validate the result
/// The error type E should combine any errors from the backend
/// as well as ProofError
///
/// `compiled` should the result of calling `compile` on a backend
/// on the given program. Although even if it's given as some random
/// piece of data, this would not affect the soundness
pub fn solve_and_validate<C: Compiled, E: fmt::Debug + From<C::Error> + From<ProofError>>(
    compiled: &C,
    program: &Program,
    mut facts: Vec<Rule>,
    goal: &Term,

    // Some options
    debug: bool,
    allow_unsupported_builtin: bool,
) -> (res: Result<ValidationResult, E>)
    ensures
        res matches Ok(ValidationResult::Success(thm)) ==> {
            &&& thm@.wf(SpecProgram {
                rules: program@.rules + facts.deep_view(),
            })
            &&& thm@.stmt == goal@
        }
{
    let mut instance = compiled.solve(&facts, goal)?;

    // Extend the program with additional facts
    let ghost old_facts = facts.deep_view();
    let mut ext_program = program.clone();
    ext_program.rules.append(&mut facts);

    assert(ext_program@.rules =~= program@.rules + old_facts);

    let thm = read_events::<_, E>(&mut instance, &ext_program, goal, debug, allow_unsupported_builtin);
    let proven = instance.proven()?;

    match (proven, thm) {
        (true, Ok(Some(thm))) => Ok(ValidationResult::Success(thm)),
        (true, Ok(None)) => Ok(ValidationResult::ProofFailure),
        (true, Err(err)) => {
            if debug {
                eprintln_join!("[debug] proof failure: ", format_dbg(err));
            }
            Ok(ValidationResult::ProofFailure)
        },
        (false, _) => Ok(ValidationResult::BackendFailure),
    }
}

}
