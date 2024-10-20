// The main validation routine

use vstd::prelude::*;

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

/// Solve a goal and validate the result
/// The error type E should combine any errors from the backend
/// as well as ProofError
///
/// `compiled` should the result of calling `compile` on a backend
/// on the given program. Although even if it's given as some random
/// piece of data, this would not affect the soundness
pub fn solve_and_validate<C: Compiled, E: From<C::Error> + From<ProofError>>(
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
    let mut goal_thm: Option<Theorem> = None;

    // Extend the program with additional facts
    let ghost old_facts = facts.deep_view();
    let mut ext_program = program.clone();
    ext_program.rules.append(&mut facts);

    assert(ext_program@.rules =~= program@.rules + old_facts);

    let mut validator = TraceValidator::new(&ext_program);

    {
        let mut events = instance.events()?;

        // Process all events until the goal is proven or the backend terminates
        loop
            invariant
                validator.wf(ext_program@),
                goal_thm matches Some(thm) ==> {
                    &&& thm@.wf(ext_program@)
                    &&& thm@.stmt == goal@
                },
        {
            if let Some(event) = events.next()? {
                let thm = validator.process_event(&ext_program, &event, debug, allow_unsupported_builtin)?;
                if (&thm.stmt).eq(goal) {
                    goal_thm = Some(thm.clone());
                    break;
                }
            } else {
                break;
            }
        }
    }

    if instance.proven()? {
        if let Some(thm) = goal_thm {
            Ok(ValidationResult::Success(thm))
        } else {
            Ok(ValidationResult::ProofFailure)
        }
    } else {
        Ok(ValidationResult::BackendFailure)
    }
}

}
