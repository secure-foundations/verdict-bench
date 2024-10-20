use vstd::prelude::*;
use polyfill::*;

use crate::proof::*;
use crate::checker::*;
use crate::containers::HashMapWithView;

// Checks the proofs as traces from an on-the-shelf Prolog solver
// Traces = Hilbert-style proofs with less details

verus! {

broadcast use TermX::axiom_view, SpecTerm::axiom_subst, crate::containers::group_hash_map_axioms;

pub type EventId = usize;

/**
 * A trace is a sequence of events of the form
 *   <id> <term> by <tactic>
 * where
 * - <id> is the unique id of the event,
 * - <term> is the goal proved, and
 * - <tactic> is the tactic applied to get here.
 */
#[derive(Debug)]
pub struct Event {
    pub id: EventId,
    pub term: Option<Term>,
    pub tactic: Tactic,
}

#[derive(Debug)]
pub enum Tactic {
    Apply { rule_id: RuleId, subproof_ids: Vec<EventId> },
    TrueIntro,
    AndIntro(EventId, EventId),
    OrIntroLeft(EventId),
    OrIntroRight(EventId),
    ForallMember(Vec<EventId>),
    ForallBase(Vec<EventId>),
    BuiltIn,
}

/**
 * TraceValidator dynamically reads in events and construct a Theorem for each event
 * and also stores the theorem for future rule applications
 *
 * TODO: all proofs should have unique parents, so we can probably remove theorems
 * once they are used
 */
pub struct TraceValidator {
    pub thms: HashMapWithView<EventId, Theorem>,
}

impl TraceValidator {
    pub fn new(program: &Program) -> (res: Self)
        ensures res.wf(program@) && res.thms@.len() == 0
    {
        Self { thms: HashMapWithView::new() }
    }

    pub open spec fn wf(self, program: SpecProgram) -> bool {
        forall |id| self.thms@.contains_key(id) ==> (#[trigger] self.thms@[id]).wf(program)
    }

    // pub closed spec fn match_terms_trigger(subst: &Subst, term1: SpecTerm, term2: SpecTerm);

    pub fn add_theorem(&mut self, program: &Program, event_id: EventId, thm: Theorem) -> (res: &Theorem)
        requires
            old(self).wf(program@),
            thm.wf(program@),

        ensures
            self.wf(program@),
            self.thms@.contains_key(event_id),
            self.thms@[event_id] == thm,
            res == thm
    {
        self.thms.insert(event_id, thm);
        &self.thms.get(&event_id).unwrap()
    }

    pub fn get_theorem(&self, program: &Program, event_id: EventId) -> (res: Result<&Theorem, ProofError>)
        requires self.wf(program@)
        ensures res matches Ok(thm) ==> thm.wf(program@)
    {
        if let Some(thm) = self.thms.get(&event_id) {
            Ok(thm)
        } else {
            proof_err!("theorem ", event_id, " does not exist")
        }
    }

    pub fn remove_theorem(&mut self, program: &Program, event_id: EventId) -> (res: Result<Theorem, ProofError>)
        requires old(self).wf(program@)
        ensures
            self.wf(program@),

            // Does not change other theorems
            forall |id| id != event_id && old(self).thms@.contains_key(id) ==>
                self.thms@.contains_key(id) &&
                #[trigger] self.thms@[id] == old(self).thms@[id],

            res matches Ok(thm) ==> thm.wf(program@),
    {
        if let Some(thm) = self.thms.remove(&event_id) {
            Ok(thm)
        } else {
            proof_err!("theorem ", event_id, " does not exist")
        }
    }

    /// Process an event and construct a Theorem with the same statement claimed in the event
    /// Retuen the Theorem object if successful
    pub fn process_event(
        &mut self,
        program: &Program,
        event: &Event,
        debug: bool,
        allow_unsupported_builtin: bool,

        // // Do not check if the final statement after applying and/or intro
        // // is the same as the statement claimed
        // // This is to allow some flexibility in the trace
        // // e.g. findall(X, p(X), Xs) ~ findall(Y, p(Y), Xs)
        // // Since sometimes GC in Prolog will change internal variable names
        // no_stmt_check: bool,
    ) -> (res: Result<&Theorem, ProofError>)
        requires
            old(self).wf(program@),

        ensures
            res matches Ok(thm) ==> {
                &&& self.wf(program@)
                &&& thm.wf(program@)

                &&& self.thms@.contains_key(event.id)
                &&& self.thms@[event.id] == thm

                // &&& !no_stmt_check ==> event.term@ == thm.stmt@
            }
    {
        match &event.tactic {
            // Try to convert the event to a theorem via Theorem::apply_rule
            Tactic::Apply { rule_id, subproof_ids } => {
                if *rule_id >= program.rules.len() {
                    return proof_err!("rule ", rule_id, " does not exist");
                }

                let rule = &program.rules[*rule_id];

                if subproof_ids.len() != rule.body.len() {
                    return proof_err!("incorrect number of subproofs");

                }

                if debug {
                    eprintln_join!("[debug] applying rule: ", rule);
                }

                // Figure out the substitution for the rule application
                let mut subst = Subst::new();
                let mut subproofs: Vec<&Theorem> = vec![];

                // Match rule head against goal first
                let goal = if let Some(term) = &event.term {
                    term
                } else {
                    return proof_err!("missing goal for rule application");
                };
                TermX::match_terms(&mut subst, &rule.head, goal)?;

                // Match each rule body against existing subproof
                for i in 0..subproof_ids.len()
                    invariant
                        subproof_ids.len() == rule.body.len(),

                        // Invariants to show that subproofs are valid
                        subproofs.len() == i,
                        self.wf(program@),
                        forall |j| 0 <= j < i ==> (#[trigger] subproofs[j]).wf(program@),
                {
                    subproofs.push(self.get_theorem(program, subproof_ids[i])?);

                    if debug {
                        eprint("[debug]   subproof: "); eprintln(&subproofs[i].stmt);
                    }

                    TermX::match_terms(&mut subst, &rule.body[i], &subproofs[i].stmt)?;
                }

                if debug {
                    eprint("[debug] matching substitution: "); eprintln(&subst);
                }

                // Apply and proof-check the final result
                let thm = Theorem::apply_rule(program, *rule_id, &subst, subproofs)?;

                if (&thm.stmt).eq(goal) {
                    // Remove the used subproofs to save memory
                    // for i in 0..subproof_ids.len()
                    //     invariant self.wf(program@)
                    // {
                    //     if subproof_ids[i] != event.id {
                    //         self.remove_theorem(program, subproof_ids[i])?;
                    //     }
                    // }

                    Ok(self.add_theorem(program, event.id, thm))
                } else {
                    proof_err!("incorrect proved result: expecting ", goal, ", got ", &thm.stmt)
                }
            }

            Tactic::TrueIntro => {
                Ok(self.add_theorem(program, event.id, Theorem::true_intro(program)))
            }

            Tactic::AndIntro(left_id, right_id) => {
                let thm = Theorem::and_intro(
                    program,
                    self.get_theorem(program, *left_id)?,
                    self.get_theorem(program, *right_id)?,
                );

                Ok(self.add_theorem(program, event.id, thm))
            }

            Tactic::OrIntroLeft(subproof_id) => {
                let goal = if let Some(term) = &event.term {
                    term
                } else {
                    return proof_err!("missing goal for or intro left");
                };
                let args = goal.headed_by(FN_NAME_OR, 2)?;
                let thm = Theorem::or_intro_left(program, self.get_theorem(program, *subproof_id)?, &args[1]);
                Ok(self.add_theorem(program, event.id, thm))
            }

            Tactic::OrIntroRight(subproof_id) => {
                let goal = if let Some(term) = &event.term {
                    term
                } else {
                    return proof_err!("missing goal for or intro right");
                };
                let args = goal.headed_by(FN_NAME_OR, 2)?;
                let thm = Theorem::or_intro_right(program, &args[0], self.get_theorem(program, *subproof_id)?);
                Ok(self.add_theorem(program, event.id, thm))
            }

            Tactic::ForallMember(subproof_ids) => {
                let mut subproofs: Vec<&Theorem> = vec![];

                // Collect all subproofs via the ids
                for i in 0..subproof_ids.len()
                    invariant
                        subproofs.len() == i,
                        self.wf(program@),
                        forall |j| 0 <= j < i ==> (#[trigger] subproofs[j]).wf(program@),
                {
                    subproofs.push(self.get_theorem(program, subproof_ids[i])?);
                }

                let goal = if let Some(term) = &event.term {
                    term
                } else {
                    return proof_err!("missing goal for forall-member");
                };

                if debug {
                    eprintln_join!("[debug] apply forall-member: ", goal);
                }

                let thm = Theorem::forall_member(program, goal, subproofs)?;
                Ok(self.add_theorem(program, event.id, thm))
            }

            Tactic::ForallBase(subproof_ids) => {
                let mut subproofs: Vec<&Theorem> = vec![];

                // Collect all subproofs via the ids
                for i in 0..subproof_ids.len()
                    invariant
                        subproofs.len() == i,
                        self.wf(program@),
                        forall |j| 0 <= j < i ==> (#[trigger] subproofs[j]).wf(program@),
                {
                    subproofs.push(self.get_theorem(program, subproof_ids[i])?);
                }

                let goal = if let Some(term) = &event.term {
                    term
                } else {
                    return proof_err!("missing goal for forall-base");
                };

                if debug {
                    eprintln_join!("[debug] apply forall-base: ", goal);
                }

                let thm = Theorem::forall_base(program, goal, subproofs)?;
                Ok(self.add_theorem(program, event.id, thm))
            }

            Tactic::BuiltIn => {
                let goal = if let Some(term) = &event.term {
                    term
                } else {
                    return proof_err!("missing goal for built-in");
                };

                if let TermX::App(FnName::User(name, arity), args) = arc_as_ref(goal) {
                    let thm = Theorem::try_built_in(program, goal, allow_unsupported_builtin)?;
                    return Ok(self.add_theorem(program, event.id, thm));
                }

                proof_err!("incorrect goal for BuiltIn: ", goal)
            }
        }
    }
}

}
