use vstd::prelude::*;
use std::sync::Arc;
use polyfill::*;

use crate::containers::StringHashMap;
use crate::proof::*;
use crate::matching::*;

// A dynamic builder of proofs with verified checks

verus! {

broadcast use TermX::axiom_view, SpecTerm::axiom_subst, SpecTerm::axiom_matches, lemma_ext_equal_deep;

pub type Var = Arc<str>;
pub type UserFnName = Arc<str>;
pub type RuleId = usize;
pub type Arity = usize;

/// TODO: right now we limit integers to 64-bit
/// but Prolog actually supports arbitrary precision integers
pub type LiteralInt = i64;
pub type LiteralString = Arc<str>;
pub type LiteralAtom = Arc<str>;

#[derive(Debug)]
pub enum FnName {
    // User-defined symbol: (name, arity)
    User(UserFnName, Arity),
    Nil,
    Cons,
}

#[derive(Debug)]
pub enum Literal {
    Int(LiteralInt),
    String(LiteralString),
    Atom(LiteralAtom),
    Directive,
}

pub type Term = Arc<TermX>;
#[derive(Debug)]
pub enum TermX {
    Var(Var),
    Literal(Literal),
    App(FnName, Vec<Term>),
}

pub type Rule = Arc<RuleX>;
#[derive(Debug)]
pub struct RuleX {
    pub head: Term,
    pub body: Vec<Term>,
}

#[derive(Debug)]
pub struct Program {
    pub rules: Vec<Rule>,
}

#[derive(Debug)]
pub struct Subst(pub StringHashMap<Term>);

pub struct Theorem {
    pub stmt: Term,
    pub proof: Ghost<SpecProof>,
}

/// Error in proof checking
#[derive(Debug)]
pub struct ProofError(pub String);

/// A helper macro for constructing Err(ProofError(..))
#[cfg(debug_assertions)]
#[allow(unused_macros)]
#[macro_export]
macro_rules! proof_err {
    ($($args:expr),+) => {
        Err(ProofError(join!(file!(), ":", line!(), ": ", $($args),+)))
    };
}

/// Release version of proof_err, which omits the error message
#[cfg(not(debug_assertions))]
#[allow(unused_macros)]
#[macro_export]
macro_rules! proof_err {
    ($($args:expr),+) => {
        Err(ProofError("<omitted>".to_string()))
    };
}

#[allow(unused_imports)]
pub use proof_err;

impl FnName {
    pub fn user(name: &str, arity: usize) -> (res: FnName)
        ensures res@ == SpecFnName::User(name@, arity as int)
    {
        FnName::User(str_to_arc_str(name), arity)
    }

    pub fn eq(&self, other: &Self) -> (res: bool)
        ensures res == (self@ == other@)
    {
        match (self, other) {
            (FnName::User(name1, arity1), FnName::User(name2, arity2)) =>
                arc_str_eq(name1, name2) && arity1 == arity2,
            (FnName::Nil, FnName::Nil) => true,
            (FnName::Cons, FnName::Cons) => true,
            _ => false,
        }
    }
}

impl Clone for FnName {
    fn clone(&self) -> (res: Self)
        ensures self@ == res@
    {
        match self {
            FnName::User(name, arity) => FnName::User(name.clone(), *arity),
            FnName::Nil => FnName::Nil,
            FnName::Cons => FnName::Cons,
        }
    }
}

impl Literal {
    pub fn eq(&self, other: &Self) -> (res: bool)
        ensures res == (self@ == other@)
    {
        match (self, other) {
            (Literal::Int(i1), Literal::Int(i2)) => i1 == i2,
            (Literal::String(s1), Literal::String(s2)) => arc_str_eq(s1, s2),
            (Literal::Atom(a1), Literal::Atom(a2)) => arc_str_eq(a1, a2),
            (Literal::Directive, Literal::Directive) => true,
            _ => false,
        }
    }
}

impl TermX {
    // Some utility functions to construct Term
    pub fn var(v: &Var) -> (res: Term)
        ensures res@ == SpecTerm::Var(v@)
    {
        Arc::new(TermX::Var(v.clone()))
    }

    pub fn var_str(v: &str) -> (res: Term)
        ensures res@ == SpecTerm::Var(v@)
    {
        TermX::var(&str_to_arc_str(v))
    }

    pub fn app(name: &FnName, args: Vec<Term>) -> (res: Term)
        ensures res@ == SpecTerm::App(name@, args.deep_view())
    {
        Arc::new(TermX::App(name.clone(), args))
    }

    pub fn app_str(name: &str, args: Vec<Term>) -> (res: Term)
        ensures res@ == SpecTerm::App(SpecFnName::User(name@, args.len() as int), args.deep_view())
    {
        TermX::app(&FnName::user(name, args.len()), args)
    }

    /// Constants are nullary applications, *different* from atoms
    pub fn constant(name: &str) -> (res: Term)
        ensures res@ == SpecTerm::App(SpecFnName::User(name@, 0), seq![])
    {
        let res = TermX::app(&FnName::user(name, 0), vec![]);
        assert(res@->App_1 =~= seq![]);
        res
    }

    pub fn atom(name: &str) -> (res: Term)
        ensures res@ == SpecTerm::Literal(SpecLiteral::Atom(name@))
    {
        Arc::new(TermX::Literal(Literal::Atom(str_to_arc_str(name))))
    }

    pub fn bool(b: bool) -> (res: Term)
        ensures res@ == SpecTerm::Literal(SpecLiteral::Atom(if b { "true"@ } else { "false"@ }))
    {
        Self::atom(if b { "true" } else { "false" })
    }

    pub fn int(i: LiteralInt) -> (res: Term)
        ensures res@ == SpecTerm::Literal(SpecLiteral::Int(i as int))
    {
        Arc::new(TermX::Literal(Literal::Int(i)))
    }

    pub fn str(s: &str) -> (res: Term)
        ensures res@ == SpecTerm::Literal(SpecLiteral::String(s@))
    {
        Arc::new(TermX::Literal(Literal::String(str_to_arc_str(s))))
    }

    /// Apply substitution to a term
    pub fn subst(term: &Term, subst: &Subst) -> (res: Term)
        ensures res@ == term@.subst(subst@)
    {
        match arc_as_ref(term) {
            TermX::Var(v) =>
                if let Some(k) = subst.0.get(v) {
                    k.clone()
                } else {
                    term.clone()
                },

            TermX::Literal(..) => term.clone(),

            TermX::App(name, args) => {
                // Apply substitution to each argument
                let subst_args = vec_map(args, |arg| -> (res: Term)
                    ensures res@ == arg@.subst(subst@)
                    { TermX::subst(arg, subst) });

                assert(subst_args.deep_view() =~= args.deep_view().map_values(|arg: SpecTerm| arg.subst(subst@)));
                TermX::app(name, subst_args)
            }
        }
    }

    pub fn eq(&self, other: &Self) -> (res: bool)
        ensures res == (self@ == other@)
    {
        match (self, other) {
            (TermX::Var(v1), TermX::Var(v2)) => arc_str_eq(v1, v2),
            (TermX::Literal(l1), TermX::Literal(l2)) => l1.eq(l2),
            (TermX::App(f1, args1), TermX::App(f2, args2)) => {
                if !f1.eq(f2) {
                    return false;
                }

                if args1.len() != args2.len() {
                    assert(self@->App_1 !~= other@->App_1);
                    return false;
                }

                for i in 0..args1.len()
                    invariant
                        args1.len() == args2.len(),
                        args1.deep_view() =~= self@->App_1,
                        args2.deep_view() =~= other@->App_1,
                        forall |j: int| 0 <= j < i ==> (#[trigger] args1[j as int])@ == args2[j as int]@,
                {
                    assert(args1[i as int]@ == self@->App_1[i as int]);
                    if !(&args1[i]).eq(&args2[i]) {
                        return false;
                    }
                }

                assert(self@->App_1 =~= other@->App_1);
                true
            }
            _ => false,
        }
    }

    /// Corresponds to SpecTerm::as_list
    pub fn as_list(&self) -> (res: Result<Vec<&Term>, ProofError>)
        ensures res matches Ok(list) ==> self@.as_list() =~= Some(list.deep_view())
    {
        match self {
            TermX::App(FnName::Nil, args) =>
                if args.len() == 0 {
                    Ok(vec![])
                } else {
                    proof_err!("ill-formed term: ", self)
                },

            TermX::App(FnName::Cons, args) =>
                if args.len() == 2 {
                    let mut tail = (&args[1]).as_list()?;
                    tail.insert(0, &args[0]);
                    Ok(tail)
                } else {
                    proof_err!("cannot convert to list: ", self)
                },

            _ => proof_err!("cannot convert to list: ", self),
        }
    }

    pub fn as_int(&self) -> (res: Result<i64, ProofError>)
        ensures res matches Ok(i) ==> self@ =~= SpecTerm::Literal(SpecLiteral::Int(i as int))
    {
        match self {
            TermX::Literal(Literal::Int(i)) => Ok(*i),
            _ => proof_err!("expecting int literal: ", self),
        }
    }

    pub fn as_atom(&self) -> (res: Result<&LiteralAtom, ProofError>)
        ensures res matches Ok(s) ==> self@ =~= SpecTerm::Literal(SpecLiteral::Atom(s@))
    {
        match self {
            TermX::Literal(Literal::Atom(s)) => Ok(s),
            _ => proof_err!("expecting atom: ", self),
        }
    }

    pub fn as_string(&self) -> (res: Result<&LiteralString, ProofError>)
        ensures res matches Ok(s) ==> self@ =~= SpecTerm::Literal(SpecLiteral::String(s@))
    {
        match self {
            TermX::Literal(Literal::String(s)) => Ok(s),
            _ => proof_err!("expecting string literal: ", self),
        }
    }

    pub fn as_var(&self) -> (res: Result<&Var, ProofError>)
        ensures res matches Ok(v) ==> self@ =~= SpecTerm::Var(v@)
    {
        match self {
            TermX::Var(v) => Ok(v),
            _ => proof_err!("expecting variable: ", self),
        }
    }

    /// Check if `self` occurs in the list of terms
    pub fn is_member(&self, list: &Vec<&Term>) -> (res: bool)
        ensures res == list.deep_view().contains(self@)
    {
        for i in 0..list.len()
            invariant forall |j| 0 <= j < i ==> self@ != #[trigger] list.deep_view()[j]
        {
            if self.eq(list[i]) {
                assert(list.deep_view()[i as int] == self@);
                return true;
            }
        }
        return false;
    }

    /// Corresponds to SpecTerm::not_unifiable
    pub fn not_unifiable(&self, other: &Term) -> (res: bool)
        ensures res == self@.not_unifiable(other@)
    {
        match (self, arc_as_ref(other)) {
            (TermX::Literal(l1), TermX::Literal(l2)) => !l1.eq(l2),

            // Distinct head symbol, or non-unifiable subterms
            (TermX::App(f1, args1), TermX::App(f2, args2)) => {
                if !f1.eq(f2) || args1.len() != args2.len() {
                    return true;
                }

                // Check if any subterms are not unifiable
                for i in 0..args1.len()
                    invariant
                        args1.len() == args2.len(),
                        self@ =~= SpecTerm::App(f1@, args1.deep_view()),
                        other@ =~= SpecTerm::App(f2@, args2.deep_view()),
                        forall |j| 0 <= j < i ==> !(#[trigger] args1[j])@.not_unifiable(args2[j]@),
                {
                    if (&args1[i]).not_unifiable(&args2[i]) {
                        assert(self@->App_1[i as int].not_unifiable(other@->App_1[i as int]));
                        return true;
                    }
                }

                false
            }

            (TermX::Literal(..), TermX::App(..)) => true,
            (TermX::App(..), TermX::Literal(..)) => true,

            _ => false,
        }
    }

    /// A helper function to check the arity and name
    /// of the head symbol of the term; and returns the arguments
    /// Corresponds to SpecTerm::headed_by
    pub fn headed_by<'a, 'b>(&'a self, expected_name: &'b str, expected_arity: usize) -> (res: Result<&'a Vec<Term>, ProofError>)
        ensures match res {
            Ok(res) => Some(res.deep_view()) == self@.headed_by(expected_name, expected_arity as int),
            Err(..) => self@.headed_by(expected_name, expected_arity as int).is_none(),
        }
    {
        match self {
            TermX::App(FnName::User(name, arity), args) =>
                if *arity == args.len() &&
                    arc_str_eq_str(name, expected_name) &&
                    *arity == expected_arity {
                    Ok(args)
                } else {
                    proof_err!("expecting symbol ", expected_name, " with ", expected_arity, ", got: ", self)
                },
            _ => proof_err!("expecting application, got: ", self),
        }
    }

    /// Corresponds to SpecTerm::eval_arith
    /// In addition, this function needs to check for overflow
    pub fn eval_arith(&self) -> (res: Result<i64, ProofError>)
        // NOTE: Since i64 may overflow, if we get res == None
        // we can't deduce that the spec should also be None
        ensures res matches Ok(i) ==> self@.eval_arith() == Some(i as int)
    {
        if let TermX::Literal(Literal::Int(i)) = self {
            Ok(*i)
        } else if let Ok(args) = self.headed_by(FN_NAME_ADD, 2) {
            if let Some(res) = (&args[0]).eval_arith()?.checked_add((&args[1]).eval_arith()?) {
                Ok(res)
            } else {
                proof_err!("potential overflow in ", self)
            }

        } else if let Ok(args) = self.headed_by(FN_NAME_SUB, 2) {
            if let Some(res) = (&args[0]).eval_arith()?.checked_sub((&args[1]).eval_arith()?) {
                Ok(res)
            } else {
                proof_err!("potential overflow in ", self)
            }

        } else if let Ok(args) = self.headed_by(FN_NAME_MUL, 2) {
            if let Some(res) = (&args[0]).eval_arith()?.checked_mul((&args[1]).eval_arith()?) {
                Ok(res)
            } else {
                proof_err!("potential overflow in ", self)
            }

        } else {
            proof_err!("unsupported arithmetic term: ", self)
        }
    }
}

impl RuleX {
    pub fn new(head: Term, body: Vec<Term>) -> (res: Rule)
        ensures res == (RuleX { head, body })
    {
        Arc::new(RuleX { head, body })
    }

    pub fn fact(name: &str, args: Vec<Term>) -> (res: Rule)
        ensures res@ =~= (SpecRule {
            head: SpecTerm::App(SpecFnName::User(name@, args.len() as int), args.deep_view()),
            body: seq![],
        })
    {
        RuleX::new(TermX::app(&FnName::user(name, args.len()), args), vec![])
    }
}

impl Program {
    pub fn new(rules: Vec<Rule>) -> (res: Program)
        ensures res.rules == rules
    {
        Program { rules }
    }
}

impl Theorem {
    /// A theorem has the invariant that the ghost proof object is
    /// a valid proof for the statement
    pub open spec fn wf(self, program: SpecProgram) -> bool {
        self@.wf(program)
    }

    /// Build on subproofs via the axiom SpecProof::ApplyRule
    pub fn apply_rule(program: &Program, rule_id: RuleId, subst: &Subst, subproofs: Vec<&Theorem>) -> (res: Result<Theorem, ProofError>)
        requires
            0 <= rule_id < program.rules.len(),
            forall |i| 0 <= i < subproofs.len() ==> (#[trigger] subproofs[i]).wf(program@),

        ensures
            res matches Ok(thm) ==> thm.wf(program@)
    {
        let rule = &program.rules[rule_id];
        let conclusion = TermX::subst(&rule.head, subst);

        if rule.body.len() != subproofs.len() {
            return proof_err!("unmatched number of subproofs");
        }

        // Check that each subproof matches the corresponding body term (after substitution)
        for i in 0..rule.body.len()
            invariant
                rule.body.len() == subproofs.len(),
                forall |j| 0 <= j < i ==> (#[trigger] rule.body[j])@.subst(subst@) == subproofs[j].stmt@,
        {
            let obligation = &TermX::subst(&rule.body[i], subst);
            if !obligation.eq(&subproofs[i].stmt) {
                return proof_err!(
                    i, "-th subproof mismatch: expecting ", obligation,
                    ", got ", &subproofs[i].stmt,
                    " (under substitution ", subst, ")");
            }
        }

        // Construct the final proof object
        Ok(Theorem {
            stmt: conclusion,
            proof: Ghost(SpecProof::ApplyRule {
                rule_id: rule_id as int,
                subst: subst@,
                subproofs: subproofs.deep_view(),
            }),
        })
    }

    pub fn true_intro(program: &Program, goal: &Term) -> (res: Result<Theorem, ProofError>)
        ensures res matches Ok(thm) ==> thm.stmt@ == goal@ && thm.wf(program@)
    {
        if goal.headed_by(FN_NAME_TRUE, 0).is_ok() || goal.eq(&TermX::atom(FN_NAME_TRUE)) {
            Ok(Theorem {
                stmt: goal.clone(),
                proof: Ghost(SpecProof::TrueIntro),
            })
        } else {
            proof_err!("true intro does not apply to goal: ", goal)
        }
    }

    /// Introduce (a, b) given proofs of both a and b
    pub fn and_intro(program: &Program, left: &Theorem, right: &Theorem) -> (res: Theorem)
        requires left.wf(program@) && right.wf(program@)
        ensures res.wf(program@)
    {
        Theorem {
            stmt: TermX::app(&FnName::user(FN_NAME_AND, 2), vec![left.stmt.clone(), right.stmt.clone()]),
            proof: Ghost(SpecProof::AndIntro(Box::new(left@), Box::new(right@))),
        }
    }

    /// Introduce (a; b) given a proof a
    pub fn or_intro_left(program: &Program, subproof: &Theorem, right: &Term) -> (res: Theorem)
        requires subproof.wf(program@)
        ensures
            res.wf(program@),
            res@.stmt == SpecTerm::App(SpecFnName::User(FN_NAME_OR.view(), 2), seq![subproof@.stmt, right@]),
    {
        let disjunct = vec![subproof.stmt.clone(), right.clone()];
        assert(disjunct.deep_view() =~= seq![subproof@.stmt, right@]);
        Theorem {
            stmt: TermX::app(&FnName::user(FN_NAME_OR, 2), disjunct),
            proof: Ghost(SpecProof::OrIntroLeft(Box::new(subproof@))),
        }
    }

    /// Introduce (a; b) given a proof b
    pub fn or_intro_right(program: &Program, left: &Term, subproof: &Theorem) -> (res: Theorem)
        requires subproof.wf(program@)
        ensures
            res.wf(program@),
            res@.stmt == SpecTerm::App(SpecFnName::User(FN_NAME_OR.view(), 2), seq![left@, subproof@.stmt]),
    {
        let disjunct = vec![left.clone(), subproof.stmt.clone()];
        assert(disjunct.deep_view() =~= seq![left@, subproof@.stmt]);
        Theorem {
            stmt: TermX::app(&FnName::user(FN_NAME_OR, 2), disjunct),
            proof: Ghost(SpecProof::OrIntroRight(Box::new(subproof@))),
        }
    }

    /// Construct a proof for forall(member(loop_var, list_term), goal), see SpecProof::ForallMember for more detail
    pub fn forall_member(program: &Program, outer_goal: &Term, subproofs: Vec<&Theorem>) -> (res: Result<Theorem, ProofError>)
        ensures
            res matches Ok(thm) ==> thm.stmt@ == outer_goal@ && thm.wf(program@)
    {
        // Check that outer_goal is of the form forall(member(loop_var, list_term), goal)
        let forall_args = outer_goal.headed_by(FN_NAME_FORALL, 2)?;
        let member_args = (&forall_args[0]).headed_by(FN_NAME_MEMBER, 2)?;

        let loop_var = (&member_args[0]).as_var()?;
        let list = (&member_args[1]).as_list()?;
        let goal = &forall_args[1];

        if list.len() != subproofs.len() {
            return proof_err!("unmatched list length to the number of subproofs: ", list.len(), " vs ", subproofs.len());
        }

        // For each subproof, check that the statement is exactly
        // Goal[loop_var |-> list[i]]
        for i in 0..list.len()
            invariant
                list.len() == subproofs.len(),

                forall |j| 0 <= j < i ==> {
                    let subst = SpecSubst(map!{ loop_var@ => list[j]@ });
                    let subst_goal = goal@.subst(subst);
                    (#[trigger] subproofs[j]).stmt@ == subst_goal
                },
        {
            let mut subst = Subst::new();
            subst.insert(loop_var.clone(), list[i].clone());
            let subst_goal = TermX::subst(goal, &subst);

            if !(&subproofs[i].stmt).eq(&subst_goal) {
                return proof_err!(
                    i, "-th subproof mismatch: expecting ", subst_goal,
                    ", got ", &subproofs[i].stmt,
                    " (under substitution ", &subst, ")");
            }
        }

        Ok(Theorem {
            stmt: outer_goal.clone(),
            proof: Ghost(SpecProof::ForallMember(subproofs.deep_view())),
        })
    }

    /// Match pattern against every head of a rule
    /// and check the assumption that each rule head (program.only_unifiable_with_base)
    /// - Either is matched by pattern and is a fact
    /// - Or is not unifiable with pattern
    ///
    /// Essentially this exhausts all possible solutions to pattern
    /// and substitute that solution into template,
    /// assuming that the pattern is headed by a "base" predicate symbol
    fn match_subst_base_predicates(program: &Program, pattern: &Term, template: &Term) -> (res: Result<Vec<Term>, ProofError>)
        ensures
            res matches Ok(insts) ==> {
                &&& program@.only_unifiable_with_base(pattern@)
                &&& filter_map(program@.rules, |rule: SpecRule| {
                    if let Some(subst) = pattern@.matches(rule.head) {
                        Some(template@.subst(subst))
                    } else {
                        None
                    }
                }) =~= insts.deep_view()
            }
    {
        let ghost filter = |rule: SpecRule| {
            if let Some(subst) = pattern@.matches(rule.head) {
                Some(template@.subst(subst))
            } else {
                None
            }
        };

        let mut insts = vec![];

        for i in 0..program.rules.len()
            invariant
                // filter stays unchanged
                filter == |rule: SpecRule| {
                    if let Some(subst) = pattern@.matches(rule.head) {
                        Some(template@.subst(subst))
                    } else {
                        None
                    }
                },

                // A prefix version of program.only_unifiable_with_base
                forall |j: int| 0 <= j < i ==>
                    (#[trigger] program@.rules[j]).matching_or_not_unifiable(pattern@),

                // The first i rules are corrected processed
                filter_map(program@.rules.take(i as int), filter) =~= insts.deep_view(),
        {
            let rule = &program.rules[i];
            if rule.body.len() != 0 {
                // Non-fact rules should not unify with the pattern
                if !pattern.not_unifiable(&rule.head) {
                    return proof_err!("non-fact rule should not unify with pattern ", pattern, ", but found a rule that might unify: ", rule);
                }

                proof {
                    pattern@.lemma_non_unifiable_to_non_matching(rule@.head);
                    lemma_filter_map_skip(program@.rules, filter, i as int);
                }
            } else {
                // Any fact should either be matched by pattern
                // or not unifiable (i.e. nothing in between)
                let mut subst = Subst::new();
                let ghost old_subst = subst@;

                if let Ok(..) = TermX::match_terms(&mut subst, &pattern, &rule.head) {
                    insts.push(TermX::subst(template, &subst));

                    proof {
                        // Append the mapped element to the filtered list
                        lemma_filter_map_no_skip(program@.rules, filter, i as int);
                        let matches_subst = pattern@.matches(rule@.head).unwrap();
                        old_subst.lemma_merge_empty_left(matches_subst);
                    }
                } else if !pattern.not_unifiable(&rule.head) {
                    return proof_err!("pattern ", pattern, " might still unify with the rule (even though matching failed): ", rule);
                } else {
                    proof {
                        // No change to the filtered list
                        lemma_filter_map_skip(program@.rules, filter, i as int);
                    }
                }
            }
        }

        assert(program@.rules.take(program.rules.len() as int) == program@.rules);

        Ok(insts)
    }

    /// Proof-check base case of findall
    pub fn findall_base(program: &Program, goal: &Term) -> (res: Result<Theorem, ProofError>)
        ensures
            res matches Ok(thm) ==> thm.stmt@ == goal@ && thm.wf(program@)
    {
        let args = goal.headed_by(FN_NAME_FINDALL, 3)?;

        let template = &args[0];
        let pattern = &args[1];

        let list = (&args[2]).as_list()?;
        let insts = Self::match_subst_base_predicates(program, pattern, template)?;

        // Check that the instances coincides with the list
        if insts.len() != list.len() {
            return proof_err!("unmatched number of instances in the list");
        }

        for i in 0..insts.len()
            invariant
                insts.len() == list.len(),
                forall |j| #![auto] 0 <= j < i ==> insts[j]@ == list[j]@
        {
            if !(&insts[i]).eq(list[i]) {
                return proof_err!("unmatched instance");
            }
        }

        return Ok(Theorem {
            stmt: goal.clone(),
            proof: Ghost(SpecProof::BuiltIn),
        });
    }

    /// Apply and proof-check SpecProof::ForallBase
    pub fn forall_base(program: &Program, goal: &Term, subproofs: Vec<&Theorem>) -> (res: Result<Theorem, ProofError>)
        ensures
            res matches Ok(thm) ==> thm.stmt@ == goal@ && thm.wf(program@)
    {
        let args = goal.headed_by(FN_NAME_FORALL, 2)?;

        let pattern = &args[0];
        let template = &args[1];

        let insts = Self::match_subst_base_predicates(program, pattern, template)?;

        if insts.len() != subproofs.len() {
            return proof_err!("unmatched number of subproofs");
        }

        // Check that the instances match the statements of the subproofs
        for i in 0..insts.len()
            invariant
                insts.len() == subproofs.len(),
                forall |j| #![auto] 0 <= j < i ==> insts[j]@ == subproofs[j].stmt@,
        {
            if !(&insts[i]).eq(&subproofs[i].stmt) {
                return proof_err!(
                    i, "-th subproof mismatch: expecting ", &insts[i],
                    ", got ", &subproofs[i].stmt);
            }
        }

        return Ok(Theorem {
            stmt: goal.clone(),
            proof: Ghost(SpecProof::ForallBase(subproofs.deep_view())),
        });
    }

    /// Try applying the axiom of a domain function for ints, strings, or lists
    pub fn try_built_in(program: &Program, goal: &Term, allow_unsupported_builtin: bool) -> (res: Result<Theorem, ProofError>)
        ensures
            res matches Ok(thm) ==> thm.stmt@ == goal@ && thm.wf(program@)
    {
        // Get symbol, arity, and arguments from the goal term
        let (symbol, arity, args) = if let TermX::App(FnName::User(name, arity), args) = arc_as_ref(goal) {
            if *arity != args.len() {
                return proof_err!("ill-formed term: ", goal);
            }
            (name, *arity, args)
        } else {
            return proof_err!("expecting application for built-in goal: ", goal);
        };

        // Theorem object if successful
        let success = Ok(Theorem { stmt: goal.clone(), proof: Ghost(SpecProof::BuiltIn) });

        let result = match (arc_str_to_str(symbol), arity) {
            // =/2, ==/2
            (FN_NAME_EQ, 2) => (&args[0]).eq(&args[1]),
            (FN_NAME_EQUIV, 2) => (&args[0]).eq(&args[1]),

            // \=/2, \==/2
            (FN_NAME_NOT_EQ, 2) => (&args[0]).not_unifiable(&args[1]),
            (FN_NAME_NOT_EQUIV, 2) => !(&args[0]).eq(&args[1]),

            // is/2
            (FN_NAME_IS, 2) => (&args[0]).eq(&Arc::new(TermX::Literal(Literal::Int((&args[1]).eval_arith()?)))),

            // =:=/2, =\=/2
            (FN_NAME_EVAL_EQ, 2) => (&args[0]).eval_arith()? == (&args[1]).eval_arith()?,
            (FN_NAME_EVAL_NOT_EQ, 2) => (&args[0]).eval_arith()? != (&args[1]).eval_arith()?,

            // >/2, >=/2, </2, =</2
            (FN_NAME_GT, 2) => (&args[0]).eval_arith()? > (&args[1]).eval_arith()?,
            (FN_NAME_GE, 2) => (&args[0]).eval_arith()? >= (&args[1]).eval_arith()?,
            (FN_NAME_LT, 2) => (&args[0]).eval_arith()? < (&args[1]).eval_arith()?,
            (FN_NAME_LE, 2) => (&args[0]).eval_arith()? <= (&args[1]).eval_arith()?,

            // length/2
            (FN_NAME_LENGTH, 2) => (&args[0]).as_list()?.len() == i64_try_into_usize((&args[1]).as_int()?)?,

            // member/2
            (FN_NAME_MEMBER, 2) => (&args[0]).is_member(&(&args[1]).as_list()?),

            // \+/1 (base case only)
            (FN_NAME_NOT, 1) => {
                // \+P holds if P is not unifiable with head of any rule
                // TODO: improve performance by pre-filtering the head symbol
                for i in 0..program.rules.len()
                    invariant
                        args.len() == 1,
                        forall |j| 0 <= j < i ==> (#[trigger] program.rules[j]).head@.not_unifiable(args[0]@)
                {
                    if !(&program.rules[i].head).not_unifiable(&args[0]) {
                        return proof_err!("trying to prove ", goal, ", but found a rule that might be unifiable: ", &program.rules[i]);
                    }
                }
                true
            }

            // findall/3 (base case only)
            (FN_NAME_FINDALL, 3) => return Self::findall_base(program, goal),


            // nonvar/1, var/1
            (FN_NAME_NONVAR, 1) => match arc_as_ref(&args[0]) {
                TermX::Var(..) => false,
                _ => true,
            },
            (FN_NAME_VAR, 1) => match arc_as_ref(&args[0]) {
                TermX::Var(..) => true,
                _ => false,
            },

            // atom_string/2
            (FN_NAME_ATOM_STRING, 2) => arc_str_eq((&args[0]).as_atom()?, (&args[1]).as_string()?),

            // string_chars/2
            (FN_NAME_STRING_CHARS, 2) => {
                let string = (&args[0]).as_string()?;
                let chars = (&args[1]).as_list()?;

                if chars.len() != string.unicode_len() {
                    return proof_err!("goal failed: ", goal);
                }

                // Compare each char
                // TODO: get_char and unicode_len are O(n)
                // Verus doesn't support iterator string.chars() yet
                for i in 0..chars.len()
                    invariant
                        chars.len() == string@.len(),
                        forall |j| 0 <= j < i ==>
                            (#[trigger] chars[j])@ =~= SpecTerm::Literal(SpecLiteral::Atom(seq![string@[j as int]])),
                {
                    let s = (&chars[i]).as_atom()?;
                    if s.unicode_len() == 1 && s.get_char(0) == string.get_char(i) {
                        assert(s@ =~= seq![string@[i as int]]);
                    } else {
                        return proof_err!("goal failed: ", goal);
                    }
                }
                true
            }

            // sub_string/5 (only supporting single character separator, and no padding)
            (FN_NAME_SUB_STRING, 5) => {
                let string = (&args[0]).as_string()?;
                let before = i64_try_into_usize((&args[1]).as_int()?)?;
                let len = i64_try_into_usize((&args[2]).as_int()?)?;
                let after = i64_try_into_usize((&args[3]).as_int()?)?;
                let substring = (&args[4]).as_string()?;

                if let Some(end) = before.checked_add(len) {
                    if let Some(sum) = end.checked_add(after) {
                        string.unicode_len() == sum &&
                        substring.unicode_len() == len &&
                        (len == 0 || arc_str_eq_str(substring, string.substring_char(before, end)))
                    } else {
                        return proof_err!("potential overflow in goal: ", goal);
                    }
                } else {
                    return proof_err!("potential overflow in goal: ", goal);
                }
            }

            // reverse/2
            (FN_NAME_REVERSE, 2) => {
                let mut list = (&args[0]).as_list()?;
                let reversed = (&args[1]).as_list()?;

                let ghost old_list = list.deep_view();
                vec_reverse(&mut list);

                // Check that list == reversed
                if list.len() != reversed.len() {
                    return proof_err!("goal failed: ", goal);
                }

                for i in 0..list.len()
                    invariant
                        list.len() == reversed.len(),
                        forall |j| 0 <= j < i ==> #[trigger] list[j]@ == reversed[j]@,
                {
                    if !list[i].eq(reversed[i]) {
                        return proof_err!("goal failed: ", goal);
                    }
                }
                true
            }

            // split_string/4
            (FN_NAME_SPLIT_STRING, 4) => {
                let string = (&args[0]).as_string()?;
                let sep = (&args[1]).as_string()?;
                let padding = (&args[2]).as_string()?;
                let list = (&args[3]).as_list()?;

                if sep.unicode_len() == 1 && padding.unicode_len() == 0 {
                    let mut split_strs: Vec<&str> = Vec::new();

                    // Check that each element in args[3] is a string literal
                    // and store it into split_strs
                    for i in 0..list.len()
                        invariant
                            i == split_strs.len(),
                            forall |j| 0 <= j < i ==> #[trigger] list[j]@ =~= SpecTerm::Literal(SpecLiteral::String(split_strs[j]@)),
                    {
                        split_strs.push(arc_str_to_str((&list[i]).as_string()?));
                    }

                    assert(split_strs@.map_values(|s: &str| s@)
                        =~= Seq::new(list.deep_view().len(), |i| list.deep_view()[i]->Literal_0->String_0));

                    let joined_string = join_strs(&split_strs, sep);
                    arc_str_eq_str(string, joined_string.as_str())
                } else {
                    return proof_err!("unsupported goal: ", goal);
                }
            }

            // nth1/3
            (FN_NAME_NTH1, 3) => {
                let index = i64_try_into_usize((&args[0]).as_int()?)?;
                let list = (&args[1]).as_list()?;

                if index < 1 || index > list.len() {
                    return proof_err!("index out of bounds: ", goal);
                }

                list[index - 1].eq(&args[2])
            }

            // string_length/2
            (FN_NAME_STRING_LENGTH, 2) => {
                let string = (&args[0]).as_string()?;
                let len = i64_try_into_usize((&args[1]).as_int()?)?;
                string.unicode_len() == len
            }

            // append/3
            (FN_NAME_APPEND, 3) => {
                let mut list1 = (&args[0]).as_list()?;
                let mut list2 = (&args[1]).as_list()?;
                let list3 = (&args[2]).as_list()?;

                let ghost old_list1 = list1.deep_view();
                let ghost old_list2 = list2.deep_view();

                list1.append(&mut list2);

                let appended = list1;

                if appended.len() != list3.len() {
                    return proof_err!("unmatched list lengths: ", goal);
                }

                for i in 0..appended.len()
                    invariant
                        appended.len() == list3.len(),
                        appended.deep_view() =~= old_list1 + old_list2,
                        forall |j| 0 <= j < i ==> #[trigger] appended[j]@ == list3[j]@,
                {
                    if !appended[i].eq(&list3[i]) {
                        return proof_err!("unmatched element: ", goal);
                    }
                }

                true
            }

            _ => false,
        };

        if result {
            return success;
        }

        Self::unverified_builtins(program, goal, allow_unsupported_builtin)
    }

    /// Some unverified built-in functions due to lack of specs
    /// TODO: move this to the verified check
    #[verifier::external_body]
    fn unverified_builtins(program: &Program, goal: &Term, allow_unsupported_builtin: bool) -> (res: Result<Theorem, ProofError>)
        ensures
            res matches Ok(thm) ==> thm.stmt@ == goal@ && thm.wf(program@)
    {
        if let Ok(args) = goal.headed_by("string_lower", 2) {
            if let (
                TermX::Literal(Literal::String(s1)),
                TermX::Literal(Literal::String(s2)),
            ) = (arc_as_ref(&args[0]), arc_as_ref(&args[1])) {
                if s1.to_lowercase() == s2.as_ref() {
                    return Ok(Theorem { stmt: goal.clone(), proof: Ghost(SpecProof::BuiltIn) });
                }
            } else if let (
                TermX::Literal(Literal::Atom(s1)),
                TermX::Literal(Literal::String(s2)),
            ) = (arc_as_ref(&args[0]), arc_as_ref(&args[1])) {
                if s1.to_lowercase() == s2.as_ref() {
                    return Ok(Theorem { stmt: goal.clone(), proof: Ghost(SpecProof::BuiltIn) });
                }
            }
        } else if let Ok(args) = goal.headed_by("uri_encoded", 3) {
            // TODO: uri_encoded(path, <atom>, <string>) doesn't seem to work
            if let (
                TermX::Literal(Literal::Atom(component)),
                TermX::Literal(Literal::Atom(s1)),
                TermX::Literal(Literal::String(s2)),
            ) | (
                TermX::Literal(Literal::Atom(component)),
                TermX::Literal(Literal::String(s1)),
                TermX::Literal(Literal::Atom(s2)),
            ) | (
                TermX::Literal(Literal::Atom(component)),
                TermX::Literal(Literal::Atom(s1)),
                TermX::Literal(Literal::Atom(s2)),
            ) | (
                TermX::Literal(Literal::Atom(component)),
                TermX::Literal(Literal::String(s1)),
                TermX::Literal(Literal::String(s2)),
            ) = (arc_as_ref(&args[0]), arc_as_ref(&args[1]), arc_as_ref(&args[2])) {
                let mode = if arc_str_eq_str(component, "query_value") {
                    URIEncodeMode::QueryValue
                } else if arc_str_eq_str(component, "fragment") {
                    URIEncodeMode::Fragment
                } else if arc_str_eq_str(component, "path") {
                    URIEncodeMode::Path
                } else if arc_str_eq_str(component, "segment") {
                    URIEncodeMode::Segment
                } else {
                    return proof_err!("unsupported uri_encoded mode: ", component);
                };

                if uri_encode(mode, s1) == s2.as_ref() {
                    return Ok(Theorem { stmt: goal.clone(), proof: Ghost(SpecProof::BuiltIn) });
                }

                // return Ok(Theorem { stmt: goal.clone(), proof: Ghost(SpecProof::BuiltIn) });
            }
        }

        if allow_unsupported_builtin {
            eprintln_join!("unsupported built-in: ", goal);
            return Ok(Theorem { stmt: goal.clone(), proof: Ghost(SpecProof::BuiltIn) });
        }

        proof_err!("unsupported goal: ", goal)
    }
}

/// Following https://www.swi-prolog.org/pldoc/man?predicate=uri_encoded/3
enum URIEncodeMode {
    QueryValue,
    Fragment,
    Path,
    Segment,
}

/// TODO: unverified
/// Following https://www.swi-prolog.org/pldoc/man?predicate=uri_encoded/3
#[verifier::external_body]
fn uri_encode(mode: URIEncodeMode, input: &str) -> String {
    let mut encoded = String::new();

    for byte in input.bytes() {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() {
            encoded.push(ch);
        } else if match mode {
            URIEncodeMode::QueryValue | URIEncodeMode::Fragment => "-._~!$'()*,;@/?".contains(ch),
            URIEncodeMode::Path => "-._~!$&'()*,;=@/".contains(ch),
            URIEncodeMode::Segment => "-._~!$&'()*,;=@".contains(ch),
        } {
            encoded.push(ch);
        } else {
            encoded.push_str(&format!("%{:02X}", byte));
        }
    }

    encoded
}

impl Clone for Theorem {
    fn clone(&self) -> (res: Self)
        ensures self@ == res@
    {
        Theorem {
            stmt: self.stmt.clone(),
            proof: self.proof,
        }
    }
}

impl Subst {
    pub fn new() -> (res: Subst)
        ensures res@.0 =~= Map::<SpecVar, SpecTerm>::empty() && res@.is_empty()
    {
        Subst(StringHashMap::new())
    }

    pub fn get(&self, var: &Var) -> (res: Option<&Term>)
        ensures
            self@.contains_var(var@) == res.is_some() &&
            (if self@.contains_var(var@) {
                res matches Some(term) && term@ == self@.get(var@)
            } else {
                res matches None
            })
    {
        self.0.get(var)
    }

    pub fn insert(&mut self, var: Var, term: Term)
        ensures self@.0 =~= old(self)@.0.insert(var@, term@),
    {
        self.0.insert(arc_str_to_str(&var).to_string(), term);
    }
}

impl Clone for Subst {
    fn clone(&self) -> (res: Self)
        ensures self@.0 == res@.0
    {
        Subst(self.0.clone())
    }
}

/// `Program::clone` is only used in non-Verus code right now
impl Clone for Program {
    #[verifier::external_body]
    fn clone(&self) -> (res: Self)
        ensures self@ == res@
    {
        Program { rules: self.rules.clone() }
    }
}

}
