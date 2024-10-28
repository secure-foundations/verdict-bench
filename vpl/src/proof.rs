use vstd::prelude::*;

use polyfill::seq_join;

// Define proofs of queries in Prolog

verus! {

pub const FN_NAME_TRUE: &'static str = "true";

pub const FN_NAME_AND: &'static str = ",";

pub const FN_NAME_OR: &'static str = ";";

pub const FN_NAME_EQ: &'static str = "=";
  // equality checks for unification
pub const FN_NAME_NOT_EQ: &'static str = "\\=";

pub const FN_NAME_EQUIV: &'static str = "==";
  // equivalence checks for syntactic equality (e.g. X \== Y)
pub const FN_NAME_NOT_EQUIV: &'static str = "\\==";

pub const FN_NAME_NOT: &'static str = "\\+";

pub const FN_NAME_FORALL: &'static str = "forall";

pub const FN_NAME_FINDALL: &'static str = "findall";

pub const FN_NAME_MEMBER: &'static str = "member";

pub const FN_NAME_LENGTH: &'static str = "length";

pub const FN_NAME_PRED_IND: &'static str = "/";
  // e.g. functor/3
pub const FN_NAME_ADD: &'static str = "+";

pub const FN_NAME_SUB: &'static str = "-";

pub const FN_NAME_MUL: &'static str = "*";

pub const FN_NAME_GT: &'static str = ">";

pub const FN_NAME_GE: &'static str = ">=";

pub const FN_NAME_LT: &'static str = "<";

pub const FN_NAME_LE: &'static str = "=<";

pub const FN_NAME_IS: &'static str = "is";
  // is evaluates only the RHS
pub const FN_NAME_EVAL_EQ: &'static str = "=:=";
  // =:= evaluates both sides
pub const FN_NAME_EVAL_NOT_EQ: &'static str = "=\\=";

pub const FN_NAME_STRING_CHARS: &'static str = "string_chars";

pub const FN_NAME_SUB_STRING: &'static str = "sub_string";

pub const FN_NAME_ATOM_STRING: &'static str = "atom_string";

pub const FN_NAME_REVERSE: &'static str = "reverse";

pub const FN_NAME_SPLIT_STRING: &'static str = "split_string";

pub const FN_NAME_NONVAR: &'static str = "nonvar";

pub const FN_NAME_VAR: &'static str = "var";

pub const FN_NAME_NTH1: &'static str = "nth1";

pub const FN_NAME_STRING_LENGTH: &'static str = "string_length";

pub const FN_NAME_APPEND: &'static str = "append";

pub type SpecVar = Seq<char>;

pub type SpecUserFnName = Seq<char>;

pub type SpecRuleId = int;

pub type SpecArity = int;

pub type SpecIntLiteral = int;

pub type SpecStringLiteral = Seq<char>;

pub type SpecAtomLiteral = Seq<char>;

#[verifier::ext_equal]
pub enum SpecFnName {
    // User-defined symbol: (name, arity)
    User(SpecUserFnName, SpecArity),
    // List nil/0 and cons/2
    Nil,
    Cons,
}

#[verifier::ext_equal]
pub enum SpecLiteral {
    Int(SpecIntLiteral),
    String(SpecStringLiteral),
    Atom(SpecAtomLiteral),

    // A special symbol for denoting headless clauses/directives
    // e.g. <Directive> :- ...
    Directive,
}

/**
 * A few notes:
 * 1. Atoms are different from nullary applications (e.g. check a == a(). in swipl).
 *    See also https://www.swi-prolog.org/pldoc/man?predicate=atom/1
 * 2. [] == '[]' is false, but '[|]'(a, b) == [a|b] is true; we single out both Nil and Cons
 *    in SpecFnName for simplicity.
 * 3. Both true and true() are true predicates in swipl.
 */

#[verifier::ext_equal]
pub enum SpecTerm {
    Var(SpecVar),
    Literal(SpecLiteral),
    App(SpecFnName, Seq<SpecTerm>),
}

#[verifier::ext_equal]
pub struct SpecRule {
    pub head: SpecTerm,
    pub body: Seq<SpecTerm>,
}

#[verifier::ext_equal]
pub struct SpecProgram {
    pub rules: Seq<SpecRule>,
}

#[verifier::ext_equal]
pub struct SpecSubst(pub Map<SpecVar, SpecTerm>);

/// A proof includes a statement and its proof tree
/// Free variables in the statement are implicitly existentially quantified
pub struct SpecTheorem {
    pub stmt: SpecTerm,
    pub proof: SpecProof,
}

pub enum SpecProof {
    /// Apply an instance of an existing rule
    ApplyRule { rule_id: SpecRuleId, subst: SpecSubst, subproofs: Seq<SpecTheorem> },
    /// Proves true
    TrueIntro,
    /// Show a, b if we have proven a and b separately
    AndIntro(Box<SpecTheorem>, Box<SpecTheorem>),
    /// Show a; b if we have proven a or b
    OrIntroLeft(Box<SpecTheorem>),
    OrIntroRight(Box<SpecTheorem>),
    /// Proves goals of the form
    ///   forall(member(X, L), <Goal>)
    /// where X has to be a variable
    /// and L has to be a concrete list
    ForallMember(Seq<SpecTheorem>),
    /// Proves goals of the form
    ///   forall(P(...), Q(...))
    /// where P is a base predicate
    ForallBase(Seq<SpecTheorem>),
    /// Built-in function evaluation for integers, strings, and lists
    BuiltIn,
}

impl SpecTerm {
    /// Substitute a term
    /// TODO: Using an axiom here due to Verus issue #1222
    pub closed spec fn subst(self, subst: SpecSubst) -> SpecTerm;

    #[verifier::external_body]
    pub broadcast proof fn axiom_subst(self, subst: SpecSubst)
        ensures
            #[trigger] self.subst(subst) == match self {
                SpecTerm::Var(v) => if subst.contains_var(v) {
                    subst.get(v)
                } else {
                    self
                },
                SpecTerm::Literal(..) => self,
                SpecTerm::App(f, args) => SpecTerm::App(
                    f,
                    args.map_values(|arg: SpecTerm| arg.subst(subst)),
                ),
            },
    {
    }

    /// Check if a term is headed in the given name
    pub open spec fn is_app_of(self, name: SpecFnName) -> bool {
        self matches SpecTerm::App(f, ..) && f == name
    }

    pub open spec fn args(self) -> Seq<SpecTerm> {
        self->App_1
    }

    /// Try to convert a term in the form of a Prolog list [t1 | [t2 | ...]]
    /// to a Seq of terms [t1, t2, ...]
    /// If there are non-cons or non-nil terms, return None
    pub open spec fn as_list(self) -> Option<Seq<SpecTerm>>
        decreases self,
    {
        match self {
            SpecTerm::App(SpecFnName::Nil, args) => if args.len() == 0 {
                Some(seq![])
            } else {
                None
            },
            SpecTerm::App(SpecFnName::Cons, args) => if args.len() == 2 {
                match args[1].as_list() {
                    Some(tail) => { Some(seq![args[0]] + tail) },
                    None => None,
                }
            } else {
                None
            },
            _ => None,
        }
    }

    /// Specifies a sufficient condition for two terms to be non-unifiable
    /// NOTE: this does not completely cover non-unifiability
    pub open spec fn not_unifiable(self, other: SpecTerm) -> bool
        decreases self,
    {
        match (self, other) {
            (SpecTerm::Literal(l1), SpecTerm::Literal(l2)) => l1 != l2,
            // Distinct head symbol, or non-unifiable subterms
            (SpecTerm::App(f1, args1), SpecTerm::App(f2, args2)) => f1 != f2 || args1.len()
                != args2.len() || (exists|i|
                0 <= i < args1.len() && (#[trigger] args1[i]).not_unifiable(#[trigger] args2[i])),
            (SpecTerm::Literal(..), SpecTerm::App(..)) => true,
            (SpecTerm::App(..), SpecTerm::Literal(..)) => true,
            _ => false,
        }
    }

    /// Check if self matches other
    /// i.e. variables in other are considered constants
    /// and variables in self are used for unification
    pub closed spec fn matches(self, other: SpecTerm) -> Option<SpecSubst>;

    #[verifier::external_body]
    pub broadcast proof fn axiom_matches(self, other: SpecTerm)
        ensures
            #[trigger] self.matches(other) == match (self, other) {
                (SpecTerm::Var(v), _) => Some(SpecSubst(map!{ v => other })),
                (SpecTerm::Literal(l1), SpecTerm::Literal(l2)) => if l1 == l2 {
                    Some(SpecSubst::empty())
                } else {
                    None
                },
                (SpecTerm::App(f1, args1), SpecTerm::App(f2, args2)) => if f1 == f2 && args1.len()
                    == args2.len() {
                    SpecTerm::matches_multiple(args1, args2)
                } else {
                    None
                },
                _ => None,
            },
    {
    }

    /// Match multiple terms and merge substitutions
    pub open spec fn matches_multiple(terms1: Seq<SpecTerm>, terms2: Seq<SpecTerm>) -> Option<
        SpecSubst,
    >
        decreases terms1.len(),
    {
        if terms1.len() != terms2.len() {
            None
        } else if terms1.len() == 0 {
            Some(SpecSubst(map!{}))
        } else {
            match terms1[0].matches(terms2[0]) {
                Some(subst1) => {
                    match SpecTerm::matches_multiple(terms1.drop_first(), terms2.drop_first()) {
                        Some(subst2) => subst1.merge(subst2),
                        None => None,
                    }
                },
                None => None,
            }
        }
    }

    /// Check if the term is headed by the given user symbol
    /// with specified arity. If so return the arguments
    pub open spec fn headed_by(self, expected_name: &str, expected_arity: int) -> Option<
        Seq<SpecTerm>,
    > {
        match self {
            SpecTerm::App(SpecFnName::User(name, arity), args) if name == expected_name.view()
                && arity == expected_arity && args.len() == expected_arity => Some(args),
            _ => None,
        }
    }

    /// Evaluates arithmetic operators in the term
    /// Only succeeds if term contains only arithmetic
    /// expressions and constants without variables
    pub open spec fn eval_arith(self) -> Option<int>
        decreases self,
    {
        if let SpecTerm::Literal(SpecLiteral::Int(i)) = self {
            Some(i)
        } else if let Some(args) = self.headed_by(FN_NAME_ADD, 2) {
            if let (Some(lhs), Some(rhs)) = (args[0].eval_arith(), args[1].eval_arith()) {
                Some(lhs + rhs)
            } else {
                None
            }
        } else if let Some(args) = self.headed_by(FN_NAME_SUB, 2) {
            if let (Some(lhs), Some(rhs)) = (args[0].eval_arith(), args[1].eval_arith()) {
                Some(lhs - rhs)
            } else {
                None
            }
        } else if let Some(args) = self.headed_by(FN_NAME_MUL, 2) {
            if let (Some(lhs), Some(rhs)) = (args[0].eval_arith(), args[1].eval_arith()) {
                Some(lhs * rhs)
            } else {
                None
            }
        } else {
            None
        }
    }
}

impl SpecSubst {
    pub open spec fn get(self, v: SpecVar) -> SpecTerm {
        self.0[v]
    }

    pub open spec fn dom(self) -> Set<SpecVar> {
        self.0.dom()
    }

    pub open spec fn contains_var(self, v: SpecVar) -> bool {
        self.0.contains_key(v)
    }

    pub open spec fn empty() -> SpecSubst {
        SpecSubst(Map::empty())
    }

    pub open spec fn is_empty(self) -> bool {
        self.dom() == Set::<SpecVar>::empty()
    }

    pub open spec fn mergeable(self, other: SpecSubst) -> bool {
        forall|v| #[trigger]
            self.contains_var(v) && other.contains_var(v) ==> self.get(v) == other.get(v)
    }

    /// Two substitutions are mergeable if they agree on the
    /// intersection of their domains
    pub open spec fn merge(self, other: SpecSubst) -> Option<SpecSubst> {
        if self.mergeable(other) {
            Some(
                SpecSubst(
                    Map::new(
                        |v| self.contains_var(v) || other.contains_var(v),
                        |v|
                            if self.contains_var(v) {
                                self.get(v)
                            } else {
                                other.get(v)
                            },
                    ),
                ),
            )
        } else {
            None
        }
    }
}

impl SpecRule {
    /// A technical constraint that a term either
    /// matches the rule head and the rule is a fact
    /// or the term is not unifiable with the head
    ///
    /// e.g. cannot be the case that
    /// - The term matches the head but the rule is not a fact.
    /// - The term does not match the head but it's unifiable with the head
    pub open spec fn matching_or_not_unifiable(self, term: SpecTerm) -> bool {
        ||| self.body.len() == 0 && term.matches(self.head).is_some()
        ||| term.not_unifiable(self.head)
    }
}

impl SpecProgram {
    /// Check that
    /// 1. The term can only be unified with base predicates
    /// 2. In all unifiable cases, the term as a pattern has to match the head of the rule
    ///    (unification and matching coincides for the term)
    ///
    /// This used as a simplifying assumption for proof-checking forall and findall
    pub open spec fn only_unifiable_with_base(self, term: SpecTerm) -> bool {
        forall|i|
            0 <= i < self.rules.len() ==> (#[trigger] self.rules[i]).matching_or_not_unifiable(term)
    }
}

/// Similar to iterator's filter_map
pub open spec fn filter_map<T, S>(s: Seq<T>, f: spec_fn(T) -> Option<S>) -> Seq<S>
    decreases s.len(),
{
    if s.len() == 0 {
        seq![]
    } else {
        match f(s[0]) {
            Some(v) => seq![v] + filter_map(s.drop_first(), f),
            None => filter_map(s.drop_first(), f),
        }
    }
}

impl SpecTheorem {
    /// Defines whether a proof is well-formed
    pub open spec fn wf(self, program: SpecProgram) -> bool
        decreases self,
    {
        match self.proof {
            SpecProof::ApplyRule { rule_id, subst, subproofs } => {
                &&& 0 <= rule_id
                    < program.rules.len()
                // Subproofs correspond to each term in the body of the rule
                &&& subproofs.len() == program.rules[rule_id].body.len()
                &&& forall|i|
                    0 <= i < subproofs.len() ==> #[trigger] program.rules[rule_id].body[i].subst(
                        subst,
                    ) == (
                    #[trigger] subproofs[i]).stmt
                // All subproofs are well-formed
                &&& forall|i|
                    0 <= i < subproofs.len() ==> (#[trigger] subproofs[i]).wf(
                        program,
                    )
                // The final conclusion should coincide with head of the rule after subst
                &&& program.rules[rule_id].head.subst(subst)
                    == self.stmt
                // NOTE: we do not require subst to cover all free variables in the rule
                // because we need to allow proofs for terms such as forall(p(x), q(x)),
                // in which x can remain as a variable.

            },
            SpecProof::TrueIntro => {
                // Both true and true() are valid
                ||| self.stmt.headed_by(FN_NAME_TRUE, 0).is_some()
                ||| self.stmt matches SpecTerm::Literal(SpecLiteral::Atom(atom)) && atom
                    == FN_NAME_TRUE.view()
            },
            SpecProof::AndIntro(left, right) => {
                &&& self.stmt.headed_by(FN_NAME_AND, 2) matches Some(args)
                &&& left.stmt == args[0]
                &&& right.stmt == args[1]
            },
            SpecProof::OrIntroLeft(subproof) => {
                &&& self.stmt.headed_by(FN_NAME_OR, 2) matches Some(args)
                &&& subproof.stmt == args[0]
            },
            SpecProof::OrIntroRight(subproof) => {
                &&& self.stmt.headed_by(FN_NAME_OR, 2) matches Some(args)
                &&& subproof.stmt == args[1]
            },
            SpecProof::ForallMember(subproofs) => {
                // Check that the statement of the form
                //   forall(member(X, L), <Goal>)
                // where X has to be a variable
                // and L has to be a concrete list
                &&& self.stmt.headed_by(FN_NAME_FORALL, 2) matches Some(forall_args)
                &&& forall_args[0].headed_by(FN_NAME_MEMBER, 2) matches Some(member_args)
                &&& member_args[0] matches SpecTerm::Var(loop_var)
                &&& member_args[1].as_list() matches Some(
                    list,
                )
                // Then the proof obligation is that
                // for each i in 0..list.len(), subproofs[i] is a proof of <Goal>[X |-> list[i]]
                &&& subproofs.len() == list.len()
                &&& forall|i|
                    0 <= i < list.len() ==> (#[trigger] subproofs[i]).stmt == forall_args[1].subst(
                        SpecSubst(map!{ loop_var => list[i] }),
                    )
            },
            SpecProof::ForallBase(subproofs) => {
                &&& self.stmt.headed_by(FN_NAME_FORALL, 2) matches Some(
                    args,
                )
                // For all rules, either
                // - the rule is a fact and matches the predicate
                // - the head of the rule is not unifiable with the predicate
                //
                // NOTE: there might be terms in between (i.e. unifiable but not matching)
                // we enforce the absence of these case for a simpler spec
                //
                // TODO: maybe extend this to full unification?
                &&& program.only_unifiable_with_base(
                    args[0],
                )
                // First filter rules to those that match the predicate
                // then check that each filtered rule has the correct proof
                &&& filter_map(
                    program.rules,
                    |rule: SpecRule|
                        {
                            if let Some(subst) = args[0].matches(rule.head) {
                                Some(args[1].subst(subst))
                            } else {
                                None
                            }
                        },
                ) =~= subproofs.map_values(|thm: SpecTheorem| thm.stmt)
            },
            // Specifications for built-in functions
            SpecProof::BuiltIn => {
                ||| {
                    &&& self.stmt.headed_by(FN_NAME_EQ, 2) matches Some(args)
                    &&& args[0] == args[1]
                }
                ||| {
                    &&& self.stmt.headed_by(FN_NAME_EQUIV, 2) matches Some(args)
                    &&& args[0] == args[1]
                }
                ||| {
                    &&& self.stmt.headed_by(FN_NAME_NOT_EQ, 2) matches Some(args)
                    &&& args[0].not_unifiable(args[1])
                }
                ||| {
                    &&& self.stmt.headed_by(FN_NAME_NOT_EQUIV, 2) matches Some(args)
                    &&& args[0] != args[1]
                }
                ||| {
                    &&& self.stmt.headed_by(FN_NAME_LENGTH, 2) matches Some(args)
                    &&& args[0].as_list() matches Some(list)
                    &&& args[1] matches SpecTerm::Literal(SpecLiteral::Int(len))
                    &&& list.len() == len
                }
                ||| {
                    &&& self.stmt.headed_by(FN_NAME_MEMBER, 2) matches Some(args)
                    &&& args[1].as_list() matches Some(list)
                    &&& list.contains(args[0])
                }
                ||| {
                    // Base case for negation
                    // If the term is not unifiable with any rule head
                    // then the negation of the term holds
                    &&& self.stmt.headed_by(FN_NAME_NOT, 1) matches Some(
                        args,
                    )
                    // NOTE: this might be innefficient to check if implemented naively
                    // TODO: if self.stmt is headed by a built-in, this might introduce
                    // unsoundness
                    &&& forall|i|
                        0 <= i < program.rules.len() ==> (
                        #[trigger] program.rules[i]).head.not_unifiable(args[0])
                }
                ||| {
                    // A special case of findall where the goal is a base predicate
                    // see https://www.swi-prolog.org/pldoc/man?predicate=findall/3
                    &&& self.stmt.headed_by(FN_NAME_FINDALL, 3) matches Some(
                        args,
                    )
                    // The third argument is a concrete list
                    &&& args[2].as_list() matches Some(
                        list,
                    )
                    // Same constraint as in ForallBase
                    &&& program.only_unifiable_with_base(args[1])
                    &&& filter_map(
                        program.rules,
                        |rule: SpecRule|
                            {
                                // Match args[1] first, then use the substitution
                                // to instantiate args[0]
                                if let Some(subst) = args[1].matches(rule.head) {
                                    Some(args[0].subst(subst))
                                } else {
                                    None
                                }
                            },
                    ) =~= list
                }
                ||| {
                    &&& self.stmt.headed_by(FN_NAME_GT, 2) matches Some(args)
                    &&& args[0].eval_arith() matches Some(lhs)
                    &&& args[1].eval_arith() matches Some(rhs)
                    &&& lhs > rhs
                }
                ||| {
                    &&& self.stmt.headed_by(FN_NAME_GE, 2) matches Some(args)
                    &&& args[0].eval_arith() matches Some(lhs)
                    &&& args[1].eval_arith() matches Some(rhs)
                    &&& lhs >= rhs
                }
                ||| {
                    &&& self.stmt.headed_by(FN_NAME_LT, 2) matches Some(args)
                    &&& args[0].eval_arith() matches Some(lhs)
                    &&& args[1].eval_arith() matches Some(rhs)
                    &&& lhs < rhs
                }
                ||| {
                    &&& self.stmt.headed_by(FN_NAME_LE, 2) matches Some(args)
                    &&& args[0].eval_arith() matches Some(lhs)
                    &&& args[1].eval_arith() matches Some(rhs)
                    &&& lhs <= rhs
                }
                ||| {
                    // is/2 only evaluates the RHS
                    &&& self.stmt.headed_by(FN_NAME_IS, 2) matches Some(args)
                    &&& args[1].eval_arith() matches Some(rhs)
                    &&& args[0] == SpecTerm::Literal(SpecLiteral::Int(rhs))
                }
                ||| {
                    &&& self.stmt.headed_by(FN_NAME_EVAL_EQ, 2) matches Some(args)
                    &&& args[0].eval_arith() matches Some(lhs)
                    &&& args[1].eval_arith() matches Some(rhs)
                    &&& lhs == rhs
                }
                ||| {
                    &&& self.stmt.headed_by(FN_NAME_EVAL_NOT_EQ, 2) matches Some(args)
                    &&& args[0].eval_arith() matches Some(lhs)
                    &&& args[1].eval_arith() matches Some(rhs)
                    &&& lhs != rhs
                }
                ||| {
                    &&& self.stmt.headed_by(FN_NAME_ATOM_STRING, 2) matches Some(args)
                    &&& args[0] matches SpecTerm::Literal(SpecLiteral::Atom(atom))
                    &&& args[1] matches SpecTerm::Literal(SpecLiteral::String(string))
                    &&& atom == string
                }
                ||| {
                    &&& self.stmt.headed_by(FN_NAME_STRING_CHARS, 2) matches Some(args)
                    &&& args[0] matches SpecTerm::Literal(SpecLiteral::String(string))
                    &&& args[1].as_list() matches Some(chars)
                    &&& string.len() == chars.len()
                    &&& forall|i|
                        0 <= i < string.len() ==> #[trigger] chars[i] == SpecTerm::Literal(
                            SpecLiteral::Atom(seq![string[i]]),
                        )
                }
                ||| {
                    &&& self.stmt.headed_by(FN_NAME_SUB_STRING, 5) matches Some(args)
                    &&& args[0] matches SpecTerm::Literal(SpecLiteral::String(string))
                    &&& args[1] matches SpecTerm::Literal(SpecLiteral::Int(before))
                    &&& args[2] matches SpecTerm::Literal(SpecLiteral::Int(len))
                    &&& args[3] matches SpecTerm::Literal(SpecLiteral::Int(after))
                    &&& args[4] matches SpecTerm::Literal(SpecLiteral::String(substring))
                    &&& before >= 0 && len >= 0 && after >= 0
                    &&& string.len() == before + len + after
                    &&& substring.len() == len
                    &&& string.skip(before).take(len) =~= substring
                }
                ||| {
                    &&& self.stmt.headed_by(FN_NAME_REVERSE, 2) matches Some(args)
                    &&& args[0].as_list() matches Some(list)
                    &&& args[1].as_list() matches Some(reverse)
                    &&& list.reverse() =~= reverse
                }
                ||| {
                    &&& self.stmt.headed_by(FN_NAME_SPLIT_STRING, 4) matches Some(args)
                    &&& args[0] matches SpecTerm::Literal(SpecLiteral::String(string))
                    &&& args[1] matches SpecTerm::Literal(SpecLiteral::String(separator))
                    &&& args[2] matches SpecTerm::Literal(SpecLiteral::String(padding))
                    &&& args[3].as_list() matches Some(
                        results,
                    )
                    // TODO: right now we only support the special case where the padding is empty
                    // and the separator is a single character
                    //
                    // See https://www.swi-prolog.org/pldoc/man?predicate=split_string/4 for the general case
                    &&& separator.len() == 1
                    &&& padding.len() == 0
                    &&& (forall|i|
                        0 <= i < results.len() ==> #[trigger] results[i] matches SpecTerm::Literal(
                            SpecLiteral::String(_),
                        ))
                    &&& seq_join(
                        Seq::new(results.len(), |i| results[i]->Literal_0->String_0),
                        separator,
                    ) =~= string
                }
                // TODO: nonvar and var are a bit sketchy.
                // Are they semantically well-behaved?
                ||| {
                    &&& self.stmt.headed_by(FN_NAME_NONVAR, 1) matches Some(args)
                    &&& !(args[0] matches SpecTerm::Var(..))
                }
                ||| {
                    &&& self.stmt.headed_by(FN_NAME_VAR, 1) matches Some(args)
                    &&& args[0] matches SpecTerm::Var(..)
                }
                // nth1 starts from index 1
                ||| {
                    &&& self.stmt.headed_by(FN_NAME_NTH1, 3) matches Some(args)
                    &&& args[0] matches SpecTerm::Literal(SpecLiteral::Int(index))
                    &&& args[1].as_list() matches Some(list)
                    &&& 1 <= index && index <= list.len()
                    &&& list[index - 1] == args[2]
                }
                ||| {
                    &&& self.stmt.headed_by(FN_NAME_STRING_LENGTH, 2) matches Some(args)
                    &&& args[0] matches SpecTerm::Literal(SpecLiteral::String(string))
                    &&& args[1] matches SpecTerm::Literal(SpecLiteral::Int(len))
                    &&& string.len() == len
                }
                ||| {
                    &&& self.stmt.headed_by(FN_NAME_APPEND, 3) matches Some(args)
                    &&& args[0].as_list() matches Some(list1)
                    &&& args[1].as_list() matches Some(list2)
                    &&& args[2].as_list() matches Some(list3)
                    &&& list1 + list2 =~= list3
                }
            },
        }
    }
}

pub broadcast proof fn lemma_spec_term_ext_equal_deep(t1: SpecTerm, t2: SpecTerm)
    ensures
        #[trigger] ext_equal_deep(t1, t2) <==> match (t1, t2) {
            (SpecTerm::Var(v1), SpecTerm::Var(v2)) => v1 =~~= v2,
            (SpecTerm::Literal(l1), SpecTerm::Literal(l2)) => l1 =~~= l2,
            (SpecTerm::App(f1, args1), SpecTerm::App(f2, args2)) => f1 =~~= f2 && args1 =~~= args2,
            _ => false,
        },
{}

pub broadcast proof fn lemma_spec_rule_ext_equal_deep(r1: SpecRule, r2: SpecRule)
    ensures
        #[trigger] ext_equal_deep(r1, r2) <==> r1.head =~~= r2.head && r1.body =~~= r2.body,
{}

pub broadcast proof fn lemma_spec_literal_ext_equal_deep(l1: SpecLiteral, l2: SpecLiteral)
    ensures
        #[trigger] ext_equal_deep(l1, l2) <==> match (l1, l2) {
            (SpecLiteral::Int(i1), SpecLiteral::Int(i2)) => i1 == i2,
            (SpecLiteral::String(s1), SpecLiteral::String(s2)) => s1 =~~= s2,
            (SpecLiteral::Atom(a1), SpecLiteral::Atom(a2)) => a1 =~~= a2,
            (SpecLiteral::Directive, SpecLiteral::Directive) => true,
            _ => false,
        },
{}

pub broadcast proof fn lemma_spec_fn_name_ext_equal_deep(f1: SpecFnName, f2: SpecFnName)
    ensures
        #[trigger] ext_equal_deep(f1, f2) <==> match (f1, f2) {
            (SpecFnName::User(n1, a1), SpecFnName::User(n2, a2)) => n1 =~~= n2 && a1 == a2,
            (SpecFnName::Nil, SpecFnName::Nil) => true,
            (SpecFnName::Cons, SpecFnName::Cons) => true,
            _ => false,
        },
{}

pub broadcast proof fn lemma_spec_program_ext_equal_deep(p1: SpecProgram, p2: SpecProgram)
    ensures
        #[trigger] ext_equal_deep(p1, p2) <==> p1.rules =~~= p2.rules,
{}

/// Extensional equalities for terms, rules, etc.
pub broadcast group lemma_ext_equal_deep {
    lemma_spec_term_ext_equal_deep,
    lemma_spec_rule_ext_equal_deep,
    lemma_spec_literal_ext_equal_deep,
    lemma_spec_fn_name_ext_equal_deep,
    lemma_spec_program_ext_equal_deep,
}

} // verus!
