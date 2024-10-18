use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Arc;

use peg;

use crate::checker::*;
use crate::proof::*;
use crate::trace::*;

/// e.g. edge(_, _) => edge(%1, %2)
/// when displaying, all variables starting with % is replaced with _
pub const ANON_VAR_PREFIX: &'static str = "%";

struct ParserState<'a> {
    source: &'a str,
    anon_var_counter: Cell<usize>,
}

impl ParserState<'_> {
    fn new(source: &str) -> ParserState {
        ParserState {
            source,
            anon_var_counter: Cell::new(0),
        }
    }

    fn fresh_anon_var(&self) -> String {
        let counter = self.anon_var_counter.get();
        self.anon_var_counter.set(counter + 1);
        format!("{}{}", ANON_VAR_PREFIX, counter)
    }
}

enum UnescapeState {
    Normal,
    Escape,
}

/// Unescape a string
/// e.g. "\\n" => "\n"
/// Incomplete, see https://www.swi-prolog.org/pldoc/man?section=charescapes
/// TODO: verify
pub fn unescape_string(s: &str) -> String {
    let mut res = String::new();
    let mut state = UnescapeState::Normal;

    for c in s.chars() {
        match state {
            UnescapeState::Normal => {
                if c == '\\' {
                    state = UnescapeState::Escape;
                } else {
                    res.push(c);
                }
            }
            UnescapeState::Escape => {
                match c {
                    'n' => res.push('\n'),
                    'r' => res.push('\r'),
                    't' => res.push('\t'),
                    _ => res.push(c),
                }
                state = UnescapeState::Normal;
            }
        }
    }

    res
}

/// Escape a string for printing
/// e.g. "\n" => "\\n"
/// Quotes are not included in the result
/// but if a character matches the quote,
/// it will be escaped
/// TODO: verify
pub fn escape_string(s: &str, quote: char) -> String {
    let mut res = String::new();
    for c in s.chars() {
        match c {
            '\n' => res.push_str("\\n"),
            '\r' => res.push_str("\\r"),
            '\t' => res.push_str("\\t"),
            '\\' => res.push_str("\\\\"),
            _ => {
                if c == quote {
                    res.push('\\');
                    res.push(c);
                } else {
                    res.push(c)
                }
            }
        }
    }
    res
}

// Grammar of Prolog
peg::parser!(grammar prolog(state: &ParserState) for str {
    rule ignore()
        // whitespaces
        = quiet!{[' ' | '\t' | '\r' | '\n']}
        // Inline comments
        / "%" [^'\n']*
        / "#!" [^'\n']*

    rule _ = ignore()*

    /// Comma separated list without extra trailing comma
    rule comma_sep<T>(x: rule<T>) -> Vec<T> = v:(x() ** (_ "," _)) { v }

    /// Same as comma_sep, but requires at least one element
    rule comma_sep_plus<T>(x: rule<T>) -> Vec<T> = v:(x() ++ (_ "," _)) { v }

    /// Escape quotes
    rule ident_char() = "\\'" / [^'\'']
    rule string_char() = "\\\"" / [^'"']

    rule ident() -> UserFnName
        = name:quiet!{$(['a'..='z']['_' | ':' | 'a'..='z' | 'A'..='Z' | '0'..='9']*)} { name.into() }
        / "'" name:$(ident_char()*) "'" { unescape_string(name).into() }
        / expected!("identifier")

    /// Operators
    rule op() -> &'input str
        = name:$[ '*' | '-' | '+' | ';' ] { name }
        / name:$"\\+" { name }
        / name:$"=:=" { name }
        / name:$"=\\=" { name }
        / name:$"\\==" { name }
        / name:$"\\=" { name }
        / name:$"==" { name }
        / name:$">=" { name }
        / name:$">" { name }
        / name:$"<" { name }
        / name:$"=<" { name }
        / name:$"=" { name }

    /// Allow operators to be identifiers
    rule canon_ident() -> UserFnName
        = op:op() { op.into() }
        / ident()

    rule var() -> &'input str
        = name:quiet!{$(['A'..='Z' | '_']['_' | 'a'..='z' | 'A'..='Z' | '0'..='9']*)} { name }
        / expected!("variable")

    rule nat() -> usize
        = n:quiet!{$(['0'..='9']+)} {? n.parse().map_err(|_| "failed to parse nat") }
        / expected!("nat")

    rule int() -> i64
        = n:quiet!{$("-"?['0'..='9']+)} {? n.parse().map_err(|_| "failed to parse int") }
        / expected!("int")

    /// TODO: handle escape strings and newlines
    /// also see https://www.swi-prolog.org/pldoc/man?section=charescapes
    rule string() -> LiteralString
        = "\"" s:$(string_char()*) "\"" { unescape_string(s).into() }
        / expected!("string")

    /// Prolog lists, e.g., [], [a,b|[]], [a,b,c]
    rule list(t: rule<Term>) -> Term
        = "[" _ "]" { Arc::new(TermX::App(FnName::Nil, vec![])) }
        / "[" _ elems:comma_sep_plus(<t()>) _ "]"
            {
                let mut list = Arc::new(TermX::App(FnName::Nil, vec![]));
                for elem in elems.into_iter().rev() {
                    list = Arc::new(TermX::App(FnName::Cons, vec![elem, list]));
                }
                list
            }
        / "[" _ heads:comma_sep_plus(<t()>) _ "|" _ tail:t() _ "]"
            {
                let mut list = tail;
                for head in heads.into_iter().rev() {
                    list = Arc::new(TermX::App(FnName::Cons, vec![head, list]));
                }
                list
            }

    /// Prolog terms
    /// See https://www.swi-prolog.org/pldoc/man?section=operators
    /// for default precedence of operators
    ///
    /// See https://docs.rs/peg/latest/peg/ for precedence!
    pub rule term() -> Term = precedence! {
        t1:@ _ ";" _ t2:(@) { Arc::new(TermX::App(FnName::user(FN_NAME_OR, 2), vec![t1, t2])) }
        --
        t1:@ _ "," _ t2:(@) { Arc::new(TermX::App(FnName::user(FN_NAME_AND, 2), vec![t1, t2])) }
        --
        t:small_term() { t }
    }

    /// Terms without comma or disjunction
    /// This is to avoid [a, b, c] being parsed as a singleton list of conjunction (a, b, c)
    ///
    /// TODO: Prolog syntax is weird.
    /// For example, disjunction (;/2) has lower precedence than conjunction (,/2).
    /// However, we have
    /// - Illegal: [a|b,c]
    /// - Legal: [a|(b;c)]
    /// - Legal: [a|(b,c)]
    pub rule small_term() -> Term = precedence! {
        "\\+" _ t:@ { Arc::new(TermX::App(FnName::user(FN_NAME_NOT, 1), vec![t])) }
        --
        t1:@ _ "=" _ t2:(@) { Arc::new(TermX::App(FnName::user(FN_NAME_EQ, 2), vec![t1, t2])) }
        t1:@ _ "\\=" _ t2:(@) { Arc::new(TermX::App(FnName::user(FN_NAME_NOT_EQ, 2), vec![t1, t2])) }
        t1:@ _ "==" _ t2:(@) { Arc::new(TermX::App(FnName::user(FN_NAME_EQUIV, 2), vec![t1, t2])) }
        t1:@ _ "\\==" _ t2:(@) { Arc::new(TermX::App(FnName::user(FN_NAME_NOT_EQUIV, 2), vec![t1, t2])) }

        t1:@ _ ">" _ t2:(@) { Arc::new(TermX::App(FnName::user(FN_NAME_GT, 2), vec![t1, t2])) }
        t1:@ _ ">=" _ t2:(@) { Arc::new(TermX::App(FnName::user(FN_NAME_GE, 2), vec![t1, t2])) }
        t1:@ _ "<" _ t2:(@) { Arc::new(TermX::App(FnName::user(FN_NAME_LT, 2), vec![t1, t2])) }
        t1:@ _ "=<" _ t2:(@) { Arc::new(TermX::App(FnName::user(FN_NAME_LE, 2), vec![t1, t2])) }
        t1:@ _ "is" _ t2:(@) { Arc::new(TermX::App(FnName::user(FN_NAME_IS, 2), vec![t1, t2])) }
        t1:@ _ "=:=" _ t2:(@) { Arc::new(TermX::App(FnName::user(FN_NAME_EVAL_EQ, 2), vec![t1, t2])) }
        t1:@ _ "=\\=" _ t2:(@) { Arc::new(TermX::App(FnName::user(FN_NAME_EVAL_NOT_EQ, 2), vec![t1, t2])) }
        --
        t1:(@) _ "+" _ t2:@ { Arc::new(TermX::App(FnName::user(FN_NAME_ADD, 2), vec![t1, t2])) }
        t1:(@) _ "-" _ t2:@ { Arc::new(TermX::App(FnName::user(FN_NAME_SUB, 2), vec![t1, t2])) }
        --
        t1:(@) _ "*" _ t2:@ { Arc::new(TermX::App(FnName::user(FN_NAME_MUL, 2), vec![t1, t2])) }
        t1:(@) _ "/" _ t2:@ { Arc::new(TermX::App(FnName::user(FN_NAME_PRED_IND, 2), vec![t1, t2])) }
        --

        t:base_term(<ident()>, <small_term()>, <term()>) { t }
    }

    rule app_args(term: rule<Term>) -> Vec<Term>
        = _ "(" _ args:comma_sep(<term()>) _ ")" { args }

    /// Base term without operators parametric to
    /// - id: allowed identifiers
    /// - term_wo_comma: term without comma
    /// - any_term: any term
    rule base_term(id: rule<UserFnName>, term_wo_comma: rule<Term>, any_term: rule<Term>) -> Term
        = "(" _ t:any_term() _ ")" { t }

        // Applications or atoms
        / name:id() args:app_args(<term_wo_comma()>)? {
            match args {
                Some(args) => Arc::new(TermX::App(FnName::User(name, args.len()), args)),
                None => Arc::new(TermX::Literal(Literal::Atom(name))),
            }
        }

        / var:var() {
            if var == "_" {
                // There is a special case of the anonymous variable "_"
                // different occurrences of "_" in a clause is considered different variables
                // so we need to generate fresh names for them
                TermX::var_str(&state.fresh_anon_var())
            } else {
                TermX::var_str(var)
            }
        }

        // Literals
        / i:int() { Arc::new(TermX::Literal(Literal::Int(i))) }
        / s:string() { Arc::new(TermX::Literal(Literal::String(s))) }

        // Lists
        / list:list(<term_wo_comma()>) { list }

    /// A special rule to parse terms output by write_canonical/1 in Prolog
    pub rule canon_term() -> Term = base_term(<canon_ident()>, <canon_term()>, <canon_term()>)

    pub rule clause() -> (Rule, usize)
        = pos:position!() head:term() _ "."
            { (RuleX::new(head, vec![]), pos) }

        // Conjunction as a binary operator
        / pos:position!() head:term() _ ":-" _ body:term() _ "."
            { (RuleX::new(head, vec![body]), pos) }

        // Headless clauses are converted into `true :- ... .`
        / pos:position!() ":-" _ body:term() _ "."
            {
                let head = Arc::new(TermX::Literal(Literal::Directive));
                (RuleX::new(head, vec![body]), pos)
            }

    /// Returns a program and a map from line number to rule id
    pub rule program() -> (Program, HashMap<usize, RuleId>)
        = _ rules:(clause() ** _) _ {
            let mut program_rules = vec![];
            let mut line_map = HashMap::new();

            let mut last_pos = 0;
            let mut num_lines = 1; // 1 + number of newline symbols in &source[0..last_pos]

            for (i, (rule, pos)) in rules.into_iter().enumerate() {
                // Convert position to line number
                assert!(pos >= last_pos);

                // Need to count how many newline symbols
                // there are in [last_pos, pos)
                let new_lines = state.source[last_pos..pos]
                    .chars().filter(|c| *c == '\n').count();

                last_pos = pos;
                num_lines += new_lines;

                program_rules.push(rule);
                line_map.insert(num_lines, i);
            }

            (Program::new(program_rules), line_map)
        }

    /// Parser of a trace event
    pub rule event(line_map: &HashMap<usize, RuleId>) -> Event
        = _ id:nat() _ "." _ term:canon_term() _ "by" _ tactic:tactic(line_map) _
            { Event { id, term: term, tactic: tactic } }

    rule nested_nat_list() -> Vec<usize>
        = v:nat() { vec![v] }
        / "[" _ l:(nested_nat_list() ** (_ "," _)) _ "]" { l.into_iter().flatten().collect() }

    /// Read a line number, and convert it to a rule id
    /// using the line_map; fails if no entry found in line_map
    rule rule_id(line_map: &HashMap<usize, RuleId>) -> RuleId
        = rule_line:nat() {?
            line_map.get(&rule_line).cloned()
                .ok_or("failed to find rule by the line number")
        }

    rule tactic(line_map: &HashMap<usize, RuleId>) -> Tactic
        = "fact" _ "(" _ id:rule_id(&line_map) _ ")"
            { Tactic::Apply { rule_id: id, subproof_ids: vec![] } }
        / "apply" _ "(" _ subgoals:nested_nat_list() _ "," _ id:rule_id(&line_map) _ ")"
            { Tactic::Apply { rule_id: id, subproof_ids: subgoals } }
        / "true"
            { Tactic::TrueIntro }
        / "and" _ "(" _ left:nat() _ "," _ right:nat() _ ")"
            { Tactic::AndIntro(left, right) }
        / "or-left" _ "(" _ left:nat() _ ")"
            { Tactic::OrIntroLeft(left) }
        / "or-right" _ "(" _ right:nat() _ ")"
            { Tactic::OrIntroRight(right) }
        / "forall-member" _ "(" _ subproofs:nested_nat_list() _ ")"
            { Tactic::ForallMember(subproofs) }
        / "forall-base" _ "(" _ subproofs:nested_nat_list() _ ")"
            { Tactic::ForallBase(subproofs) }
        / "built-in" { Tactic::BuiltIn }
});

/// First argument is the path
#[derive(Debug)]
pub struct ParseError(
    pub Option<String>,
    pub peg::error::ParseError<peg::str::LineCol>,
);

/// Parse a Prolog program source
/// Returns a program and a map from line numbers to rule ids
pub fn parse_program(
    source: impl AsRef<str>,
    path: impl AsRef<str>,
) -> Result<(Program, HashMap<usize, RuleId>), ParseError> {
    let state = ParserState::new(source.as_ref());
    prolog::program(source.as_ref(), &state)
        .map_err(|e| ParseError(Some(path.as_ref().to_string()), e))
}

/// Parse a Prolog term
pub fn parse_term(source: impl AsRef<str>) -> Result<Term, ParseError> {
    let state = ParserState::new(source.as_ref());
    prolog::term(source.as_ref(), &state).map_err(|e| ParseError(None, e))
}

/// Parse a trace event
pub fn parse_trace_event(
    source: impl AsRef<str>,
    line_map: &HashMap<usize, RuleId>,
) -> Result<Event, ParseError> {
    let state = ParserState::new(source.as_ref());
    prolog::event(source.as_ref(), &state, &line_map).map_err(|e| ParseError(None, e))
}

pub fn test() {
    let (program, line_map) = parse_program(
        r#"
node(n0).
node(n1).
node(n2).
node(n3).
edge(n1, n3).
edge(n1, n2).
edge(n0, n1).
source(n0).
destination(n3).
connected(A, B) :- edge(A, B).
connected(A, B) :- edge(A, M), connected(M, B).
query(S, D) :- source(S), destination(D), connected(S, D).
go :- query(n0, n3).
"#,
        "test.pl",
    )
    .unwrap();

    println!("program: {:?}", program);
    println!("line_map: {:?}", line_map);
}
