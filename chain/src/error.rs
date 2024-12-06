use vstd::prelude::*;
use parser::ParseError;
use crate::policy::ExecPolicyError;

verus! {

#[derive(Debug)]
pub enum ValidationError {
    IntegerOverflow,
    EmptyChain,
    ProofFailure,
    TimeParseError,
    RSAPubKeyParseError,
    UnexpectedExtParam,
    PolicyError(ExecPolicyError),
    ParseError(ParseError),
}

impl From<ParseError> for ValidationError {
    fn from(err: ParseError) -> Self {
        ValidationError::ParseError(err)
    }
}

}
