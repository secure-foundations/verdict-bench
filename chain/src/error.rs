use vstd::prelude::*;
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
}

}
