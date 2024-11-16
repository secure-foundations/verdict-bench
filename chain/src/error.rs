use vstd::prelude::*;

verus! {

#[derive(Debug)]
pub enum ValidationError {
    IntegerOverflow,
    EmptyChain,
    ProofFailure,
    TimeParseError,
    RSAPubKeyParseError,
    UnexpectedExtParam,
    UnsupportedTask,
}

}
