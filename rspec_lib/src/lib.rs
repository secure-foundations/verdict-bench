use vstd::prelude::*;

verus! {

/// Use this type to tell rspec to generate
/// String as exec impl instead of Vec<char>
pub type SpecString = Seq<char>;

pub struct RSpec;

/// Verus doesn't support exec mode equalities between certain types
/// so we implement our own versions
pub trait BinOpEq<A: ?Sized + View, B: ?Sized + View<V = A::V>> {
    fn eq(a: &A, b: &B) -> (res: bool)
        ensures res == (a@ == b@);
}

impl<'a, 'b> BinOpEq<&'a str, &'b str> for RSpec {
    #[verifier::external_body]
    fn eq(a: &&'a str, b: &&'b str) -> (res: bool)
    {
        a == b
    }
}

impl<'a, 'b> BinOpEq<&'a String, &'b str> for RSpec {
    #[verifier::external_body]
    fn eq(a: &&'a String, b: &&'b str) -> (res: bool)
    {
        a == b
    }
}

impl BinOpEq<u32, u32> for RSpec {
    fn eq(a: &u32, b: &u32) -> (res: bool)
    {
        a == b
    }
}

pub fn eq<A: View, B: View<V = A::V>>(a: A, b: B) -> (res: bool)
    where RSpec: BinOpEq<A, B>
    ensures res == (a@ == b@)
{
    RSpec::eq(&a, &b)
}

}
