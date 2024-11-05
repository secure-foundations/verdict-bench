use vstd::prelude::*;

verus! {

/// Use this type to tell rspec to generate
/// String as exec impl instead of Vec<char>
pub type SpecString = Seq<char>;

pub struct RSpec;

/// Verus doesn't support exec mode equalities between certain types
/// so we implement our own versions
pub trait Eq<A: View, B: View<V = A::V>> {
    fn eq(a: A, b: B) -> (res: bool)
        ensures res == (a@ == b@);
}

impl<'a, 'b> Eq<&'a String, &'b str> for RSpec {
    #[verifier::external_body]
    fn eq(a: &'a String, b: &'b str) -> (res: bool) {
        a == b
    }
}

impl<'a, 'b> Eq<&'a str, &'b String> for RSpec {
    #[verifier::external_body]
    fn eq(a: &'a str, b: &'b String) -> (res: bool) {
        a == b
    }
}

impl<T: Copy + PartialEq + View> Eq<T, T> for RSpec {
    #[verifier::external_body]
    fn eq(a: T, b: T) -> (res: bool) {
        a == b
    }
}

impl<'a, T: Copy + PartialEq + View> Eq<&'a T, T> for RSpec {
    #[verifier::external_body]
    fn eq(a: &'a T, b: T) -> (res: bool) {
        *a == b
    }
}

impl<'b, T: Copy + PartialEq + View> Eq<T, &'b T> for RSpec {
    #[verifier::external_body]
    fn eq(a: T, b: &'b T) -> (res: bool) {
        a == *b
    }
}

/// At the spec level, we allow more conversions such as &T -> T
pub trait SpecFrom<T>: Sized {
    spec fn from(t: T) -> (res: Self);
}

impl<'a, T> SpecFrom<&'a T> for T {
    open spec fn from(t: &'a T) -> T { *t }
}

impl<T> SpecFrom<T> for T {
    open spec fn from(t: T) -> T { t }
}

/// An index trait for both Vec and String
/// ExecT and SpecT are separated to support both returning a reference
/// and returning a Copy value (e.g. String => char)
pub trait Index<ExecT, SpecT: SpecFrom<ExecT>>: View<V = Seq<SpecT>> {
    fn rspec_index(&self, i: usize) -> (res: ExecT)
        requires i < self@.len()
        ensures SpecT::from(res) == self@[i as int];
}

/// NODE/TODO: this behaves differently than the native index
/// The reason is that String indexing behaves differently
/// than in Rust: we directly index into the Unicode char
/// instead of bytes
impl<'a: 'b, 'b, E> Index<&'b E, E> for &'a Vec<E>
{
    fn rspec_index(&self, i: usize) -> (res: &'b E) {
        &self[i]
    }
}

impl<E: Copy> Index<E, E> for Vec<E>
{
    fn rspec_index(&self, i: usize) -> (res: E) {
        self[i]
    }
}

impl Index<char, char> for String {
    fn rspec_index(&self, i: usize) -> (res: char) {
        self.as_str().get_char(i)
    }
}

impl Index<char, char> for str {
    fn rspec_index(&self, i: usize) -> (res: char) {
        self.get_char(i)
    }
}

/// Length method for both Vec and String
pub trait Len<E>: View<V = Seq<E>> {
    fn rspec_len(&self) -> (res: usize)
        ensures res == self@.len();
}

impl<E> Len<E> for Vec<E> {
    fn rspec_len(&self) -> (res: usize) {
        self.len()
    }
}

impl Len<char> for String {
    fn rspec_len(&self) -> (res: usize) {
        self.as_str().unicode_len()
    }
}

}
