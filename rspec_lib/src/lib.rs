use vstd::prelude::*;

verus! {

/// Use this type to tell rspec to generate
/// String as exec impl instead of Vec<char>
pub type SpecString = Seq<char>;

pub struct RSpec;

/// Verus doesn't support exec mode equalities between certain types
/// so we implement our own versions
pub trait Eq<A: DeepView, B: DeepView<V = A::V>> {
    fn eq(a: A, b: B) -> (res: bool)
        ensures res == (a.deep_view() == b.deep_view());
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

impl<T: Copy + PartialEq + DeepView> Eq<T, T> for RSpec {
    #[verifier::external_body]
    fn eq(a: T, b: T) -> (res: bool) {
        a == b
    }
}

impl<'a, T: Copy + PartialEq + DeepView> Eq<&'a T, T> for RSpec {
    #[verifier::external_body]
    fn eq(a: &'a T, b: T) -> (res: bool) {
        *a == b
    }
}

impl<'b, T: Copy + PartialEq + DeepView> Eq<T, &'b T> for RSpec {
    #[verifier::external_body]
    fn eq(a: T, b: &'b T) -> (res: bool) {
        a == *b
    }
}

/// An index trait for both Vec and String
/// ExecT and SpecT are separated to support both returning a reference
/// and returning a Copy value (e.g. String => char)
pub trait Index<E: DeepView>: DeepView<V = Seq<E::V>> {
    fn rspec_index(&self, i: usize) -> (res: &E)
        requires i < self.deep_view().len()
        ensures res.deep_view() == self.deep_view()[i as int];
}

impl<E: DeepView> Index<E> for Vec<E> {
    fn rspec_index(&self, i: usize) -> (res: &E) {
        &self[i]
    }
}

pub trait SpecCharAt {
    spec fn char_at(&self, i: int) -> char;
}

impl SpecCharAt for SpecString {
    open spec fn char_at(&self, i: int) -> char {
        self[i]
    }
}

pub trait CharAt: DeepView<V = Seq<char>> {
    fn rspec_char_at(&self, i: usize) -> (res: char)
        requires i < self.deep_view().len()
        ensures res == self.deep_view()[i as int];
}

impl CharAt for String {
    fn rspec_char_at(&self, i: usize) -> (res: char) {
        self.as_str().get_char(i)
    }
}

impl CharAt for str {
    fn rspec_char_at(&self, i: usize) -> (res: char) {
        self.get_char(i)
    }
}

/// Length method for both Vec and String
pub trait Len<E: DeepView>: DeepView<V = Seq<E::V>> {
    fn rspec_len(&self) -> (res: usize)
        ensures res == self.deep_view().len();
}

impl<E: DeepView> Len<E> for Vec<E> {
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
