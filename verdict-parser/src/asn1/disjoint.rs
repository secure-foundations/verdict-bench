/// Some SpecDisjointFrom and DisjointFrom impls for tagged combinators

use vstd::prelude::*;
use super::*;

verus! {

/// If T1 and T2 have different tags, then their tagged encodings are disjoint
impl<T1, T2> DisjointFrom<ASN1<T1>> for ASN1<T2> where
    T1: ASN1Tagged + SpecCombinator,
    T2: ASN1Tagged + SpecCombinator,
{
    open spec fn disjoint_from(&self, other: &ASN1<T1>) -> bool {
        self.0.spec_tag() != other.0.spec_tag()
    }

    proof fn parse_disjoint_on(&self, other: &ASN1<T1>, buf: Seq<u8>) {}
}

/// If T1 and T2 have different tags, then (T1, ...) is disjoint from T2
impl<T1, T2, S> DisjointFrom<(ASN1<T1>, S)> for ASN1<T2> where
    T1: ASN1Tagged + SpecCombinator + SecureSpecCombinator,
    T2: ASN1Tagged + SpecCombinator,
    S: SpecCombinator,
{
    open spec fn disjoint_from(&self, other: &(ASN1<T1>, S)) -> bool {
        self.0.spec_tag() != other.0.0.spec_tag()
    }

    proof fn parse_disjoint_on(&self, other: &(ASN1<T1>, S), buf: Seq<u8>) {}
}

// NOTE: We can't do impl<T1, T2, S> SpecDisjointFrom<ASN1<T2>> for (ASN1<T1>, S) since
// both SpecDisjointFrom and tuple type is not defined in this crate
// For this purpose, use Pair instead of the native tuple type

/// Same as above, but uses a custom
impl<T1, T2, S> DisjointFrom<Pair<ASN1<T1>, S>> for ASN1<T2> where
    T1: ASN1Tagged + SecureSpecCombinator,
    T2: ASN1Tagged + SecureSpecCombinator,
    S: SecureSpecCombinator,
{
    open spec fn disjoint_from(&self, other: &Pair<ASN1<T1>, S>) -> bool {
        self.0.spec_tag() != other.0.0.spec_tag()
    }

    proof fn parse_disjoint_on(&self, other: &Pair<ASN1<T1>, S>, buf: Seq<u8>) {}
}

/// The other direction of the above
impl<T1, T2, S> DisjointFrom<ASN1<T2>> for Pair<ASN1<T1>, S> where
    T1: ASN1Tagged + SecureSpecCombinator,
    T2: ASN1Tagged + SecureSpecCombinator,
    S: SecureSpecCombinator,
{
    open spec fn disjoint_from(&self, other: &ASN1<T2>) -> bool {
        other.0.spec_tag() != self.0.0.spec_tag()
    }

    proof fn parse_disjoint_on(&self, other: &ASN1<T2>, buf: Seq<u8>) {}
}

/// If T2 and T3 are both disjoint from T1, then
/// something like Optional<T1, Optional<T2, T3>> is doable
impl<T1, T2, T3> DisjointFrom<T1> for Optional<T2, T3> where
    T1: SecureSpecCombinator,
    T2: SecureSpecCombinator,
    T3: SecureSpecCombinator,
    T2: DisjointFrom<T1>,
    T3: DisjointFrom<T1>,
    T3: DisjointFrom<T2>,
{
    open spec fn disjoint_from(&self, other: &T1) -> bool {
        self.0.disjoint_from(other) &&
        self.1.disjoint_from(other)
    }

    proof fn parse_disjoint_on(&self, other: &T1, buf: Seq<u8>) {
        self.0.parse_disjoint_on(other, buf);
        self.1.parse_disjoint_on(other, buf);
    }
}

/// Similar to Optional
impl<T1, T2, T3> DisjointFrom<T1> for Default<T2::SpecResult, T2, T3> where
    T1: SecureSpecCombinator,
    T2: SecureSpecCombinator,
    T3: SecureSpecCombinator,
    T2: DisjointFrom<T1>,
    T3: DisjointFrom<T1>,
    T3: DisjointFrom<T2>,
{
    open spec fn disjoint_from(&self, other: &T1) -> bool {
        self.1.disjoint_from(other) &&
        self.2.disjoint_from(other)
    }

    proof fn parse_disjoint_on(&self, other: &T1, buf: Seq<u8>) {
        self.1.parse_disjoint_on(other, buf);
        self.2.parse_disjoint_on(other, buf);
    }
}

impl<T> DisjointFrom<ASN1<T>> for End where
    T: ASN1Tagged + SpecCombinator,
{
    open spec fn disjoint_from(&self, other: &ASN1<T>) -> bool { true }
    proof fn parse_disjoint_on(&self, other: &ASN1<T>, buf: Seq<u8>) {}
}

impl<T1, T2> DisjointFrom<ASN1<T1>> for Cond<ASN1<T2>> where
    T1: ASN1Tagged + SpecCombinator,
    T2: ASN1Tagged + SpecCombinator,
 {
    open spec fn disjoint_from(&self, other: &ASN1<T1>) -> bool {
        self.inner.0.spec_tag() != other.0.spec_tag()
    }

    proof fn parse_disjoint_on(&self, other: &ASN1<T1>, buf: Seq<u8>) {}
}

impl<T1, T2> DisjointFrom<Cached<ASN1<T1>>> for ASN1<T2> where
    T1: ASN1Tagged + SpecCombinator,
    T2: ASN1Tagged + SpecCombinator,
{
    open spec fn disjoint_from(&self, other: &Cached<ASN1<T1>>) -> bool {
        self.0.spec_tag() != other.0.0.spec_tag()
    }

    proof fn parse_disjoint_on(&self, other: &Cached<ASN1<T1>>, buf: Seq<u8>) {}
}

impl<T1, T2, S> DisjointFrom<Cached<ASN1<T2>>> for Pair<ASN1<T1>, S> where
    T1: ASN1Tagged + SecureSpecCombinator,
    T2: ASN1Tagged + SecureSpecCombinator,
    S: SecureSpecCombinator,
{
    open spec fn disjoint_from(&self, other: &Cached<ASN1<T2>>) -> bool {
        other.0.0.spec_tag() != self.0.0.spec_tag()
    }

    proof fn parse_disjoint_on(&self, other: &Cached<ASN1<T2>>, buf: Seq<u8>) {}
}

}
