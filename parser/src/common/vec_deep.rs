use vstd::prelude::*;
use super::clone::*;

verus! {

/// A wrapper for Vec with its View implemented
/// one layer deeper than the original Vec
///
/// Otherwise inherits all methods from Vec
#[derive(Debug, Eq, PartialEq)]
pub struct VecDeep<T>(pub Vec<T>);

impl<T: View> View for VecDeep<T> {
    type V = Seq<T::V>;

    open spec fn view(&self) -> Self::V {
        Seq::new(self.0.len() as nat, |i: int| self.0@[i]@)
    }
}

/// Cloning VecDeep clones each element
impl<T: PolyfillClone> PolyfillClone for VecDeep<T> where
{
    /// Same as clone of Vec, but this is a "deep" copy
    fn clone(&self) -> Self {
        let mut cloned: Vec<T> = Vec::new();

        for i in 0..self.0.len()
            invariant
                cloned.len() == i,
                forall |j| 0 <= j < i ==> cloned[j]@ == #[trigger] self.0[j]@,
        {
            cloned.push(self.0[i].clone());
        }

        assert(VecDeep(cloned)@ =~= self@);

        VecDeep(cloned)
    }
}

impl<T: View> VecDeep<T> {
    pub fn new() -> (res: Self)
        ensures
            res@ =~= Seq::<T::V>::empty(),
    {
        VecDeep(Vec::new())
    }

    pub fn push(&mut self, value: T)
        ensures
            self@ =~= old(self)@.push(value@)
    {
        self.0.push(value);
    }

    pub fn len(&self) -> (res: usize)
        ensures
            res == self@.len()
    {
        self.0.len()
    }

    pub fn get(&self, i: usize) -> (res: &T)
        requires
            i < self@.len(),
        ensures
            res@ == self@[i as int],
    {
        &self.0[i]
    }

    pub fn remove(&mut self, i: usize) -> (res: T)
        requires
            i < old(self)@.len(),
        ensures
            res@ =~= old(self)@[i as int],
            self@ =~= old(self)@.remove(i as int),
    {
        self.0.remove(i)
    }

    pub fn append(&mut self, other: &mut VecDeep<T>)
        ensures
            self@ =~= old(self)@ + old(other)@,
            other@ =~= Seq::<T::V>::empty(),
    {
        self.0.append(&mut other.0);
    }

    pub fn append_owned(&mut self, mut other: VecDeep<T>)
        ensures
            self@ =~= old(self)@ + other@,
    {
        self.0.append(&mut other.0);
    }

    /// TODO: verify this?
    #[verifier::external_body]
    pub fn flatten(v: VecDeep<VecDeep<T>>) -> (res: VecDeep<T>)
        ensures res@ == v@.flatten()
    {
        Self::from_vec(v.0.into_iter().map(|u| u.0).flatten().collect())
    }

    pub fn split_off(&mut self, at: usize) -> (res: VecDeep<T>)
        requires
            at <= old(self)@.len(),
        ensures
            self@ =~= old(self)@.subrange(0, at as int),
            res@ =~= old(self)@.subrange(at as int, old(self)@.len() as int),
    {
        VecDeep(self.0.split_off(at))
    }

    pub fn from_vec(v: Vec<T>) -> (res: Self)
        ensures
            res@ =~= VecDeep(v)@,
    {
        VecDeep(v)
    }

    #[verifier::external_body]
    pub fn from_slice(slice: &[T]) -> (res: Self)
        where T: Clone
        ensures
            res@ =~= slice@.map_values(|x: T| x@),
    {
        VecDeep(slice.to_vec())
    }

    pub fn to_vec_owned(self) -> (res: Vec<T>)
        ensures
            self@ =~= VecDeep(res)@,
    {
        self.0
    }

    pub fn to_vec(&self) -> (res: &Vec<T>)
        ensures
            self@ =~= VecDeep(*res)@,
    {
        &self.0
    }
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! vec_deep {
    ($($x:tt)*) => {
        VecDeep::from_vec(vec![$($x)*])
    };
}
pub use vec_deep;

}
