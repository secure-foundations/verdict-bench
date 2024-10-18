use vstd::prelude::*;
use polyfill::*;

use crate::checker::*;
use crate::proof::*;

// Verified implementation of a matching algorithm
// (matching = one-sided unification)
// TODO: too messy, clean up these proofs

verus! {

broadcast use
    TermX::axiom_view,
    SpecTerm::axiom_subst,
    SpecTerm::axiom_matches,
    vstd::set::group_set_axioms;

impl SpecSubst {
    /// Merging with an empty substitution gives the same substitution
    pub proof fn lemma_merge_empty_left(self, other: SpecSubst)
        requires
            self.is_empty(),
        ensures
            self.merge(other) =~= Some(other),
    {
    }

    // Merging is associative
    pub proof fn lemma_merge_assoc(subst1: SpecSubst, subst2: SpecSubst, subst3: SpecSubst)
        requires
    // All merges are well-defined

            subst1.merge(subst2).is_some(),
            subst1.merge(subst2).unwrap().merge(subst3).is_some(),
        ensures
            subst1.merge(subst2.merge(subst3).unwrap()).is_some(),
            subst1.merge(subst2.merge(subst3).unwrap()) =~= subst1.merge(subst2).unwrap().merge(
                subst3,
            ),
    {
        let merged12 = subst1.merge(subst2).unwrap();
        let merged23 = subst2.merge(subst3).unwrap();
        assert(forall|v|
            merged12.contains_var(v) && subst3.contains_var(v) ==> merged12.get(v) == subst3.get(
                v,
            ));
    }

    /// True iff other is a subset of self as a relation
    pub open spec fn subsumes(self, other: SpecSubst) -> bool {
        forall|v| other.contains_var(v) ==> self.contains_var(v) && self.get(v) == other.get(v)
    }

    /// Subsumption preserves merging failure
    pub proof fn lemma_subsumption_preserves_merging_fail(
        subst1: SpecSubst,
        subst2: SpecSubst,
        subst3: SpecSubst,
    )
        requires
            subst3.subsumes(subst2) && subst1.merge(subst2).is_none(),
        ensures
            subst1.merge(subst3).is_none(),
    {
    }

    pub proof fn lemma_merge_subsume(subst1: SpecSubst, subst2: SpecSubst)
        ensures
            subst1.merge(subst2) matches Some(subst) ==> subst.subsumes(subst1) && subst.subsumes(
                subst2,
            ),
    {
    }

    /// If subst1 and subst2 are mergeable, and subst1 subsumes subst3
    /// then subst1 and subst3 are mergeable
    pub proof fn lemma_merge_monotone_wrt_subsume(
        subst1: SpecSubst,
        subst2: SpecSubst,
        subst3: SpecSubst,
    )
        requires
            subst1.merge(subst2).is_some(),
            subst1.subsumes(subst3),
        ensures
            subst1.merge(subst3).is_some(),
    {
    }
}

impl SpecTerm {
    /// If self is not unifiable with other, then they should not match either
    pub proof fn lemma_non_unifiable_to_non_matching(self, other: SpecTerm)
        requires
            self.not_unifiable(other),
        ensures
            self.matches(other).is_none(),
        decreases self,
    {
        match (self, other) {
            (SpecTerm::Literal(l1), SpecTerm::Literal(l2)) => {},
            (SpecTerm::App(f1, args1), SpecTerm::App(f2, args2)) => {
                if f1 == f2 && args1.len() == args2.len() {
                    // Choose the non-unifiable index and induct on it
                    let i = choose|i|
                        0 <= i < args1.len() && (#[trigger] args1[i]).not_unifiable(
                            #[trigger] args2[i],
                        );
                    args1[i].lemma_non_unifiable_to_non_matching(args2[i]);
                    Self::lemma_not_matches_multiple(args1, args2, i);
                }
            },
            _ => {},
        }
    }

    /// If two seqs of terms match, then each pair should also match
    pub proof fn lemma_matches_multiple(terms1: Seq<SpecTerm>, terms2: Seq<SpecTerm>, i: int)
        requires
            0 <= i < terms1.len(),
            SpecTerm::matches_multiple(terms1, terms2).is_some(),
        ensures
            terms1[i].matches(terms2[i]).is_some(),
        decreases i,
    {
        if i != 0 {
            Self::lemma_matches_multiple(terms1.drop_first(), terms2.drop_first(), i - 1);
        }
    }

    /// Contrapositive of lemma_matches_multiple
    pub proof fn lemma_not_matches_multiple(terms1: Seq<SpecTerm>, terms2: Seq<SpecTerm>, i: int)
        requires
            0 <= i < terms1.len(),
            0 <= i < terms2.len(),
            terms1[i].matches(terms2[i]).is_none(),
        ensures
            SpecTerm::matches_multiple(terms1, terms2).is_none(),
    {
        if SpecTerm::matches_multiple(terms1, terms2).is_some() {
            Self::lemma_matches_multiple(terms1, terms2, i);
        }
    }

    /// If two seqs of terms match, then each pair should also match
    pub proof fn lemma_matches_multiple_individual_match(
        terms1: Seq<SpecTerm>,
        terms2: Seq<SpecTerm>,
    )
        requires
            SpecTerm::matches_multiple(terms1, terms2).is_some(),
        ensures
            forall|i| 0 <= i < terms1.len() ==> (#[trigger] terms1[i]).matches(terms2[i]).is_some(),
        decreases terms1.len(),
    {
        if terms1.len() != 0 {
            Self::lemma_matches_multiple_individual_match(terms1.drop_first(), terms2.drop_first());
            assert(forall|i|
                #![auto]
                1 <= i < terms1.len() ==> terms1[i] == terms1.drop_first()[i - 1]);
            assert(forall|i|
                #![auto]
                1 <= i < terms2.len() ==> terms2[i] == terms2.drop_first()[i - 1]);
        }
    }

    /// If two seqs of terms match, we can extend it by adding one more pair
    /// assuming no issue from the merge
    pub proof fn lemma_matches_multiple_extend(
        terms1: Seq<SpecTerm>,
        terms2: Seq<SpecTerm>,
        term1: SpecTerm,
        term2: SpecTerm,
    )
        requires
            SpecTerm::matches_multiple(terms1, terms2).is_some(),
            term1.matches(term2).is_some(),
            // SpecTerm::matches_multiple(terms1 + seq![term1], terms2 + seq![term2]).is_some()
            SpecTerm::matches_multiple(terms1, terms2).unwrap().merge(
                term1.matches(term2).unwrap(),
            ).is_some(),
        ensures
    // Required additional IH for induction

            terms1.len() != 0 ==> SpecTerm::matches_multiple(
                terms1.drop_first() + seq![term1],
                terms2.drop_first() + seq![term2],
            ).is_some(),
            SpecTerm::matches_multiple(terms1 + seq![term1], terms2 + seq![term2])
                =~= SpecTerm::matches_multiple(terms1, terms2).unwrap().merge(
                term1.matches(term2).unwrap(),
            ),
        decreases terms1.len(),
    {
        let ext_terms1 = terms1 + seq![term1];
        let ext_terms2 = terms2 + seq![term2];

        let ext_terms1_tail = terms1.drop_first() + seq![term1];
        let ext_terms2_tail = terms2.drop_first() + seq![term2];

        reveal_with_fuel(SpecTerm::matches_multiple, 2);

        if terms1.len() != 0 {
            assert(ext_terms1.drop_first() =~= ext_terms1_tail);
            assert(ext_terms2.drop_first() =~= ext_terms2_tail);

            Self::lemma_matches_multiple(terms1, terms2, 0);

            // 0 .. terms1.len()
            let old_subst = SpecTerm::matches_multiple(terms1, terms2).unwrap();
            // at terms1.len()
            let tail_subst = term1.matches(term2).unwrap();
            // at 0
            let head_subst = terms1[0].matches(terms2[0]).unwrap();
            // 1 .. terms1.len()
            let mid_subst = SpecTerm::matches_multiple(
                terms1.drop_first(),
                terms2.drop_first(),
            ).unwrap();

            // assert(old_subst.merge(tail_subst).is_some());
            // let final_subst = old_subst.merge(tail_subst).unwrap();

            assert(old_subst.subsumes(mid_subst));

            SpecSubst::lemma_merge_monotone_wrt_subsume(old_subst, tail_subst, mid_subst);
            Self::lemma_matches_multiple_extend(
                terms1.drop_first(),
                terms2.drop_first(),
                term1,
                term2,
            );

            // assert(SpecTerm::matches_multiple(ext_terms1_tail, ext_terms2_tail).is_some());
            let ext_tail_subst = SpecTerm::matches_multiple(
                ext_terms1_tail,
                ext_terms2_tail,
            ).unwrap();

            // WTS: LHS == RHS, where
            // LHS = head_subst.merge(ext_tail_subst)
            // RHS = old_subst.merge(tail_subst)

            // By IH, ext_tail_subst == mid_subst.merge(tail_subst)

            let mid_tail_subst = mid_subst.merge(tail_subst).unwrap();
            SpecSubst::lemma_merge_assoc(head_subst, mid_subst, tail_subst);

            // assert(ext_tail_subst == mid_tail_subst);
            // assert(head_subst.merge(ext_tail_subst) == head_subst.merge(mid_tail_subst));
            // assert(head_subst.merge(mid_subst).unwrap() == old_subst);
            // assert(head_subst.merge(mid_tail_subst) == old_subst.merge(tail_subst));
        }
    }

    /// The matching substitution of terms1 and terms2
    /// should subsume the matching substitution of terms1[i] and terms2[i]
    pub proof fn lemma_matches_multiple_subsume(
        terms1: Seq<SpecTerm>,
        terms2: Seq<SpecTerm>,
        i: int,
    )
        requires
            0 <= i < terms1.len(),
            SpecTerm::matches_multiple(terms1, terms2).is_some(),
            terms1[i].matches(terms2[i]).is_some(),
        ensures
            ({
                let subst1 = SpecTerm::matches_multiple(terms1, terms2).unwrap();
                let subst2 = terms1[i].matches(terms2[i]).unwrap();
                subst1.subsumes(subst2)
            }),
        decreases i,
    {
        if i != 0 {
            Self::lemma_matches_multiple_subsume(terms1.drop_first(), terms2.drop_first(), i - 1);
        }
    }

    /// If there are two indices i, j such that the matching substitution
    /// of (terms1[i], terms2[i]) and (terms1[j], terms2[j])
    /// are different, then SpecTerm::matches_multiple should fail
    pub proof fn lemma_conflict_to_merge_fail(
        terms1: Seq<SpecTerm>,
        terms2: Seq<SpecTerm>,
        i: int,
        j: int,
        conflict_var: SpecVar,
    )
        requires
            0 <= i < terms1.len(),
            0 <= j < terms1.len(),
            terms1[i].matches(terms2[i]).is_some(),
            terms1[j].matches(terms2[j]).is_some(),
            // Exists a merge conflict
            ({
                let subst1 = terms1[i].matches(terms2[i]).unwrap();
                let subst2 = terms1[j].matches(terms2[j]).unwrap();

                subst1.contains_var(conflict_var) && subst2.contains_var(conflict_var)
                    && subst1.get(conflict_var) != subst2.get(conflict_var)
            }),
        ensures
            SpecTerm::matches_multiple(terms1, terms2).is_none(),
    {
        // Proof by contradiction
        if SpecTerm::matches_multiple(terms1, terms2).is_some() {
            Self::lemma_matches_multiple_subsume(terms1, terms2, i);
            Self::lemma_matches_multiple_subsume(terms1, terms2, j);
        }
    }
}

pub proof fn lemma_filter_map_commute_with_add<T, S>(
    s1: Seq<T>,
    s2: Seq<T>,
    f: spec_fn(T) -> Option<S>,
)
    ensures
        filter_map(s1 + s2, f) == filter_map(s1, f) + filter_map(s2, f),
    decreases s1.len(),
{
    if s1.len() != 0 {
        lemma_filter_map_commute_with_add(s1.drop_first(), s2, f);

        match f(s1[0]) {
            Some(v) => {
                assert((s1 + s2).drop_first() =~= s1.drop_first() + s2);
                assert(seq![v] + (filter_map(s1.drop_first(), f) + filter_map(s2, f)) =~= (seq![v]
                    + filter_map(s1.drop_first(), f)) + filter_map(s2, f));
            },
            None => {
                assert((s1 + s2).drop_first() =~= s1.drop_first() + s2);
            },
        }
    }
}

/// If f is None at index i, then filter_map should ignore s[i] in the result
pub proof fn lemma_filter_map_skip<T, S>(s: Seq<T>, f: spec_fn(T) -> Option<S>, i: int)
    requires
        0 <= i && i + 1 <= s.len() && f(s[i]).is_none(),
    ensures
        filter_map(s.take(i), f) == filter_map(s.take(i + 1), f),
{
    reveal_with_fuel(filter_map, 2);
    assert(s.take(i) + seq![s[i]] =~= s.take(i + 1));
    lemma_filter_map_commute_with_add(s.take(i), seq![s[i]], f);
}

/// If f is Some(..) at index i, then filter_map should not ignore s[i] in the result
pub proof fn lemma_filter_map_no_skip<T, S>(s: Seq<T>, f: spec_fn(T) -> Option<S>, i: int)
    requires
        0 <= i && i + 1 <= s.len() && f(s[i]).is_some(),
    ensures
        filter_map(s.take(i), f) + seq![f(s[i])->Some_0] == filter_map(s.take(i + 1), f),
{
    reveal_with_fuel(filter_map, 2);
    assert(s.take(i) + seq![s[i]] =~= s.take(i + 1));
    lemma_filter_map_commute_with_add(s.take(i), seq![s[i]], f);
}

impl TermX {
    /// Corresponds to SpecTerm::matches
    pub fn match_terms(subst: &mut Subst, pattern: &Term, inst: &Term) -> (res: Result<
        (),
        ProofError,
    >)
        ensures
    // Succeeds only if both pattern matching and merging
    // with the original substitution are successful

            (if let Some(subst2) = pattern@.matches(inst@) {
                if let Some(subst3) = old(subst)@.merge(subst2) {
                    res matches Ok(..) && subst@ =~= subst3
                } else {
                    res matches Err(..)
                }
            } else {
                res matches Err(..)
            }),
    {
        let ghost subst2 = pattern@.matches(inst@).unwrap();
        let ghost subst3 = old(subst)@.merge(subst2).unwrap();

        match (arc_as_ref(pattern), arc_as_ref(inst)) {
            (TermX::Var(var), _) => {
                if let Some(existing) = subst.get(var) {
                    if !existing.eq(inst) {
                        proof_err!("inconsistent substitution for ", var, ": ", existing, " vs ", inst)
                    } else {
                        Ok(())
                    }
                } else {
                    subst.insert(var.clone(), inst.clone());
                    Ok(())
                }
            },
            (TermX::Literal(l1), TermX::Literal(l2)) => {
                if !l1.eq(l2) {
                    proof_err!("unmatched literals: ", l1, " vs ", l2)
                } else {
                    Ok(())
                }
            },
            (TermX::App(f1, args1), TermX::App(f2, args2)) => {
                if !f1.eq(f2) {
                    return proof_err!("unmatched symbols: ", f1, " vs ", f2);
                }
                if args1.len() != args2.len() {
                    return proof_err!("unmatched argument length");
                }
                // Match each subterm

                for i in 0..args1.len()
                    invariant
                        args1.len() == args2.len(),
                        pattern@ =~= SpecTerm::App(f1@, args1.deep_view()),
                        inst@ =~= SpecTerm::App(f2@, args2.deep_view()),
                        // All previous matchings should be successful
                        forall|j: int|
                            0 <= j < i ==> (#[trigger] args1[j])@.matches(args2[j]@).is_some(),
                        // All variables in the current subst
                        // should either be in old(subst) or one
                        // of the matching results
                        forall|v| #[trigger]
                            subst@.contains_var(v) ==> old(subst)@.contains_var(v) || (exists|
                                j: int,
                            |
                                0 <= j < i && (#[trigger] args1[j])@.matches(
                                    args2[j]@,
                                ).unwrap().contains_var(v)),
                        // old(subst) and j-th matching substitution is subsumed by the current subst for every j
                        forall|j: int|
                            0 <= j < i ==> subst@.subsumes(
                                (#[trigger] args1[j])@.matches(args2[j]@).unwrap(),
                            ),
                        // First i arguments match successfully
                        SpecTerm::matches_multiple(
                            args1.deep_view().take(i as int),
                            args2.deep_view().take(i as int),
                        ) matches Some(subst2)
                            &&
                        // And the current substitution is the merge of
                        // all first i matching substitutions
                        Some(subst@) =~= old(subst)@.merge(subst2),
                {
                    let ghost subst_before_iter = subst@;
                    proof {
                        SpecSubst::lemma_merge_subsume(
                            subst@,
                            args1[i as int]@.matches(args2[i as int]@).unwrap(),
                        );
                    }
                    match TermX::match_terms(subst, &args1[i], &args2[i]) {
                        Ok(..) => {
                            // Essentially we need to use the associativity of merging here
                            // since in the code, we do
                            //     (old(subst)).merge(<first match>).merge(<second match>)...
                            // whereas in the spec (loop invariant), we do
                            //     old(subst).merge(merge(<first match>, <second match>, ...))
                            proof {
                                let subst1 = SpecTerm::matches_multiple(
                                    args1.deep_view().take(i as int),
                                    args2.deep_view().take(i as int),
                                ).unwrap();
                                let subst2 = args1[i as int]@.matches(args2[i as int]@).unwrap();
                                // let subst3 = subst1.merge(subst2).unwrap();

                                assert(args1.deep_view().take(i + 1 as int)
                                    =~= args1.deep_view().take(i as int) + seq![args1[i as int]@]);
                                assert(args2.deep_view().take(i + 1 as int)
                                    =~= args2.deep_view().take(i as int) + seq![args2[i as int]@]);

                                SpecSubst::lemma_merge_assoc(old(subst)@, subst1, subst2);
                                SpecTerm::lemma_matches_multiple_extend(
                                    args1.deep_view().take(i as int),
                                    args2.deep_view().take(i as int),
                                    args1[i as int]@,
                                    args2[i as int]@,
                                );
                            }
                        },
                        Err(msg) => {
                            proof {
                                if let Some(arg_i_subst) = args1[i as int]@.matches(
                                    args2[i as int]@,
                                ) {
                                    // Matching succeeds, but merging fails due to variables in old(subst)
                                    assert(subst_before_iter.merge(arg_i_subst).is_none());

                                    // Since merging failed, there has to be a conflicting variable
                                    // so we choose that variable here
                                    let conflict_var = choose|v|
                                        subst_before_iter.contains_var(v)
                                            && arg_i_subst.contains_var(v) && subst_before_iter.get(
                                            v,
                                        ) != arg_i_subst.get(v);

                                    // By loop inv, the conflict has to be either in old(subst)
                                    // or one of the previous matching substitutions
                                    if old(subst)@.contains_var(conflict_var) {
                                        // A conflict in old(subst) would have caused the entire merge to fail
                                        // even if matching can succeed
                                        if let Some(entire_subst) = pattern@.matches(inst@) {
                                            SpecTerm::lemma_matches_multiple_subsume(
                                                args1.deep_view(),
                                                args2.deep_view(),
                                                i as int,
                                            );
                                            SpecSubst::lemma_subsumption_preserves_merging_fail(
                                                subst_before_iter,
                                                arg_i_subst,
                                                entire_subst,
                                            );
                                        }
                                    } else {
                                        // Choose the index of the matching substitution
                                        // that causes the conflict
                                        let j = choose|j: int|
                                            0 <= j < i && (#[trigger] args1[j])@.matches(
                                                args2[j]@,
                                            ).unwrap().contains_var(conflict_var);
                                        SpecTerm::lemma_conflict_to_merge_fail(
                                            args1.deep_view(),
                                            args2.deep_view(),
                                            i as int,
                                            j,
                                            conflict_var,
                                        );
                                    }
                                } else {
                                    // Matching failed by itself
                                    SpecTerm::lemma_not_matches_multiple(
                                        args1.deep_view(),
                                        args2.deep_view(),
                                        i as int,
                                    );
                                }
                            }
                            return Err(msg)
                        },
                    }
                }
                assert(args1.deep_view() =~= args1.deep_view().take(args1.len() as int));
                assert(args2.deep_view() =~= args2.deep_view().take(args1.len() as int));

                Ok(())
            },
            _ => proof_err!("unmatched terms: ", pattern, " vs ", inst),
        }
    }
}

} // verus!
