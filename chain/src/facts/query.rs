use vstd::prelude::*;
use vpl::*;
use parser::{*, x509::*};

use crate::validate::*;
use crate::specs::*;
use crate::error::*;

use super::*;

verus! {

broadcast use vpl::lemma_ext_equal_deep;

pub type QueryFacts = seq_facts![ ChainFacts, RootFacts, EnvFacts ];

/// Generate all facts about a chain of certificates
pub struct ChainFacts;

/// Generate facts about root certificates that issued
/// any of the chain certificates
pub struct RootFacts;

/// Environment facts
pub struct EnvFacts;

/// A query consists of root certificates, certificate chain (leaf and intermediates),
/// and a domain to be validated
#[derive(View)]
pub struct QueryPoly<Roots, Chain, Domain> {
    pub roots: Roots,
    pub chain: Chain,
    pub domain: Domain,
    pub now: i64, // current UNIX timestamp
}

pub type SpecQuery = QueryPoly<Seq<SpecCertificateValue>, Seq<SpecCertificateValue>, SpecStringLiteral>;
pub type Query<'a, 'b, 'c, 'd, 'e> = QueryPoly<&'a VecDeep<CertificateValue<'b>>, &'c VecDeep<CertificateValue<'d>>, &'e str>;

impl SpecQuery {
    /// Get a chain certificate and assign a unique index
    pub closed spec fn get_chain(self, i: int) -> CertIndexed<SpecCertificateValue>
    {
        CertIndexed::new(self.chain[i], i as LiteralInt)
    }

    /// Get a root certificate and assign a unique index
    pub closed spec fn get_root(self, i: int) -> CertIndexed<SpecCertificateValue>
    {
        CertIndexed::new(self.roots[i], (i + self.chain.len()) as LiteralInt)
    }
}

impl<'a, 'b, 'c, 'd, 'e> Query<'a, 'b, 'c, 'd, 'e> {
    /// Exec version of SpecQuery::get_chain
    pub fn get_chain(&self, i: usize) -> (res: CertIndexed<&'c CertificateValue<'d>>)
        requires i < self.chain@.len()
        ensures res@ == self@.get_chain(i as int)
    {
        CertIndexed::new(self.chain.get(i), i as LiteralInt)
    }

    /// Exec version of SpecQuery::get_root
    pub fn get_root(&self, i: usize) -> (res: CertIndexed<&'a CertificateValue<'b>>)
        requires
            i < self.roots@.len(),
            i + self.chain@.len() <= LiteralInt::MAX as usize,

        ensures res@ == self@.get_root(i as int)
    {
        CertIndexed::new(self.roots.get(i), (i + self.chain.len()) as LiteralInt)
    }
}

impl<'a, 'b, 'c, 'd, 'e> Facts<Query<'a, 'b, 'c, 'd, 'e>> for ChainFacts {
    closed spec fn spec_facts(t: SpecQuery) -> Option<Seq<SpecRule>>
    {
        if_let! {
            let Some(facts) = Self::spec_facts_helper(t, 0);
            Some(facts + seq![
                spec_fact!("envDomain", spec_str!(t.domain)),
            ])
        }
    }

    fn facts(t: &Query<'a, 'b, 'c, 'd, 'e>, out: &mut VecDeep<Rule>) -> (res: Result<(), ValidationError>) {
        let len = t.chain.len();

        if len > LiteralInt::MAX as usize {
            return Err(ValidationError::IntegerOverflow);
        }

        // Generate facts for each certificate
        for i in 0..len
            invariant
                len == t.chain@.len(),

                Self::spec_facts_helper(t@, i as int) matches Some(rest) ==> {
                    &&& Self::spec_facts_helper(t@, 0) matches Some(full)
                    &&& old(out)@ + full =~~= out@ + rest
                }
        {
            if i > 0 &&
                likely_issued(t.chain.get(i), t.chain.get(i - 1)) &&
                verify_signature(t.chain.get(i), t.chain.get(i - 1)) {
                out.push(RuleX::fact("issuer", vec![ t.get_chain(i - 1).cert(), t.get_chain(i).cert() ]));
            }

            CertificateFacts::facts(&t.get_chain(i), out)?;
        }

        out.push(RuleX::fact("envDomain", vec![ TermX::str(t.domain) ]));

        Ok(())
    }
}

impl<'a, 'b, 'c, 'd, 'e> Facts<Query<'a, 'b, 'c, 'd, 'e>> for RootFacts {
    closed spec fn spec_facts(t: SpecQuery) -> Option<Seq<SpecRule>> {
        Self::spec_facts_helper(t, 0)
    }

    fn facts(t: &Query<'a, 'b, 'c, 'd, 'e>, out: &mut VecDeep<Rule>) -> (res: Result<(), ValidationError>) {
        let roots_len = t.roots.len();
        let chain_len = t.chain.len();

        if chain_len > LiteralInt::MAX as usize || roots_len > LiteralInt::MAX as usize - chain_len {
            return Err(ValidationError::IntegerOverflow);
        }

        // Go through each root certificate, and generate
        // facts about it only if some chain certificate is dependent on it
        for i in 0..roots_len
            invariant
                roots_len == t.roots@.len(),
                chain_len == t.chain@.len(),
                roots_len + chain_len <= LiteralInt::MAX as usize,

                Self::spec_facts_helper(t@, i as int) matches Some(rest) ==> {
                    &&& Self::spec_facts_helper(t@, 0) matches Some(full)
                    &&& old(out)@ + full =~~= out@ + rest
                },
        {
            let ghost prev_out = out@;
            let mut used = false;

            // Check for each chain cert if it was issued by root cert i
            for j in 0..chain_len
                invariant
                    roots_len == t.roots@.len(),
                    chain_len == t.chain@.len(),
                    roots_len + chain_len <= LiteralInt::MAX as usize,

                    0 <= i < roots_len,

                    Self::spec_facts_helper_inner(t@, i as int, j as int) matches Some(rest) ==> {
                        &&& Self::spec_facts_helper_inner(t@, i as int, 0) matches Some(full)
                        &&& prev_out + full =~~= out@ + rest

                        // used iff there is some chain cert dependent on root cert i
                        &&& full.len() >= rest.len()
                        &&& used <==> full.len() != rest.len()
                    },
            {
                if likely_issued(t.roots.get(i), t.chain.get(j)) &&
                   verify_signature(t.roots.get(i), t.chain.get(j)) {
                    used = true;
                    out.push(RuleX::fact("issuer", vec![ t.get_chain(j).cert(), t.get_root(i).cert() ]));
                }
            }

            if used {
                out.push(RuleX::fact("issuer", vec![ t.get_root(i).cert(), t.get_root(i).cert() ]));
                CertificateFacts::facts(&t.get_root(i), out)?;
            }
        }

        Ok(())
    }
}

impl<'a, 'b, 'c, 'd, 'e> Facts<Query<'a, 'b, 'c, 'd, 'e>> for EnvFacts {
    closed spec fn spec_facts(t: SpecQuery) -> Option<Seq<SpecRule>>
    {
        Some(seq![
            spec_fact!("envDomain", spec_str!(t.domain)),
            spec_fact!("envNow", spec_int!(t.now as int)),
        ])
    }

    fn facts(t: &Query<'a, 'b, 'c, 'd, 'e>, out: &mut VecDeep<Rule>) -> (res: Result<(), ValidationError>)
    {
        out.push(RuleX::fact("envDomain", vec![ TermX::str(t.domain) ]));
        out.push(RuleX::fact("envNow", vec![ TermX::int(t.now) ]));
        Ok(())
    }
}

impl ChainFacts {
    /// Generate facts for each certificate from index i, until hit end or None
    pub closed spec fn spec_facts_helper(t: SpecQuery, i: int) -> Option<Seq<SpecRule>>
        decreases t.chain.len() - i
    {
        if i >= t.chain.len() {
            Some(seq![])
        } else {
            if_let! {
                let Some(facts) = CertificateFacts::spec_facts(t.get_chain(i));
                let Some(rest) = Self::spec_facts_helper(t, i + 1);

                if i > 0 &&
                    spec_likely_issued(t.chain[i], t.chain[i - 1]) &&
                    spec_verify_signature(t.chain[i], t.chain[i - 1]) {
                    // If the current chain cert issued the last one, add an issuer fact about it
                    Some(seq![
                        spec_fact!("issuer", t.get_chain(i - 1).spec_cert(), t.get_chain(i).spec_cert()),
                    ] + facts + rest)
                 } else {
                    Some(facts + rest)
                 }
            }
        }
    }
}

impl RootFacts {
    /// For a given root cert i, check if any chain cert in t.chain[j..] was issued by it
    pub closed spec fn spec_facts_helper_inner(t: SpecQuery, i: int, j: int) -> Option<Seq<SpecRule>>
        decreases t.chain.len() - j
    {
        if j >= t.chain.len() {
            Some(seq![])
        } else {
            // Check if roots[i] issued chain[j]
            if spec_likely_issued(t.roots[i], t.chain[j]) &&
               spec_verify_signature(t.roots[i], t.chain[j]) {
                // If so add an issuer fact
                if_let! {
                    let Some(rest) = Self::spec_facts_helper_inner(t, i, j + 1);
                    Some(seq![
                        spec_fact!("issuer", t.get_chain(j).spec_cert(), t.get_root(i).spec_cert()),
                    ] + rest)
                }
            } else {
                Self::spec_facts_helper_inner(t, i, j + 1)
            }
        }
    }

    /// Generate facts about root certificate in [i, t.roots.len())
    pub closed spec fn spec_facts_helper(t: SpecQuery, i: int) -> Option<Seq<SpecRule>>
        decreases t.roots.len() - i
    {
        if i >= t.roots.len() {
            Some(seq![])
        } else {
            if_let! {
                let Some(facts) = Self::spec_facts_helper_inner(t, i, 0);
                let Some(rest) = Self::spec_facts_helper(t, i + 1);

                if facts.len() != 0 {
                    if_let! {
                        let Some(root_cert_facts) = CertificateFacts::spec_facts(t.get_root(i));

                        // Generate facts of
                        // 1. Which chain certs are issued by root cert i
                        // 2. Self-issuing fact: issuer(cert(i), cert(i))
                        // 3. Facts about the root cert itself
                        Some(facts + seq![
                            // Self-issuing fact
                            spec_fact!("issuer", t.get_root(i).spec_cert(), t.get_root(i).spec_cert()),
                        ] + root_cert_facts + rest)
                    }
                } else {
                    Some(rest)
                }
            }
        }
    }
}

}
