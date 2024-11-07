/// The high-level spec and impl of domain validation

use vstd::prelude::*;

use parser::{*, x509::*};

use crate::policy;
use crate::issue::*;
use crate::error::*;

verus! {

/// A high-level spec specifying when a certificate chain is considered valid
/// with respect to a domain
pub open spec fn spec_valid_domain(
    policy: policy::Policy,
    roots: Seq<SpecCertificateValue>,
    chain: Seq<SpecCertificateValue>,
    domain: Seq<char>,
) -> bool
{
    exists |i, j| {
        &&& 0 <= i < roots.len()
        &&& 0 <= j < chain.len()
        &&& forall |k: int| 0 <= k < j ==> spec_likely_issued(chain[k + 1], #[trigger] chain[k])
        &&& spec_likely_issued(roots[i], chain[j])

        // Check if the candidate chain satisfies the policy constraints
        &&& {
            let candidate = chain.take(j + 1) + seq![roots[i]];
            let abstract_candidate = Seq::new(candidate.len(), |i| policy::Certificate::spec_from(candidate[i]).unwrap());

            &&& forall |i| #![trigger candidate[i]] 0 <= i < candidate.len() ==> policy::Certificate::spec_from(candidate[i]).is_some()
            &&& policy::valid_chain(&policy, &abstract_candidate, &domain)
        }
    }
}

/// Check that the chain[i] is likely issued by chain[i + 1]
/// up until chain[n]
pub fn check_chain_likely_issue(chain: &VecDeep<CertificateValue>, n: usize) -> (res: bool)
    requires 0 <= n < chain@.len()
    ensures res == forall |i: int| 0 <= i < n ==> spec_likely_issued(chain@[i + 1], #[trigger] chain@[i]),
{
    for i in 0..n
        invariant
            n < chain@.len(),
            forall |j: int| 0 <= j < i ==> spec_likely_issued(chain@[j + 1], #[trigger] chain@[j]),
    {
        if !likely_issued(chain.get(i + 1), chain.get(i)) {
            return false;
        }
    }
    true
}

/// Exec version of spec_valid_domain
/// TODO: completeness
pub fn valid_domain<'a, 'b>(
    policy: &policy::ExecPolicy,
    roots: &VecDeep<CertificateValue<'a>>,
    chain: &VecDeep<CertificateValue<'b>>,
    domain: &str,
) -> (res: Result<bool, ValidationError>)
    ensures
        res.is_ok() && res.unwrap() ==>
            spec_valid_domain(policy.deep_view(), roots@, chain@, domain@)
{
    let roots_len = roots.len();
    let chain_len = chain.len();

    for i in 0..roots_len
        invariant
            roots_len == roots@.len(),
            chain_len == chain@.len(),
    {
        // Check if any intermediate certificate is issued by the root
        for j in 0..chain_len
            invariant
                roots_len == roots@.len(),
                chain_len == chain@.len(),
                0 <= i < roots_len,
        {
            if likely_issued(roots.get(i), chain.get(j)) {
                if check_chain_likely_issue(chain, j) {
                    let mut candidate: Vec<policy::ExecCertificate> = Vec::new();

                    // Abstract chain up to j
                    for k in 0..j + 1
                        invariant
                            chain_len == chain@.len(),
                            0 <= j < chain_len,
                            candidate.len()
                             == k,
                            forall |l: int| #![auto] 0 <= l < k ==> Some(candidate@[l].deep_view()) == policy::Certificate::spec_from(chain@[l]),
                    {
                        candidate.push(policy::Certificate::from(chain.get(k))?);
                    }

                    candidate.push(policy::Certificate::from(roots.get(i))?);

                    assert(candidate.deep_view() =~= {
                        let candidate = chain@.take(j + 1) + seq![roots@[i as int]];
                        Seq::new(candidate.len(), |i| policy::Certificate::spec_from(candidate[i]).unwrap())
                    });

                    if policy::exec_valid_chain(policy, &candidate, &domain.to_string()) {
                        return Ok(true);
                    }
                }
            }
        }
    }

    Ok(false)
}

}
