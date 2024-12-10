/// Traits of `Policy` that specify rules from RFC 5280

use vstd::prelude::*;
use super::common::*;

verus! {

/// A validated chain should not contain expired certificates
pub trait NoExpiration: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task) matches Ok(res) && res
        ensures
            forall |i: usize| #![trigger chain[i as int]]
                0 <= i < chain.len() ==>
                chain[i as int].not_before < self.validation_time() < chain[i as int].not_after;
}

/// Outer signature algorithm should match the inner one
pub trait OuterInnerSigMatch: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task) matches Ok(res) && res
        ensures
            forall |i: usize| #![trigger chain[i as int]]
                0 <= i < chain.len() ==>
                chain[i as int].sig_alg_inner.bytes == chain[i as int].sig_alg_outer.bytes;
}

/// If the extension KeyUsage is present, at least one bit must be set
pub trait KeyUsageNonEmpty: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task) matches Ok(res) && res
        ensures
            forall |i: usize| #![trigger chain[i as int]]
                0 <= i < chain.len() ==>
                (chain[i as int].ext_key_usage matches Some(key_usage) ==> {
                    ||| key_usage.digital_signature
                    ||| key_usage.non_repudiation
                    ||| key_usage.key_encipherment
                    ||| key_usage.data_encipherment
                    ||| key_usage.key_agreement
                    ||| key_usage.key_cert_sign
                    ||| key_usage.crl_sign
                    ||| key_usage.encipher_only
                    ||| key_usage.decipher_only
                });
}

/// Issuer and subject UID should only appear if version is 2 or 3
pub trait IssuerSubjectUIDVersion: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task) matches Ok(res) && res
        ensures
            forall |i: usize| #![trigger chain[i as int]]
                0 <= i < chain.len() ==>
                (chain[i as int].issuer_uid matches Some(_) ||
                 chain[i as int].subject_uid matches Some(_)) ==>
                chain[i as int].version == 2 || chain[i as int].version == 3;
}

/// PathLenConstraints should be non-negative
pub trait PathLenNonNegative: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task) matches Ok(res) && res
        ensures
            forall |i: usize| #![trigger chain[i as int]]
                0 <= i < chain.len() ==>
                (chain[i as int].ext_basic_constraints matches Some(bc) ==>
                (bc.path_len matches Some(limit) ==> limit >= 0));
}

/// If BasicConstraints.PathLenConstraint is present,
/// is_ca is set, and key_usage.key_cert_sign is set (if present)
/// then the cert must not be followed by more than PathLenConstraint
/// non-leaf certificates
pub trait PathLenConstraint: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task) matches Ok(res) && res
        ensures
            forall |i: usize| #![trigger chain[i as int]]
                1 <= i < chain.len() ==> {
                    &chain[i as int].ext_basic_constraints matches Some(bc) ==> {
                        bc.path_len matches Some(limit) ==> {
                            bc.is_ca &&
                            (chain[i as int].ext_key_usage matches Some(key_usage) ==> key_usage.key_cert_sign)
                            ==>
                            (i - 1) <= limit as usize
                        }
                    }
                };
}

/// Every non-leaf certificate must be a CA certificate
pub trait NonLeafMustBeCA: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task) matches Ok(res) && res
        ensures
            forall |i: usize| #![trigger chain[i as int]]
                1 <= i < chain.len() ==>
                (&chain[i as int].ext_basic_constraints matches Some(bc) && bc.is_ca);
}

/// Every non-leaf certificate must have keyCertSign set in KeyUsage (if present)
pub trait NonLeafHasKeyCertSign: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task) matches Ok(res) && res
        ensures
            forall |i: usize| #![trigger chain[i as int]]
                1 <= i < chain.len() ==>
                (&chain[i as int].ext_key_usage matches Some(key_usage) ==> key_usage.key_cert_sign);
}

/// If SubjectAltName is present, it should contain at least one name
pub trait NonEmptySAN: Policy {
    proof fn conformance(&self, chain: Seq<Certificate>, task: Task)
        requires self.spec_valid_chain(chain, task) matches Ok(res) && res
        ensures
            forall |i: usize| #![trigger chain[i as int]]
                0 <= i < chain.len() ==>
                (chain[i as int].ext_subject_alt_name matches Some(san) ==> san.names.len() > 0);
}

}
