use vstd::prelude::*;
use rspec::rspec;
use rspec_lib::*;

use super::common::*;

verus! {

rspec! {

use ExecDirectoryName as DirectoryName;
use ExecGeneralName as GeneralName;
use ExecSubjectKey as SubjectKey;
use ExecExtendedKeyUsageType as ExtendedKeyUsageType;
use ExecExtendedKeyUsage as ExtendedKeyUsage;
use ExecBasicConstraints as BasicConstraints;
use ExecKeyUsage as KeyUsage;
use ExecSubjectAltName as SubjectAltName;
use ExecNameConstraints as NameConstraints;
use ExecCertificatePolicies as CertificatePolicies;
use ExecCertificate as Certificate;

use exec_str_lower as str_lower;

pub struct Environment {
    pub time: u64,

    /// NOTE: crlSet in Hammurabi
    pub crl: Seq<SpecString>,

    /// All trusted root stores
    pub trusted: Seq<SpecString>,

    pub symantec_roots: Seq<SpecString>,
    pub symantec_exceptions: Seq<SpecString>,
}

pub open spec fn is_valid_pki(cert: &Certificate) -> bool {
    match cert.subject_key {
        SubjectKey::RSA { mod_length } => mod_length >= 1024,
        SubjectKey::DSA { p_len, q_len, g_len } => p_len >= 1024,
        SubjectKey::Other => true,
    }
}

pub open spec fn name_match(pattern: &SpecString, name: &SpecString) -> bool {
    if pattern.len() > 2 && pattern.char_at(0) == '*' && pattern.char_at(1) == '.' {
        let suffix = pattern.skip(2);

        ||| &suffix == name
        ||| suffix.len() + 1 < name.len() && // `name` should be longer than ".{suffix}"
            &suffix == &name.skip(name.len() - suffix.len()) &&
            name.char_at(name.len() - suffix.len() - 1) == '.' &&
            // the prefix of `name` that matches '*' should not contain '.'
            !name.take(name.len() - suffix.len() - 1).has_char('.')
    } else {
        pattern == name
    }
}

/// TODO: nameValid
pub open spec fn valid_name(env: &Environment, name: &SpecString) -> bool {
    true
}

/// TODO: getEVStatus
pub open spec fn is_ev(env: &Environment, cert: &Certificate) -> bool {
    true
}

pub open spec fn not_in_crl(env: &Environment, cert: &Certificate) -> bool {
    forall |i: usize| 0 <= i < env.crl.len() ==> &cert.fingerprint != env.crl[i as int]
}

pub open spec fn strong_signature(alg: &SpecString) -> bool {
    // ECDSA + SHA512
    ||| alg == "1.2.840.10045.4.3.2"@
    // ECDSA + SHA384
    ||| alg == "1.2.840.10045.4.3.3"@
    // ECDSA + SHA512
    ||| alg == "1.2.840.10045.4.3.4"@
    // RSA + SHA256
    ||| alg == "1.2.840.113549.1.1.11"@
    // RSA + SHA384
    ||| alg == "1.2.840.113549.1.1.12"@
    // RSA + SHA512
    ||| alg == "1.2.840.113549.1.1.13"@
}

pub open spec fn key_usage_valid_non_leaf(cert: &Certificate) -> bool {
    match &cert.ext_basic_constraints {
        Some(bc) =>
            match &cert.ext_key_usage {
                Some(key_usage) => bc.is_ca && key_usage.key_cert_sign,
                _ => true,
            }
        _ => true,
    }
}

pub open spec fn key_usage_valid_leaf(cert: &Certificate) -> bool {
    match &cert.ext_basic_constraints {
        Some(bc) =>
            match &cert.ext_key_usage {
                Some(key_usage) => {
                    ||| key_usage.digital_signature
                    ||| key_usage.key_encipherment
                    ||| key_usage.key_agreement
                }
                _ => true,
            }
        _ => true,
    }
}

pub open spec fn extended_key_usage_valid(cert: &Certificate) -> bool {
    match (&cert.ext_basic_constraints, &cert.ext_extended_key_usage) {
        (Some(bc), Some(key_usage)) =>
            if bc.is_ca {
                exists |i: usize| 0 <= i < key_usage.usages.len() &&
                    match #[trigger] key_usage.usages[i as int] {
                        ExtendedKeyUsageType::ServerAuth => true,
                        _ => false,
                    }
            } else {
                // Has ServerAuth
                &&& exists |i: usize| 0 <= i < key_usage.usages.len() &&
                    match #[trigger] key_usage.usages[i as int] {
                        ExtendedKeyUsageType::ServerAuth => true,
                        _ => false,
                    }
                // No OCSPSigning
                &&& forall |i: usize| 0 <= i < key_usage.usages.len() ==>
                    match #[trigger] key_usage.usages[i as int] {
                        ExtendedKeyUsageType::OCSPSigning => false,
                        _ => true,
                    }
            }

        // TODO check if this is equivalent to extKetUsageValid in Hammurabi

        _ => true,
    }
}

/// TODO: notRevoked
pub open spec fn not_revoked(env: &Environment, cert: &Certificate) -> bool {
    true
}

pub open spec fn match_common_name_domain(env: &Environment, cert: &Certificate, domain: &SpecString) -> bool {
    exists |i: usize| #![auto]
        0 <= i < cert.subject_name.len() && {
            &&& &cert.subject_name[i as int].oid == "2.5.4.3"@ // common name
            &&& valid_name(&env, &cert.subject_name[i as int].value)
            &&& name_match(&cert.subject_name[i as int].value, &domain)
        }
}

pub open spec fn match_san_domain(env: &Environment, san: &SubjectAltName, domain: &SpecString) -> bool {
    &&& forall |i: usize|
        0 <= i < san.names.len() ==>
        valid_name(&env, #[trigger] &san.names[i as int])
    &&& exists |i: usize|
        0 <= i < san.names.len() &&
        name_match(#[trigger] &san.names[i as int], &domain)
}

/// TODO: notInternationalInvalidIntermediate
pub open spec fn not_international_invalid_intermediate(cert: &Certificate, leaf: &Certificate) -> bool {
    true
}

pub open spec fn cert_verified_non_leaf(env: &Environment, cert: &Certificate, leaf: &Certificate, depth: usize) -> bool {
    &&& not_international_invalid_intermediate(cert, leaf)

    &&& is_valid_pki(cert)

    // Check path length limit and is CA
    &&& depth <= 6 // global max intermediates limit in Firefox
    &&& match &cert.ext_basic_constraints {
        Some(bc) => {
            // TODO: should we check for is_ca even if basic constraints is not present?
            &&& bc.is_ca
            &&& match bc.path_len {
                Some(limit) => depth <= limit,
                None => true,
            }
        }
        None => false,
    }

    &&& cert.not_before < env.time
    &&& cert.not_after > env.time

    &&& key_usage_valid_non_leaf(cert)
}

pub open spec fn is_bad_symantec_root(env: &Environment, cert: &Certificate) -> bool {
    &&& exists |i: usize| 0 <= i < env.symantec_roots.len() && &cert.fingerprint == &env.symantec_roots[i as int]
    &&& forall |i: usize| 0 <= i < env.symantec_exceptions.len() ==> &cert.fingerprint != &env.symantec_exceptions[i as int]

    // NOTE: no check on dates like Chrome
}

/// TODO: internationalValid in Hammurabi
/// https://wiki.mozilla.org/CA/Additional_Trust_Changes#ANSSI
pub open spec fn is_international_valid(cert: &Certificate, leaf: &Certificate) -> bool {
    true
}

pub open spec fn cert_verified_root(env: &Environment, cert: &Certificate, leaf: &Certificate, depth: usize, domain: &SpecString) -> bool {
    &&& cert_verified_non_leaf(env, cert, leaf, depth)

    &&& exists |i: usize| 0 <= i < env.trusted.len() &&
        &cert.fingerprint == &env.trusted[i as int]

    &&& !is_bad_symantec_root(env, cert)
    &&& is_international_valid(cert, leaf)
}

pub open spec fn cert_verified_intermediate(env: &Environment, cert: &Certificate, leaf: &Certificate, depth: usize) -> bool {
    &&& cert_verified_non_leaf(env, cert, leaf, depth)
    &&& not_in_crl(env, cert)
    &&& strong_signature(&cert.sig_alg)
    &&& extended_key_usage_valid(cert)
    &&& not_revoked(env, cert)
    // TODO: check name constraints
}

pub open spec fn cert_verified_leaf(env: &Environment, cert: &Certificate, domain: &SpecString) -> bool {
    &&& is_valid_pki(cert)

    // Check that SAN or CN is valid
    // and the domain belongs to one of them
    &&& match &cert.ext_subject_alt_name {
        Some(san) => match_san_domain(env, san, domain),

        // If SAN is not present, check CN instead
        None => match_common_name_domain(env, cert, domain),
    }

    &&& match &cert.ext_basic_constraints {
        Some(bc) => !bc.is_ca,
        None => true,
    }

    // leafDurationValid in Hammurabi
    &&& !is_ev(env, cert) || {
        &&& cert.not_after >= cert.not_before
        &&& cert.not_after - cert.not_before < 71712000 // 27 months
    }

    &&& not_in_crl(env, cert)

    &&& cert.not_before < env.time
    &&& cert.not_after > env.time

    &&& strong_signature(&cert.sig_alg)
    &&& key_usage_valid_leaf(cert)
    &&& extended_key_usage_valid(cert)
    &&& not_revoked(env, cert)
}

/// chain[0] is the leaf, and assume chain[i] is issued by chain[i + 1] for all i < chain.len() - 1
/// chain.last() must be a trusted root
pub open spec fn valid_chain(env: &Environment, chain: &Seq<Certificate>, domain: &SpecString) -> bool
{
    chain.len() >= 2 && {
        let leaf = &chain[0];
        let root = &chain[chain.len() - 1];

        &&& cert_verified_leaf(env, leaf, domain)
        &&& forall |i: usize| 1 <= i < chain.len() - 1 ==> cert_verified_intermediate(&env, #[trigger] &chain[i as int], &leaf, (i - 1) as usize)
        &&& cert_verified_root(env, root, leaf, (chain.len() - 2) as usize, domain)
    }
}

}

}
