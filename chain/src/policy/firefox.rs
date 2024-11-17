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
use ExecTask as Task;
use ExecPolicyResult as PolicyResult;

use exec_str_lower as str_lower;
use exec_match_name as match_name;
use exec_check_auth_key_id as check_auth_key_id;
use exec_is_subtree_of as is_subtree_of;
use exec_permit_name as permit_name;
// use rspec_debug as debug;

pub struct EVPolicy {
    pub oid: SpecString,
    pub country: Option<SpecString>,
    pub common_name: Option<SpecString>,
    pub locality: Option<SpecString>,
    pub state: Option<SpecString>,
    pub organization: Option<SpecString>,
}

pub struct Environment {
    pub time: u64,

    /// NOTE: crlSet in Hammurabi
    pub crl: Seq<SpecString>,

    //// All trusted root stores
    // pub trusted: Seq<SpecString>,

    pub symantec_roots: Seq<SpecString>,
    pub symantec_exceptions: Seq<SpecString>,

    // pub ev_policies: Seq<EVPolicy>,

    // tubitak1Fingerprint/Subtree
    pub tubitak1_trusted: Seq<SpecString>,
    pub tubitak1_domains: Seq<SpecString>,

    // anssiFingerprint/Subtree
    pub anssi_trusted: Seq<SpecString>,
    pub anssi_domains: Seq<SpecString>,
}

pub open spec fn is_valid_pki(cert: &Certificate) -> bool {
    match cert.subject_key {
        SubjectKey::RSA { mod_length } => mod_length >= 1024,
        SubjectKey::DSA { p_len, q_len, g_len } => p_len >= 1024,
        SubjectKey::Other => true,
    }
}

/// Mostly the same as Chrome's, except without checking
/// publix suffix, and requiring that after '*.' there
/// should be at least two components (i.e. "*.com" is invalid)
pub open spec fn valid_name(env: &Environment, name: &SpecString) -> bool {
    if name.has_char('*') {
        &&& name.len() > 2
        &&& name.char_at(0) == '*'
        &&& name.char_at(1) == '.'
        &&& name.char_at(name.len() - 1) != '.'
        &&& name.skip(2).has_char('.') // at least two components
    } else {
        &&& name.len() > 0
        &&& name.char_at(0) != '.'
        &&& name.char_at(name.len() - 1) != '.'
    }
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
    (&cert.ext_basic_constraints, &cert.ext_key_usage) matches (Some(bc), Some(key_usage))
    ==> bc.is_ca && key_usage.key_cert_sign
}

pub open spec fn key_usage_valid_leaf(cert: &Certificate) -> bool {
    (&cert.ext_basic_constraints, &cert.ext_key_usage) matches (Some(bc), Some(key_usage))
    ==> {
        ||| key_usage.digital_signature
        ||| key_usage.key_encipherment
        ||| key_usage.key_agreement
    }
}

pub open spec fn extended_key_usage_valid(cert: &Certificate) -> bool {
    (&cert.ext_basic_constraints, &cert.ext_extended_key_usage) matches (Some(bc), Some(key_usage))
    ==>
        if bc.is_ca {
            exists |i: usize| 0 <= i < key_usage.usages.len() &&
                #[trigger] key_usage.usages[i as int] matches ExtendedKeyUsageType::ServerAuth
        } else {
            // Has ServerAuth
            &&& exists |i: usize| 0 <= i < key_usage.usages.len() &&
                    (#[trigger] key_usage.usages[i as int] matches ExtendedKeyUsageType::ServerAuth)

            // No OCSPSigning
            &&& forall |i: usize| 0 <= i < key_usage.usages.len() ==>
                    !(#[trigger] key_usage.usages[i as int] matches ExtendedKeyUsageType::OCSPSigning)
        }

    // TODO check if this is equivalent to extKetUsageValid in Hammurabi
}

pub open spec fn not_revoked(env: &Environment, cert: &Certificate) -> bool {
    ||| cert.not_after >= cert.not_before && cert.not_after - cert.not_before < 864001 // 10 days

    // notOCSPRevoked
    ||| true
}

pub open spec fn match_common_name_domain(env: &Environment, cert: &Certificate, domain: &SpecString) -> bool {
    exists |i: usize| #![trigger cert.subject_name[i as int]]
        0 <= i < cert.subject_name.len() &&
    exists |j: usize| #![trigger cert.subject_name[i as int][j as int]]
        0 <= j < cert.subject_name[i as int].len() &&
        {
            let name = &cert.subject_name[i as int][j as int];
            &&& &name.oid == "2.5.4.3"@ // common name
            &&& valid_name(&env, &name.value)
            &&& match_name(&name.value, &domain)
        }
}

pub open spec fn match_san_domain(env: &Environment, san: &SubjectAltName, domain: &SpecString) -> bool {
    &&& forall |i: usize| #![trigger &san.names[i as int]]
            0 <= i < san.names.len() ==> {
                &san.names[i as int] matches GeneralName::DNSName(dns_name)
                    ==> valid_name(&env, dns_name)
            }

    &&& exists |i: usize|
            0 <= i < san.names.len() && {
                &&& #[trigger] &san.names[i as int] matches GeneralName::DNSName(dns_name)
                &&& match_name(&str_lower(dns_name), &domain)
            }
}

pub open spec fn is_suffix_of(a: &SpecString, b: &SpecString) -> bool {
    a.len() <= b.len() && &b.skip(b.len() - a.len()) == a
}

pub open spec fn has_subject_name(cert: &Certificate, oid: &SpecString, value: &SpecString) -> bool {
    exists |i: usize| #![trigger cert.subject_name[i as int]] 0 <= i < cert.subject_name.len() &&
    exists |j: usize| 0 <= j < cert.subject_name[i as int].len() &&
        {
            let name = #[trigger] &cert.subject_name[i as int][j as int];
            &name.oid == oid &&
            &name.value == value
        }
}

pub open spec fn is_international_invalid_name(cert: &Certificate, name: &SpecString) -> bool {
    ||| {
        &&& !is_suffix_of(&".gov.tr"@, name)
        &&& !is_suffix_of(&".k12.tr"@, name)
        &&& !is_suffix_of(&".pol.tr"@, name)
        &&& !is_suffix_of(&".mil.tr"@, name)
        &&& !is_suffix_of(&".tsk.tr"@, name)
        &&& !is_suffix_of(&".kep.tr"@, name)
        &&& !is_suffix_of(&".bel.tr"@, name)
        &&& !is_suffix_of(&".edu.tr"@, name)
        &&& !is_suffix_of(&".org.tr"@, name)
        &&& {
            &&& has_subject_name(cert, &"2.5.4.3"@, &"TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1"@)
            &&& has_subject_name(cert, &"2.5.4.6"@, &"TR"@)
            &&& has_subject_name(cert, &"2.5.4.7"@, &"Gebze - Kocaeli"@)
            &&& has_subject_name(cert, &"2.5.4.10"@, &"Turkiye Bilimsel ve Teknolojik Arastirma Kurumu - TUBITAK"@)
        }
    }
    ||| {
        &&& !is_suffix_of(&".fr"@, name)
        &&& !is_suffix_of(&".gp"@, name)
        &&& !is_suffix_of(&".gf"@, name)
        &&& !is_suffix_of(&".mq"@, name)
        &&& !is_suffix_of(&".re"@, name)
        &&& !is_suffix_of(&".yt"@, name)
        &&& !is_suffix_of(&".pm"@, name)
        &&& !is_suffix_of(&".bl"@, name)
        &&& !is_suffix_of(&".mf"@, name)
        &&& !is_suffix_of(&".wf"@, name)
        &&& !is_suffix_of(&".pf"@, name)
        &&& !is_suffix_of(&".nc"@, name)
        &&& !is_suffix_of(&".tf"@, name)
        &&& {
            &&& has_subject_name(cert, &"2.5.4.3"@, &"IGC/A"@)
            &&& has_subject_name(cert, &"2.5.4.6"@, &"FR"@)
            &&& has_subject_name(cert, &"2.5.4.7"@, &"Paris"@)
            &&& has_subject_name(cert, &"2.5.4.8"@, &"France"@)
            &&& has_subject_name(cert, &"2.5.4.10"@, &"PM/SGDN"@)
        }
    }
}

pub open spec fn is_international_invalid_san(cert: &Certificate, san: &SubjectAltName) -> bool {
    exists |i: usize| 0 <= i < san.names.len() && {
        &&& #[trigger] &san.names[i as int] matches GeneralName::DNSName(dns_name)
        &&& is_international_invalid_name(&cert, dns_name)
    }
}

// internationalInvalidIntermediate in Hammurabi
pub open spec fn is_international_invalid_non_leaf(cert: &Certificate, leaf: &Certificate) -> bool {
    &&& &leaf.ext_subject_alt_name matches Some(san) ==> is_international_invalid_san(&cert, san)

    // No common name is invalid
    &&& forall |i: usize| #![trigger leaf.subject_name[i as int]] 0 <= i < leaf.subject_name.len() ==>
        forall |j: usize| 0 <= j < leaf.subject_name[i as int].len() ==>
        !{
            let name = #[trigger] &leaf.subject_name[i as int][j as int];
            &&& &name.oid == "2.5.4.3"@
            &&& is_international_invalid_name(&cert, &name.value)
        }
}

pub open spec fn cert_verified_non_leaf(env: &Environment, cert: &Certificate, leaf: &Certificate, depth: usize) -> bool {
    &&& is_international_valid(env, cert, leaf)
    &&& is_valid_pki(cert)

    // Check path length limit and is CA
    &&& depth <= 6 // global max intermediates limit in Firefox
    &&& &cert.ext_basic_constraints matches Some(bc)
    &&& bc.is_ca
    &&& bc.path_len matches Some(limit) ==> depth <= limit

    &&& cert.not_before < env.time
    &&& cert.not_after > env.time

    &&& key_usage_valid_non_leaf(cert)
}

pub open spec fn is_bad_symantec_root(env: &Environment, cert: &Certificate) -> bool {
    &&& exists |i: usize| 0 <= i < env.symantec_roots.len() && &cert.fingerprint == &env.symantec_roots[i as int]
    &&& forall |i: usize| 0 <= i < env.symantec_exceptions.len() ==> &cert.fingerprint != &env.symantec_exceptions[i as int]
    // NOTE: no check on dates like Chrome
}

pub open spec fn is_international_valid_name(env: &Environment, cert: &Certificate, name: &SpecString) -> bool {
    let is_tubitak1_fingerprint = exists |i: usize| 0 <= i < env.tubitak1_trusted.len() && &cert.fingerprint == &env.tubitak1_trusted[i as int];
    let is_anssi_fingerprint = exists |i: usize| 0 <= i < env.anssi_trusted.len() && &cert.fingerprint == &env.anssi_trusted[i as int];

    &&& is_tubitak1_fingerprint ==>
        exists |i: usize| #![auto] 0 <= i < env.tubitak1_domains.len() &&
            match_name(&env.tubitak1_domains[i as int], &name)
    &&& is_anssi_fingerprint ==>
        exists |i: usize| #![auto] 0 <= i < env.anssi_domains.len() &&
            match_name(&env.anssi_domains[i as int], &name)
}

pub open spec fn is_international_valid_san(env: &Environment, cert: &Certificate, san: &SubjectAltName, leaf: &Certificate) -> bool {
    forall |i: usize| #![trigger &san.names[i as int]]
        0 <= i < san.names.len() ==> {
            &san.names[i as int] matches GeneralName::DNSName(dns_name)
            ==> is_international_valid_name(&env, &cert, dns_name)
        }
}

/// internationalValid in Hammurabi
/// https://wiki.mozilla.org/CA/Additional_Trust_Changes#ANSSI
///
/// TODO: this seems a bit weird, since it only checks if there is one valid SAN?
pub open spec fn is_international_valid(env: &Environment, cert: &Certificate, leaf: &Certificate) -> bool {
    &leaf.ext_subject_alt_name matches Some(san)
    ==> is_international_valid_san(env, cert, san, leaf)
}

pub open spec fn cert_verified_root(env: &Environment, cert: &Certificate, leaf: &Certificate, depth: usize, domain: &SpecString) -> bool {
    &&& cert_verified_non_leaf(env, cert, leaf, depth)
    &&& !is_bad_symantec_root(env, cert)
    &&& is_international_valid(env, cert, leaf)
}

/// Check if a NameConstraints has a directory name constraint in the permitted list
pub open spec fn has_directory_name_constraint(constraints: &NameConstraints) -> bool {
    exists |i: usize| 0 <= i < constraints.permitted.len() &&
        #[trigger] &constraints.permitted[i as int] matches GeneralName::DirectoryName(_)
}

/// Check subject names in the leaf cert against name constraints
/// See https://searchfox.org/mozilla-central/source/security/nss/lib/mozpkix/lib/pkixnames.cpp#829
/// TODO: right now this is done using the same code as Chrome, update it to match Firefox's impl
pub open spec fn check_subject_name_constraints(leaf: &Certificate, constraints: &NameConstraints) -> bool {
    let directory_name_enabled = has_directory_name_constraint(constraints);

    &&& directory_name_enabled ==>
            exists |j: usize| 0 <= j < constraints.permitted.len() && {
                &&& #[trigger] &constraints.permitted[j as int] matches GeneralName::DirectoryName(permitted_name)
                &&& is_subtree_of(&permitted_name, &leaf.subject_name)
            }

    // Not explicitly excluded
    &&& forall |j: usize| #![trigger &constraints.excluded[j as int]]
            0 <= j < constraints.excluded.len() ==> {
                &constraints.excluded[j as int] matches GeneralName::DirectoryName(excluded_name)
                ==> !is_subtree_of(&excluded_name, &leaf.subject_name)
            }
}

/// Different from Chrome, Firefox does not clean name first
pub open spec fn valid_name_constraint(name: &SpecString) -> bool {
    &&& name.len() > 0
    &&& name.char_at(name.len() - 1) != '.'
    &&& !name.has_char('*')
}

/// All (permitted/excluded) DNS name constraints are valid
pub open spec fn valid_dns_name_constraints(constraints: &NameConstraints) -> bool {
    &&& forall |i: usize| #![trigger &constraints.permitted[i as int]]
            0 <= i < constraints.permitted.len() ==> {
                &constraints.permitted[i as int] matches GeneralName::DNSName(permitted_name)
                ==> valid_name_constraint(permitted_name)
            }

    &&& forall |i: usize| #![trigger &constraints.excluded[i as int]]
            0 <= i < constraints.excluded.len() ==> {
                &constraints.excluded[i as int] matches GeneralName::DNSName(excluded_name)
                ==> valid_name_constraint(excluded_name)
            }
}

pub open spec fn has_permitted_dns_name(constraints: &NameConstraints) -> bool {
    exists |j: usize|
        0 <= j < constraints.permitted.len() &&
        #[trigger] constraints.permitted[j as int] matches GeneralName::DNSName(_)
}

/// Check a (cleaned) DNS name against name constraints
/// NOTE: no name cleaning like in Chrome
pub open spec fn check_dns_name_constraints(name: &SpecString, constraints: &NameConstraints) -> bool {
    // Check that `name` is permitted by some name constraint in `permitted`
    &&& !has_permitted_dns_name(constraints) ||
        exists |i: usize| 0 <= i < constraints.permitted.len() && {
            &&& #[trigger] &constraints.permitted[i as int] matches GeneralName::DNSName(permitted_name)
            &&& permit_name(permitted_name, &name)
        }

    // Check that `name` is not covered by any name constraint in `excluded`
    &&& forall |i: usize| #![trigger &constraints.excluded[i as int]]
            0 <= i < constraints.excluded.len() ==> {
                &constraints.excluded[i as int] matches GeneralName::DNSName(excluded_name)
                ==> !permit_name(excluded_name, &name)
            }
}

/// Check the entire SAN section against name constraints
/// NOTE: factored out due to a proof issue related to nested matches
pub open spec fn check_san_name_constraints(san: &SubjectAltName, constraints: &NameConstraints) -> bool {
    forall |i: usize| #![trigger &san.names[i as int]]
        0 <= i < san.names.len() ==> {
            &san.names[i as int] matches GeneralName::DNSName(dns_name)
                ==> check_dns_name_constraints(dns_name, &constraints)
        }
}

pub open spec fn check_common_name_constraints(cert: &Certificate, constraints: &NameConstraints) -> bool {
    forall |i: usize| #![trigger cert.subject_name[i as int]] 0 <= i < cert.subject_name.len() ==>
    forall |j: usize| 0 <= j < cert.subject_name[i as int].len() ==>
        {
            let name = #[trigger] &cert.subject_name[i as int][j as int];
            &&& &name.oid == "2.5.4.3"@ // common name
            &&& check_dns_name_constraints(&name.value, &constraints)
        }
}

/// Check a leaf certificate against the name constraints in a parent certificate
pub open spec fn check_name_constraints(cert: &Certificate, leaf: &Certificate) -> bool {
    &cert.ext_name_constraints matches Some(constraints)
    ==> {
        &&& valid_dns_name_constraints(&constraints)
        &&& constraints.permitted.len() != 0 || constraints.excluded.len() != 0

        // Check SAN section against name constraints
        &&& match &leaf.ext_subject_alt_name {
            Some(leaf_san) => check_san_name_constraints(leaf_san, constraints),
            // Otherwise fall back to common name
            None => check_common_name_constraints(leaf, constraints),
        }

        &&& check_subject_name_constraints(leaf, constraints)
    }
}

pub open spec fn cert_verified_intermediate(env: &Environment, cert: &Certificate, leaf: &Certificate, depth: usize) -> bool {
    &&& cert_verified_non_leaf(env, cert, leaf, depth)
    &&& not_in_crl(env, cert)
    &&& strong_signature(&cert.sig_alg)
    &&& extended_key_usage_valid(cert)
    &&& not_revoked(env, cert)
    &&& check_name_constraints(cert, leaf)
}

pub open spec fn cert_verified_leaf(env: &Environment, cert: &Certificate, domain: &SpecString, ev: bool) -> bool {
    &&& is_valid_pki(cert)

    // Check that SAN or CN is valid
    // and the domain belongs to one of them
    &&& match &cert.ext_subject_alt_name {
        Some(san) => match_san_domain(env, san, domain),

        // If SAN is not present, check CN instead
        None => match_common_name_domain(env, cert, domain),
    }

    &&& &cert.ext_basic_constraints matches Some(bc) ==> !bc.is_ca

    // leafDurationValid in Hammurabi
    &&& ev ==> {
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
pub open spec fn valid_chain(env: &Environment, chain: &Seq<Certificate>, task: &Task) -> PolicyResult
{
    match task {
        Task::DomainValidation(domain) => {
            let domain = str_lower(domain);

            if chain.len() >= 2 && {
                let leaf = &chain[0];
                let root = &chain[chain.len() - 1];

                &&& forall |i: usize| 0 <= i < chain.len() - 1 ==> check_auth_key_id(&chain[i + 1], #[trigger] &chain[i as int])
                &&& cert_verified_leaf(env, leaf, &domain, false) // EV chains are not yet supported
                &&& forall |i: usize| 1 <= i < chain.len() - 1 ==> cert_verified_intermediate(&env, #[trigger] &chain[i as int], &leaf, (i - 1) as usize)
                &&& cert_verified_root(env, root, leaf, (chain.len() - 2) as usize, &domain)
            } {
                PolicyResult::Valid
            } else {
                PolicyResult::Invalid
            }
        }
        _ => PolicyResult::UnsupportedTask,
    }
}

}

}
