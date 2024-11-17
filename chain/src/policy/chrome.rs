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

pub struct Environment {
    pub time: u64,

    /// This should include all of `publicSuffix` in Hammurabi
    /// and all of their suffixes
    pub public_suffix: Seq<SpecString>,

    /// NOTE: crlSet in Hammurabi
    pub crl: Seq<SpecString>,

    //// All trusted root stores
    // pub trusted: Seq<SpecString>,

    pub symantec_roots: Seq<SpecString>,
    pub symantec_exceptions: Seq<SpecString>,

    // indiaFingerprint/Domain
    pub india_trusted: Seq<SpecString>,
    pub india_domains: Seq<SpecString>,

    // anssiFingerprint/Domain
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

/// NOTE: leafDurationValid in Hammurabi
pub open spec fn leaf_duration_valid(cert: &Certificate) -> bool {
    &&& cert.not_before <= cert.not_after
    &&& {
        let duration = cert.not_after - cert.not_before;

        let july_2012 = 1341100800u64;
        let april_2015 = 1427846400u64;
        let march_2018 = 1519862400u64;
        let july_2019 = 1561939200u64;
        let sep_2020 = 1598918400u64;
        let ten_years = 315532800u64;
        let sixty_months = 157852800u64;
        let thirty_nine_months = 102643200u64;
        let eight_twenty_five_days = 71280000u64;
        let three_ninety_eight_days = 34387200u64;

        ||| cert.not_before < july_2012 && cert.not_after < july_2019 && duration <= ten_years
        ||| cert.not_before >= july_2012 && cert.not_before < april_2015 && duration <= sixty_months
        ||| cert.not_before >= april_2015 && cert.not_before < march_2018 && duration <= thirty_nine_months
        ||| cert.not_before >= march_2018 && cert.not_before < sep_2020 && duration <= eight_twenty_five_days
        ||| cert.not_before >= sep_2020 && duration <= three_ninety_eight_days
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
    // RSA-PSS + SHA256
    ||| alg == "1.2.840.113549.1.1.10"@
}

pub open spec fn key_usage_valid(cert: &Certificate) -> bool {
    (&cert.ext_basic_constraints, &cert.ext_key_usage) matches (Some(bc), Some(key_usage))
    ==>
    if bc.is_ca {
        key_usage.key_cert_sign
    } else {
        !key_usage.key_cert_sign && {
            ||| key_usage.digital_signature
            ||| key_usage.key_encipherment
            ||| key_usage.key_agreement
        }
    }
}

pub open spec fn extended_key_usage_valid(cert: &Certificate) -> bool {
    match &cert.ext_extended_key_usage {
        Some(key_usage) =>
            exists |i: usize| 0 <= i < key_usage.usages.len() &&
                match #[trigger] key_usage.usages[i as int] {
                    ExtendedKeyUsageType::ServerAuth => true,
                    ExtendedKeyUsageType::Any => true,
                    _ => false,
                },
        None => true,
    }
}

/// TODO: URI encoding
pub open spec fn clean_name(name: &SpecString) -> SpecString {
    let lower = str_lower(name);
    if lower.len() > 0 && lower.char_at(lower.len() - 1) == '.' {
        lower.take(lower.len() - 1)
    } else {
        lower
    }
}

pub open spec fn valid_name(env: &Environment, name: &SpecString) -> bool {
    if name.has_char('*') {
        &&& name.len() > 2
        &&& name.char_at(0) == '*'
        &&& name.char_at(1) == '.'
        &&& name.char_at(name.len() - 1) != '.'
        &&& forall |i: usize| 0 <= i < env.public_suffix.len() ==>
            !match_name(&name, #[trigger] &env.public_suffix[i as int])
    } else {
        &&& name.len() > 0
        &&& name.char_at(0) != '.'
        &&& name.char_at(name.len() - 1) != '.'
    }
}

pub open spec fn valid_san(env: &Environment, san: &SubjectAltName) -> bool {
    &&& san.names.len() > 0
    &&& forall |i: usize| #![trigger &san.names[i as int]]
            0 <= i < san.names.len() ==> {
                &san.names[i as int] matches GeneralName::DNSName(dns_name)
                ==> valid_name(&env, &clean_name(dns_name))
            }
}

pub open spec fn match_san(env: &Environment, san: &SubjectAltName, name: &SpecString) -> bool {
    exists |i: usize| 0 <= i < san.names.len() && {
        &&& #[trigger] &san.names[i as int] matches GeneralName::DNSName(dns_name)
        &&& match_name(&clean_name(dns_name), &name)
    }
}

/// Domain matches one of the SANs
pub open spec fn domain_matches_san(env: &Environment, cert: &Certificate, domain: &SpecString) -> bool {
    &&& &cert.ext_subject_alt_name matches Some(san)
    &&& valid_san(env, san)
    &&& match_san(env, san, domain)
}

pub open spec fn cert_verified_leaf(env: &Environment, cert: &Certificate, domain: &SpecString) -> bool {
    &&& cert.version == 2
    &&& is_valid_pki(cert)

    &&& cert.not_before < env.time
    &&& cert.not_after > env.time

    &&& domain_matches_san(env, cert, domain)

    &&& leaf_duration_valid(cert)

    &&& not_in_crl(env, cert)
    &&& strong_signature(&cert.sig_alg)
    &&& key_usage_valid(cert)
    &&& extended_key_usage_valid(cert)
}

pub open spec fn cert_verified_non_leaf(env: &Environment, cert: &Certificate, depth: usize) -> bool {
    &&& cert.version == 2
    &&& is_valid_pki(cert)

    &&& cert.not_before < env.time
    &&& cert.not_after > env.time

    &&& &cert.ext_basic_constraints matches Some(bc)
    &&& bc.is_ca
    &&& bc.path_len matches Some(limit) ==> depth <= limit
}

pub open spec fn valid_name_constraint(name: &SpecString) -> bool {
    let name = clean_name(name);
    &&& name.len() > 0
    &&& name.char_at(name.len() - 1) != '.'
    &&& !name.has_char('*')
}

pub open spec fn has_permitted_dns_name(constraints: &NameConstraints) -> bool {
    exists |j: usize|
        0 <= j < constraints.permitted.len() &&
        #[trigger] constraints.permitted[j as int] matches GeneralName::DNSName(_)
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

/// Check a (cleaned) DNS name against name constraints
pub open spec fn check_dns_name_constraints(name: &SpecString, constraints: &NameConstraints) -> bool {
    let name = clean_name(name);

    // Check that `name` is permitted by some name constraint in `permitted`
    &&& has_permitted_dns_name(constraints) ==>
        exists |i: usize| 0 <= i < constraints.permitted.len() && {
            &&& #[trigger] &constraints.permitted[i as int] matches GeneralName::DNSName(permitted_name)
            &&& permit_name(&permitted_name, &name)
        }

    // Check that `name` is not covered by any name constraint in `excluded`
    &&& forall |i: usize| #![trigger &constraints.excluded[i as int]]
            0 <= i < constraints.excluded.len() ==> {
                &constraints.excluded[i as int] matches GeneralName::DNSName(excluded_name)
                ==> !permit_name(&excluded_name, &name)
            }
}

/// Check the entire SAN section against name constraints
/// NOTE: factored out due to a proof issue related to nested matches
pub open spec fn check_san_name_constraints(san: &SubjectAltName, constraints: &NameConstraints) -> bool {
    forall |i: usize| #![trigger &san.names[i as int]]
        0 <= i < san.names.len() ==> {
            &san.names[i as int] matches GeneralName::DNSName(dns_name)
            ==>
            check_dns_name_constraints(&clean_name(dns_name), &constraints)
        }
}

/// Check if a NameConstraints has a directory name constraint in the permitted list
pub open spec fn has_directory_name_constraint(constraints: &NameConstraints) -> bool {
    exists |i: usize| 0 <= i < constraints.permitted.len() &&
        #[trigger] &constraints.permitted[i as int] matches GeneralName::DirectoryName(_)
}

/// Check subject names in the leaf cert against name constraints
/// See https://github.com/google/boringssl/blob/571c76e919c0c48219ced35bef83e1fc83b00eed/pki/name_constraints.cc#L663
pub open spec fn check_subject_name_constraints(leaf: &Certificate, constraints: &NameConstraints) -> bool {
    let directory_name_enabled = has_directory_name_constraint(constraints);

    &&& directory_name_enabled ==>
            exists |j: usize| 0 <= j < constraints.permitted.len() && {
                &&& #[trigger] &constraints.permitted[j as int]
                        matches GeneralName::DirectoryName(permitted_name)
                &&& is_subtree_of(&permitted_name, &leaf.subject_name)
            }

    // Not explicitly excluded
    &&& forall |j: usize| 0 <= j < constraints.excluded.len() ==>
            (#[trigger] &constraints.excluded[j as int] matches GeneralName::DirectoryName(excluded_name) ==>
                !is_subtree_of(&excluded_name, &leaf.subject_name))
}

/// Check a leaf certificate against the name constraints in a parent certificate
pub open spec fn check_name_constraints(cert: &Certificate, leaf: &Certificate) -> bool {
    &cert.ext_name_constraints matches Some(constraints) ==> {
        &&& valid_dns_name_constraints(&constraints)
        &&& constraints.permitted.len() != 0 || constraints.excluded.len() != 0

        // Check SAN section against name constraints
        &&& &leaf.ext_subject_alt_name matches Some(leaf_san)
        &&& check_san_name_constraints(leaf_san, constraints)

        &&& check_subject_name_constraints(leaf, constraints)
    }
}

pub open spec fn cert_verified_intermediate(env: &Environment, cert: &Certificate, leaf: &Certificate, depth: usize) -> bool {
    &&& cert_verified_non_leaf(env, cert, depth)
    &&& not_in_crl(env, cert)
    &&& strong_signature(&cert.sig_alg)
    &&& key_usage_valid(cert)
    &&& extended_key_usage_valid(cert)
    &&& check_name_constraints(cert, leaf)
}

/// NOTE: badSymantec in Hammurabi
pub open spec fn is_bad_symantec_root(env: &Environment, cert: &Certificate) -> bool {
    &&& exists |i: usize| 0 <= i < env.symantec_roots.len() && &cert.fingerprint == &env.symantec_roots[i as int]
    &&& forall |i: usize| 0 <= i < env.symantec_exceptions.len() ==> &cert.fingerprint != &env.symantec_exceptions[i as int]
    &&& {
        ||| cert.not_before < 1464739200 // June 2016
        ||| cert.not_before > 1512086400 // Dec 2017
    }
}

/// NOTE: fingerprintValid in Hammurabi
pub open spec fn valid_root_fingerprint(env: &Environment, cert: &Certificate, domain: &SpecString) -> bool {
    // &&& exists |i: usize| 0 <= i < env.trusted.len() && &cert.fingerprint == &env.trusted[i as int]

    let is_india_fingerprint = exists |i: usize| 0 <= i < env.india_trusted.len() && &cert.fingerprint == &env.india_trusted[i as int];
    let is_anssi_fingerprint = exists |i: usize| 0 <= i < env.anssi_trusted.len() && &cert.fingerprint == &env.anssi_trusted[i as int];

    &&& is_india_fingerprint ==> exists |i: usize| #![auto] 0 <= i < env.india_domains.len() && match_name(&env.india_domains[i as int], &domain)
    &&& is_anssi_fingerprint ==> exists |i: usize| #![auto] 0 <= i < env.anssi_domains.len() && match_name(&env.anssi_domains[i as int], &domain)
}

pub open spec fn cert_verified_root(env: &Environment, cert: &Certificate, leaf: &Certificate, depth: usize, domain: &SpecString) -> bool {
    &&& cert_verified_non_leaf(env, cert, depth)

    &&& &cert.ext_key_usage matches Some(key_usage) ==> key_usage.crl_sign

    &&& valid_root_fingerprint(env, cert, domain)
    &&& !is_bad_symantec_root(env, cert)
    &&& extended_key_usage_valid(cert)
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
                &&& cert_verified_leaf(env, leaf, &domain)
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

} // rspec!

/// A validated chain should not contain expired certificates
proof fn property_non_expiring(env: &Environment, chain: &Seq<Certificate>, task: &Task)
    requires valid_chain(env, chain, task) == PolicyResult::Valid
    ensures
        forall |i: usize| #![trigger chain[i as int]] 0 <= i < chain.len() ==>
            chain[i as int].not_before < env.time < chain[i as int].not_after
{
    assert(chain[0].not_before < env.time < chain[0].not_after);
}

} // verus!
