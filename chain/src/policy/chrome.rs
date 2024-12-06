#![allow(unused_parens)]

use vstd::prelude::*;
use rspec::rspec;
use rspec_lib::*;

use super::common::*;

verus! {

rspec! {

use ExecAttribute as Attribute;
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
use ExecPolicyError as PolicyError;

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
        SubjectKey::DSA { p_len, .. } => p_len >= 1024,
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
    &cert.ext_key_usage matches Some(key_usage)
    ==>
        if &cert.ext_basic_constraints matches Some(bc) && bc.is_ca {
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

pub open spec fn match_san(san: &SubjectAltName, name: &SpecString) -> bool {
    exists |i: usize| 0 <= i < san.names.len() && {
        &&& #[trigger] &san.names[i as int] matches GeneralName::DNSName(dns_name)
        &&& match_name(&clean_name(dns_name), &name)
    }
}

/// Domain matches one of the SANs
pub open spec fn match_san_domain(env: &Environment, cert: &Certificate, domain: &SpecString) -> bool {
    &&& &cert.ext_subject_alt_name matches Some(san)
    &&& valid_san(env, san)
    &&& match_san(san, domain)
}

pub open spec fn cert_verified_leaf(env: &Environment, cert: &Certificate, domain: &SpecString) -> bool {
    &&& cert.version == 2
    &&& is_valid_pki(cert)

    &&& &cert.sig_alg_inner.bytes == &cert.sig_alg_outer.bytes
    &&& cert.not_before < env.time
    &&& cert.not_after > env.time

    &&& match_san_domain(env, cert, domain)

    &&& leaf_duration_valid(cert)

    &&& not_in_crl(env, cert)
    &&& strong_signature(&cert.sig_alg_inner.id)
    &&& key_usage_valid(cert)
    &&& extended_key_usage_valid(cert)

    &&& &cert.ext_basic_constraints matches Some(bc) ==> (bc.path_len matches Some(limit) ==> limit >= 0)
    &&& (cert.issuer_uid matches Some(_) || cert.subject_uid matches Some(_)) ==> cert.version == 2 || cert.version == 3
}

pub open spec fn cert_verified_non_leaf(env: &Environment, cert: &Certificate, depth: usize) -> bool {
    &&& cert.version == 2
    &&& is_valid_pki(cert)

    &&& &cert.sig_alg_inner.bytes == &cert.sig_alg_outer.bytes
    &&& cert.not_before < env.time
    &&& cert.not_after > env.time

    &&& &cert.ext_basic_constraints matches Some(bc)
    &&& bc.is_ca
    &&& bc.path_len matches Some(limit) ==> limit >= 0 && depth <= limit as usize
    &&& key_usage_valid(cert)
    &&& extended_key_usage_valid(cert)

    &&& (cert.issuer_uid matches Some(_) || cert.subject_uid matches Some(_)) ==> cert.version == 2 || cert.version == 3
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
                &&& is_subtree_of(&permitted_name, &leaf.subject_name, true)
            }

    // Not explicitly excluded
    &&& forall |j: usize| 0 <= j < constraints.excluded.len() ==>
            (#[trigger] &constraints.excluded[j as int] matches GeneralName::DirectoryName(excluded_name) ==>
                !is_subtree_of(&excluded_name, &leaf.subject_name, true))
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
    &&& strong_signature(&cert.sig_alg_inner.id)
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

pub open spec fn cert_verified_root(env: &Environment, cert: &Certificate, depth: usize, domain: &SpecString) -> bool {
    &&& cert_verified_non_leaf(env, cert, depth)

    &&& &cert.ext_key_usage matches Some(key_usage) ==> key_usage.crl_sign

    &&& valid_root_fingerprint(env, cert, domain)
    &&& !is_bad_symantec_root(env, cert)
}

/// chain[0] is the leaf, and assume chain[i] is issued by chain[i + 1] for all i < chain.len() - 1
/// chain.last() must be a trusted root
pub open spec fn valid_chain(env: &Environment, chain: &Seq<Certificate>, task: &Task) -> Result<bool, PolicyError>
{
    match task {
        Task::DomainValidation(domain) => {
            let domain = str_lower(domain);

            Ok(chain.len() >= 2 && {
                let leaf = &chain[0];
                let root = &chain[chain.len() - 1];

                &&& forall |i: usize| 0 <= i < chain.len() - 1 ==> check_auth_key_id(&chain[i + 1], #[trigger] &chain[i as int])
                &&& cert_verified_leaf(env, leaf, &domain)
                &&& forall |i: usize| 1 <= i < chain.len() - 1 ==> cert_verified_intermediate(&env, #[trigger] &chain[i as int], &leaf, (i - 1) as usize)
                &&& cert_verified_root(env, root, (chain.len() - 2) as usize, &domain)
            })
        }
        _ => Err(PolicyError::UnsupportedTask),
    }
}

} // rspec!

/// A subset of RFC rules
proof fn rfc_properties(env: &Environment, chain: &Seq<Certificate>, task: &Task)
    requires valid_chain(env, chain, task) == Ok::<_, PolicyError>(true)
    ensures
        // A validated chain should not contain expired certificates
        forall |i: usize| #![trigger chain[i as int]] 0 <= i < chain.len() ==>
            chain[i as int].not_before < env.time < chain[i as int].not_after,

        // Outer signature algorithm should match the inner one
        forall |i: usize| #![trigger chain[i as int]] 0 <= i < chain.len() ==>
            chain[i as int].sig_alg_inner.bytes == chain[i as int].sig_alg_outer.bytes,

        // If the extension KeyUsage is present, at least one bit must be set
        forall |i: usize| #![trigger chain[i as int]] 0 <= i < chain.len() ==>
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
            }),

        // Issuer and subject UID should only appear if version is 2 or 3
        forall |i: usize| #![trigger chain[i as int]] 0 <= i < chain.len() ==>
            (chain[i as int].issuer_uid matches Some(_) || chain[i as int].subject_uid matches Some(_))
            ==>
            chain[i as int].version == 2 || chain[i as int].version == 3,

        // PathLenConstraints should be non-negative
        forall |i: usize| #![trigger chain[i as int]] 0 <= i < chain.len() ==>
            (chain[i as int].ext_basic_constraints matches Some(bc)
            ==> (bc.path_len matches Some(limit) ==> limit >= 0)),

        // If SubjectAltName is present, it should contain at least one name
        // NOTE: not checked for intermediate certs
        // forall |i: usize| #![trigger chain[i as int]] 0 <= i < chain.len() ==>
        //     chain[i as int].ext_subject_alt_name matches Some(san) ==> san.names.len() > 0,

        // If BasicConstraints.PathLenConstraint is present,
        // is_ca is set, and key_usage.key_cert_sign is set (if present)
        // then the cert must not be followed by more than PathLenConstraint
        // non-leaf certificates
        forall |i: usize| #![trigger chain[i as int]] 0 <= i < chain.len() ==> {
            &chain[i as int].ext_basic_constraints matches Some(bc) ==> {
                bc.path_len matches Some(limit) ==> {
                    bc.is_ca && (chain[i as int].ext_key_usage matches Some(key_usage) ==> key_usage.key_cert_sign)
                    ==>
                    (i - 1) <= limit as usize
                }
            }
        },

        // Every non-leaf certificate must be a CA certificate
        forall |i: usize| #![trigger chain[i as int]] 1 <= i < chain.len() ==>
            (&chain[i as int].ext_basic_constraints matches Some(bc) && bc.is_ca),

        // Every non-leaf certificate must have keyCertSign set in KeyUsage (if present)
        forall |i: usize| #![trigger chain[i as int]] 1 <= i < chain.len() ==>
            (&chain[i as int].ext_key_usage matches Some(key_usage) ==> key_usage.key_cert_sign),
{
    assert(chain[0].not_before < env.time < chain[0].not_after);
}

} // verus!
