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

    /// This should include all of `publicSuffix` in Hammurabi
    /// and all of their suffixes
    pub public_suffix: Seq<SpecString>,

    /// NOTE: crlSet in Hammurabi
    pub crl: Seq<SpecString>,

    /// All trusted root stores
    pub trusted: Seq<SpecString>,

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
    match &cert.ext_basic_constraints {
        Some(bc) =>
            match &cert.ext_key_usage {
                Some(key_usage) =>
                    if bc.is_ca {
                        key_usage.key_cert_sign
                    } else {
                        !key_usage.key_cert_sign && {
                            ||| key_usage.digital_signature
                            ||| key_usage.key_encipherment
                            ||| key_usage.key_agreement
                        }
                    }
                _ => true,
            }
        _ => true,
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
            !name_match(&name, #[trigger] &env.public_suffix[i as int])
    } else {
        &&& name.len() > 0
        &&& name.char_at(0) != '.'
        &&& name.char_at(name.len() - 1) != '.'
    }
}

pub open spec fn valid_san(env: &Environment, san: &SubjectAltName) -> bool {
    &&& san.names.len() > 0
    &&& forall |i: usize| 0 <= i < san.names.len() ==>
        valid_name(&env, #[trigger] &san.names[i as int])
}

pub open spec fn name_match_san(env: &Environment, san: &SubjectAltName, name: &SpecString) -> bool {
    exists |i: usize| 0 <= i < san.names.len() &&
        name_match(&clean_name(#[trigger] &san.names[i as int]), &name)
}

/// Domain matches one of the SANs
pub open spec fn domain_matches_san(env: &Environment, cert: &Certificate, domain: &SpecString) -> bool {
    match &cert.ext_subject_alt_name {
        Some(san) => {
            &&& valid_san(env, san)
            &&& name_match_san(env, san, domain)
        }
        None => false,
    }
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

    &&& match &cert.ext_basic_constraints {
        Some(bc) => {
            &&& bc.is_ca
            &&& match bc.path_len {
                Some(limit) => depth <= limit,
                None => true,
            }
        }
        None => false,
    }
}

pub open spec fn valid_name_constraint(name: &SpecString) -> bool {
    let name = clean_name(name);
    &&& name.len() > 0
    &&& name.char_at(name.len() - 1) != '.'
    &&& !name.has_char('*')
}

pub open spec fn permit_name(name_constraint: &SpecString, name: &SpecString) -> bool {
    ||| name_constraint.len() == 0 // empty string matches everything
    ||| if name_constraint.char_at(0) == '.' {
        // name_constraint starts with '.': name_constraint should be a suffix of name
        &&& name_constraint.len() <= name.len()
        &&& &name.skip(name.len() - name_constraint.len()) == name_constraint
    } else {
        // name_constraint starts with a label: name must be the same
        // or have a suffix of '.<name_constraint>'
        ||| name == name_constraint
        ||| name.len() > name_constraint.len() &&
            name.char_at(name.len() - name_constraint.len() - 1) == '.' &&
            &name.skip(name.len() - name_constraint.len()) == name_constraint
    }
}

/// NOTE: nameNotExcluded in Hammurabi
pub open spec fn not_exclude_name(name_constraint: &SpecString, name: &SpecString) -> bool {
    // TODO: Check if this is equivalent to Hammmurabi
    !permit_name(name_constraint, name)
}

pub open spec fn same_directory_name_type(name1: &DirectoryName, name2: &DirectoryName) -> bool {
    &name1.oid == &name2.oid
}

pub open spec fn same_directory_name(name1: &DirectoryName, name2: &DirectoryName) -> bool {
    &name1.oid == &name2.oid && &name1.value == &name2.value
}

pub open spec fn has_permitted_dns_name(constraints: &NameConstraints) -> bool {
    exists |j: usize|
        0 <= j < constraints.permitted.len() &&
        match #[trigger] constraints.permitted[j as int] {
            GeneralName::DNSName(_) => true,
            _ => false,
        }
}

/// All (permitted/excluded) DNS name constraints are valid
pub open spec fn valid_dns_name_constraints(constraints: &NameConstraints) -> bool {
    &&& forall |i: usize| 0 <= i < constraints.permitted.len() ==> {
        match #[trigger] &constraints.permitted[i as int] {
            GeneralName::DNSName(permitted_name) => valid_name_constraint(&permitted_name),
            _ => true,
        }
    }

    &&& forall |i: usize| 0 <= i < constraints.excluded.len() ==> {
        match #[trigger] &constraints.excluded[i as int] {
            GeneralName::DNSName(excluded_name) => valid_name_constraint(&excluded_name),
            _ => true,
        }
    }
}

/// Check a (cleaned) DNS name against name constraints
pub open spec fn check_dns_name_constraints(name: &SpecString, constraints: &NameConstraints) -> bool {
    let name = clean_name(name);

    // Check that `name` is permitted by some name constraint in `permitted`
    &&& !has_permitted_dns_name(constraints) ||
        exists |i: usize| 0 <= i < constraints.permitted.len() && {
            match #[trigger] &constraints.permitted[i as int] {
                GeneralName::DNSName(permitted_name) =>
                    permit_name(&permitted_name, &clean_name(&name)),
                _ => false,
            }
        }

    // Check that `name` is not covered by any name constraint in `excluded`
    &&& forall |i: usize| 0 <= i < constraints.excluded.len() ==>
        match #[trigger] &constraints.excluded[i as int] {
            GeneralName::DNSName(excluded_name) =>
                not_exclude_name(&excluded_name, &name),
            _ => true,
        }
}

/// Check the entire SAN section against name constraints
/// NOTE: factored out due to a proof issue related to nested matches
pub open spec fn check_san_name_constraints(san: &SubjectAltName, constraints: &NameConstraints) -> bool {
    forall |i: usize| #![auto] 0 <= i < san.names.len() ==>
        check_dns_name_constraints(
            &clean_name(&san.names[i as int]),
            &constraints,
        )
}

/// Check if there is any permitted name with the same type as the given name
/// (if so, the permitted list is enabled)
pub open spec fn has_permitted_dir_name_with_the_same_type(constraints: &NameConstraints, name: &DirectoryName) -> bool {
    exists |i: usize| #![trigger constraints.permitted[i as int]]
        0 <= i < constraints.permitted.len() &&
        match &constraints.permitted[i as int] {
            GeneralName::DirectoryName(permitted_name) =>
                same_directory_name_type(&name, &permitted_name),
            _ => false,
        }
}

/// Only certain directory name types are checked
pub open spec fn is_checked_directory_name_type(name: &DirectoryName) -> bool {
    ||| &name.oid == "2.5.4.6"@ // country
    ||| &name.oid == "2.5.4.10"@ // organization
    ||| &name.oid == "2.5.4.42"@ // given name
    ||| &name.oid == "2.5.4.4"@ // surname
    ||| &name.oid == "2.5.4.8"@ // state
    ||| &name.oid == "2.5.4.9"@ // street address
    ||| &name.oid == "2.5.4.7"@ // locality
    ||| &name.oid == "2.5.4.17"@ // postal code
}

/// Check subject names in the leaf cert against name constraints
pub open spec fn check_subject_name_constraints(leaf: &Certificate, constraints: &NameConstraints) -> bool {
    forall |i: usize| 0 <= i < leaf.subject_name.len() ==> {
        let leaf_name = #[trigger] &leaf.subject_name[i as int];
        let permitted_enabled = has_permitted_dir_name_with_the_same_type(&constraints, leaf_name);

        // TODO: some oddity: in Hammurabi, the name constraints are all flattened (originally it is a list general names, which
        // in the case of directory names, is essentially Vec<Vec<Vec<(OID, value)>>>)
        // but when subject name of the cert is encoded, only the *last* one corresponding to each OID is recorded
        // see, e.g., https://github.com/semaj/hammurabi/blob/16b253ebd8e2768f9295439bf70e2d50954fba73/src/cert.rs#L206
        // so the check here should be only done against the last name in each OID
        // For an example using this, see certificate 4106d1f3f6a02098aa6b84289c7a68ecbd6904f73b720c44f6cb3e12cc0662ea in part-10 of mega-crl

        !is_checked_directory_name_type(&leaf_name) || {
            // If permitted list is enabled, check if `leaf_name`
            // is at least permitted by one of them
            &&& !permitted_enabled ||
                exists |j: usize| 0 <= j < constraints.permitted.len() && {
                    match #[trigger] &constraints.permitted[j as int] {
                        GeneralName::DirectoryName(permitted_name) =>
                            same_directory_name(&leaf_name, &permitted_name),
                        _ => false,
                    }
                }

            // Not explicitly excluded
            &&& forall |j: usize| 0 <= j < constraints.excluded.len() ==>
                match #[trigger] &constraints.excluded[j as int] {
                    GeneralName::DirectoryName(excluded_name) =>
                        !same_directory_name(&leaf_name, &excluded_name),
                    _ => true,
                }
        }
    }
}

/// Check a leaf certificate against the name constraints in a parent certificate
pub open spec fn check_name_constraints(cert: &Certificate, leaf: &Certificate) -> bool {
    match &cert.ext_name_constraints {
        Some(constraints) => {
            &&& valid_dns_name_constraints(&constraints)
            &&& constraints.permitted.len() != 0 || constraints.excluded.len() != 0

            // Check SAN section against name constraints
            &&& match &leaf.ext_subject_alt_name {
                Some(leaf_san) => check_san_name_constraints(leaf_san, constraints),
                None => false,
            }

            &&& check_subject_name_constraints(leaf, constraints)
        }
        None => true,
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

/// NOTE: isChromeRoot in Hammurabi
pub open spec fn is_chrome_root(env: &Environment, cert: &Certificate, domain: &SpecString) -> bool {
    &&& exists |i: usize| 0 <= i < env.trusted.len() && &cert.fingerprint == &env.trusted[i as int]

    // See fingerprintValid in Hammurabi
    &&& {
        let is_india_fingerprint = exists |i: usize| 0 <= i < env.india_trusted.len() && &cert.fingerprint == &env.india_trusted[i as int];
        let is_anssi_fingerprint = exists |i: usize| 0 <= i < env.anssi_trusted.len() && &cert.fingerprint == &env.anssi_trusted[i as int];

        &&& !is_india_fingerprint || exists |i: usize| #![auto] 0 <= i < env.india_domains.len() && name_match(&env.india_domains[i as int], &domain)
        &&& !is_anssi_fingerprint || exists |i: usize| #![auto] 0 <= i < env.anssi_domains.len() && name_match(&env.anssi_domains[i as int], &domain)
    }
}

pub open spec fn cert_verified_root(env: &Environment, cert: &Certificate, leaf: &Certificate, depth: usize, domain: &SpecString) -> bool {
    &&& cert_verified_non_leaf(env, cert, depth)

    &&& match &cert.ext_key_usage {
        Some(key_usage) => key_usage.key_cert_sign,
        None => true,
    }

    &&& is_chrome_root(env, cert, domain)
    &&& !is_bad_symantec_root(env, cert)
    &&& extended_key_usage_valid(cert)
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

} // rspec!

} // verus!
