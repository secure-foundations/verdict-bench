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

    /// All trusted root stores
    pub trusted: Seq<SpecString>,

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

// pub open spec fn is_ev_leaf(env: &Environment, cert: &Certificate) -> bool {
//     match &cert.ext_certificate_policies {
//         Some(ext) => {
//             // Contains a policy with the same OID as one of env.ev_policy
//             exists |i: usize| 0 <= i < env.ev_policies.len() &&
//                 exists |j: usize| 0 <= j < ext.policies.len() &&
//                     &ext.policies[j as int] == &env.ev_policies[i as int].oid
//         }

//         None => false,
//     }
// }

// pub open spec fn is_ev_intermediate(env: &Environment, cert: &Certificate, prev_oid: &SpecString) -> bool {
//     false
// }

// pub open spec fn is_ev_root(env: &Environment, cert: &Certificate, prev_oid: &SpecString) -> bool {
//     exists |i: usize| 0 <= i < env.ev_policies.len() &&
//         match &cert.ext_certificate_policies {
//             Some(ext) => exists |j: usize| 0 <= j < ext.policies.len() &&
//                 &ext.policies[j as int] == &env.ev_policies[i as int].oid,
//             None => false,
//         }
// }

/// TODO: getEVStatus, this requires some searching that is currently not supported
/// See https://wiki.mozilla.org/EV
pub open spec fn is_ev_chain(env: &Environment, chain: &Seq<Certificate>) -> bool {
    false
    // chain.len() >= 2 && {
    //     let leaf = &chain[0];
    //     let root = &chain[chain.len() - 1];

    //     &&& is_ev_leaf(env, leaf)
    //     &&& forall |i: usize| 1 <= i < chain.len() - 1 ==> {
    //         is_ev_intermediate(env, #[trigger] &chain[i as int])
    //     }
    //     &&& is_ev_root(env, root)
    // }
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

pub open spec fn not_revoked(env: &Environment, cert: &Certificate) -> bool {
    ||| cert.not_after >= cert.not_before && cert.not_after - cert.not_before < 864001 // 10 days

    // notOCSPRevoked
    ||| true
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
        name_match(&str_lower(#[trigger] &san.names[i as int]), &domain)
}

pub open spec fn is_suffix_of(a: &SpecString, b: &SpecString) -> bool {
    a.len() <= b.len() && &b.skip(b.len() - a.len()) == a
}

pub open spec fn has_subject_name(cert: &Certificate, oid: &SpecString, value: &SpecString) -> bool {
    exists |i: usize| #![auto] 0 <= i < cert.subject_name.len() && {
        &cert.subject_name[i as int].oid == oid &&
        &cert.subject_name[i as int].value == value
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
    forall |i: usize| #![auto] 0 <= i < san.names.len() ==>
        !is_international_invalid_name(&cert, &san.names[i as int])
}

// internationalInvalidIntermediate in Hammurabi
pub open spec fn is_international_invalid_non_leaf(cert: &Certificate, leaf: &Certificate) -> bool {
    &&& match &leaf.ext_subject_alt_name {
        Some(san) => is_international_invalid_san(&cert, san),
        None => true,
    }
    // No common name is invalid
    &&& forall |i: usize| #![auto] 0 <= i < leaf.subject_name.len() ==> !{
        &&& &leaf.subject_name[i as int].oid == "2.5.4.3"@
        &&& is_international_invalid_name(&cert, &leaf.subject_name[i as int].value)
    }
}

pub open spec fn cert_verified_non_leaf(env: &Environment, cert: &Certificate, leaf: &Certificate, depth: usize) -> bool {
    &&& is_international_valid(env, cert, leaf)
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

pub open spec fn is_international_valid_name(env: &Environment, cert: &Certificate, name: &SpecString) -> bool {
    let is_tubitak1_fingerprint = exists |i: usize| 0 <= i < env.tubitak1_trusted.len() && &cert.fingerprint == &env.tubitak1_trusted[i as int];
    let is_anssi_fingerprint = exists |i: usize| 0 <= i < env.anssi_trusted.len() && &cert.fingerprint == &env.anssi_trusted[i as int];

    &&& !is_tubitak1_fingerprint ||
        exists |i: usize| #![auto] 0 <= i < env.tubitak1_domains.len() &&
            name_match(&env.tubitak1_domains[i as int], &name)
    &&& !is_anssi_fingerprint ||
        exists |i: usize| #![auto] 0 <= i < env.anssi_domains.len() &&
            name_match(&env.anssi_domains[i as int], &name)
}

pub open spec fn is_international_valid_san(env: &Environment, cert: &Certificate, san: &SubjectAltName, leaf: &Certificate) -> bool {
    exists |i: usize| 0 <= i < san.names.len() &&
        is_international_valid_name(&env, &cert, #[trigger] &san.names[i as int])
}

/// internationalValid in Hammurabi
/// https://wiki.mozilla.org/CA/Additional_Trust_Changes#ANSSI
///
/// TODO: this seems a bit weird, since it only checks if there is one valid SAN?
pub open spec fn is_international_valid(env: &Environment, cert: &Certificate, leaf: &Certificate) -> bool {
    match &leaf.ext_subject_alt_name {
        Some(san) => is_international_valid_san(env, cert, san, leaf),
        None => true,
    }
}

pub open spec fn same_directory_name_type(name1: &DirectoryName, name2: &DirectoryName) -> bool {
    &name1.oid == &name2.oid
}

pub open spec fn same_directory_name(name1: &DirectoryName, name2: &DirectoryName) -> bool {
    &name1.oid == &name2.oid && &name1.value == &name2.value
}

pub open spec fn cert_verified_root(env: &Environment, cert: &Certificate, leaf: &Certificate, depth: usize, domain: &SpecString) -> bool {
    &&& cert_verified_non_leaf(env, cert, leaf, depth)

    &&& exists |i: usize| 0 <= i < env.trusted.len() &&
        &cert.fingerprint == &env.trusted[i as int]

    &&& !is_bad_symantec_root(env, cert)
    &&& is_international_valid(env, cert, leaf)
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
            //
            // NOTE: Firefox policy differs slightly from Chrome
            // here where in Chrome, this check is disabled if
            // permitted_enabled is false
            &&& forall |j: usize| 0 <= j < constraints.excluded.len() ==>
                match #[trigger] &constraints.excluded[j as int] {
                    GeneralName::DirectoryName(excluded_name) =>
                        !same_directory_name(&leaf_name, &excluded_name),
                    _ => true,
                }
        }
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

pub open spec fn has_permitted_dns_name(constraints: &NameConstraints) -> bool {
    exists |j: usize|
        0 <= j < constraints.permitted.len() &&
        match #[trigger] constraints.permitted[j as int] {
            GeneralName::DNSName(_) => true,
            _ => false,
        }
}

/// Check a (cleaned) DNS name against name constraints
/// NOTE: no name cleaning like in Chrome
pub open spec fn check_dns_name_constraints(name: &SpecString, constraints: &NameConstraints) -> bool {
    // Check that `name` is permitted by some name constraint in `permitted`
    &&& !has_permitted_dns_name(constraints) ||
        exists |i: usize| 0 <= i < constraints.permitted.len() && {
            match #[trigger] &constraints.permitted[i as int] {
                GeneralName::DNSName(permitted_name) =>
                    permit_name(&permitted_name, &name),
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
            &&san.names[i as int],
            &constraints,
        )
}

pub open spec fn check_common_name_constraints(cert: &Certificate, constraints: &NameConstraints) -> bool {
    forall |i: usize| #![auto] 0 <= i < cert.subject_name.len() ==> {
        &&& &cert.subject_name[i as int].oid == "2.5.4.3"@ // common name
        &&& check_dns_name_constraints(
            &cert.subject_name[i as int].value,
            &constraints,
        )
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
                // Otherwise fall back to common name
                None => check_common_name_constraints(leaf, constraints),
            }

            // Excluded constraints do not conatin any "domain component" directory name
            // NOTE: this is an additional check in Firefox not in Chrome
            &&& forall |i: usize| 0 <= i < constraints.excluded.len() ==>
                match #[trigger] &constraints.excluded[i as int] {
                    GeneralName::DirectoryName(excluded) =>
                        &excluded.oid != "0.9.2342.19200300.100.1.25"@,
                    _ => true,
                }

            &&& check_subject_name_constraints(leaf, constraints)
        }
        None => true,
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

    &&& match &cert.ext_basic_constraints {
        Some(bc) => !bc.is_ca,
        None => true,
    }

    // leafDurationValid in Hammurabi
    &&& !ev || {
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

        &&& cert_verified_leaf(env, leaf, domain, is_ev_chain(env, chain))
        &&& forall |i: usize| 1 <= i < chain.len() - 1 ==> cert_verified_intermediate(&env, #[trigger] &chain[i as int], &leaf, (i - 1) as usize)
        &&& cert_verified_root(env, root, leaf, (chain.len() - 2) as usize, domain)
    }
}

}

}
