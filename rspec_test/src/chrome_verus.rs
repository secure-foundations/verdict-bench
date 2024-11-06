use vstd::prelude::*;
use crate::chrome::*;
use rspec_lib::*;

verus! {

pub open spec fn is_valid_pki(cert: Certificate) -> bool {
    match cert.subject_key {
        SubjectKey::RSA { mod_length } => mod_length >= 1024,
        SubjectKey::DSA { p_len, q_len, g_len } => p_len >= 1024,
        SubjectKey::Other => true,
    }
}

/// See std:stringMatch in Hammurabi
/// Matching name against pattern
/// pattern can be a string without '*'
/// or with '*.' occurring at the beginning
/// and '*' matches any string without '.'
pub open spec fn name_match(pattern: SpecString, name: SpecString) -> bool {
    if pattern.len() > 2 && pattern[0] == '*' && pattern[1] == '.' {
        let suffix = pattern.skip(2);

        ||| suffix == name
        ||| suffix.len() + 1 < name.len() && // `name` should be longer than ".{suffix}"
            suffix == name.skip(name.len() - suffix.len()) &&
            name[name.len() - suffix.len() - 1] == '.' &&
            // the prefix of `name` that matches '*' should not contain '.'
            !name.take(name.len() - suffix.len() - 1).contains('.')
    } else {
        pattern == name
    }
}

/// NOTE: leafDurationValid in Hammurabi
pub open spec fn leaf_duration_valid(cert: Certificate) -> bool {
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

pub open spec fn not_in_crl(env: Environment, cert: Certificate) -> bool {
    forall |i| 0 <= i < env.crl.len() ==> cert.fingerprint != env.crl[i]
}

pub open spec fn strong_signature(alg: SpecString) -> bool {
    // ECDSA + SHA512
    ||| alg == "1.2.840.10045.4.3.2".view()
    // ECDSA + SHA384
    ||| alg == "1.2.840.10045.4.3.3".view()
    // ECDSA + SHA512
    ||| alg == "1.2.840.10045.4.3.4".view()
    // RSA + SHA256
    ||| alg == "1.2.840.113549.1.1.11".view()
    // RSA + SHA384
    ||| alg == "1.2.840.113549.1.1.12".view()
    // RSA + SHA512
    ||| alg == "1.2.840.113549.1.1.13".view()
    // RSA-PSS + SHA256
    ||| alg == "1.2.840.113549.1.1.10".view()
}

pub open spec fn key_usage_valid(cert: Certificate) -> bool {
    match (cert.ext_basic_constraints, cert.ext_key_usage) {
        (Some(bc), Some(key_usage)) => {
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
        _ => true,
    }
}

pub open spec fn extended_key_usage_valid(cert: Certificate) -> bool {
    match cert.ext_extended_key_usage {
        Some(key_usage) => {
            ||| key_usage.usages.contains(ExtendedKeyUsageTypes::ServerAuth)
            ||| key_usage.usages.contains(ExtendedKeyUsageTypes::Any)
        }
        None => true,
    }
}

pub closed spec fn str_lower(s: Seq<char>) -> Seq<char>;

#[verifier::external_body]
fn exec_str_lower(s: &str) -> (res: String)
    ensures res@ == str_lower(s@)
{
    s.to_lowercase()
}

/// TODO: URI encoding
pub open spec fn clean_name(name: SpecString) -> SpecString {
    let lower = str_lower(name);

    if lower.len() > 0 && lower.last() == '.' {
        lower.drop_last()
    } else {
        lower
    }
}

pub open spec fn valid_name(env: Environment, name: SpecString) -> bool {
    if name.contains('*') {
        &&& name.len() > 2
        &&& name[0] == '*'
        &&& name[1] == '.'
        &&& name.last() != '.'
        &&& forall |i| 0 <= i < env.public_suffix.len() ==>
            !name_match(name, #[trigger] env.public_suffix[i])
    } else {
        &&& name.len() > 0
        &&& name[0] != '.'
        &&& name.last() != '.'
    }
}

pub open spec fn cert_verified_leaf(env: Environment, cert: Certificate, domain: SpecString) -> bool {
    &&& cert.version == 2
    &&& is_valid_pki(cert)

    &&& cert.not_before < env.time
    &&& cert.not_after > env.time

    // Domain matches one of the SANs
    &&& cert.ext_subject_alt_name matches Some(subject_alt_name)
    &&& subject_alt_name.names.len() > 0
    &&& forall |i| #![auto] 0 <= i < subject_alt_name.names.len() ==>
            valid_name(env, subject_alt_name.names[i])
    &&& exists |i| #![auto] 0 <= i < subject_alt_name.names.len() &&
            name_match(clean_name(subject_alt_name.names[i]), domain)

    &&& leaf_duration_valid(cert)

    &&& not_in_crl(env, cert)
    &&& strong_signature(cert.sig_alg)
    &&& key_usage_valid(cert)
    &&& extended_key_usage_valid(cert)
}

pub open spec fn cert_verified_non_leaf(env: Environment, cert: Certificate, depth: int) -> bool {
    &&& cert.version == 2
    &&& is_valid_pki(cert)

    &&& cert.not_before < env.time
    &&& cert.not_after > env.time

    &&& cert.ext_basic_constraints matches Some(bc)
    &&& bc.path_len matches Some(limit) ==> depth <= limit
    &&& bc.is_ca
}

pub open spec fn valid_name_constraint(name: SpecString) -> bool {
    let name = clean_name(name);
    &&& name.len() > 0
    &&& name.last() != '.'
    &&& !name.contains('*')
}

/// NOTE: namePermitted in Hammurabi
pub open spec fn permit_name(name_constraint: SpecString, name: SpecString) -> bool {
    ||| name_constraint.len() == 0 // empty string matches everything
    ||| if name_constraint[0] == '.' {
        // name_constraint starts with '.': name_constraint should be a suffix of name
        &&& name_constraint.len() <= name.len()
        &&& name.skip(name.len() - name_constraint.len()) == name_constraint
    } else {
        // name_constraint starts with a label: name must be the same
        // or have a suffix of '.<name_constraint>'
        ||| name == name_constraint
        ||| name.len() > name_constraint.len() &&
            name[name.len() - name_constraint.len() - 1] == '.' &&
            name.skip(name.len() - name_constraint.len()) == name_constraint
    }
}

/// NOTE: nameNotExcluded in Hammurabi
pub open spec fn not_exclude_name(name_constraint: SpecString, name: SpecString) -> bool {
    // TODO: Check if this is correct
    !permit_name(name_constraint, name)
}

pub open spec fn same_directory_name_type(name1: DirectoryName, name2: DirectoryName) -> bool {
    match (name1, name2) {
        (DirectoryName::CommonName(_), DirectoryName::CommonName(_)) => true,
        (DirectoryName::Country(_), DirectoryName::Country(_)) => true,
        (DirectoryName::OrganizationName(_), DirectoryName::OrganizationName(_)) => true,
        (DirectoryName::OrganizationalUnit(_), DirectoryName::OrganizationalUnit(_)) => true,
        (DirectoryName::Locality(_), DirectoryName::Locality(_)) => true,
        (DirectoryName::State(_), DirectoryName::State(_)) => true,
        (DirectoryName::PostalCode(_), DirectoryName::PostalCode(_)) => true,
        (DirectoryName::Surname(_), DirectoryName::Surname(_)) => true,
        _ => false,
    }
}

pub open spec fn same_directory_name(name1: DirectoryName, name2: DirectoryName) -> bool {
    match (name1, name2) {
        (DirectoryName::CommonName(name1), DirectoryName::CommonName(name2)) => name1 == name2,
        (DirectoryName::Country(name1), DirectoryName::Country(name2)) => name1 == name2,
        (DirectoryName::OrganizationName(name1), DirectoryName::OrganizationName(name2)) => name1 == name2,
        (DirectoryName::OrganizationalUnit(name1), DirectoryName::OrganizationalUnit(name2)) => name1 == name2,
        (DirectoryName::Locality(name1), DirectoryName::Locality(name2)) => name1 == name2,
        (DirectoryName::State(name1), DirectoryName::State(name2)) => name1 == name2,
        (DirectoryName::PostalCode(name1), DirectoryName::PostalCode(name2)) => name1 == name2,
        (DirectoryName::Surname(name1), DirectoryName::Surname(name2)) => name1 == name2,
        _ => false,
    }
}

pub open spec fn check_name_constraints(cert: Certificate, leaf: Certificate) -> bool {
    cert.ext_name_constraints matches Some(constraints) ==> {
        // Permitted check if enabled only if there is at least one DNS name
        // in the permitted list
        let has_permitted_dns_name = exists |j|
            0 <= j < constraints.permitted.len() &&
            (#[trigger] constraints.permitted[j]) matches GeneralName::DNSName(permitted_name);

        &&& constraints.permitted.len() != 0 || constraints.excluded.len() != 0

        // Leaf SANs should be in permitted (if permitted.len() != 0)
        // and not in any of the excluded
        // NOTE: see dnsNameConstrained in Hammurabi
        &&& leaf.ext_subject_alt_name matches Some(leaf_san)
        &&& forall |i| 0 <= i < leaf_san.names.len() ==> {
            let leaf_name = clean_name(#[trigger] leaf_san.names[i]);

            // All DNS name constraint should be valid
            &&& forall |j| 0 <= j < constraints.permitted.len() ==> {
                (#[trigger] constraints.permitted[j]) matches GeneralName::DNSName(permitted_name) ==>
                    valid_name_constraint(permitted_name)
            }

            // Check that `leaf_name` is permitted by some name constraint in `permitted`
            &&& has_permitted_dns_name ==> exists |j| 0 <= j < constraints.permitted.len() && {
                &&& (#[trigger] constraints.permitted[j]) matches GeneralName::DNSName(permitted_name)
                &&& valid_name_constraint(permitted_name)
                &&& permit_name(permitted_name, leaf_name)
            }

            // Check that `leaf_name` is not covered by any name constraint in `excluded`
            &&& forall |j| 0 <= j < constraints.excluded.len() ==> {
                (#[trigger] constraints.excluded[j]) matches GeneralName::DNSName(excluded_name) ==> {
                    &&& valid_name_constraint(excluded_name)
                    &&& not_exclude_name(excluded_name, leaf_name)
                }
            }
        }

        // NOTE: see the long "Directory/xxx" checks in Hammurabi
        // TODO: performance?
        &&& forall |i| 0 <= i < leaf.subject_name.len() ==> {
            let leaf_name = #[trigger] leaf.subject_name[i];
            let permitted_enabled = exists |j| 0 <= j < constraints.permitted.len() && {
                (#[trigger] constraints.permitted[j]) matches GeneralName::DirectoryName(permitted_name) &&
                    same_directory_name_type(leaf_name, permitted_name)
            };

            // Not explicitly excluded
            &&& forall |j| 0 <= j < constraints.excluded.len() ==> {
                (#[trigger] constraints.excluded[j]) matches GeneralName::DirectoryName(excluded_name) ==>
                    !same_directory_name(leaf_name, excluded_name)
            }

            // If enabled, check if `leaf_name` is at least permitted by one of them
            &&& permitted_enabled ==> exists |j| 0 <= j < constraints.permitted.len() && {
                (#[trigger] constraints.permitted[j]) matches GeneralName::DirectoryName(permitted_name) &&
                    same_directory_name(leaf_name, permitted_name)
            }
        }
    }
}

pub open spec fn cert_verified_intermediate(env: Environment, cert: Certificate, leaf: Certificate, depth: int) -> bool {
    &&& cert_verified_non_leaf(env, cert, depth)
    &&& not_in_crl(env, cert)
    &&& strong_signature(cert.sig_alg)
    &&& key_usage_valid(cert)
    &&& extended_key_usage_valid(cert)
    &&& check_name_constraints(cert, leaf)
}

/// NOTE: badSymantec in Hammurabi
pub open spec fn is_bad_symantec_root(env: Environment, cert: Certificate) -> bool {
    &&& exists |i| 0 <= i < env.symantec_roots.len() && cert.fingerprint == env.symantec_roots[i]
    &&& forall |i| 0 <= i < env.symantec_exceptions.len() ==> cert.fingerprint != env.symantec_exceptions[i]
    &&& {
        ||| cert.not_before < 1464739200 // June 2016
        ||| cert.not_before > 1512086400 // Dec 2017
    }
}

/// NOTE: isChromeRoot in Hammurabi
pub open spec fn is_chrome_root(env: Environment, cert: Certificate, domain: SpecString) -> bool {
    &&& exists |i| 0 <= i < env.trusted.len() && cert.fingerprint == env.trusted[i]

    // See fingerprintValid in Hammurabi
    &&& {
        let is_india_fingerprint = exists |i| 0 <= i < env.india_trusted.len() && cert.fingerprint == env.india_trusted[i];
        let is_anssi_fingerprint = exists |i| 0 <= i < env.anssi_trusted.len() && cert.fingerprint == env.anssi_trusted[i];

        &&& is_india_fingerprint ==> exists |i| #![auto] 0 <= i < env.india_domains.len() && name_match(env.india_domains[i], domain)
        &&& is_anssi_fingerprint ==> exists |i| #![auto] 0 <= i < env.anssi_domains.len() && name_match(env.anssi_domains[i], domain)
    }
}

pub open spec fn cert_verified_root(env: Environment, cert: Certificate, leaf: Certificate, depth: int, domain: SpecString) -> bool {
    &&& cert_verified_non_leaf(env, cert, depth)

    &&& cert.ext_key_usage matches Some(key_usage) ==> key_usage.key_cert_sign

    &&& is_chrome_root(env, cert, domain)
    &&& !is_bad_symantec_root(env, cert)
    &&& extended_key_usage_valid(cert)
}

/// chain[0] is the leaf, and assume chain[i] is issued by chain[i + 1] for all i < chain.len() - 1
/// chain.last() must be a trusted root
pub open spec fn cert_verified_chain(env: Environment, chain: Seq<Certificate>, domain: SpecString) -> bool
{
    &&& chain.len() > 1
    &&& cert_verified_leaf(env, chain[0], domain)
    &&& forall |i| 0 < i < chain.len() - 1 ==> cert_verified_intermediate(env, #[trigger] chain[i], chain[0], i - 1)
    &&& cert_verified_root(env, chain.last(), chain[0], chain.len() - 2, domain)
}

}
