use vstd::prelude::*;

verus! {

pub type SpecString = Seq<char>;

pub enum DirectoryName {
    CommonName(SpecString),
    Country(SpecString),
    OrganizationName(SpecString),
    OrganizationalUnit(SpecString),
    Locality(SpecString),
    State(SpecString),
    PostalCode(SpecString),
    Surname(SpecString),
}

pub enum GeneralName {
    DNSName(SpecString),
    DirectoryName(DirectoryName),
}

pub enum SubjectKey {
    RSA {
        mod_length: usize,
    },
    DSA {
        p_len: u64,
        q_len: u64,
        g_len: u64,
    },
    Other,
}

pub enum ExtendedKeyUsageTypes {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OCSPSigning,
    Any,
}

pub struct ExtendedKeyUsage {
    pub critical: bool,
    pub usages: Seq<ExtendedKeyUsageTypes>,
}

pub struct BasicConstraints {
    pub critical: bool,
    pub is_ca: bool,
    pub path_len: Option<usize>,
}

pub struct KeyUsage {
    pub critical: bool,
    pub digital_signature: bool,
    pub content_commitment: bool,
    pub key_encipherment: bool,
    pub data_encipherment: bool,
    pub key_agreement: bool,
    pub key_cert_sign: bool,
    pub crl_sign: bool,
    pub encipher_only: bool,
    pub decipher_only: bool,
}

pub struct SubjectAltName {
    pub critical: bool,
    pub names: Seq<SpecString>,
}

pub struct NameConstraints {
    pub critical: bool,
    pub permitted: Seq<GeneralName>,
    pub excluded: Seq<GeneralName>,
}

pub struct CertificatePolicies {
    pub critical: bool,
    pub policies: Seq<SpecString>,
}

pub struct Certificate {
    pub fingerprint: SpecString,
    pub version: u32,
    pub sig_alg: SpecString,
    pub not_after: u64,
    pub not_before: u64,

    pub subject_name: Seq<DirectoryName>,
    pub subject_key: SubjectKey,

    pub ext_extended_key_usage: Option<ExtendedKeyUsage>,
    pub ext_basic_constraints: Option<BasicConstraints>,
    pub ext_key_usage: Option<KeyUsage>,
    pub ext_subject_alt_name: Option<SubjectAltName>,
    pub ext_name_constraints: Option<NameConstraints>,
    pub ext_certificate_policies: Option<CertificatePolicies>,
}

pub struct Environment {
    pub time: u64,
}

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

/// TODO
pub open spec fn leaf_duration_valid(cert: Certificate) -> bool {
    true
}

/// TODO
pub open spec fn not_in_crl(cert: Certificate) -> bool {
    true
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

/// TODO: lower case, URI encoding, and removing trailing '.'
pub open spec fn clean_subject_alt_name(name: SpecString) -> SpecString {
    name
}

/// TODO: nameValid in Hammurabi
pub open spec fn valid_name(name: SpecString) -> bool {
    true
}

pub open spec fn cert_verified_leaf(env: Environment, cert: Certificate, domain: SpecString) -> bool {
    &&& cert.version == 2
    &&& is_valid_pki(cert)

    &&& cert.not_before < env.time
    &&& cert.not_after > env.time

    // Domain matches one of the SANs
    &&& cert.ext_subject_alt_name matches Some(subject_alt_name)
    &&& subject_alt_name.names.len() > 0
    &&& forall |i| #![auto] 0 < i <= subject_alt_name.names.len() ==>
            valid_name(subject_alt_name.names[i])
    &&& exists |i| #![auto] 0 < i <= subject_alt_name.names.len() &&
            name_match(clean_subject_alt_name(subject_alt_name.names[i]), domain)

    &&& leaf_duration_valid(cert)

    &&& not_in_crl(cert)
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

/// TODO
pub open spec fn check_name_constraints(cert: Certificate, leaf: Certificate) -> bool {
    cert.ext_name_constraints matches Some(constraints) ==> {
        &&& constraints.permitted.len() != 0 || constraints.excluded.len() != 0

        // Leaf SANs should be in permitted (if permitted.len() != 0)
        // and not in any of the excluded
        &&& leaf.ext_subject_alt_name matches Some(leaf_san)
        &&& forall |i| 0 <= i < leaf_san.names.len() ==> {
            let leaf_name = clean_subject_alt_name(#[trigger] leaf_san.names[i]);

            // Permitted check if enabled only if there is at least one DNS name
            // in the permitted list
            let has_permitted_dns_name = exists |j|
                0 <= j < constraints.permitted.len() &&
                (#[trigger] constraints.permitted[j]) matches GeneralName::DNSName(allowed_name);

            &&& has_permitted_dns_name ==> {
                &&& true // TODO: check that `leaf_name` is in some `constraints.permitted`
            }
            // &&& forall |j: int| 0 <= j < constraints.excluded.len() ==> {
            //     &&& true // TODO: check that `leaf_name` is not in `constraints.excluded[j]`
            // }
        }

        // TODO: for each directory name in leaf's subject_name
        // check if corresponding name constraints
    }
}

pub open spec fn cert_verified_intermediate(env: Environment, cert: Certificate, leaf: Certificate, depth: int) -> bool {
    &&& cert_verified_non_leaf(env, cert, depth)
    &&& not_in_crl(cert)
    &&& strong_signature(cert.sig_alg)
    &&& key_usage_valid(cert)
    &&& extended_key_usage_valid(cert)
    &&& check_name_constraints(cert, leaf)
}

/// TODO
pub open spec fn is_bad_symantec_root(cert: Certificate) -> bool {
    // symantecRoot
    // not symantecException
    // symantecUntrusted
    false
}

/// TODO
pub open spec fn is_chrome_root(cert: Certificate) -> bool {
    true
}

pub open spec fn cert_verified_root(env: Environment, cert: Certificate, leaf: Certificate, depth: int) -> bool {
    &&& cert_verified_non_leaf(env, cert, depth)

    &&& cert.ext_key_usage matches Some(key_usage) ==> key_usage.key_cert_sign

    &&& is_chrome_root(cert)
    &&& !is_bad_symantec_root(cert)
    &&& extended_key_usage_valid(cert)
}

/// chain[0] is the leaf, and assume chain[i] is issued by chain[i + 1] for all i < chain.len() - 1
/// chain.last() must be a trusted root
pub open spec fn cert_verified_chain(env: Environment, chain: Seq<Certificate>, domain: SpecString) -> bool
{
    &&& chain.len() > 1
    &&& cert_verified_leaf(env, chain[0], domain)
    &&& forall |i| 0 < i < chain.len() - 1 ==> cert_verified_intermediate(env, #[trigger] chain[i], chain[0], i - 1)
    &&& cert_verified_root(env, chain.last(), chain[0], chain.len() - 2)
}

}
