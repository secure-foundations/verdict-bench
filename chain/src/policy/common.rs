#![allow(unused_parens)]

use vstd::prelude::*;
use rspec::rspec;
use rspec_lib::*;

use crate::issue;

#[allow(unused_imports)]
pub use super::*;

verus! {

pub trait Policy {
    /// User-defined issuing relation without checking signature
    spec fn spec_likely_issued(&self, issuer: Certificate, subject: Certificate) -> bool;

    fn likely_issued(&self, issuer: &ExecCertificate, subject: &ExecCertificate) -> (res: bool)
        ensures res == self.spec_likely_issued(issuer.deep_view(), subject.deep_view());

    /// User-defined chain/path validation
    spec fn spec_valid_chain(&self, chain: Seq<Certificate>, task: Task) -> Result<bool, PolicyError>;

    fn valid_chain(&self, chain: &Vec<&ExecCertificate>, task: &ExecTask) -> (res: Result<bool, ExecPolicyError>)
        ensures res.deep_view() == self.spec_valid_chain(chain.deep_view(), task.deep_view());

    spec fn validation_time(&self) -> u64;
}

rspec! {

/// Corresponds to `AttributeTypeAndValue` in X.509
pub struct Attribute {
    pub oid: SpecString,
    pub value: SpecString,
}

pub struct DistinguishedName(pub Seq<Seq<Attribute>>);

pub enum GeneralName {
    DNSName(SpecString),
    DirectoryName(DistinguishedName),
}

pub enum SubjectKey {
    RSA {
        mod_length: usize,
    },
    DSA {
        p_len: usize,
        q_len: usize,
        g_len: usize,
    },
    Other,
}

pub struct AuthorityKeyIdentifier {
    pub critical: bool,
    pub key_id: Option<SpecString>,
    pub serial: Option<SpecString>,
}

pub struct SubjectKeyIdentifier {
    pub critical: bool,
    pub key_id: SpecString,
}

pub enum ExtendedKeyUsageType {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OCSPSigning,
    Any,
    Other(SpecString),
}

pub struct ExtendedKeyUsage {
    pub critical: bool,
    pub usages: Seq<ExtendedKeyUsageType>,
}

pub struct BasicConstraints {
    pub critical: bool,
    pub is_ca: bool,
    pub path_len: Option<i64>,
}

pub struct KeyUsage {
    pub critical: bool,
    pub digital_signature: bool,
    pub non_repudiation: bool,
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
    pub names: Seq<GeneralName>,
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

pub struct SignatureAlgorithm {
    pub id: SpecString,
    pub bytes: SpecString,
}

pub struct Extension {
    pub oid: SpecString,
    pub critical: bool,
}

pub struct Certificate {
    pub fingerprint: SpecString,
    pub version: u32,
    pub serial: SpecString,
    pub sig_alg_outer: SignatureAlgorithm,
    pub sig_alg_inner: SignatureAlgorithm,
    pub not_after: u64,
    pub not_before: u64,

    pub issuer: DistinguishedName,
    pub subject: DistinguishedName,
    pub subject_key: SubjectKey,

    pub issuer_uid: Option<SpecString>,
    pub subject_uid: Option<SpecString>,

    pub ext_authority_key_id: Option<AuthorityKeyIdentifier>,
    pub ext_subject_key_id: Option<SubjectKeyIdentifier>,
    pub ext_extended_key_usage: Option<ExtendedKeyUsage>,
    pub ext_basic_constraints: Option<BasicConstraints>,
    pub ext_key_usage: Option<KeyUsage>,
    pub ext_subject_alt_name: Option<SubjectAltName>,
    pub ext_name_constraints: Option<NameConstraints>,
    pub ext_certificate_policies: Option<CertificatePolicies>,

    // All extensions without parameters
    pub all_exts: Option<Seq<Extension>>,
}

#[derive(Copy, Clone)]
pub enum Purpose {
    ServerAuth,
}

pub enum Task {
    DomainValidation(SpecString),
    ChainValidation(Purpose),
}

pub enum PolicyError {
    UnsupportedTask,
}

/// Match a pattern with wildcard (e.g. "*.example.com") against a string
pub open spec fn match_name(pattern: &SpecString, name: &SpecString) -> bool {
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

/// Additional checks for issuing relation
/// TODO: check subject.akid.auth_cert_issuer
/// References:
/// - RFC 2459, 4.2.1.1
/// - https://github.com/openssl/openssl/blob/ed6862328745c51c2afa2b6485cc3e275d543c4e/crypto/x509/v3_purp.c#L1002
pub open spec fn check_auth_key_id(issuer: &Certificate, subject: &Certificate) -> bool {
    match &subject.ext_authority_key_id {
        Some(auth_key_id) => {
            // Subject's AKID matches issuer's SKID if both exist
            &&& match (&issuer.ext_subject_key_id, &auth_key_id.key_id) {
                (Some(skid), Some(akid)) => &skid.key_id == akid,
                _ => true,
            }

            // Subject's AKID serial matches issuer's serial if both exist
            &&& match &auth_key_id.serial {
                Some(akid_serial) => akid_serial == &issuer.serial,
                None => true,
            }
        }
        None => true,
    }
}

use exec_normalize_string as normalize_string;

/// We offer a switch `normalize` since:
/// - Chrome does string normalization (folding the ASCII space and lower casing (ASCII-only))
///   - https://github.com/chromium/chromium/blob/0590dcf7b036e15c133de35213be8fe0986896aa/net/cert/internal/verify_name_match.cc#L70
/// - Firefox does not do string normalization
///   - https://searchfox.org/mozilla-central/source/security/nss/lib/mozpkix/lib/pkixnames.cpp#1345
/// - OpenSSL considers more characters as white space (https://github.com/openssl/openssl/blob/ea5817854cf67b89c874101f209f06ae016fd333/crypto/ctype.c#L21),
///   whereas Chrome only considers a single ASCII space character ' '
pub open spec fn rdn_has_name(rdn: &Seq<Attribute>, name: &Attribute, normalize: bool) -> bool {
    exists |i: usize| 0 <= i < rdn.len() && {
        &&& #[trigger] &rdn[i as int].oid == &name.oid
        &&& if normalize {
            &normalize_string(&rdn[i as int].value) == &normalize_string(&name.value)
        } else {
            &rdn[i as int].value == &name.value
        }
    }
}

/// Check if for any item in rdn2, there is a corresponding item in rdn1 with the same OID
/// and same value
pub open spec fn is_subtree_rdn(rdn1: &Seq<Attribute>, rdn2: &Seq<Attribute>, normalize: bool) -> bool {
    &&& rdn1.len() <= rdn2.len()
    &&& forall |i: usize| 0 <= i < rdn1.len() ==> rdn_has_name(&rdn2, #[trigger] &rdn1[i as int], normalize)
}

/// Check if name1 is a subset set of name2
/// See: https://github.com/google/boringssl/blob/571c76e919c0c48219ced35bef83e1fc83b00eed/pki/verify_name_match.cc#L261C6-L261C29
pub open spec fn is_subtree_of(name1: &DistinguishedName, name2: &DistinguishedName, normalize: bool) -> bool {
    &&& name1.0.len() <= name2.0.len()
    &&& forall |i: usize| 0 <= i < name1.0.len() ==> is_subtree_rdn(#[trigger] &name1.0[i as int], &name2.0[i as int], normalize)
}

pub open spec fn same_attr(attr1: &Attribute, attr2: &Attribute, normalize: bool) -> bool
{
    &&& &attr1.oid == &attr2.oid
    &&& if normalize {
        &normalize_string(&attr1.value) == &normalize_string(&attr2.value)
    } else {
        &attr1.value == &attr2.value
    }
}

pub open spec fn same_rdn(rdn1: &Seq<Attribute>, rdn2: &Seq<Attribute>, normalize: bool) -> bool
{
    &&& rdn1.len() == rdn2.len()
    &&& forall |i: usize| 0 <= i < rdn1.len()
        ==> same_attr(#[trigger] &rdn1[i as int], &rdn2[i as int], normalize)
}

/// Check if two distinguished names are the same, with/without normalization
/// References:
/// - RFC 5280, 4.1.2.4
/// - https://github.com/openssl/openssl/blob/ed6862328745c51c2afa2b6485cc3e275d543c4e/crypto/x509/x509_cmp.c#L254
pub open spec fn same_dn(name1: &DistinguishedName, name2: &DistinguishedName, normalize: bool) -> bool
{
    &&& name1.0.len() == name2.0.len()
    &&& forall |i: usize| 0 <= i < name1.0.len()
        ==> same_rdn(#[trigger] &name1.0[i as int], &name2.0[i as int], normalize)
}

/// Similar to `match_name`, but used for checking name constraints
/// TODO: reference
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

} // rspec!

/// NOTE: unspecified
pub closed spec fn str_lower(s: &SpecString) -> SpecString;

#[verifier::external_body]
pub fn exec_str_lower(s: &String) -> (res: String)
    ensures res.deep_view() == str_lower(&s.deep_view())
{
    s.to_lowercase()
}

impl Clone for ExecAttribute {
    fn clone(&self) -> (res: Self)
        ensures res.deep_view() == self.deep_view()
    {
        ExecAttribute {
            oid: self.oid.clone(),
            value: self.value.clone(),
        }
    }
}

pub open spec fn normalize_string(s: &SpecString) -> SpecString {
    issue::spec_normalize_string(*s)
}

pub fn exec_normalize_string(s: &String) -> (res: String)
    ensures res.deep_view() == normalize_string(&s.deep_view())
{
    issue::normalize_string(s.as_str())
}

impl Clone for ExecTask {
    fn clone(&self) -> (res: Self)
        ensures res.deep_view() == self.deep_view()
    {
        match self {
            ExecTask::DomainValidation(domain) => ExecTask::DomainValidation(domain.clone()),
            ExecTask::ChainValidation(purpose) => ExecTask::ChainValidation(*purpose),
        }
    }
}

} // verus!
