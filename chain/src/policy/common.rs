use vstd::prelude::*;
use rspec::rspec;
use rspec_lib::*;

verus! {

rspec! {

pub struct DirectoryName {
    pub oid: SpecString,
    pub value: SpecString,
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
        p_len: usize,
        q_len: usize,
        g_len: usize,
    },
    Other,
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
    pub path_len: Option<usize>,
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

} // rspec!

/// NOTE: unspecified
pub closed spec fn str_lower(s: &SpecString) -> SpecString;

#[verifier::external_body]
pub fn exec_str_lower(s: &String) -> (res: String)
    ensures res.deep_view() == str_lower(&s.deep_view())
{
    s.to_lowercase()
}

impl Clone for ExecDirectoryName {
    fn clone(&self) -> (res: Self)
        ensures res.deep_view() == self.deep_view()
    {
        ExecDirectoryName {
            oid: self.oid.clone(),
            value: self.value.clone(),
        }
    }
}

impl DirectoryName {
    pub open spec fn to_string(&self) -> &SpecString
    {
        &self.value
    }
}

impl ExecDirectoryName {
    pub fn to_string(&self) -> &String
    {
        &self.value
    }
}

impl GeneralName {
    pub open spec fn to_string(&self) -> &SpecString
    {
        match self {
            GeneralName::DNSName(x) => x,
            GeneralName::DirectoryName(x) => x.to_string(),
        }
    }
}

impl ExecGeneralName {
    pub fn to_string(&self) -> &String
    {
        match self {
            ExecGeneralName::DNSName(x) => x,
            ExecGeneralName::DirectoryName(x) => x.to_string(),
        }
    }
}

} // verus!
