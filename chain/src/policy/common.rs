use vstd::prelude::*;
use rspec::rspec;
use rspec_lib::*;

verus! {

rspec! {

pub enum DirectoryName {
    CommonName(SpecString),
    Country(SpecString),
    OrganizationName(SpecString),
    OrganizationalUnit(SpecString),
    Locality(SpecString),
    State(SpecString),
    PostalCode(SpecString),
    Surname(SpecString),
    Other(SpecString, SpecString),
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
        match self {
            ExecDirectoryName::CommonName(x) => ExecDirectoryName::CommonName(x.clone()),
            ExecDirectoryName::Country(x) => ExecDirectoryName::Country(x.clone()),
            ExecDirectoryName::OrganizationName(x) => ExecDirectoryName::OrganizationName(x.clone()),
            ExecDirectoryName::OrganizationalUnit(x) => ExecDirectoryName::OrganizationalUnit(x.clone()),
            ExecDirectoryName::Locality(x) => ExecDirectoryName::Locality(x.clone()),
            ExecDirectoryName::State(x) => ExecDirectoryName::State(x.clone()),
            ExecDirectoryName::PostalCode(x) => ExecDirectoryName::PostalCode(x.clone()),
            ExecDirectoryName::Surname(x) => ExecDirectoryName::Surname(x.clone()),
            ExecDirectoryName::Other(x, y) => ExecDirectoryName::Other(x.clone(), y.clone()),
        }
    }
}

impl DirectoryName {
    pub open spec fn to_string(&self) -> &SpecString
    {
        match self {
            DirectoryName::CommonName(x) => x,
            DirectoryName::Country(x) => x,
            DirectoryName::OrganizationName(x) => x,
            DirectoryName::OrganizationalUnit(x) => x,
            DirectoryName::Locality(x) => x,
            DirectoryName::State(x) => x,
            DirectoryName::PostalCode(x) => x,
            DirectoryName::Surname(x) => x,
            DirectoryName::Other(x, y) => y,
        }
    }
}

impl ExecDirectoryName {
    pub fn to_string(&self) -> &String
    {
        match self {
            ExecDirectoryName::CommonName(x) => x,
            ExecDirectoryName::Country(x) => x,
            ExecDirectoryName::OrganizationName(x) => x,
            ExecDirectoryName::OrganizationalUnit(x) => x,
            ExecDirectoryName::Locality(x) => x,
            ExecDirectoryName::State(x) => x,
            ExecDirectoryName::PostalCode(x) => x,
            ExecDirectoryName::Surname(x) => x,
            ExecDirectoryName::Other(x, y) => y,
        }
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
