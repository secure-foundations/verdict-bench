use vstd::prelude::*;

use chrono::NaiveDate;

use polyfill::*;
use parser::{*, asn1::*, x509::*};

use crate::policy;
use crate::hash;
use crate::issue::*;
use crate::error::*;

verus! {

/// A high-level spec specifying when a certificate chain is considered valid
/// with respect to a domain
pub open spec fn spec_valid_domain(
    policy: policy::Policy,
    roots: Seq<SpecCertificateValue>,
    chain: Seq<SpecCertificateValue>,
    domain: Seq<char>,
) -> bool
{
    exists |i, j| {
        &&& 0 <= i < roots.len()
        &&& 0 <= j < chain.len()
        &&& forall |k: int| 0 <= k < j ==> spec_likely_issued(chain[k + 1], #[trigger] chain[k])
        &&& spec_likely_issued(roots[i], chain[j])

        // Check if the candidate chain satisfies the policy constraints
        &&& {
            let candidate = chain.take(j + 1) + seq![roots[i]];
            let abstract_candidate = Seq::new(candidate.len(), |i| policy::Certificate::spec_from(candidate[i]).unwrap());

            &&& forall |i| #![trigger candidate[i]] 0 <= i < candidate.len() ==> policy::Certificate::spec_from(candidate[i]).is_some()
            &&& policy::valid_chain(&policy, &abstract_candidate, &domain)
        }
    }
}

/// Check that the chain[i] is likely issued by chain[i + 1]
/// up until chain[n]
pub fn check_chain_likely_issue(chain: &VecDeep<CertificateValue>, n: usize) -> (res: bool)
    requires 0 <= n < chain@.len()
    ensures res == forall |i: int| 0 <= i < n ==> spec_likely_issued(chain@[i + 1], #[trigger] chain@[i]),
{
    for i in 0..n
        invariant
            n < chain@.len(),
            forall |j: int| 0 <= j < i ==> spec_likely_issued(chain@[j + 1], #[trigger] chain@[j]),
    {
        if !likely_issued(chain.get(i + 1), chain.get(i)) {
            return false;
        }
    }
    true
}

/// Exec version of spec_valid_domain
/// TODO: completeness
pub fn valid_domain<'a, 'b>(
    policy: &policy::ExecPolicy,
    roots: &VecDeep<CertificateValue<'a>>,
    chain: &VecDeep<CertificateValue<'b>>,
    domain: &str,
) -> (res: Result<bool, ValidationError>)
    ensures
        res.is_ok() && res.unwrap() ==>
            spec_valid_domain(policy.deep_view(), roots@, chain@, domain@)
{
    let roots_len = roots.len();
    let chain_len = chain.len();

    for i in 0..roots_len
        invariant
            roots_len == roots@.len(),
            chain_len == chain@.len(),
    {
        // Check if any intermediate certificate is issued by the root
        for j in 0..chain_len
            invariant
                roots_len == roots@.len(),
                chain_len == chain@.len(),
                0 <= i < roots_len,
        {
            if likely_issued(roots.get(i), chain.get(j)) {
                if check_chain_likely_issue(chain, j) {
                    let mut candidate: Vec<policy::ExecCertificate> = Vec::new();

                    // Abstract chain up to j
                    for k in 0..j + 1
                        invariant
                            chain_len == chain@.len(),
                            0 <= j < chain_len,
                            candidate.len()
                             == k,
                            forall |l: int| #![auto] 0 <= l < k ==> Some(candidate@[l].deep_view()) == policy::Certificate::spec_from(chain@[l]),
                    {
                        candidate.push(policy::Certificate::from(chain.get(k))?);
                    }

                    candidate.push(policy::Certificate::from(roots.get(i))?);

                    // assert(candidate.deep_view() =~= {
                    //     let candidate = chain@.take(j + 1) + seq![roots@[i as int]];
                    //     Seq::new(candidate.len(), |i| policy::Certificate::spec_from(candidate[i]).unwrap())
                    // });

                    if policy::exec_valid_chain(policy, &candidate, &domain.to_string()) {
                        return Ok(true);
                    }
                }
            }
        }
    }

    Ok(false)
}

impl policy::Certificate {
    /// Convert a more concrete parsed certificate to
    /// an abstract certificate to be used in a policy
    pub open spec fn spec_from(c: SpecCertificateValue) -> Option<policy::Certificate> {
        if_let! {
            let Ok(ser_cert) = ASN1(CertificateInner).view().spec_serialize(c);
            let Some(not_after) = Self::spec_time_to_timestamp(c.cert.validity.not_after);
            let Some(not_before) = Self::spec_time_to_timestamp(c.cert.validity.not_before);
            let Some(subject_key) = policy::SubjectKey::spec_from(c.cert.subject_key);

            Some(policy::Certificate {
                fingerprint: hash::spec_to_hex_upper(hash::spec_sha256_digest(ser_cert)),
                version: c.cert.version as u32,
                sig_alg: Self::spec_oid_to_string(c.sig_alg.id),

                not_after: not_after as u64,
                not_before: not_before as u64,

                subject_name: policy::DirectoryName::spec_from(c.cert.subject),
                subject_key,

                // TODO
                ext_extended_key_usage: None,
                ext_basic_constraints: None,
                ext_key_usage: None,
                ext_subject_alt_name: None,
                ext_name_constraints: None,
                ext_certificate_policies: None,
            })
        }
    }

    /// Exec version of spec_from
    pub fn from<'a, 'b>(c: &'b CertificateValue<'a>) -> (res: Result<policy::ExecCertificate, ValidationError>)
        ensures
            res matches Ok(res) ==> Some(res.deep_view()) =~= Self::spec_from(c@),
    {
        let not_after = Self::time_to_timestamp(&c.get().cert.get().validity.not_after)
            .ok_or(ValidationError::TimeParseError)?;

        let not_before = Self::time_to_timestamp(&c.get().cert.get().validity.not_before)
            .ok_or(ValidationError::TimeParseError)?;

        if not_after < 0 || not_before < 0 {
            return Err(ValidationError::TimeParseError);
        }

        let subject_key = policy::SubjectKey::from(&c.get().cert.get().subject_key)?;

        Ok(policy::ExecCertificate {
            fingerprint: hash::to_hex_upper(&hash::sha256_digest(c.serialize())),
            version: c.get().cert.get().version as u32,
            sig_alg: Self::oid_to_string(&c.get().sig_alg.id),

            not_after: not_after as u64,
            not_before: not_before as u64,

            subject_name: policy::DirectoryName::from(&c.get().cert.get().subject),
            subject_key,

            // TODO
            ext_extended_key_usage: None,
            ext_basic_constraints: None,
            ext_key_usage: None,
            ext_subject_alt_name: None,
            ext_name_constraints: None,
            ext_certificate_policies: None,
        })
    }

    /// Convert OID to a string by concatenating all arcs with '.'
    pub closed spec fn spec_oid_to_string(oid: SpecObjectIdentifierValue) -> Seq<char>
    {
        seq_join(Seq::new(oid.len(), |i| spec_u64_to_string(oid[i])), "."@)
    }

    /// Exec version of the above
    pub fn oid_to_string(oid: &ObjectIdentifierValue) -> (res: String)
        ensures res@ =~= Self::spec_oid_to_string(oid@)
    {
        let strings = vec_map(oid.0.to_vec(),
            |id: &u64| -> (res: String)
            ensures res@ == spec_u64_to_string(*id)
            { u64_to_string(*id) });

        assert(Seq::new(strings@.len(), |i| strings@[i]@) =~= Seq::new(oid@.len(), |i| spec_u64_to_string(oid@[i])));
        assert(Seq::new(strings@.len(), |i| strings@[i]@) =~= strings@.map_values(|v: String| v@));

        join_strings(&strings, ".")
    }

    pub closed spec fn spec_time_to_timestamp(time: SpecTimeValue) -> Option<i64>;

    /// Convert an X.509 Time to a UNIX timestamp
    /// NOTE: this implementation is unverified and trusted
    #[verifier::external_body]
    pub fn time_to_timestamp(time: &TimeValue) -> (res: Option<i64>)
        ensures res == Self::spec_time_to_timestamp(time@)
    {
        // Convert UTCTime/GeneralizedTime to chrono::NaiveDateTime
        let dt = match time {
            TimeValue::UTCTime(t) => {
                let date = NaiveDate::from_ymd_opt(t.year as i32, t.month as u32, t.day as u32)?;
                let naive = date.and_hms_opt(
                    t.hour as u32,
                    t.minute as u32,
                    *t.second.as_ref().unwrap_or(&0) as u32,
                )?;

                if let UTCTimeZone::UTC = t.time_zone {
                    naive.and_utc()
                } else {
                    return Option::None;
                }
            }
            TimeValue::GeneralizedTime(t) => {
                let date = NaiveDate::from_ymd_opt(t.year as i32, t.month as u32, t.day as u32)?;
                let naive = date.and_hms_opt(
                    t.hour as u32,
                    *t.minute.as_ref().unwrap_or(&0) as u32,
                    *t.second.as_ref().unwrap_or(&0) as u32,
                )?;

                if let GeneralizedTimeZone::UTC = t.time_zone {
                    naive.and_utc()
                } else {
                    return Option::None;
                }
            }

            TimeValue::Unreachable => return Option::None,
        };

        Option::Some(dt.timestamp())
    }
}

impl policy::SubjectKey {
    /// Convert SpecPublicKeyInfoValue to the more abstract version
    pub open spec fn spec_from(spki: SpecPublicKeyInfoValue) -> Option<policy::SubjectKey> {
        match spki.alg.param {
            SpecAlgorithmParamValue::DSASignature(Either::Left(param)) => {
                Some(policy::SubjectKey::DSA {
                    p_len: ((param.p.len() - 1) as usize * 8) as usize,
                    q_len: ((param.q.len() - 1) as usize * 8) as usize,
                    g_len: ((param.g.len() - 1) as usize * 8) as usize,
                })
            }

            SpecAlgorithmParamValue::RSAEncryption(..) => {
                // Parse the public key field to get the modulus length
                let pub_key = BitStringValue::spec_bytes(spki.pub_key);

                if_let! {
                    let Ok((_, parsed)) = ASN1(RSAParam).view().spec_parse(pub_key);
                    Some(policy::SubjectKey::RSA {
                        mod_length: ((parsed.modulus.len() - 1) as usize * 8) as usize,
                    })
                }
            }

            _ => Some(policy::SubjectKey::Other),
        }
    }

    /// Exec version of spec_from
    pub fn from<'a, 'b> (spki: &'b PublicKeyInfoValue<'a>) -> (res: Result<policy::ExecSubjectKey, ValidationError>)
        ensures
            res matches Ok(res) ==> Some(res.deep_view()) =~= Self::spec_from(spki@),
    {
        match &spki.alg.param {
            AlgorithmParamValue::DSASignature(Either::Left(param)) => {
                let p_len = param.p.byte_len();
                let q_len = param.q.byte_len();
                let g_len = param.g.byte_len();

                if p_len > usize::MAX / 8 ||
                   q_len > usize::MAX / 8 ||
                   g_len > usize::MAX / 8 {
                    return Err(ValidationError::IntegerOverflow);
                }

                Ok(policy::ExecSubjectKey::DSA {
                    p_len: p_len * 8,
                    q_len: q_len * 8,
                    g_len: g_len * 8,
                })
            }

            AlgorithmParamValue::RSAEncryption(..) => {
                let pub_key = spki.pub_key.bytes();
                let parsed = match ASN1(RSAParam).parse(pub_key) {
                    Ok((_, parsed)) => parsed,
                    Err(_) => return Err(ValidationError::RSAPubKeyParseError),
                };

                let mod_len = parsed.modulus.byte_len();

                if mod_len > usize::MAX / 8 {
                    return Err(ValidationError::IntegerOverflow);
                }

                Ok(policy::ExecSubjectKey::RSA {
                    mod_length: mod_len * 8,
                })
            }

            _ => Ok(policy::ExecSubjectKey::Other),
        }
    }
}

impl policy::DirectoryName {
    pub closed spec fn spec_from(name: SpecNameValue) -> Seq<policy::DirectoryName>
        decreases name.len()
    {
        if name.len() == 0 {
            seq![]
        } else {
            Self::spec_rdn_to_dir_names(name.first()) + Self::spec_from(name.drop_first())
        }
    }

    /// Exec version of spec_from
    pub fn from<'a, 'b>(name: &'b NameValue<'a>) -> (res: Vec<policy::ExecDirectoryName>)
        ensures res.deep_view() == Self::spec_from(name@),
    {
        let mut dir_names = Vec::new();
        let len = name.len();

        assert(name@.skip(0) == name@);

        for i in 0..len
            invariant
                len == name@.len(),
                Self::spec_from(name@) =~= dir_names.deep_view() + Self::spec_from(name@.skip(i as int)),
        {
            let mut new_names = Self::rdn_to_dir_names(name.get(i));
            dir_names.append(&mut new_names);
            assert(name@.skip(i + 1) == name@.skip(i as int).drop_first());
        }

        dir_names
    }

    /// Convert each attribute of RDN to a DirectoryName, ignoring unsupported ones
    /// TODO: support for more dir strings
    pub closed spec fn spec_rdn_to_dir_names(rdn: SpecRDNValue) -> Seq<policy::DirectoryName>
        decreases rdn.len()
    {
        if rdn.len() == 0 {
            seq![]
        } else {
            if let Some(dir_name) = Self::spec_attr_to_dir_name(rdn.first()) {
                seq![dir_name] + Self::spec_rdn_to_dir_names(rdn.drop_first())
            } else {
                Self::spec_rdn_to_dir_names(rdn.drop_first())
            }
        }
    }

    /// Exec version of spec_rdn_to_dir_names
    pub fn rdn_to_dir_names<'a, 'b>(rdn: &'b RDNValue<'a>) -> (res: Vec<policy::ExecDirectoryName>)
        ensures res.deep_view() == Self::spec_rdn_to_dir_names(rdn@),
    {
        let mut names = Vec::new();
        let len = rdn.len();

        assert(rdn@.skip(0) == rdn@);

        for i in 0..len
            invariant
                len == rdn@.len(),
                Self::spec_rdn_to_dir_names(rdn@) =~= names.deep_view() + Self::spec_rdn_to_dir_names(rdn@.skip(i as int)),
        {
            if let Some(dir_name) = Self::attr_to_dir_name(rdn.get(i)) {
                names.push(dir_name);
            }

            assert(rdn@.skip(i + 1) == rdn@.skip(i as int).drop_first());
        }

        names
    }

    pub closed spec fn spec_attr_to_dir_name(attr: SpecAttributeTypeAndValueValue) -> Option<policy::DirectoryName> {
        if_let! {
            let Some(value) = Self::spec_dir_string_to_string(attr.value);

            Some(policy::DirectoryName::Other(
                policy::Certificate::spec_oid_to_string(attr.typ),
                value,
            ))
        }
    }

    /// Exec version of spec_attr_to_dir_name
    pub fn attr_to_dir_name<'a, 'b>(attr: &'b AttributeTypeAndValueValue<'a>) -> (res: Option<policy::ExecDirectoryName>)
        ensures res.deep_view() == Self::spec_attr_to_dir_name(attr@),
    {
        Some(policy::ExecDirectoryName::Other(
            policy::Certificate::oid_to_string(&attr.typ),
            Self::dir_string_to_string(&attr.value)?.to_string(),
        ))
    }

    /// Convert a dir string to string
    /// NOTE: DirectoryString refers to a overloaded string type in X.509
    /// DirectoryName refers to the string attached with an OID used in subject name
    pub closed spec fn spec_dir_string_to_string(dir: SpecDirectoryStringValue) -> Option<Seq<char>>
    {
        match dir {
            SpecDirectoryStringValue::PrintableString(s) => Some(s),
            SpecDirectoryStringValue::UTF8String(s) => Some(s),
            SpecDirectoryStringValue::IA5String(s) => Some(s),
            SpecDirectoryStringValue::TeletexString(s) => None,
            SpecDirectoryStringValue::UniversalString(s) => None,
            SpecDirectoryStringValue::BMPString(s) => None,
            SpecDirectoryStringValue::Unreachable => None,
        }
    }

    /// Exec version of spec_dir_string_to_string
    pub fn dir_string_to_string<'a, 'b>(dir: &'b DirectoryStringValue<'a>) -> (res: Option<&'a str>)
        ensures
            res matches Some(res) ==> Self::spec_dir_string_to_string(dir@) == Some(res@),
            res.is_none() ==> Self::spec_dir_string_to_string(dir@).is_none(),
    {
        match dir {
            DirectoryStringValue::PrintableString(s) => Some(s),
            DirectoryStringValue::UTF8String(s) => Some(s),
            DirectoryStringValue::IA5String(s) => Some(s),
            DirectoryStringValue::TeletexString(s) => None,
            DirectoryStringValue::UniversalString(s) => None,
            DirectoryStringValue::BMPString(s) => None,
            DirectoryStringValue::Unreachable => None,
        }
    }
}

/// Used for error handling in specs
#[allow(unused_macros)]
macro_rules! if_let {
    ($body:expr) => {
        ::builtin_macros::verus_proof_expr! { $body }
    };

    (let $pat:pat = $opt:expr; $(let $rest_pat:pat = $rest_opt:expr;)* $body:expr) => {
        #[allow(irrefutable_let_patterns)]
        if let $pat = ::builtin_macros::verus_proof_expr! { $opt } {
            if_let!($(let $rest_pat = $rest_opt;)* { $body })
        } else {
            None
        }
    };
}
pub(crate) use if_let;

}
