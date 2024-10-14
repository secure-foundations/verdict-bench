use vstd::prelude::*;

use chrono::NaiveDate;

use polyfill::*;
use vpl::*;
use parser::{*, asn1::*, x509::*};

use crate::hash;
use crate::error::*;

use super::*;

verus! {

broadcast use vpl::lemma_ext_equal_deep;

pub type CertificateFacts = seq_facts![BasicFacts, TimeFacts, SubjectNameFacts, SubjectPKIFacts, ExtensionFacts];

/// Basic facts about a certificate, such as fingerprint, version, etc.
pub struct BasicFacts;

/// Encode the validity field of a certificate
pub struct TimeFacts;

/// Facts about the subject field
pub struct SubjectNameFacts;

/// Facts about subject public key info
pub struct SubjectPKIFacts;

/// Attach a certificate index to an arbitrary type
#[derive(View)]
pub struct CertIndexed<T> {
    pub x: T,
    pub idx: LiteralInt,
}

impl<T> CertIndexed<T> {
    pub open spec fn spec_new(x: T, idx: LiteralInt) -> Self {
        CertIndexed { x, idx }
    }

    #[verifier::when_used_as_spec(spec_new)]
    pub fn new(x: T, idx: LiteralInt) -> (res: Self)
        ensures res == Self::spec_new(x, idx)
    {
        CertIndexed { x, idx }
    }

    /// Construct term cert(i)
    pub closed spec fn spec_cert(self) -> SpecTerm
    {
        // NOTE: instead of doing cert_i as in the original Hammurabi
        // we use cert(i) to avoid int::to_string in the spec
        spec_app!("cert", spec_int!(self.idx as int))
    }
}

impl<T: View> CertIndexed<T> {
    /// Exec version of spec_cert
    pub fn cert(&self) -> (res: Term)
        ensures
            res@ =~~= self@.spec_cert(),
            res@ =~~= self.spec_cert(),
    {
        TermX::app_str("cert", vec![TermX::int(self.idx)])
    }
}

impl<'a, 'b> Facts<CertIndexed<&'b CertificateValue<'a>>> for BasicFacts {
    closed spec fn spec_facts(t: CertIndexed<SpecCertificateValue>) -> Option<Seq<SpecRule>> {
        if_let! {
            let Ok(ser_cert) = ASN1(CertificateInner).view().spec_serialize(t.x);

            Some(seq![
                spec_fact!("fingerprint",
                    t.spec_cert(),
                    spec_str!(hash::spec_to_hex_upper(hash::spec_sha256_digest(ser_cert))),
                ),

                spec_fact!("version", t.spec_cert(), spec_int!(t.x.cert.version as int)),

                spec_fact!("signatureAlgorithm", t.spec_cert(), spec_str!(Self::spec_oid_to_string(t.x.sig_alg.id))),
            ])
        }
    }

    fn facts(t: &CertIndexed<&'b CertificateValue<'a>>, out: &mut VecDeep<Rule>) -> (res: Result<(), ValidationError>) {
        out.append_owned(vec_deep![
            RuleX::fact("fingerprint", vec![
                t.cert(),
                TermX::str(hash::to_hex_upper(&hash::sha256_digest(t.x.serialize())).as_str()),
            ]),

            RuleX::fact("version", vec![ t.cert(), TermX::int(t.x.get().cert.get().version) ]),

            RuleX::fact("signatureAlgorithm", vec![
                t.cert(),
                TermX::str(Self::oid_to_string(&t.x.get().sig_alg.id).as_str()),
            ]),
        ]);
        Ok(())
    }
}

impl<'a, 'b> Facts<CertIndexed<&'b CertificateValue<'a>>> for TimeFacts {
    closed spec fn spec_facts(t: CertIndexed<SpecCertificateValue>) -> Option<Seq<SpecRule>> {
        if_let! {
            let Some(not_after) = Self::spec_time_to_timestamp(t.x.cert.validity.not_after);
            let Some(not_before) = Self::spec_time_to_timestamp(t.x.cert.validity.not_before);

            Some(seq![
                spec_fact!("notAfter", t.spec_cert(), spec_int!(not_after as int)),
                spec_fact!("notBefore", t.spec_cert(), spec_int!(not_before as int)),
            ])
        }
    }

    fn facts(t: &CertIndexed<&'b CertificateValue<'a>>, out: &mut VecDeep<Rule>) -> (res: Result<(), ValidationError>) {
        let not_after = Self::time_to_timestamp(&t.x.get().cert.get().validity.not_after)
            .ok_or(ValidationError::TimeParseError)?;

        let not_before = Self::time_to_timestamp(&t.x.get().cert.get().validity.not_before)
            .ok_or(ValidationError::TimeParseError)?;

        out.push(RuleX::fact("notAfter", vec![ t.cert(), TermX::int(not_after) ]));
        out.push(RuleX::fact("notBefore", vec![ t.cert(), TermX::int(not_before) ]));

        Ok(())
    }
}

impl<'a, 'b> Facts<CertIndexed<&'b CertificateValue<'a>>> for SubjectNameFacts {
    closed spec fn spec_facts(t: CertIndexed<SpecCertificateValue>) -> Option<Seq<SpecRule>> {
        Some(seq![
            spec_fact!("subject", t.spec_cert(),
                // common name
                spec_str!(Self::spec_get_rdn(t.x.cert.subject, spec_oid!(COMMON_NAME)).unwrap_or("".view())),
                // country
                spec_str!(Self::spec_get_rdn(t.x.cert.subject, spec_oid!(COUNTRY_NAME)).unwrap_or("".view())),
                // locality
                spec_str!(Self::spec_get_rdn(t.x.cert.subject, spec_oid!(LOCALITY_NAME)).unwrap_or("".view())),
                // state or province name
                spec_str!(Self::spec_get_rdn(t.x.cert.subject, spec_oid!(STATE_NAME)).unwrap_or("".view())),
                // organization name
                spec_str!(Self::spec_get_rdn(t.x.cert.subject, spec_oid!(ORGANIZATION_NAME)).unwrap_or("".view())),
            ),

            // TODO: duplicate with the subject pred?
            spec_fact!("commonName", t.spec_cert(),
                spec_str!(Self::spec_get_rdn(t.x.cert.subject, spec_oid!(COMMON_NAME)).unwrap_or("".view())),
            ),

            spec_fact!("country", t.spec_cert(),
                spec_str!(Self::spec_get_rdn(t.x.cert.subject, spec_oid!(COUNTRY_NAME)).unwrap_or("".view())),
            ),

            spec_fact!("givenName", t.spec_cert(),
                spec_str!(Self::spec_get_rdn(t.x.cert.subject, spec_oid!(GIVEN_NAME)).unwrap_or("".view())),
            ),

            spec_fact!("localityName", t.spec_cert(),
                spec_str!(Self::spec_get_rdn(t.x.cert.subject, spec_oid!(LOCALITY_NAME)).unwrap_or("".view())),
            ),

            spec_fact!("organizationName", t.spec_cert(),
                spec_str!(Self::spec_get_rdn(t.x.cert.subject, spec_oid!(ORGANIZATION_NAME)).unwrap_or("".view())),
            ),

            spec_fact!("postalCode", t.spec_cert(),
                spec_str!(Self::spec_get_rdn(t.x.cert.subject, spec_oid!(POSTAL_CODE)).unwrap_or("".view())),
            ),

            spec_fact!("stateOrProvinceName", t.spec_cert(),
                spec_str!(Self::spec_get_rdn(t.x.cert.subject, spec_oid!(STATE_NAME)).unwrap_or("".view())),
            ),

            spec_fact!("streetAddress", t.spec_cert(),
                spec_str!(Self::spec_get_rdn(t.x.cert.subject, spec_oid!(STREET_ADDRESS)).unwrap_or("".view())),
            ),

            spec_fact!("surname", t.spec_cert(),
                spec_str!(Self::spec_get_rdn(t.x.cert.subject, spec_oid!(SURNAME)).unwrap_or("".view())),
            ),
        ])
    }

    fn facts(t: &CertIndexed<&'b CertificateValue<'a>>, out: &mut VecDeep<Rule>) -> (res: Result<(), ValidationError>) {
        out.append_owned(vec_deep![
            RuleX::fact("subject", vec![
                t.cert(),
                TermX::str(Self::get_rdn(&t.x.get().cert.get().subject, &oid!(COMMON_NAME)).unwrap_or("")),
                TermX::str(Self::get_rdn(&t.x.get().cert.get().subject, &oid!(COUNTRY_NAME)).unwrap_or("")),
                TermX::str(Self::get_rdn(&t.x.get().cert.get().subject, &oid!(LOCALITY_NAME)).unwrap_or("")),
                TermX::str(Self::get_rdn(&t.x.get().cert.get().subject, &oid!(STATE_NAME)).unwrap_or("")),
                TermX::str(Self::get_rdn(&t.x.get().cert.get().subject, &oid!(ORGANIZATION_NAME)).unwrap_or("")),
            ]),

            RuleX::fact("commonName", vec![
                t.cert(),
                TermX::str(Self::get_rdn(&t.x.get().cert.get().subject, &oid!(COMMON_NAME)).unwrap_or("")),
            ]),

            RuleX::fact("country", vec![
                t.cert(),
                TermX::str(Self::get_rdn(&t.x.get().cert.get().subject, &oid!(COUNTRY_NAME)).unwrap_or("")),
            ]),

            RuleX::fact("givenName", vec![
                t.cert(),
                TermX::str(Self::get_rdn(&t.x.get().cert.get().subject, &oid!(GIVEN_NAME)).unwrap_or("")),
            ]),

            RuleX::fact("localityName", vec![
                t.cert(),
                TermX::str(Self::get_rdn(&t.x.get().cert.get().subject, &oid!(LOCALITY_NAME)).unwrap_or("")),
            ]),

            RuleX::fact("organizationName", vec![
                t.cert(),
                TermX::str(Self::get_rdn(&t.x.get().cert.get().subject, &oid!(ORGANIZATION_NAME)).unwrap_or("")),
            ]),

            RuleX::fact("postalCode", vec![
                t.cert(),
                TermX::str(Self::get_rdn(&t.x.get().cert.get().subject, &oid!(POSTAL_CODE)).unwrap_or("")),
            ]),

            RuleX::fact("stateOrProvinceName", vec![
                t.cert(),
                TermX::str(Self::get_rdn(&t.x.get().cert.get().subject, &oid!(STATE_NAME)).unwrap_or("")),
            ]),

            RuleX::fact("streetAddress", vec![
                t.cert(),
                TermX::str(Self::get_rdn(&t.x.get().cert.get().subject, &oid!(STREET_ADDRESS)).unwrap_or("")),
            ]),

            RuleX::fact("surname", vec![
                t.cert(),
                TermX::str(Self::get_rdn(&t.x.get().cert.get().subject, &oid!(SURNAME)).unwrap_or("")),
            ]),
        ]);
        Ok(())
    }
}

impl<'a, 'b> Facts<CertIndexed<&'b CertificateValue<'a>>> for SubjectPKIFacts {
    closed spec fn spec_facts(t: CertIndexed<SpecCertificateValue>) -> Option<Seq<SpecRule>> {
        if_let! {
            // Fact about DSA parameters
            let dsa_fact = match t.x.cert.subject_key.alg.param {
                SpecAlgorithmParamValue::DSASignature(Either::Left(param)) => {
                    spec_fact!("spkiDSAParameters",
                        t.spec_cert(),
                        spec_int!((param.p.len() - 1) as usize * 8),
                        spec_int!((param.q.len() - 1) as usize * 8),
                        spec_int!((param.g.len() - 1) as usize * 8),
                    )
                }

                _ => spec_fact!("spkiDSAParameters",
                    t.spec_cert(),
                    spec_atom!("na".view()),
                    spec_atom!("na".view()),
                    spec_atom!("na".view()),
                ),
            };

            // Fact about RSA modulus length
            let Some(rsa_fact) = match t.x.cert.subject_key.alg.param {
                SpecAlgorithmParamValue::RSAEncryption(..) => {
                    // Parse the public key field to get the modulus length
                    let pub_key = BitStringValue::spec_bytes(t.x.cert.subject_key.pub_key);

                    if_let! {
                        let Ok((_, parsed)) = ASN1(RSAParam).view().spec_parse(pub_key);
                        Some(spec_fact!("spkiRSAModLength", t.spec_cert(), spec_int!((parsed.modulus.len() - 1) as usize * 8)))
                    }
                }

                _ => Some(spec_fact!("spkiRSAModLength", t.spec_cert(), spec_atom!("na".view()))),
            };

            Some(seq![dsa_fact, rsa_fact])
        }
    }

    fn facts(t: &CertIndexed<&'b CertificateValue<'a>>, out: &mut VecDeep<Rule>) -> (res: Result<(), ValidationError>) {
        let dsa_fact = match &t.x.get().cert.get().subject_key.alg.param {
            AlgorithmParamValue::DSASignature(Either::Left(param)) => {
                let p_len = param.p.byte_len();
                let q_len = param.q.byte_len();
                let g_len = param.g.byte_len();

                if p_len > LiteralInt::MAX as usize / 8 ||
                   q_len > LiteralInt::MAX as usize / 8 ||
                   g_len > LiteralInt::MAX as usize / 8 {
                    return Err(ValidationError::IntegerOverflow);
                }

                RuleX::fact("spkiDSAParameters", vec![
                    t.cert(),
                    TermX::int((p_len * 8) as LiteralInt),
                    TermX::int((q_len * 8) as LiteralInt),
                    TermX::int((g_len * 8) as LiteralInt),
                ])
            }

            _ => RuleX::fact("spkiDSAParameters", vec![
                t.cert(),
                TermX::atom("na"),
                TermX::atom("na"),
                TermX::atom("na"),
            ]),
        };

        let rsa_fact = match &t.x.get().cert.get().subject_key.alg.param {
            AlgorithmParamValue::RSAEncryption(..) => {
                let pub_key = t.x.get().cert.get().subject_key.pub_key.bytes();
                let parsed = match ASN1(RSAParam).parse(pub_key) {
                    Ok((_, parsed)) => parsed,
                    Err(_) => return Err(ValidationError::RSAPubKeyParseError),
                };

                let mod_len = parsed.modulus.byte_len();

                if mod_len > LiteralInt::MAX as usize / 8 {
                    return Err(ValidationError::IntegerOverflow);
                }

                RuleX::fact("spkiRSAModLength", vec![
                    t.cert(),
                    TermX::int((mod_len * 8) as LiteralInt),
                ])
            }

            _ => RuleX::fact("spkiRSAModLength", vec![ t.cert(), TermX::atom("na") ]),
        };

        out.push(dsa_fact);
        out.push(rsa_fact);
        Ok(())
    }
}

impl BasicFacts {
    pub closed spec fn spec_oid_to_string(oid: SpecObjectIdentifierValue) -> Seq<char>
    {
        seq_join(Seq::new(oid.len(), |i| spec_u64_to_string(oid[i])), "."@)
    }

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
}

impl TimeFacts {
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

impl SubjectNameFacts {
    /// Convert a dir string to string
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

    /// Get RDN value of a specific OID
    pub closed spec fn spec_get_rdn(name: SpecNameValue, oid: SpecObjectIdentifierValue) -> Option<Seq<char>>
        decreases name.len()
    {
        if name.len() == 0 {
            None
        } else {
            if name[0].len() == 1 && name[0][0].typ == oid {
                Self::spec_dir_string_to_string(name[0][0].value)
            } else {
                Self::spec_get_rdn(name.drop_first(), oid)
            }
        }
    }

    /// Exec version of spec_get_rdn
    pub fn get_rdn<'a, 'b>(name: &'b NameValue<'a>, oid: &'b ObjectIdentifierValue) -> (res: Option<&'a str>)
        ensures
            res matches Some(res) ==> Self::spec_get_rdn(name@, oid@) == Some(res@),
            res.is_none() ==> Self::spec_get_rdn(name@, oid@).is_none(),
    {
        let len = name.len();

        assert(name@.skip(0) == name@);

        for i in 0..len
            invariant
                len == name@.len(),
                Self::spec_get_rdn(name@, oid@) =~= Self::spec_get_rdn(name@.skip(i as int), oid@),
        {
            if name.get(i).len() == 1 && name.get(i).get(0).typ.polyfill_eq(oid) {
                return Self::dir_string_to_string(&name.get(i).get(0).value);
            }
            assert(name@.skip(i as int).drop_first() == name@.skip(i + 1));
        }

        return None;
    }
}

}
