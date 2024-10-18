use vstd::prelude::*;

use polyfill::*;
use vpl::*;
use parser::{*, x509::*, asn1::*};

use crate::validate::*;
use crate::specs::*;
use crate::error::*;

use super::*;

verus! {

broadcast use vpl::lemma_ext_equal_deep;

/// Facts for supported extensions
pub type ExtensionFacts = seq_facts![
    ExtBasicConstraintsFacts,
    ExtKeyUsageFacts,
    ExtSubjectAltNameFacts,
    ExtNameConstraintsFacts,
    ExtCertificatePoliciesFacts,
    ExtExtendedKeyUsageFacts,
];
pub struct ExtBasicConstraintsFacts;
pub struct ExtKeyUsageFacts;
pub struct ExtSubjectAltNameFacts;
pub struct ExtNameConstraintsFacts;
pub struct ExtCertificatePoliciesFacts;
pub struct ExtExtendedKeyUsageFacts;

impl<'a, 'b> Facts<CertIndexed<&'b CertificateValue<'a>>> for ExtExtendedKeyUsageFacts {
    closed spec fn spec_facts(t: CertIndexed<SpecCertificateValue>) -> Option<Seq<SpecRule>> {
        Some(if let OptionDeep::Some(ext) = spec_get_extension(t.x, spec_oid!(EXTENDED_KEY_USAGE)) {
            if let SpecExtensionParamValue::ExtendedKeyUsage(usages) = ext.param {
                seq![
                    spec_fact!("extendedKeyUsageExt", t.spec_cert(), spec_bool!(true)),
                    spec_fact!("extendedKeyUsageCritical", t.spec_cert(), spec_bool!(ext.critical)),
                ] + usages.map_values(|usage: SpecObjectIdentifierValue| {
                    let usage_term =
                        if usage == spec_oid!(SERVER_AUTH) {
                            spec_atom!("serverAuth".view())
                        } else if usage == spec_oid!(CLIENT_AUTH) {
                            spec_atom!("clientAuth".view())
                        } else if usage == spec_oid!(CODE_SIGNING) {
                            spec_atom!("codeSigning".view())
                        } else if usage == spec_oid!(EMAIL_PROTECTION) {
                            spec_atom!("emailProtection".view())
                        } else if usage == spec_oid!(TIME_STAMPING) {
                            spec_atom!("timeStamping".view())
                        } else if usage == spec_oid!(OCSP_SIGNING) {
                            spec_atom!("oCSPSigning".view())
                        } else if usage == spec_oid!(EXTENDED_KEY_USAGE) {
                            spec_atom!("any".view())
                        } else {
                            spec_str!(BasicFacts::spec_oid_to_string(usage))
                        };

                    spec_fact!("extendedKeyUsage", t.spec_cert(), usage_term)
                })
            } else {
                seq![
                    spec_fact!("extendedKeyUsageExt", t.spec_cert(), spec_bool!(false)),
                ]
            }
        } else {
            seq![
                spec_fact!("extendedKeyUsageExt", t.spec_cert(), spec_bool!(false)),
            ]
        })
    }

    #[verifier::loop_isolation(false)]
    fn facts(t: &CertIndexed<&'b CertificateValue<'a>>, out: &mut VecDeep<Rule>) -> (res: Result<(), ValidationError>) {
        if let OptionDeep::Some(ext) = get_extension(t.x, &oid!(EXTENDED_KEY_USAGE)) {
            if let ExtensionParamValue::ExtendedKeyUsage(usages) = &ext.param {
                out.push(RuleX::fact("extendedKeyUsageExt", vec![ t.cert(), TermX::bool(true) ]));
                out.push(RuleX::fact("extendedKeyUsageCritical", vec![ t.cert(), TermX::bool(ext.critical) ]));

                let len = usages.len();
                for i in 0..len
                    invariant
                        len == usages@.len(),
                        out@ =~~= old(out)@ + Self::spec_facts(t@).unwrap().take(i + 2),
                {
                    let usage = usages.get(i);
                    let usage_term =
                        if usage.polyfill_eq(&oid!(SERVER_AUTH)) { TermX::atom("serverAuth") }
                        else if usage.polyfill_eq(&oid!(CLIENT_AUTH)) { TermX::atom("clientAuth") }
                        else if usage.polyfill_eq(&oid!(CODE_SIGNING)) { TermX::atom("codeSigning") }
                        else if usage.polyfill_eq(&oid!(EMAIL_PROTECTION)) { TermX::atom("emailProtection") }
                        else if usage.polyfill_eq(&oid!(TIME_STAMPING)) { TermX::atom("timeStamping") }
                        else if usage.polyfill_eq(&oid!(OCSP_SIGNING)) { TermX::atom("oCSPSigning") }
                        else if usage.polyfill_eq(&oid!(EXTENDED_KEY_USAGE)) { TermX::atom("any") }
                        else { TermX::str(BasicFacts::oid_to_string(usage).as_str()) };

                    out.push(RuleX::fact("extendedKeyUsage", vec![ t.cert(), usage_term ]));
                }

                return Ok(());
            }
        }

        out.push(RuleX::fact("extendedKeyUsageExt", vec![ t.cert(), TermX::bool(false) ]));
        Ok(())
    }
}

impl<'a, 'b> Facts<CertIndexed<&'b CertificateValue<'a>>> for ExtCertificatePoliciesFacts {
    closed spec fn spec_facts(t: CertIndexed<SpecCertificateValue>) -> Option<Seq<SpecRule>> {
        Some(if let OptionDeep::Some(ext) = spec_get_extension(t.x, spec_oid!(CERT_POLICIES)) {
            if let SpecExtensionParamValue::CertificatePolicies(policies) = ext.param {
                seq![
                    spec_fact!("certificatePoliciesExt", t.spec_cert(), spec_bool!(true)),
                    spec_fact!("certificatePoliciesCritical", t.spec_cert(), spec_bool!(ext.critical)),
                ] + policies.map_values(|policy: SpecPolicyInfoValue|
                    spec_fact!("certificatePolicies", t.spec_cert(), spec_str!(BasicFacts::spec_oid_to_string(policy.policy_id))))
            } else {
                seq![
                    spec_fact!("certificatePoliciesExt", t.spec_cert(), spec_bool!(false)),
                ]
            }
        } else {
            seq![
                spec_fact!("certificatePoliciesExt", t.spec_cert(), spec_bool!(false)),
            ]
        })
    }

    #[verifier::loop_isolation(false)]
    fn facts(t: &CertIndexed<&'b CertificateValue<'a>>, out: &mut VecDeep<Rule>) -> (res: Result<(), ValidationError>) {
        if let OptionDeep::Some(ext) = get_extension(t.x, &oid!(CERT_POLICIES)) {
            if let ExtensionParamValue::CertificatePolicies(policies) = &ext.param {
                out.push(RuleX::fact("certificatePoliciesExt", vec![ t.cert(), TermX::bool(true) ]));
                out.push(RuleX::fact("certificatePoliciesCritical", vec![ t.cert(), TermX::bool(ext.critical) ]));

                let len = policies.len();
                for i in 0..len
                    invariant
                        len == policies@.len(),
                        out@ =~~= old(out)@ + Self::spec_facts(t@).unwrap().take(i + 2),
                {
                    out.push(RuleX::fact("certificatePolicies", vec![ t.cert(), TermX::str(BasicFacts::oid_to_string(&policies.get(i).policy_id).as_str()) ]));
                }

                return Ok(());
            }
        }

        out.push(RuleX::fact("certificatePoliciesExt", vec![ t.cert(), TermX::bool(false) ]));
        Ok(())
    }
}

impl<'a, 'b> Facts<CertIndexed<&'b CertificateValue<'a>>> for ExtBasicConstraintsFacts {
    closed spec fn spec_facts(t: CertIndexed<SpecCertificateValue>) -> Option<Seq<SpecRule>> {
        Some(if let OptionDeep::Some(ext) = spec_get_extension(t.x, spec_oid!(BASIC_CONSTRAINTS)) {
            if let SpecExtensionParamValue::BasicConstraints(param) = ext.param {
                seq![
                    spec_fact!("basicConstraintsExt", t.spec_cert(), spec_bool!(true)),
                    spec_fact!("basicConstraintsCritical", t.spec_cert(), spec_bool!(ext.critical)),
                    spec_fact!("isCA", t.spec_cert(), spec_bool!(param.is_ca)),

                    if let OptionDeep::Some(path_len) = param.path_len {
                        spec_fact!("pathLimit", t.spec_cert(), spec_int!(path_len as int))
                    } else {
                        spec_fact!("pathLimit", t.spec_cert(), spec_atom!("none".view()))
                    },
                ]
            } else {
                seq![
                    spec_fact!("basicConstraintsExt", t.spec_cert(), spec_bool!(false)),
                ]
            }
        } else {
            seq![
                spec_fact!("basicConstraintsExt", t.spec_cert(), spec_bool!(false)),
            ]
        })
    }

    fn facts(t: &CertIndexed<&'b CertificateValue<'a>>, out: &mut VecDeep<Rule>) -> (res: Result<(), ValidationError>) {
        if let OptionDeep::Some(ext) = get_extension(t.x, &oid!(BASIC_CONSTRAINTS)) {
            if let ExtensionParamValue::BasicConstraints(param) = &ext.param {
                out.push(RuleX::fact("basicConstraintsExt", vec![ t.cert(), TermX::bool(true) ]));
                out.push(RuleX::fact("basicConstraintsCritical", vec![ t.cert(), TermX::bool(ext.critical) ]));
                out.push(RuleX::fact("isCA", vec![ t.cert(), TermX::bool(param.is_ca) ]));

                if let OptionDeep::Some(path_len) = param.path_len {
                    out.push(RuleX::fact("pathLimit", vec![ t.cert(), TermX::int(path_len as LiteralInt) ]));
                } else {
                    out.push(RuleX::fact("pathLimit", vec![ t.cert(), TermX::atom("none") ]));
                }

                return Ok(());
            }
        }

        out.push(RuleX::fact("basicConstraintsExt", vec![ t.cert(), TermX::bool(false) ]));
        Ok(())
    }
}

impl ExtKeyUsageFacts {
    /// `usages` is a list of key usage names corresponding to each bit in the key usage bit string
    /// e.g. keyUsage(cert(..), usages[0]) is added if the 0-th bit is set in `param`
    closed spec fn spec_facts_helper(t: CertIndexed<SpecCertificateValue>, usages: Seq<Seq<char>>, param: SpecBitStringValue, i: int) -> Seq<SpecRule>
        decreases i
    {
        if i <= 0 {
            seq![]
        } else if BitStringValue::spec_has_bit(param, i - 1) {
            Self::spec_facts_helper(t, usages, param, i - 1) +
            seq![ spec_fact!("keyUsage", t.spec_cert(), spec_atom!(usages[i - 1])) ]
        } else {
            Self::spec_facts_helper(t, usages, param, i - 1)
        }
    }
}

impl<'a, 'b> Facts<CertIndexed<&'b CertificateValue<'a>>> for ExtKeyUsageFacts {
    closed spec fn spec_facts(t: CertIndexed<SpecCertificateValue>) -> Option<Seq<SpecRule>> {
        Some(if let OptionDeep::Some(ext) = spec_get_extension(t.x, spec_oid!(KEY_USAGE)) {
            if let SpecExtensionParamValue::KeyUsage(param) = ext.param {
                let usages = seq![
                    "digitalSignature".view(),
                    "nonRepudiation".view(),
                    "keyEncipherment".view(),
                    "dataEncipherment".view(),
                    "keyAgreement".view(),
                    "keyCertSign".view(),
                    "cRLSign".view(),
                    "encipherOnly".view(),
                    "decipherOnly".view(),
                ];

                seq![
                    spec_fact!("keyUsageExt", t.spec_cert(), spec_bool!(true)),
                    spec_fact!("keyUsageCritical", t.spec_cert(), spec_bool!(ext.critical)),
                ] +
                Self::spec_facts_helper(t, usages, param, usages.len() as int)
            } else {
                seq![
                    spec_fact!("keyUsageExt", t.spec_cert(), spec_bool!(false)),
                ]
            }
        } else {
            seq![
                spec_fact!("keyUsageExt", t.spec_cert(), spec_bool!(false)),
            ]
        })
    }

    fn facts(t: &CertIndexed<&'b CertificateValue<'a>>, out: &mut VecDeep<Rule>) -> (res: Result<(), ValidationError>) {
        if let OptionDeep::Some(ext) = get_extension(t.x, &oid!(KEY_USAGE)) {
            if let ExtensionParamValue::KeyUsage(param) = &ext.param {
                let usages = vec_deep![
                    "digitalSignature",
                    "nonRepudiation",
                    "keyEncipherment",
                    "dataEncipherment",
                    "keyAgreement",
                    "keyCertSign",
                    "cRLSign",
                    "encipherOnly",
                    "decipherOnly",
                ];

                out.push(RuleX::fact("keyUsageExt", vec![ t.cert(), TermX::bool(true) ]));
                out.push(RuleX::fact("keyUsageCritical", vec![ t.cert(), TermX::bool(ext.critical) ]));

                // Add fact keyUsage(.., usages[i]) for each i-th bit set in the param
                let ghost prev_out = out@;
                let len = usages.len();
                for i in 0..len
                    invariant
                        len == usages@.len(),
                        out@ =~~= prev_out + Self::spec_facts_helper(t@, usages@, param@, i as int),
                {
                    if param.has_bit(i) {
                        out.push(RuleX::fact("keyUsage", vec![ t.cert(), TermX::atom(usages.get(i)) ]));
                    }
                }

                assert(usages@ =~= seq![
                    "digitalSignature".view(),
                    "nonRepudiation".view(),
                    "keyEncipherment".view(),
                    "dataEncipherment".view(),
                    "keyAgreement".view(),
                    "keyCertSign".view(),
                    "cRLSign".view(),
                    "encipherOnly".view(),
                    "decipherOnly".view(),
                ]);

                return Ok(());
            }
        }

        out.push(RuleX::fact("keyUsageExt", vec![ t.cert(), TermX::bool(false) ]));

        Ok(())
    }
}

impl ExtSubjectAltNameFacts {
    /// Same definition as Hammurabi
    pub closed spec fn spec_oid_to_name(oid: SpecObjectIdentifierValue) -> Seq<char>
    {
        if oid == spec_oid!(COUNTRY_NAME) { "country"@ }
        else if oid == spec_oid!(ORGANIZATION_NAME) { "organization"@ }
        else if oid == spec_oid!(ORGANIZATIONAL_UNIT) { "organizational unit"@ }
        else if oid == spec_oid!(ORGANIZATIONAL_IDENT) { "organizational identifier"@ }
        else if oid == spec_oid!(COMMON_NAME) { "common name"@ }
        else if oid == spec_oid!(SURNAME) { "surname"@ }
        else if oid == spec_oid!(STATE_NAME) { "state"@ }
        else if oid == spec_oid!(STREET_ADDRESS) { "street address"@ }
        else if oid == spec_oid!(LOCALITY_NAME) { "locality"@ }
        else if oid == spec_oid!(POSTAL_CODE) { "postal code"@ }
        else if oid == spec_oid!(GIVEN_NAME) { "given name"@ }
        else if oid == spec_oid!(DOMAIN_COMPONENT) { "domain component"@ }
        else { "UNKNOWN"@ }
    }

    /// Exec version of spec_oid_to_name
    pub fn oid_to_name(oid: &ObjectIdentifierValue) -> (res: &'static str)
        ensures res@ =~= Self::spec_oid_to_name(oid@)
    {
        let id = oid!(COUNTRY_NAME); assert(id@ == spec_oid!(COUNTRY_NAME));
        let id = oid!(ORGANIZATION_NAME); assert(id@ == spec_oid!(ORGANIZATION_NAME));
        let id = oid!(ORGANIZATIONAL_UNIT); assert(id@ == spec_oid!(ORGANIZATIONAL_UNIT));
        let id = oid!(ORGANIZATIONAL_IDENT); assert(id@ == spec_oid!(ORGANIZATIONAL_IDENT));
        let id = oid!(COMMON_NAME); assert(id@ == spec_oid!(COMMON_NAME));
        let id = oid!(SURNAME); assert(id@ == spec_oid!(SURNAME));
        let id = oid!(STATE_NAME); assert(id@ == spec_oid!(STATE_NAME));
        let id = oid!(STREET_ADDRESS); assert(id@ == spec_oid!(STREET_ADDRESS));
        let id = oid!(LOCALITY_NAME); assert(id@ == spec_oid!(LOCALITY_NAME));
        let id = oid!(POSTAL_CODE); assert(id@ == spec_oid!(POSTAL_CODE));
        let id = oid!(GIVEN_NAME); assert(id@ == spec_oid!(GIVEN_NAME));
        let id = oid!(DOMAIN_COMPONENT); assert(id@ == spec_oid!(DOMAIN_COMPONENT));

        if oid.polyfill_eq(&oid!(COUNTRY_NAME)) { "country" }
        else if oid.polyfill_eq(&oid!(ORGANIZATION_NAME)) { "organization" }
        else if oid.polyfill_eq(&oid!(ORGANIZATIONAL_UNIT)) { "organizational unit" }
        else if oid.polyfill_eq(&oid!(ORGANIZATIONAL_IDENT)) { "organizational identifier" }
        else if oid.polyfill_eq(&oid!(COMMON_NAME)) { "common name" }
        else if oid.polyfill_eq(&oid!(SURNAME)) { "surname" }
        else if oid.polyfill_eq(&oid!(STATE_NAME)) { "state" }
        else if oid.polyfill_eq(&oid!(STREET_ADDRESS)) { "street address" }
        else if oid.polyfill_eq(&oid!(LOCALITY_NAME)) { "locality" }
        else if oid.polyfill_eq(&oid!(POSTAL_CODE)) { "postal code" }
        else if oid.polyfill_eq(&oid!(GIVEN_NAME)) { "given name" }
        else if oid.polyfill_eq(&oid!(DOMAIN_COMPONENT)) { "domain component" }
        else { "UNKNOWN" }
    }

    /// Generate pairs of (typ, str) where typ is the name of the variant
    /// and str is the content of the general name
    pub closed spec fn spec_extract_general_name(name: SpecGeneralNameValue) -> Seq<(Seq<char>, SpecTerm)>
    {
        match name {
            SpecGeneralNameValue::Other(..) => seq![ ("Other"@, spec_atom!("unsupported".view())) ],
            SpecGeneralNameValue::RFC822(s) => seq![ ("RFC822"@, spec_str!(s)) ],
            SpecGeneralNameValue::DNS(s) => seq![ ("DNS"@, spec_str!(s)) ],
            SpecGeneralNameValue::X400(..) => seq![ ("X400"@, spec_atom!("unsupported".view())) ],
            SpecGeneralNameValue::Directory(dir_names) => {
                dir_names.map_values(|dir_name: SpecRDNValue|
                    dir_name.map_values(|name: SpecAttributeTypeAndValueValue| (
                        "Directory/"@ + Self::spec_oid_to_name(name.typ),
                        match SubjectNameFacts::spec_dir_string_to_string(name.value) {
                            Some(s) => spec_str!(s),
                            None => spec_atom!("unsupported".view()),
                        }
                    ))
                ).flatten()
            }
            SpecGeneralNameValue::EDIParty(..) => seq![ ("EDIParty"@, spec_atom!("unsupported".view())) ],
            SpecGeneralNameValue::URI(s) => seq![ ("URI"@, spec_str!(s)) ],
            SpecGeneralNameValue::IP(..) => seq![ ("IP"@, spec_atom!("unsupported".view())) ],
            SpecGeneralNameValue::RegisteredID(..) => seq![ ("RegisteredID"@, spec_atom!("unsupported".view())) ],
            SpecGeneralNameValue::Unreachable => seq![],
        }
    }

    /// Exec version of spec_extract_general_name
    #[verifier::loop_isolation(false)]
    pub fn extract_general_name(name: &GeneralNameValue) -> (res: VecDeep<(String, Term)>)
        ensures res@ =~~= Self::spec_extract_general_name(name@)
    {
        match name {
            GeneralNameValue::Other(..) => vec_deep![("Other".to_string(), TermX::atom("unsupported"))],
            GeneralNameValue::RFC822(s) => vec_deep![("RFC822".to_string(), TermX::str(s))],
            GeneralNameValue::DNS(s) => vec_deep![("DNS".to_string(), TermX::str(s))],
            GeneralNameValue::X400(..) => vec_deep![("X400".to_string(), TermX::atom("unsupported"))],
            GeneralNameValue::Directory(dir_names) => {
                let mut dir_name_pairs = vec_deep![];

                // The spec version before flattening
                let ghost spec_nested = dir_names@.map_values(|dir_name: SpecRDNValue| {
                    dir_name.map_values(|name: SpecAttributeTypeAndValueValue| {
                        (
                            "Directory/"@ + Self::spec_oid_to_name(name.typ),
                            match SubjectNameFacts::spec_dir_string_to_string(name.value) {
                                Some(s) => spec_str!(s),
                                None => spec_atom!("unsupported".view()),
                            }
                        )
                    })
                });

                assert(spec_nested.skip(0) == spec_nested);

                let len = dir_names.len();
                for j in 0..len
                    invariant
                        len == dir_names@.len(),
                        spec_nested.flatten() =~~= dir_name_pairs@ + spec_nested.skip(j as int).flatten(),
                {
                    let ghost prev_dir_name_pairs = dir_name_pairs@;

                    // Read each RDN, and convert it to a pair of (type, value)
                    let len = dir_names.get(j).len();
                    for k in 0..len
                        invariant
                            0 <= j < dir_names@.len(),
                            len == dir_names@[j as int].len(),
                            dir_name_pairs@ =~~= prev_dir_name_pairs + spec_nested[j as int].take(k as int),
                    {
                        let attr = dir_names.get(j).get(k);
                        let typ = "Directory/".to_string().concat(Self::oid_to_name(&attr.typ));
                        let val = match SubjectNameFacts::dir_string_to_string(&attr.value) {
                            Some(s) => TermX::str(s),
                            None => TermX::atom("unsupported"),
                        };

                        dir_name_pairs.push((typ, val));
                    }

                    assert(spec_nested.skip(j as int).first() == spec_nested[j as int]);
                    assert(spec_nested.skip(j as int).drop_first() == spec_nested.skip(j + 1));
                }

                assert(dir_names@.take(len as int) == dir_names@);

                dir_name_pairs
            }
            GeneralNameValue::EDIParty(..) => vec_deep![("EDIParty".to_string(), TermX::atom("unsupported"))],
            GeneralNameValue::URI(s) => vec_deep![("URI".to_string(), TermX::str(s))],
            GeneralNameValue::IP(..) => vec_deep![("IP".to_string(), TermX::atom("unsupported"))],
            GeneralNameValue::RegisteredID(..) => vec_deep![("RegisteredID".to_string(), TermX::atom("unsupported"))],
            GeneralNameValue::Unreachable => vec_deep![],
        }
    }

    /// Extract all general names along with a string denoting their variant
    /// For directoryName, expand each RDN to a string
    pub closed spec fn spec_extract_general_names(names: Seq<SpecGeneralNameValue>) -> Seq<(Seq<char>, SpecTerm)>
    {
        Seq::new(names.len(), |i| Self::spec_extract_general_name(names[i])).flatten()
    }

    /// Exec version of spec_extract_general_names
    pub fn extract_general_names(names: &VecDeep<GeneralNameValue>) -> (res: VecDeep<(String, Term)>)
        ensures res@ =~~= Self::spec_extract_general_names(names@)
    {
        let mut typ_names = vec_deep![];

        let len = names.len();

        for i in 0..len
            invariant
                len == names@.len(),
                typ_names@ =~~= Seq::new(i as nat, |i| Self::spec_extract_general_name(names@[i as int])),
        {
            typ_names.push(Self::extract_general_name(names.get(i)));
        }

        VecDeep::flatten(typ_names)
    }
}

impl<'a, 'b> Facts<CertIndexed<&'b CertificateValue<'a>>> for ExtSubjectAltNameFacts {
    closed spec fn spec_facts(t: CertIndexed<SpecCertificateValue>) -> Option<Seq<SpecRule>> {
        Some(if let OptionDeep::Some(ext) = spec_get_extension(t.x, spec_oid!(SUBJECT_ALT_NAME)) {
            if let SpecExtensionParamValue::SubjectAltName(names) = ext.param {
                seq![
                    spec_fact!("sanExt", t.spec_cert(), spec_bool!(true)),
                    spec_fact!("sanCritical", t.spec_cert(), spec_bool!(ext.critical)),
                ] +
                Self::spec_extract_general_names(names).map_values(|v: (Seq<char>, SpecTerm)| spec_fact!("san", t.spec_cert(), v.1))
            } else {
                seq![
                    spec_fact!("sanExt", t.spec_cert(), spec_bool!(false)),
                ]
            }
        } else {
            seq![
                spec_fact!("sanExt", t.spec_cert(), spec_bool!(false)),
            ]
        })
    }

    fn facts(t: &CertIndexed<&'b CertificateValue<'a>>, out: &mut VecDeep<Rule>) -> (res: Result<(), ValidationError>) {
        if let OptionDeep::Some(ext) = get_extension(t.x, &oid!(SUBJECT_ALT_NAME)) {
            if let ExtensionParamValue::SubjectAltName(names) = &ext.param {
                out.push(RuleX::fact("sanExt", vec![ t.cert(), TermX::bool(true) ]));
                out.push(RuleX::fact("sanCritical", vec![ t.cert(), TermX::bool(ext.critical) ]));

                let typ_names = Self::extract_general_names(names);

                // Push all subject alt names as facts
                let ghost prev_out = out@;
                let len = typ_names.len();
                for i in 0..len
                    invariant
                        len == typ_names@.len(),
                        typ_names@ == Self::spec_extract_general_names(names@),
                        out@ =~~= prev_out + Self::spec_extract_general_names(names@)
                            .map_values(|v: (Seq<char>, SpecTerm)| spec_fact!("san", t.view().spec_cert(), v.1)).take(i as int),
                {
                    out.push(RuleX::fact("san", vec![ t.cert(), arc_clone(&typ_names.get(i).1) ]));
                }

                return Ok(());
            }
        }

        out.push(RuleX::fact("sanExt", vec![ t.cert(), TermX::bool(false) ]));
        Ok(())
    }
}

impl ExtNameConstraintsFacts {
    /// Generate nameConstraintsPermited and nameConstraintsExcluded facts
    pub closed spec fn spec_gen_general_subtree_facts(
        t: CertIndexed<SpecCertificateValue>,
        subtrees: Seq<SpecGeneralSubtreeValue>,
        fact_name: &str,
    ) -> Seq<Seq<SpecRule>>
    {
        Seq::new(subtrees.len(), |j| {
            let typ_names = ExtSubjectAltNameFacts::spec_extract_general_name(subtrees[j].base);

            Seq::new(typ_names.len(), |k| spec_fact!(fact_name, t.spec_cert(), spec_str!(typ_names[k].0), typ_names[k].1))
        })
    }

    /// Exec version of spec_gen_general_subtree_facts
    #[verifier::loop_isolation(false)]
    pub fn gen_general_subtree_facts<'a, 'b>(
        t: &CertIndexed<&'b CertificateValue<'a>>,
        subtrees: &VecDeep<GeneralSubtreeValue>,
        fact_name: &str,
    ) -> (res: VecDeep<VecDeep<Rule>>)
        ensures res@ =~~= Self::spec_gen_general_subtree_facts(t@, subtrees@, fact_name)
    {
        let mut facts = vec_deep![];

        // Iterate through each subtree
        let len = subtrees.len();
        for j in 0..len
            invariant
                len == subtrees@.len(),
                facts@ =~~= Self::spec_gen_general_subtree_facts(t@, subtrees@, fact_name).take(j as int),
        {
            let typ_names = ExtSubjectAltNameFacts::extract_general_name(&subtrees.get(j).base);
            let len = typ_names.len();

            let mut subtree_facts = vec_deep![];

            // Iterate through each general name in the subtree.base
            for k in 0..len
                invariant
                    len == typ_names@.len(),
                    0 <= j < subtrees@.len(),
                    typ_names@ == ExtSubjectAltNameFacts::spec_extract_general_name(subtrees@[j as int].base),
                    subtree_facts@ =~~= Self::spec_gen_general_subtree_facts(t@, subtrees@, fact_name)[j as int].take(k as int),
            {
                // nameConstraintsPermited/nameConstraintsExcluded(cert(..), <variant>, <general name>)
                subtree_facts.push(RuleX::fact(
                    fact_name,
                    vec![
                        t.cert(),
                        TermX::str(typ_names.get(k).0.as_str()),
                        arc_clone(&typ_names.get(k).1),
                    ],
                ));
            }

            facts.push(subtree_facts);
        }

        facts
    }
}

impl<'a, 'b> Facts<CertIndexed<&'b CertificateValue<'a>>> for ExtNameConstraintsFacts {
    /// TODO: avoid flatten() here
    closed spec fn spec_facts(t: CertIndexed<SpecCertificateValue>) -> Option<Seq<SpecRule>> {
        Some(if let OptionDeep::Some(ext) = spec_get_extension(t.x, spec_oid!(NAME_CONSTRAINTS)) {
            if let SpecExtensionParamValue::NameConstraints(param) = ext.param {
                seq![
                    spec_fact!("nameConstraintsExt", t.spec_cert(), spec_bool!(true)),
                    spec_fact!("nameConstraintsCritical", t.spec_cert(), spec_bool!(ext.critical)),
                ] +

                if let OptionDeep::Some(permitted) = param.permitted {
                    Self::spec_gen_general_subtree_facts(t, permitted, "nameConstraintsPermited").flatten()
                } else {
                    seq![]
                } +

                if let OptionDeep::Some(excluded) = param.excluded {
                    Self::spec_gen_general_subtree_facts(t, excluded, "nameConstraintsExcluded").flatten()
                } else {
                    seq![]
                }
            } else {
                seq![ spec_fact!("nameConstraintsExt", t.spec_cert(), spec_bool!(false)) ]
            }
        } else {
            seq![ spec_fact!("nameConstraintsExt", t.spec_cert(), spec_bool!(false)) ]
        })
    }

    fn facts(t: &CertIndexed<&'b CertificateValue<'a>>, out: &mut VecDeep<Rule>) -> (res: Result<(), ValidationError>) {
        if let OptionDeep::Some(ext) = get_extension(t.x, &oid!(NAME_CONSTRAINTS)) {
            if let ExtensionParamValue::NameConstraints(param) = &ext.param {
                out.push(RuleX::fact("nameConstraintsExt", vec![ t.cert(), TermX::bool(true) ]));
                out.push(RuleX::fact("nameConstraintsCritical", vec![ t.cert(), TermX::bool(ext.critical) ]));

                if let OptionDeep::Some(permitted) = &param.permitted {
                    let permitted_facts = ExtNameConstraintsFacts::gen_general_subtree_facts(t, permitted, "nameConstraintsPermited");
                    let permitted_facts = VecDeep::flatten(permitted_facts);
                    out.append_owned(permitted_facts);
                }

                if let OptionDeep::Some(excluded) = &param.excluded {
                    let excluded_facts = ExtNameConstraintsFacts::gen_general_subtree_facts(t, excluded, "nameConstraintsExcluded");
                    let excluded_facts = VecDeep::flatten(excluded_facts);
                    out.append_owned(excluded_facts);
                }

                return Ok(());
            }
        }

        out.push(RuleX::fact("nameConstraintsExt", vec![ t.cert(), TermX::bool(false) ]));
        Ok(())
    }
}

}
