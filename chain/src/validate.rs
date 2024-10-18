use vstd::prelude::*;

use polyfill::*;
use parser::{*, asn1::*, x509::*};
use parser::OptionDeep::*;
use vpl::*;

use crate::specs::*;
use crate::facts::*;
use crate::error::*;
use crate::rsa;
use crate::ecdsa;

verus! {

pub fn likely_issued(issuer: &CertificateValue, subject: &CertificateValue) -> (res: bool)
    ensures res == spec_likely_issued(issuer@, subject@)
{
    same_name(&issuer.get().cert.get().subject, &subject.get().cert.get().issuer) &&
    check_auth_key_id(issuer, subject)
}

pub fn check_auth_key_id(issuer: &CertificateValue, subject: &CertificateValue) -> (res: bool)
    ensures res == spec_check_auth_key_id(issuer@, subject@)
{
    if let Some(akid) = get_auth_key_id(subject) {
        // Check key id
        if let Some(key_id) = &akid.key_id {
            if let Some(skid) = get_subject_key_id(issuer) {
                assert(akid@.key_id matches OptionDeep::Some(id) && spec_get_subject_key_id(issuer@) matches Some(skid));
                if !key_id.polyfill_eq(&skid) {
                    return false;
                }

                assert(akid@.key_id matches OptionDeep::Some(id) && spec_get_subject_key_id(issuer@) matches Some(skid) && id == skid);
            }
        }

        // Check serial number
        if let Some(serial) = &akid.auth_cert_serial {
            if !serial.polyfill_eq(&issuer.get().cert.get().serial) {
                return false;
            }
        }

        return true;
    }

    true
}

pub fn get_extension<'a, 'b>(cert: &'b CertificateValue<'a>, oid: &ObjectIdentifierValue) -> (res: OptionDeep<&'b ExtensionValue<'a>>)
    ensures res@ == spec_get_extension(cert@, oid@)
{
    if let Some(exts) = &cert.get().cert.get().extensions {
        let len = exts.len();

        assert(exts@.skip(0) == exts@);

        for i in 0..len
            invariant
                len == exts@.len(),
                forall |j| #![auto] 0 <= j < i ==> exts@[j].id != oid@,
                spec_get_extension(cert@, oid@)
                    == spec_get_extension_helper(exts@.skip(i as int), oid@),
        {
            if exts.get(i).id.polyfill_eq(oid) {
                return Some(exts.get(i));
            }

            assert(exts@.skip(i as int).drop_first() == exts@.skip(i + 1));
        }

        None
    } else {
        None
    }
}

pub fn get_auth_key_id<'a, 'b>(cert: &'b CertificateValue<'a>) -> (res: OptionDeep<&'b AuthorityKeyIdentifierValue<'a>>)
    ensures res@ == spec_get_auth_key_id(cert@)
{
    if let Some(ext) = get_extension(cert, &oid!(AUTH_KEY_IDENT)) {
        if let ExtensionParamValue::AuthorityKeyIdentifier(param) = &ext.param {
            return Some(param);
        }
    }

    None
}

pub fn get_subject_key_id<'a, 'b>(cert: &'b CertificateValue<'a>) -> (res: OptionDeep<&'b [u8]>)
    ensures res@ == spec_get_subject_key_id(cert@)
{
    if let Some(ext) = get_extension(cert, &oid!(SUBJECT_KEY_IDENT)) {
        if let ExtensionParamValue::SubjectKeyIdentifier(param) = &ext.param {
            return Some(param);
        }
    }

    None
}

pub fn same_name(a: &NameValue, b: &NameValue) -> (res: bool)
    ensures res == spec_same_name(a@, b@)
{
    if a.len() != b.len() {
        return false;
    }

    let len = a.len();
    for i in 0..len
        invariant
            len == a@.len(),
            a@.len() == b@.len(),
            forall |j| #![auto] 0 <= j < i ==> spec_same_rdn(a@[j], b@[j]),
    {
        if !same_rdn(a.get(i), b.get(i)) {
            return false;
        }
    }

    true
}

pub fn same_rdn(a: &RDNValue, b: &RDNValue) -> (res: bool)
    ensures res == spec_same_rdn(a@, b@)
{
    if a.len() != b.len() {
        return false;
    }

    let len = a.len();
    for i in 0..len
        invariant
            len == a@.len(),
            a@.len() == b@.len(),
            forall |j| #![auto] 0 <= j < i ==> spec_same_attr(a@[j], b@[j]),
    {
        if !same_attr(a.get(i), b.get(i)) {
            return false;
        }
    }

    true
}

pub fn same_attr(a: &AttributeTypeAndValueValue, b: &AttributeTypeAndValueValue) -> (res: bool)
    ensures res == spec_same_attr(a@, b@)
{
    a.typ.polyfill_eq(&b.typ) && match (&a.value, &b.value) {
        (DirectoryStringValue::PrintableString(a), DirectoryStringValue::PrintableString(b)) |
        (DirectoryStringValue::UTF8String(a), DirectoryStringValue::UTF8String(b)) |
        (DirectoryStringValue::IA5String(a), DirectoryStringValue::IA5String(b)) =>
            str_eq_str(a, b),

        (DirectoryStringValue::TeletexString(a), DirectoryStringValue::TeletexString(b)) |
        (DirectoryStringValue::BMPString(a), DirectoryStringValue::BMPString(b)) |
        (DirectoryStringValue::UniversalString(a), DirectoryStringValue::UniversalString(b)) =>
            a.polyfill_eq(b),

        (DirectoryStringValue::Unreachable, DirectoryStringValue::Unreachable) => true,

        _ => false,
    }
}

pub fn verify_signature(issuer: &CertificateValue, subject: &CertificateValue) -> (res: bool)
    ensures res == spec_verify_signature(issuer@, subject@)
{
    if !subject.get().sig_alg.polyfill_eq(&subject.get().cert.get().signature) {
        return false;
    }

    let tbs_cert = subject.get().cert.serialize();

    let sig_alg = &subject.get().sig_alg;
    let pub_key = issuer.get().cert.get().subject_key.pub_key.bytes();
    let sig = subject.get().sig.bytes();

    match &issuer.get().cert.get().subject_key.alg.param {
        // RSA PKCS#1 v1.5
        AlgorithmParamValue::RSAEncryption(..) => {
            if  subject.get().sig_alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA224)) ||
                subject.get().sig_alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA256)) ||
                subject.get().sig_alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA384)) ||
                subject.get().sig_alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA512)) {
                return rsa::rsa_pkcs1_v1_5_verify(sig_alg, pub_key, sig, tbs_cert).is_ok();
            }
        }

        // ECDSA P-256 and P-384
        AlgorithmParamValue::ECPublicKey(curve) => {
            if curve.polyfill_eq(&oid!(EC_P_256)) && (
                subject.get().sig_alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA256)) ||
                subject.get().sig_alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA384)) ||
                subject.get().sig_alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA512))
            ) {
                return ecdsa::ecdsa_p256_verify(sig_alg, pub_key, sig, tbs_cert).is_ok();
            }

            if curve.polyfill_eq(&oid!(EC_P_384)) && (
                subject.get().sig_alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA256)) ||
                subject.get().sig_alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA384))
            ) {
                return ecdsa::ecdsa_p384_verify(sig_alg, pub_key, sig, tbs_cert).is_ok();
            }
        }

        _ => {}
    }

    false
}

pub fn valid_domain<'a, 'b, 'c, 'd, 'e, B: Backend, E>(
    backend: &mut B,
    mut policy: Program,
    query: &Query<'a, 'b, 'c, 'd, 'e>,
    debug: bool,
) -> (res: Result<bool, E>)
    where
        E: std::convert::From<B::Error>,
        E: std::convert::From<ValidationError>,
        E: std::convert::From<ProofError>,

    ensures res matches Ok(true) ==> spec_valid_domain(policy@, query@)
{
    if query.chain.len() == 0 {
        Err(ValidationError::EmptyChain)?;
    }

    let ghost old_policy = policy@;

    // Add all generated facts to the policy
    let mut facts = vec_deep![];
    QueryFacts::facts(&query, &mut facts)?;
    let mut facts = facts.to_vec_owned();

    if debug {
        eprintln_join!("[debug] facts:");
        for i in 0..facts.len() {
            eprintln_join!("  ", &facts[i]);
        }
    }

    policy.rules.append(&mut facts);

    let goal = TermX::app_str("certVerifiedChain", vec![ query.get_chain(0).cert() ]);

    assert(goal@->App_1 == seq![ query@.get_chain(0).spec_cert() ]);
    assert(policy@ =~= SpecProgram {
        rules: old_policy.rules + QueryFacts::spec_facts(query@).unwrap(),
    });

    // Solve and validate the goal
    match solve_and_validate::<B, E>(backend, &policy, &goal, debug, true)? {
        ValidationResult::Success(thm) => {
            Ok(true)
        }
        ValidationResult::ProofFailure => Err(ValidationError::ProofFailure)?,
        ValidationResult::BackendFailure => Ok(false),
    }
}

}
