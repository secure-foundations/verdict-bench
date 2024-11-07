// Specifications for some base operations on X.509 certificates
// e.g. comparing distinguished names, checking issuers

use vstd::prelude::*;

use polyfill::*;
use parser::{*, asn1::*, x509::*};
use parser::OptionDeep::*;

use crate::rsa;
use crate::ecdsa;

verus! {

/// If the the issuer likely issued the subject.
/// Similar to https://github.com/openssl/openssl/blob/ed6862328745c51c2afa2b6485cc3e275d543c4e/crypto/x509/v3_purp.c#L963
pub open spec fn spec_likely_issued(issuer: SpecCertificateValue, subject: SpecCertificateValue) -> bool
{
    &&& spec_same_name(issuer.cert.subject, subject.cert.issuer)
    &&& spec_check_auth_key_id(issuer, subject)
    &&& spec_verify_signature(issuer, subject)
    // TODO: more conditions
}

/// Compare two Names
/// References:
/// - RFC 2459, 4.1.2.4
/// - https://github.com/openssl/openssl/blob/ed6862328745c51c2afa2b6485cc3e275d543c4e/crypto/x509/x509_cmp.c#L254
///
/// Basically equality, except that two PrintableString's
/// are considered equal modulo upper/lower cases, leading/trailing white spaces
/// and multiple white spaces in the middle are considered as one white space.
pub open spec fn spec_same_name(a: SpecNameValue, b: SpecNameValue) -> bool {
    &&& a.len() == b.len()
    &&& forall |i| #![auto] 0 <= i < a.len() ==> spec_same_rdn(a[i], b[i])
}

/// Continuing the spec of same_name
pub open spec fn spec_same_rdn(a: SpecRDNValue, b: SpecRDNValue) -> bool {
    &&& a.len() == b.len()
    &&& forall |i| #![auto] 0 <= i < a.len() ==> spec_same_attr(a[i], b[i])
}

/// Continuing the spec of same_name
pub open spec fn spec_same_attr(a: SpecAttributeTypeAndValueValue, b: SpecAttributeTypeAndValueValue) -> bool {
    &&& a.typ =~= b.typ
    &&& match (a.value, b.value) {
        // TODO: normalize PrintableStrings
        (SpecDirectoryStringValue::PrintableString(a), SpecDirectoryStringValue::PrintableString(b)) => a =~= b,
        _ => a.value =~= b.value
    }
}

/// Given potential issuer and subject,
/// if the subject has a AuthorityKeyIdentifier extension,
/// and the issuer has a SubjectKeyIdentifier extension,
/// we compare that:
/// 1. subject.akid.key_id matches issuer.skid
/// 2. (if exists) subject.akit.serial matches issuer.serial
/// 3. TODO: subject.akid.auth_cert_issuer matches
///
/// References:
/// - RFC 2459, 4.2.1.1
/// - https://github.com/openssl/openssl/blob/ed6862328745c51c2afa2b6485cc3e275d543c4e/crypto/x509/v3_purp.c#L1002
pub open spec fn spec_check_auth_key_id(issuer: SpecCertificateValue, subject: SpecCertificateValue) -> bool {
    if let Some(akid) = spec_get_auth_key_id(subject) {
        &&& akid.key_id matches OptionDeep::Some(id)
            ==> spec_get_subject_key_id(issuer) matches Some(skid)
            ==> id =~= skid
        &&& akid.auth_cert_serial matches OptionDeep::Some(serial) ==> serial =~= issuer.cert.serial
        // TODO auth_cert_issuer
    } else {
        true
    }
}

/// Get the first extension with the given OID
/// return (critical, param)
pub open spec fn spec_get_extension(cert: SpecCertificateValue, oid: SpecObjectIdentifierValue) -> OptionDeep<SpecExtensionValue>
{
    if let Some(exts) = cert.cert.extensions {
        spec_get_extension_helper(exts, oid)
    } else {
        None
    }
}

pub open spec fn spec_get_extension_helper(exts: Seq<SpecExtensionValue>, oid: SpecObjectIdentifierValue) -> OptionDeep<SpecExtensionValue>
    decreases exts.len()
{
    if exts.len() == 0 {
        None
    } else {
        if exts[0].id =~= oid {
            Some(exts[0])
        } else {
            spec_get_extension_helper(exts.drop_first(), oid)
        }
    }
}

/// Get the AuthorityKeyIdentifier extension if it exists
pub open spec fn spec_get_auth_key_id(cert: SpecCertificateValue) -> OptionDeep<SpecAuthorityKeyIdentifierValue>
{
    if let Some(ext) = spec_get_extension(cert, spec_oid!(AUTH_KEY_IDENT)) {
        if let SpecExtensionParamValue::AuthorityKeyIdentifier(param) = ext.param {
            Some(param)
        } else {
            None
        }
    } else {
        None
    }
}

/// Get the SubjectKeyIdentifier extension if it exists
pub open spec fn spec_get_subject_key_id(cert: SpecCertificateValue) -> OptionDeep<Seq<u8>>
{
    if let Some(ext) = spec_get_extension(cert, spec_oid!(SUBJECT_KEY_IDENT)) {
        if let SpecExtensionParamValue::SubjectKeyIdentifier(param) = ext.param {
            Some(param)
        } else {
            None
        }
    } else {
        None
    }
}

/// Verify the subject cert's signature using issuer's public key
pub open spec fn spec_verify_signature(issuer: SpecCertificateValue, subject: SpecCertificateValue) -> bool
{
    // Signature algorithm is consistent in the subject cert
    &&& subject.sig_alg =~= subject.cert.signature

    &&& ASN1(TBSCertificate)@.spec_serialize(subject.cert) matches Ok(tbs_cert)

    // TODO: support more algorithms
    &&& {
        // RSA
        ||| {
            &&& issuer.cert.subject_key.alg.param is RSAEncryption
            &&& {
                ||| subject.sig_alg.id == spec_oid!(RSA_SIGNATURE_SHA224)
                ||| subject.sig_alg.id == spec_oid!(RSA_SIGNATURE_SHA256)
                ||| subject.sig_alg.id == spec_oid!(RSA_SIGNATURE_SHA384)
                ||| subject.sig_alg.id == spec_oid!(RSA_SIGNATURE_SHA512)
            }
            &&& rsa::spec_rsa_pkcs1_v1_5_verify(
                subject.sig_alg,
                BitStringValue::spec_bytes(issuer.cert.subject_key.pub_key),
                BitStringValue::spec_bytes(subject.sig),
                tbs_cert,
            )
        }

        // ECDSA P-256
        ||| {
            &&& issuer.cert.subject_key.alg.param matches SpecAlgorithmParamValue::ECPublicKey(curve)
            &&& curve == spec_oid!(EC_P_256)
            &&& {
                ||| subject.sig_alg.id == spec_oid!(ECDSA_SIGNATURE_SHA256)
                ||| subject.sig_alg.id == spec_oid!(ECDSA_SIGNATURE_SHA384)
                ||| subject.sig_alg.id == spec_oid!(ECDSA_SIGNATURE_SHA512)
            }
            &&& ecdsa::spec_ecdsa_p256_verify(
                subject.sig_alg,
                BitStringValue::spec_bytes(issuer.cert.subject_key.pub_key),
                BitStringValue::spec_bytes(subject.sig),
                tbs_cert,
            )
        }

        // ECDSA P-384
        ||| {
            &&& issuer.cert.subject_key.alg.param matches SpecAlgorithmParamValue::ECPublicKey(curve)
            &&& curve == spec_oid!(EC_P_384)
            &&& {
                ||| subject.sig_alg.id == spec_oid!(ECDSA_SIGNATURE_SHA256)
                ||| subject.sig_alg.id == spec_oid!(ECDSA_SIGNATURE_SHA384)
            }
            &&& ecdsa::spec_ecdsa_p384_verify(
                subject.sig_alg,
                BitStringValue::spec_bytes(issuer.cert.subject_key.pub_key),
                BitStringValue::spec_bytes(subject.sig),
                tbs_cert,
            )
        }
    }
}

pub fn likely_issued(issuer: &CertificateValue, subject: &CertificateValue) -> (res: bool)
    ensures res == spec_likely_issued(issuer@, subject@)
{
    same_name(&issuer.get().cert.get().subject, &subject.get().cert.get().issuer) &&
    check_auth_key_id(issuer, subject) &&
    verify_signature(issuer, subject)
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

}
