// Specifications for some base operations on X.509 certificates
// e.g. comparing distinguished names, checking issuers

use vstd::prelude::*;

use vpl::*;

use parser::{*, asn1::*, x509::*};
use parser::OptionDeep::*;

use crate::facts::*;
use crate::rsa;
use crate::ecdsa;

verus! {

/// The top-level spec stating when a certificate chain
/// is considered valid with respect to given policy,
/// root certificates, and final domain
pub open spec fn spec_valid_domain(policy: SpecProgram, query: SpecQuery) -> bool
{
    &&& query.chain.len() > 0
    &&& QueryFacts::spec_facts(query) matches Option::Some(facts)

    // Exists a proof of the final goal certVerifiedChain(cert(0))
    &&& exists |thm: SpecTheorem| {
        &&& #[trigger] thm.wf(SpecProgram {
            rules: policy.rules + facts,
        })
        &&& thm.stmt == spec_app!("certVerifiedChain", query.get_chain(0).spec_cert())
    }
}

/// If the the issuer likely issued the subject.
/// Similar to https://github.com/openssl/openssl/blob/ed6862328745c51c2afa2b6485cc3e275d543c4e/crypto/x509/v3_purp.c#L963
pub open spec fn spec_likely_issued(issuer: SpecCertificateValue, subject: SpecCertificateValue) -> bool
{
    &&& spec_same_name(issuer.cert.subject, subject.cert.issuer)
    &&& spec_check_auth_key_id(issuer, subject)
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

        // ECDSA
        ||| {
            &&& {
                ||| subject.sig_alg.id == spec_oid!(ECDSA_SIGNATURE_SHA224)
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
    }
}

}
