// Specifications for the most basic issuing relation
// i.e. only compares names and checks signature

use vstd::prelude::*;

use polyfill::*;
use parser::{*, asn1::*, x509::*};

use crate::rsa;
use crate::ecdsa;

verus! {

/// If the the issuer likely issued the subject.
/// Similar to https://github.com/openssl/openssl/blob/ed6862328745c51c2afa2b6485cc3e275d543c4e/crypto/x509/v3_purp.c#L963
pub open spec fn spec_likely_issued(issuer: SpecCertificateValue, subject: SpecCertificateValue) -> bool
{
    &&& spec_same_name(issuer.cert.subject, subject.cert.issuer)
    &&& spec_verify_signature(issuer, subject)
}

/// Compare two Names
/// References:
/// - RFC 5280, 4.1.2.4
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
/// See RFC 5280, 7.1
///
/// NOTE: for TeletexString, BMPString, UniversalString yet
/// we simply compare their encoding byte-by-byte
pub open spec fn spec_same_attr(a: SpecAttributeTypeAndValueValue, b: SpecAttributeTypeAndValueValue) -> bool {
    &&& a.typ =~= b.typ
    &&& match (a.value, b.value) {
        (SpecDirectoryStringValue::PrintableString(a), SpecDirectoryStringValue::PrintableString(b)) |
        (SpecDirectoryStringValue::UTF8String(a), SpecDirectoryStringValue::UTF8String(b)) |
        (SpecDirectoryStringValue::IA5String(a), SpecDirectoryStringValue::IA5String(b)) =>
            spec_normalize_string(a) =~= spec_normalize_string(b),

        _ => a.value =~= b.value
    }
}

/// NOTE: RFC 5280, 7.1 requires using RFC 4518's normalization procedure
/// But right now we only support a subset of these normalization rules
///
/// 1. Fold cases by Rust's char::to_lowercase
/// 2. Remove leading/trailing spaces
/// 3. Compress multiple inner spaces into one
///
/// Note that we only consider the ASCII space ' ' instead of all white spaces
pub open spec fn spec_normalize_string(s: Seq<char>) -> Seq<char> {
    spec_normalize_string_helper(s, false, false)
}

/// Helper function for spec_normalize_string
/// `seen_nw` = have seen a non-whitespace since the start of the string
/// `seen_ws` = have seen a whitespace since the last non-whitespace character
pub open spec fn spec_normalize_string_helper(s: Seq<char>, seen_nw: bool, seen_ws: bool) -> Seq<char>
    decreases s.len()
{
    if s.len() == 0 {
        seq![] // Ignores spaces seen so far
    } else if s[0] == ' ' {
        spec_normalize_string_helper(s.drop_first(), seen_nw, true)
    } else {
        let prefix = if seen_nw && seen_ws {
            seq![' '] + spec_char_lower(s[0])
        } else {
            spec_char_lower(s[0])
        };

        prefix + spec_normalize_string_helper(s.drop_first(), true, false)
    }
}

/// Verify the subject cert's signature using issuer's public key
///
/// Currently we support these signature schemes:
/// - RSA PKCS#1 v1.5 with SHA-224, SHA-256, SHA-384, SHA-512 (Evercrypt through libcrux)
/// - P-256 with SHA-256, SHA-384, SHA-512 (Evercrypt through libcrux)
/// - P-384 with SHA-256, SHA-384 (AWS-LC)
///
/// NOTE: P-384 + SHA-256 is not yet verified in AWS-LC
/// Also P-384 + SHA-384 is only verified for Intel CPUs (SandyBridge+)
/// See https://github.com/awslabs/aws-lc-verification
///
/// NOTE: Comparison of subject.sig_alg == subject.cert.signature is done in the policy
pub open spec fn spec_verify_signature(issuer: SpecCertificateValue, subject: SpecCertificateValue) -> bool
{
    &&& ASN1(TBSCertificate)@.spec_serialize(subject.cert) matches Ok(tbs_cert)
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
            &&& rsa::spec_pkcs1_v1_5_load_pub_key(BitStringValue::spec_bytes(issuer.cert.subject_key.pub_key)) matches Some(pub_key)
            &&& rsa::spec_pkcs1_v1_5_verify(
                subject.sig_alg,
                pub_key,
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
            &&& ecdsa::spec_p256_verify(
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
            &&& ecdsa::spec_p384_verify(
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
    verify_signature(issuer, subject)
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
            str_eq_str(normalize_string(a).as_str(), normalize_string(b).as_str()),

        (DirectoryStringValue::TeletexString(a), DirectoryStringValue::TeletexString(b)) |
        (DirectoryStringValue::BMPString(a), DirectoryStringValue::BMPString(b)) |
        (DirectoryStringValue::UniversalString(a), DirectoryStringValue::UniversalString(b)) =>
            a.polyfill_eq(b),

        (DirectoryStringValue::Unreachable, DirectoryStringValue::Unreachable) => true,

        _ => false,
    }
}

/// Exec version of spec_normalize_string
pub fn normalize_string(s: &str) -> (res: String)
    ensures res@ =~= spec_normalize_string(s@)
{
    let mut seen_nw = false;
    let mut seen_ws = false;

    let mut res = string_new_with_cap(str_byte_len(s));
    let mut iter = str_chars(s);
    let mut i: usize = 0;

    assert(s@.skip(0) == s@);

    // Using a custom chars iterator wrapper in polyfill
    loop
        invariant
            spec_chars_iter_str(iter) == s@,
            s@.len() <= usize::MAX,

            i == spec_chars_iter_index(iter),
            spec_normalize_string(s@) =~= res@ + spec_normalize_string_helper(s@.skip(i as int), seen_nw, seen_ws),

        ensures
            i == s@.len(),
    {
        if let Some(c) = chars_iter_next(&mut iter) {
            if c == ' ' {
                seen_ws = true;
            } else {
                if seen_nw && seen_ws {
                    res.append(" ");
                }
                res.append(char_lower(c).as_str());

                seen_nw = true;
                seen_ws = false;
            }

            proof { reveal_strlit(" "); }
            assert(s@.skip(i as int).drop_first() == s@.skip(i + 1));

            i += 1;
        } else {
            break;
        }
    }

    res
}

/// NOTE: For lower case folding, we trust Rust's built-in definition
pub closed spec fn spec_char_lower(c: char) -> Seq<char>;

#[verifier::external_body]
fn char_lower(c: char) -> (res: String)
    ensures res@ == spec_char_lower(c)
{
    c.to_lowercase().to_string()
}

pub fn verify_signature(issuer: &CertificateValue, subject: &CertificateValue) -> (res: bool)
    ensures res == spec_verify_signature(issuer@, subject@)
{
    let tbs_cert = subject.get().cert.serialize();

    let sig_alg = &subject.get().sig_alg.get();
    let pub_key = issuer.get().cert.get().subject_key.pub_key.bytes();
    let sig = subject.get().sig.bytes();

    match &issuer.get().cert.get().subject_key.alg.param {
        // RSA PKCS#1 v1.5
        AlgorithmParamValue::RSAEncryption(..) => {
            if sig_alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA224)) ||
               sig_alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA256)) ||
               sig_alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA384)) ||
               sig_alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA512)) {
                return match rsa::pkcs1_v1_5_load_pub_key(pub_key) {
                    Ok(pub_key) => rsa::pkcs1_v1_5_verify(sig_alg, &pub_key, sig, tbs_cert).is_ok(),
                    Err(..) => false,
                }
            }
        }

        // ECDSA P-256 and P-384
        AlgorithmParamValue::ECPublicKey(curve) => {
            if curve.polyfill_eq(&oid!(EC_P_256)) && (
                sig_alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA256)) ||
                sig_alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA384)) ||
                sig_alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA512))
            ) {
                return ecdsa::p256_verify(sig_alg, pub_key, sig, tbs_cert).is_ok();
            }

            if curve.polyfill_eq(&oid!(EC_P_384)) && (
                sig_alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA256)) ||
                sig_alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA384))
            ) {
                return ecdsa::p384_verify(sig_alg, pub_key, sig, tbs_cert).is_ok();
            }
        }

        _ => {}
    }

    false
}

}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn sanity() {
        assert_eq!(normalize_string(""), "");
        assert_eq!(normalize_string("  "), "");
        assert_eq!(normalize_string("  a  "), "a");
        assert_eq!(normalize_string("   aa b   C  "), "aa b c");
        assert_eq!(normalize_string("  a  b  c  "), "a b c");
    }
}
