/// Wrapper for libcrux ECDSA interface

use vstd::prelude::*;

use polyfill::slice_drop_first;

use libcrux::signature::{Signature, EcDsaP256Signature, Algorithm, DigestAlgorithm, verify};

use parser::PolyfillEq;
use parser::Combinator;
use parser::asn1::ASN1;
use parser::x509::*;

verus! {

pub enum ECDSAError {
    InvalidSignature,
    UnsupportedAlgorithm,
    VerificationFailed,
}

#[verifier::external_type_specification]
pub struct ExAlgorithm(Algorithm);

#[verifier::external_type_specification]
pub struct ExDigestAlgorithm(DigestAlgorithm);

#[verifier::external_body]
fn ecdsa_p256_verify_internal(
    alg: Algorithm,
    pub_key: &[u8],
    r: &[u8],
    s: &[u8],
    msg: &[u8],
) -> bool
{
    if r.len() > 32 || s.len() > 32 {
        return false;
    }

    let mut r_copy = [0; 32];
    let mut s_copy = [0; 32];

    (&mut r_copy[32 - r.len()..]).copy_from_slice(r);
    (&mut s_copy[32 - s.len()..]).copy_from_slice(s);

    let sig = Signature::EcDsaP256(EcDsaP256Signature::from_raw(r_copy, s_copy, alg));

    verify(msg, &sig, pub_key).is_ok()
}

pub closed spec fn spec_ecdsa_p256_verify(
    alg: SpecAlgorithmIdentifierValue,
    pub_key: Seq<u8>,
    sig: Seq<u8>,
    msg: Seq<u8>,
) -> bool;

#[verifier::external_body]
pub fn ecdsa_p256_verify(
    alg: &AlgorithmIdentifierValue,
    pub_key: &[u8],
    sig: &[u8],
    msg: &[u8],
) -> (res: Result<(), ECDSAError>)
    ensures
        res.is_ok() == spec_ecdsa_p256_verify(alg@, pub_key@, sig@, msg@),
{
    let (len, parsed_sig) = ASN1(ECDSASigValue).parse(sig)
        .or(Err(ECDSAError::InvalidSignature))?;

    if len != sig.len() {
        return Err(ECDSAError::InvalidSignature);
    }

    let r = parsed_sig.r.bytes();
    let s = parsed_sig.s.bytes();

    // ASN.1 integer may have a leading zero byte
    // to avoid the leading bit to be set for positive integers
    // so we need to remove it
    let r = if r.len() != 0 && r[0] == 0 { slice_drop_first(r) } else { &r };
    let s = if s.len() != 0 && s[0] == 0 { slice_drop_first(s) } else { &s };

    // libcrux doesn't seem to have SHA224 support yet
    let internal_alg = if alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA256)) {
        Algorithm::EcDsaP256(DigestAlgorithm::Sha256)
    } else if alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA384)) {
        Algorithm::EcDsaP256(DigestAlgorithm::Sha384)
    } else if alg.id.polyfill_eq(&oid!(ECDSA_SIGNATURE_SHA512)) {
        Algorithm::EcDsaP256(DigestAlgorithm::Sha512)
    } else {
        return Err(ECDSAError::UnsupportedAlgorithm);
    };

    if ecdsa_p256_verify_internal(
        Algorithm::EcDsaP256(DigestAlgorithm::Sha256),
        pub_key,
        r,
        s,
        msg,
    ) {
        Ok(())
    } else {
        Err(ECDSAError::VerificationFailed)
    }
}

}
