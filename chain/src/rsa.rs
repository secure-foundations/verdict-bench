// RSA PKCS#1 v1.5 signature verification

use vstd::prelude::*;

use polyfill::{slice_eq, slice_drop_first, slice_skip, usize_into_u32};

use parser::PolyfillEq;
use parser::Combinator;
use parser::asn1::ASN1;
use parser::x509::*;

use crate::hash;

verus! {

#[derive(Debug)]
pub enum RSAError {
    InvalidPublicKey,
    SizeOverflow,
    DecryptError,
    PKCS1PaddingError,
    AlgorithmMismatch,
    UnsupportedAlgorithm,
    HashMismatch,
}

#[verifier::external_body]
fn hacl_new_rsapss_load_pkey(
    mod_bits: u32,
    e_bits: u32,
    nb: &[u8],
    eb: &[u8],
) -> *mut u64
{
    unsafe {
        libcrux_hacl::Hacl_RSAPSS_new_rsapss_load_pkey(
            mod_bits,
            e_bits,
            nb.as_ptr() as _,
            eb.as_ptr() as _,
        )
    }
}

#[verifier::external_body]
fn hacl_free_pkey(pkey: *mut u64) {
    unsafe {
        libcrux_hacl::hacl_free(pkey as _);
    }
}

#[verifier::external_body]
fn hacl_rsa_decrypt(
    mod_bits: u32,
    e_bits: u32,
    pkey: *mut u64,
    sig_len: u32,
    sig: &[u8],
) -> Option<Vec<u8>>
{
    // `sig_len` should be equal to `ceil(mod_bits / 2)`
    // (also checked in Hacl_RSAPSS_rsa_decrypt)
    let len = sig_len.try_into().ok()?;
    let mut decoded: Vec<u8> = vec![0; len];

    if unsafe {
        libcrux_hacl::Hacl_RSAPSS_rsa_decrypt(
            mod_bits,
            e_bits,
            pkey,
            sig_len,
            sig.as_ptr() as _,
            decoded.as_mut_ptr() as _,
        )
    } {
        Some(decoded)
    } else {
        None
    }
}

pub closed spec fn spec_rsa_pkcs1_v1_5_verify(
    alg: SpecAlgorithmIdentifierValue,
    pub_key: Seq<u8>,
    sig: Seq<u8>,
    msg: Seq<u8>,
) -> bool;

/// Verify RSA PKCS#1 v1.5 signature
///
/// `alg` specifies the signature + digest combination to be used
/// we check that the signature algorithm should be RSA, and hash
/// the message according to the digest algorithm.
///
/// `pub_key` is an ASN.1 encoded public key:
/// ```
///     RSAPublicKey ::= SEQUENCE {
///         modulus            INTEGER, -- n
///         publicExponent     INTEGER  -- e --
///     }
/// ```
///
/// `sig` is the signature encoded in big-endian (expected to be the same length as the modulus)
/// `msg` is the message expected to be signed
#[verifier::external_body]
pub fn rsa_pkcs1_v1_5_verify(
    alg: &AlgorithmIdentifierValue,
    pub_key: &[u8],
    sig: &[u8],
    msg: &[u8],
) -> (res: Result<(), RSAError>)
    ensures
        res.is_ok() == spec_rsa_pkcs1_v1_5_verify(alg@, pub_key@, sig@, msg@),
{
    let (len, pub_key_parsed) = ASN1(RSAPublicKey).parse(pub_key)
        .or(Err(RSAError::InvalidPublicKey))?;

    if len != pub_key.len() {
        return Err(RSAError::InvalidPublicKey);
    }

    let n = pub_key_parsed.n.bytes();
    let e = pub_key_parsed.e.bytes();

    // ASN.1 integer may have a leading zero byte
    // to avoid the leading bit to be set for positive integers
    // so we need to remove it
    let n = if n.len() != 0 && n[0] == 0 { slice_drop_first(n) } else { &n };
    let e = if e.len() != 0 && e[0] == 0 { slice_drop_first(e) } else { &e };

    // Lengths in bits
    let n_len = n.len().checked_mul(8).ok_or(RSAError::SizeOverflow)?;
    let e_len = e.len().checked_mul(8).ok_or(RSAError::SizeOverflow)?;

    if n_len > u32::MAX as usize || e_len > u32::MAX as usize {
        return Err(RSAError::SizeOverflow);
    }

    // Load the public key into hacl*
    let hacl_pub_key = hacl_new_rsapss_load_pkey(
        usize_into_u32(n_len), usize_into_u32(e_len), n, e,
    );

    if sig.len() > usize::MAX as usize {
        hacl_free_pkey(hacl_pub_key);
        return Err(RSAError::SizeOverflow);
    }

    // Decrypt the signature using hacl*
    let decoded = match hacl_rsa_decrypt(
            usize_into_u32(n_len),
            usize_into_u32(e_len),
            hacl_pub_key,
            sig.len() as u32,
            sig,
        ) {
            Some(decoded) => decoded,
            None => {
                hacl_free_pkey(hacl_pub_key);
                return Err(RSAError::DecryptError);
            }
        };

    // PKCS#1 v1.5 padding
    //     msg = 0x00 || 0x01 || PS || 0x00 || T
    // where T is a DigestInfo:
    // DigestInfo ::= SEQUENCE {
    //     digestAlgorithm AlgorithmIdentifier,
    //     digest OCTET STRING
    // }
    if decoded.len() < 2 || decoded[0] != 0x00 || decoded[1] != 0x01 {
        hacl_free_pkey(hacl_pub_key);
        return Err(RSAError::PKCS1PaddingError);
    }

    let mut i = 2;
    while i < decoded.len() && decoded[i] == 0xff {
        i += 1;
    }

    if i >= decoded.len() || decoded[i] != 0x00 {
        hacl_free_pkey(hacl_pub_key);
        return Err(RSAError::PKCS1PaddingError);
    }

    let dig_info = slice_skip(decoded.as_slice(), i + 1);

    let (len, digest_info_parsed) = ASN1(DigestInfo).parse(dig_info)
        .or(Err(RSAError::PKCS1PaddingError))?;

    if len != dig_info.len() {
        hacl_free_pkey(hacl_pub_key);
        return Err(RSAError::PKCS1PaddingError);
    }

    // Check that the signature algorithms specified by the digest info
    // and the given `alg` are the same
    if digest_info_parsed.alg.id.polyfill_eq(&alg.id) {
        hacl_free_pkey(hacl_pub_key);
        return Err(RSAError::AlgorithmMismatch);
    }

    // TODO: enforce parameter field to be NULL or empty?

    // TODO: more digest algorithms
    let res = if alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA224)) {
        slice_eq(&digest_info_parsed.digest, &hash::sha224_digest(msg))
    } else if alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA256)) {
        slice_eq(&digest_info_parsed.digest, &hash::sha256_digest(msg))
    } else if alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA384)) {
        slice_eq(&digest_info_parsed.digest, &hash::sha384_digest(msg))
    } else if alg.id.polyfill_eq(&oid!(RSA_SIGNATURE_SHA512)) {
        slice_eq(&digest_info_parsed.digest, &hash::sha512_digest(msg))
    } else {
        hacl_free_pkey(hacl_pub_key);
        return Err(RSAError::UnsupportedAlgorithm);
    };

    if !res {
        hacl_free_pkey(hacl_pub_key);
        return Err(RSAError::HashMismatch);
    }

    hacl_free_pkey(hacl_pub_key);

    Ok(())
}

}
