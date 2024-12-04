// Wrappers for hash functions in libcrux

use vstd::prelude::*;

use libcrux::digest;

verus! {

/// TODO: specify this
pub closed spec fn spec_to_hex_upper(data: Seq<u8>) -> Seq<char>;

pub closed spec fn spec_sha224_digest(data: Seq<u8>) -> Seq<u8>;
pub closed spec fn spec_sha256_digest(data: Seq<u8>) -> Seq<u8>;
pub closed spec fn spec_sha384_digest(data: Seq<u8>) -> Seq<u8>;
pub closed spec fn spec_sha512_digest(data: Seq<u8>) -> Seq<u8>;

#[verifier::external_body]
#[inline(always)]
pub fn sha224_digest(data: &[u8]) -> (res: [u8; 28])
    ensures res@ == spec_sha224_digest(data@)
{
    digest::sha2_224(data)
}

#[verifier::external_body]
#[inline(always)]
pub fn sha256_digest(data: &[u8]) -> (res: [u8; 32])
    ensures res@ == spec_sha256_digest(data@)
{
    digest::sha2_256(data)
}

#[verifier::external_body]
#[inline(always)]
pub fn sha384_digest(data: &[u8]) -> (res: [u8; 48])
    ensures res@ == spec_sha384_digest(data@)
{
    digest::sha2_384(data)
}

#[verifier::external_body]
#[inline(always)]
pub fn sha512_digest(data: &[u8]) -> (res: [u8; 64])
    ensures res@ == spec_sha512_digest(data@)
{
    digest::sha2_512(data)
}

/// Convert a sequence of data to a hex string in upper case
/// e.g. [ 0xbe, 0xef ] -> "BEEF"
#[verifier::external_body]
#[inline(always)]
pub fn to_hex_upper(data: &[u8]) -> (res: String)
    ensures res@ == spec_to_hex_upper(data@)
{
    data.iter().map(|b| format!("{:02X}", b)).collect::<String>()
}

}
