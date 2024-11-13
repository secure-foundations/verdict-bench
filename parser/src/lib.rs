mod common;
pub mod asn1;
pub mod x509;

pub use common::*;

use vstd::prelude::*;

verus! {
    /// A top-level parser with soundness/completeness/non-malleability
    pub fn parse_x509_certificate<'a>(bytes: &'a [u8]) -> (res: Result<x509::CertificateValue<'a>, ParseError>)
        ensures
            res matches Ok(res) ==> {
                // Soundness
                &&& x509::Certificate.spec_parse(bytes@) matches Ok((n, spec_res))
                &&& res@ == spec_res
                &&& bytes@.len() == n

                // Non-malleability
                &&& forall |other: Seq<u8>| {
                    &&& other.len() <= usize::MAX
                    &&& #[trigger] x509::Certificate.spec_parse(other) matches Ok((m, other_res))
                    &&& m == other.len()
                    &&& other_res == spec_res
                } ==> other == bytes@
            },

            // Completeness
            res is Err ==> {
                ||| x509::Certificate.spec_parse(bytes@) is Err
                ||| x509::Certificate.spec_parse(bytes@) matches Ok((n, _)) && n != bytes@.len()
            },
    {
        let (n, cert) = x509::Certificate.parse(bytes)?;
        if n != bytes.len() {
            return Err(ParseError::Other("trailing bytes in certificate".to_string()));
        }

        proof {
            let (n, spec_res) = x509::Certificate.spec_parse(bytes@).unwrap();

            assert forall |other: Seq<u8>| {
                &&& other.len() <= usize::MAX
                &&& #[trigger] x509::Certificate.spec_parse(other) matches Ok((m, other_res))
                &&& m == other.len()
                &&& other_res == spec_res
            } implies other == bytes@ by {
                let (m, other_res) = x509::Certificate.spec_parse(other).unwrap();
                let other_ser = x509::Certificate.spec_serialize(other_res).unwrap();
                let spec_ser = x509::Certificate.spec_serialize(spec_res).unwrap();

                x509::Certificate.theorem_parse_serialize_roundtrip(other);
                x509::Certificate.theorem_parse_serialize_roundtrip(bytes@);

                assert(other_ser == other);
                assert(other == spec_ser);
                assert(spec_ser == bytes@);
            }
        }

        Ok(cert)
    }
}
