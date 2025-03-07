use std::boxed::Box;
use std::format;
use std::vec::Vec;
use std::fmt;

use verdict::error::ValidationError;
use verdict::validator::{RootStore, Validator};
use verdict::policy::{ExecPurpose, ExecTask, Policy};
use log::trace;
use pki_types::{CertificateDer, ServerName, UnixTime};

use crate::crypto::aws_lc_rs::default_provider;
use crate::crypto::CryptoProvider;
use crate::verify::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use crate::{DigitallySignedStruct, Error, SignatureScheme};
use crate::alloc::string::ToString;

use super::{verify_tls12_signature, verify_tls13_signature};

/// Interface for calling Verdict as opposed to
/// the built-in WebPkiServerVerifier
pub(crate) struct VerdictServerVerifier<P: Policy> {
    validator: Validator<'static, P>,

    // For supported schemes only
    provider: CryptoProvider,
}

/// Policy to use for verdict
#[allow(missing_docs)]
pub enum VerdictPolicy {
    Chrome,
    Firefox,
    OpenSSL,
}

impl From<ValidationError> for Error {
    fn from(value: ValidationError) -> Self {
        Self::General(format!("{:?}", value))
    }
}

impl<P: Policy> fmt::Debug for VerdictServerVerifier<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "VerdictServerVerifier {{ .. }}")
    }
}

impl<P: Policy> VerdictServerVerifier<P> {
    /// NOTE: due to interface issues, this function
    /// will create and leak the given set of root DER
    /// encodings, so that we can get a 'static lifetime
    pub(crate) fn new<'a>(policy: P, roots_der: impl IntoIterator<Item = CertificateDer<'a>>)
        -> Result<Self, Error> {
        // Copy all buffers
        let roots_der: Vec<Vec<u8>> =
            roots_der.into_iter().map(|c| c.as_ref().to_vec()).collect();

        // TODO: find a better way without memory leaks
        let store: &'static RootStore =
            Box::leak(Box::new(RootStore::from_owned_der(roots_der)));

        Ok(VerdictServerVerifier {
            validator: Validator::from_root_store(policy, store)?,
            provider: default_provider(),
        })
    }
}

impl<P: Policy> ServerCertVerifier for VerdictServerVerifier<P> {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let mut bundle = Vec::with_capacity(1 + intermediates.len());

        // TODO: avoid this extra copy
        bundle.push(end_entity.as_ref().to_vec());
        for interm in intermediates {
            bundle.push(interm.as_ref().to_vec());
        }

        let task = ExecTask {
            hostname: Some(match server_name {
                ServerName::DnsName(dns_name) => dns_name.as_ref().to_string(),
                ServerName::IpAddress(..) => unimplemented!("IP validation"),
                _ => unimplemented!(),
            }),
            purpose: ExecPurpose::ServerAuth,
            now: now.as_secs(),
        };

        if !ocsp_response.is_empty() {
            trace!("verdict ignores OCSP");
        }

        if !self.validator.validate_der(&bundle, &task)? {
            return Err(Error::General("verdict certificate validation error".to_string()));
        }

        Ok(ServerCertVerified::assertion())
    }

    /// Use the default signature verifier
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message, cert, dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    /// Use the default signature verifier
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message, cert, dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
