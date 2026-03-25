use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};
use tracing::warn;

#[derive(Debug)]
pub struct CertVerifier {
    pinned_fingerprint: Option<String>,
    provider: &'static CryptoProvider,
}

impl CertVerifier {
    pub fn new(pinned_fingerprint: Option<String>) -> Self {
        let provider = CryptoProvider::get_default()
            .expect("no default rustls crypto provider installed");
        Self { pinned_fingerprint, provider }
    }

    fn fingerprint(cert: &CertificateDer<'_>) -> String {
        let hash = Sha256::digest(cert.as_ref());
        hash.iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

impl ServerCertVerifier for CertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let fp = Self::fingerprint(end_entity);

        match &self.pinned_fingerprint {
            Some(pinned) => {
                if fp.eq_ignore_ascii_case(pinned) {
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(Error::General(format!(
                        "Certificate fingerprint mismatch: expected {pinned}, got {fp}"
                    )))
                }
            }
            None => {
                warn!(
                    "TLS certificate not verified. \
                     To pin this certificate, add: --cert-fingerprint \"{fp}\""
                );
                Ok(ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
