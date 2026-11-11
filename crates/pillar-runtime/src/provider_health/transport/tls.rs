use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use std::sync::Arc;

/// webpki tries orderings of the presented intermediates up to six deep and reparses every
/// candidate at each step on the calling worker, so their count sets the cost of rejecting a
/// chain (I-33). A verified path holds at most six intermediates.
const MAX_PRESENTED_INTERMEDIATES: usize = 6;

#[derive(Debug)]
struct BoundedChainVerifier {
    inner: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for BoundedChainVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if intermediates.len() > MAX_PRESENTED_INTERMEDIATES {
            return Err(rustls::Error::General(format!(
                "provider presented {} intermediate certificates, more than {MAX_PRESENTED_INTERMEDIATES}",
                intermediates.len()
            )));
        }
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Client TLS for provider connections: webpki roots and verification over the ring provider,
/// behind the intermediate-count bound.
pub(super) fn provider_tls_config(alpn: &[&[u8]]) -> Result<rustls::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = Arc::new(rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    ));
    let inner = WebPkiServerVerifier::builder_with_provider(roots, provider.clone())
        .build()
        .map_err(|_| "Cannot configure provider TLS verification".to_string())?;
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| "Cannot configure provider TLS".to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(BoundedChainVerifier { inner }))
        .with_no_client_auth();
    tls.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(tls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn more_than_six_intermediates_are_refused_before_path_building() {
        let roots = Arc::new(rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        ));
        let verifier = BoundedChainVerifier {
            inner: WebPkiServerVerifier::builder_with_provider(
                roots,
                Arc::new(rustls::crypto::ring::default_provider()),
            )
            .build()
            .unwrap(),
        };
        let junk = CertificateDer::from(vec![0x30, 0x00]);
        let verify = |count: usize| {
            verifier.verify_server_cert(
                &junk,
                &vec![junk.clone(); count],
                &ServerName::try_from("rpc.example").unwrap(),
                &[],
                UnixTime::now(),
            )
        };
        assert!(matches!(verify(7), Err(rustls::Error::General(_))));
        assert!(matches!(
            verify(6),
            Err(rustls::Error::InvalidCertificate(_))
        ));
    }
}
