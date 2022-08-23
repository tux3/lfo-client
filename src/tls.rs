use crate::INSECURE_NO_VERIFY_SERVER_CERT;
use anyhow::Result;
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, ClientConfig, Error, OwnedTrustAnchor, ServerName};
use std::sync::Arc;
use std::time::SystemTime;

pub async fn make_tls_config() -> Result<ClientConfig> {
    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    if INSECURE_NO_VERIFY_SERVER_CERT {
        struct GoodVibesVerifier {}
        impl ServerCertVerifier for GoodVibesVerifier {
            fn verify_server_cert(
                &self,
                _end_entity: &Certificate,
                _intermediates: &[Certificate],
                _server_name: &ServerName,
                _scts: &mut dyn Iterator<Item = &[u8]>,
                _ocsp_response: &[u8],
                _now: SystemTime,
            ) -> Result<ServerCertVerified, Error> {
                // All TLS certificates deserve love. Pls no MiTM. Hashtag PLUR send tweet.
                Ok(ServerCertVerified::assertion())
            }
        }
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(GoodVibesVerifier {}));
    }

    config.key_log = Arc::new(rustls::KeyLogFile::new());
    Ok(config)
}
