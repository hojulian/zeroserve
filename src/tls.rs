use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use monoio_rustls::TlsAcceptor;
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};

use crate::config::StaticConfig;

#[derive(Clone)]
pub struct TlsRuntime {
    pub acceptor: TlsAcceptor,
}

pub fn load_tls_if_configured(config: &Arc<StaticConfig>) -> Result<Option<TlsRuntime>> {
    match (&config.tls_addr, &config.cert_path, &config.key_path) {
        (Some(_addr), Some(cert), Some(key)) => {
            let cert_bytes = std::fs::read(cert)
                .with_context(|| format!("failed to read cert {}", cert.display()))?;
            let mut certs = Vec::new();
            for item in CertificateDer::pem_slice_iter(&cert_bytes) {
                let cert = item.map_err(|e| anyhow!("certificate parse error: {e}"))?;
                certs.push(cert);
            }
            if certs.is_empty() {
                bail!("no certificates found in {}", cert.display());
            }
            let key_bytes = std::fs::read(key)
                .with_context(|| format!("failed to read key {}", key.display()))?;
            let mut key_iter = PrivateKeyDer::pem_slice_iter(&key_bytes);
            let key = key_iter
                .next()
                .ok_or_else(|| anyhow!("no private key found in {}", key.display()))?
                .map_err(|e| anyhow!("private key parse error: {e}"))?;

            let tls_config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .context("invalid certificate/key pair")?;
            Ok(Some(TlsRuntime {
                acceptor: TlsAcceptor::from(Arc::new(tls_config)),
            }))
        }
        _ => Ok(None),
    }
}
