use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use boring::hpke::HpkeKey;
use boring::ssl::SslEchKeys;

use crate::boringtls::BoringAcceptor;
use crate::config::StaticConfig;
use crate::ech::key::EchKeySet;

#[derive(Clone)]
pub struct TlsRuntime {
    pub acceptor: BoringAcceptor,
    /// True when ECH keys are loaded (the listener still serves plain TLS too).
    pub ech_enabled: bool,
    /// The ECH public name to report as the outer SNI when ECH is accepted.
    /// `Some` only when all loaded configs share one public name (so it is
    /// unambiguous); `None` otherwise (zero or multiple distinct names).
    pub ech_public_name: Option<String>,
}

pub fn load_tls_if_configured(config: &Arc<StaticConfig>) -> Result<Option<TlsRuntime>> {
    match (&config.tls_addr, &config.cert_path, &config.key_path) {
        (Some(_addr), Some(cert), Some(key)) => {
            // Load ECH keys first (if configured) so we can install them on the
            // context during construction.
            let ech_keys = match &config.ech_key_path {
                Some(path) => {
                    let set = EchKeySet::load(path)
                        .with_context(|| format!("loading ECH keys from {}", path.display()))?;
                    if set.pairs.is_empty() {
                        bail!("ECH key set is empty");
                    }
                    Some(set)
                }
                None => None,
            };

            let ech_enabled = ech_keys.is_some();
            let acceptor = BoringAcceptor::build(cert, key, |builder| {
                if let Some(set) = &ech_keys {
                    let mut ech = SslEchKeys::builder()
                        .map_err(|e| anyhow!("SSL_ECH_KEYS_new failed: {e}"))?;
                    for pair in &set.pairs {
                        // BoringSSL only ships an X25519 HPKE key constructor
                        // (the `dhkem_p256_sha256` name is a boring misnomer —
                        // its body uses EVP_hpke_x25519_hkdf_sha256), which
                        // matches the suite our keygen emits.
                        let key = HpkeKey::dhkem_p256_sha256(&pair.private_key).map_err(|e| {
                            anyhow!(
                                "invalid ECH HPKE key (config_id 0x{:02x}): {e}",
                                pair.config.config_id
                            )
                        })?;
                        // is_retry_config = true: advertise every loaded config
                        // in `retry_configs` when a client offers a stale one.
                        ech.add_key(true, &pair.config.encode(), key).map_err(|e| {
                            anyhow!(
                                "SSL_ECH_KEYS_add failed (config_id 0x{:02x}): {e}",
                                pair.config.config_id
                            )
                        })?;
                    }
                    let ech = ech.build();
                    builder
                        .set_ech_keys(&ech)
                        .map_err(|e| anyhow!("SSL_CTX_set1_ech_keys failed: {e}"))?;
                }
                Ok(())
            })?;

            let mut ech_public_name = None;
            if let Some(set) = &ech_keys {
                use base64ct::Encoding as _;
                let list_b64 = base64ct::Base64::encode_string(&set.config_list_bytes());
                let mut names: Vec<&str> = set
                    .pairs
                    .iter()
                    .map(|p| p.config.public_name.as_str())
                    .collect();
                eprintln!(
                    "ECH enabled: {} key(s), public_name(s)={:?}; the TLS cert must cover each name. Publish ech=\"{}\"",
                    set.pairs.len(),
                    names,
                    list_b64
                );
                // Report the outer SNI only when it is unambiguous.
                names.sort_unstable();
                names.dedup();
                if let [single] = names.as_slice() {
                    ech_public_name = Some(single.to_string());
                }
            }

            Ok(Some(TlsRuntime {
                acceptor,
                ech_enabled,
                ech_public_name,
            }))
        }
        _ => Ok(None),
    }
}
