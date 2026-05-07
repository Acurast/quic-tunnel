use anyhow::{bail, Result};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus,
};
use log::{info, warn};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tunnel_common::build_alpn_acceptor;

use crate::{ServerChallenge, ServerConfig};

/// Loads a `CertifiedKey` from PEM files and returns it alongside the first cert's
/// `not_after` Unix timestamp (seconds). Used by `DiskCertResolver`.
fn load_certified_key_from_paths(
    cert_path: &str,
    key_path: &str,
) -> Result<(rustls::sign::CertifiedKey, i64)> {
    let cert_pem = std::fs::read_to_string(cert_path)?;
    let key_pem = std::fs::read_to_string(key_path)?;
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_bytes()).collect::<std::result::Result<_, _>>()?;
    if certs.is_empty() {
        bail!("no certificates found in {}", cert_path);
    }
    let not_after = x509_parser::parse_x509_certificate(&certs[0])
        .map(|(_, c)| c.validity().not_after.timestamp())
        .unwrap_or(0);
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path))?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| anyhow::anyhow!("unsupported key type: {:?}", e))?;
    Ok((
        rustls::sign::CertifiedKey::new(certs, signing_key),
        not_after,
    ))
}

/// Returns `true` if the first cert in `path` is expired or the file cannot be read/parsed.
pub(crate) fn is_cert_expired(path: &str) -> bool {
    let Ok(pem) = std::fs::read_to_string(path) else {
        return true;
    };
    let Some(Ok(cert_der)) = rustls_pemfile::certs(&mut pem.as_bytes()).next() else {
        return true;
    };
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(&cert_der) else {
        return true;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    cert.validity().not_after.timestamp() < now
}

/// Configuration for background ACME renewal, attached to a `DiskCertResolver`
/// when the cert is server-managed (i.e. `acme_domain` is set).
#[derive(Clone)]
pub(crate) struct AcmeRenewalConfig {
    pub domain: String,
    pub email: Option<String>,
    pub staging: bool,
    pub creds_path: String,
    pub cert_path: String,
    pub key_path: String,
    pub server_challenge: ServerChallenge,
    /// Trigger renewal when cert expires within this many seconds.
    pub renew_before_secs: i64,
}

pub(crate) struct DiskCertResolver {
    cert_path: String,
    key_path: String,
    /// Cache: `(certified_key, loaded_at, not_after_unix_secs)`.
    cache: std::sync::Mutex<Option<(Arc<rustls::sign::CertifiedKey>, Instant, i64)>>,
    renewal: Option<AcmeRenewalConfig>,
    renewing: Arc<AtomicBool>,
}

impl std::fmt::Debug for DiskCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiskCertResolver")
            .field("cert_path", &self.cert_path)
            .field("key_path", &self.key_path)
            .finish_non_exhaustive()
    }
}

impl DiskCertResolver {
    pub fn new(cert_path: &str, key_path: &str, renewal: Option<AcmeRenewalConfig>) -> Self {
        Self {
            cert_path: cert_path.to_string(),
            key_path: key_path.to_string(),
            cache: std::sync::Mutex::new(None),
            renewal,
            renewing: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl rustls::server::ResolvesServerCert for DiskCertResolver {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let mut cache = self.cache.lock().unwrap();

        // Use cached cert if it was loaded within the last 60 seconds.
        if let Some((ck, loaded_at, _)) = cache.as_ref() {
            if loaded_at.elapsed() < Duration::from_secs(60) {
                let ck = Arc::clone(ck);
                drop(cache);
                self.maybe_trigger_renewal(&ck);
                return Some(ck);
            }
        }

        // TTL expired — reload from disk.
        match load_certified_key_from_paths(&self.cert_path, &self.key_path) {
            Ok((ck, not_after)) => {
                let ck = Arc::new(ck);
                *cache = Some((Arc::clone(&ck), Instant::now(), not_after));
                drop(cache);
                self.maybe_trigger_renewal(&ck);
                Some(ck)
            }
            Err(e) => {
                warn!(
                    "DiskCertResolver: failed to reload cert from {}: {}",
                    self.cert_path, e
                );
                // Fall back to stale cached cert if available.
                cache.as_ref().map(|(ck, _, _)| Arc::clone(ck))
            }
        }
    }
}

impl DiskCertResolver {
    /// Checks if the cached cert is within the renewal window and, if so, spawns
    /// a background `provision_acme_cert` task (fire-and-forget, non-blocking).
    fn maybe_trigger_renewal(&self, _ck: &Arc<rustls::sign::CertifiedKey>) {
        let Some(renewal) = &self.renewal else { return };
        let not_after = self
            .cache
            .lock()
            .unwrap()
            .as_ref()
            .map(|(_, _, t)| *t)
            .unwrap_or(i64::MAX);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if not_after - now >= renewal.renew_before_secs {
            return;
        }
        // Only one renewal at a time.
        if self
            .renewing
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        let r = renewal.clone();
        let flag = Arc::clone(&self.renewing);
        info!(
            "DiskCertResolver: cert for {} expires in {}s, triggering background renewal",
            r.domain,
            not_after - now,
        );
        tokio::spawn(async move {
            if let Err(e) = provision_acme_cert(
                &r.domain,
                r.email.as_deref(),
                r.staging,
                &r.creds_path,
                &r.cert_path,
                &r.key_path,
                r.server_challenge,
            )
            .await
            {
                warn!("DiskCertResolver: background ACME renewal failed: {}", e);
            }
            flag.store(false, Ordering::SeqCst);
        });
    }
}

/// Decides which cert paths to use for the server TLS config.
/// Provisions via ACME (using `server_challenge` for the TLS-ALPN-01 handshake) if needed.
/// Returns `Some((cert_path, key_path, is_acme_managed))` or `None` for the self-signed fallback.
/// `is_acme_managed` is `true` when the cert was provisioned/selected by the built-in ACME flow;
/// `false` when it comes from an externally supplied cert (certbot etc.).
pub(crate) async fn determine_cert(
    config: &ServerConfig,
    server_challenge: &ServerChallenge,
) -> Result<Option<(String, String, bool)>> {
    let is_acme = config.acme_domain.is_some();

    if config.cert_path.is_none() && !is_acme {
        info!("TLS: no cert configured, using self-signed");
        return Ok(None);
    }

    let cert_p = config
        .cert_path
        .clone()
        .unwrap_or_else(|| "server_cert.pem".to_string());
    let key_p = config
        .key_path
        .clone()
        .unwrap_or_else(|| "server.key".to_string());

    if !is_cert_expired(&cert_p) {
        if is_acme {
            info!(
                "TLS: using ACME-managed cert at {} (auto-renew via ACME)",
                cert_p
            );
        } else {
            info!(
                "TLS: using externally-managed cert at {} (auto-reload from disk every 60s)",
                cert_p
            );
        }
        return Ok(Some((cert_p, key_p, is_acme)));
    }

    if let Some(domain) = &config.acme_domain {
        warn!(
            "TLS: cert at {} is expired or missing, provisioning via ACME",
            cert_p
        );
        provision_acme_cert(
            domain,
            config.acme_email.as_deref(),
            config.acme_staging,
            &config.acme_creds_path,
            &cert_p,
            &key_p,
            server_challenge.clone(),
        )
        .await?;
        return Ok(Some((cert_p, key_p, true)));
    }

    warn!(
        "TLS: cert at {} is expired and no ACME domain configured, using self-signed",
        cert_p
    );
    Ok(None)
}

pub(crate) async fn provision_acme_cert(
    domain: &str,
    email: Option<&str>,
    staging: bool,
    creds_path: &str,
    cert_path: &str,
    key_path: &str,
    server_challenge: ServerChallenge,
) -> Result<()> {
    info!("ACME: provisioning server cert for {}", domain);

    let keypair = load_or_generate_keypair(key_path)?;
    let mut csr_params = rcgen::CertificateParams::new(vec![domain.to_string()])?;
    csr_params.distinguished_name = rcgen::DistinguishedName::new();
    let csr_der = csr_params.serialize_request(&keypair)?.der().to_vec();

    let account = acme_load_or_create_account(email, staging, creds_path).await?;
    let mut order = account
        .new_order(&NewOrder::new(&[Identifier::Dns(domain.to_string())]))
        .await?;

    let mut key_authorization = String::new();
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result?;
            if authz.status == AuthorizationStatus::Valid {
                continue;
            }
            let challenge = authz
                .challenge(ChallengeType::TlsAlpn01)
                .ok_or_else(|| anyhow::anyhow!("no TLS-ALPN-01 challenge for {}", domain))?;
            key_authorization = challenge.key_authorization().as_str().to_string();
        }
    }

    let alpn_acceptor = build_alpn_acceptor(domain, &key_authorization)?;
    *server_challenge.lock().await = Some((domain.to_string(), alpn_acceptor));

    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result?;
            if authz.status == AuthorizationStatus::Valid {
                continue;
            }
            if let Some(mut challenge) = authz.challenge(ChallengeType::TlsAlpn01) {
                challenge.set_ready().await?;
                break;
            }
        }
    }

    let mut delay = Duration::from_secs(2);
    for _ in 0..12 {
        tokio::time::sleep(delay).await;
        let state = order.refresh().await?;
        match state.status {
            OrderStatus::Ready | OrderStatus::Valid => break,
            OrderStatus::Invalid => bail!("ACME order invalid for {}", domain),
            _ => {}
        }
        delay = (delay * 2).min(Duration::from_secs(15));
    }

    order.finalize_csr(&csr_der).await?;

    let cert_chain_pem = loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if let Some(pem) = order.certificate().await? {
            break pem;
        }
    };

    *server_challenge.lock().await = None;

    tokio::fs::write(cert_path, &cert_chain_pem).await?;
    tokio::fs::write(key_path, keypair.serialize_pem()).await?;

    info!("ACME: server cert provisioned and saved to {}", cert_path);
    Ok(())
}

fn load_or_generate_keypair(path: &str) -> Result<rcgen::KeyPair> {
    if Path::new(path).exists() {
        let pem = std::fs::read_to_string(path)?;
        Ok(rcgen::KeyPair::from_pem(&pem)?)
    } else {
        let kp = rcgen::KeyPair::generate()?;
        std::fs::write(path, kp.serialize_pem())?;
        Ok(kp)
    }
}

async fn acme_load_or_create_account(
    email: Option<&str>,
    staging: bool,
    path: &str,
) -> Result<Account> {
    if Path::new(path).exists() {
        let json = tokio::fs::read_to_string(path).await?;
        let creds: AccountCredentials = serde_json::from_str(&json)?;
        return Ok(Account::builder()?.from_credentials(creds).await?);
    }
    let contact = email.map(|e| format!("mailto:{}", e));
    let contact_refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();
    let url = if staging {
        LetsEncrypt::Staging.url().to_owned()
    } else {
        LetsEncrypt::Production.url().to_owned()
    };
    let (account, credentials) = Account::builder()?
        .create(
            &NewAccount {
                contact: &contact_refs,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            url,
            None,
        )
        .await?;
    tokio::fs::write(path, serde_json::to_string_pretty(&credentials)?).await?;
    Ok(account)
}

pub(crate) fn build_server_tls_config(
    config: &ServerConfig,
    cert_paths: &Option<(String, String, bool)>,
    server_challenge: &ServerChallenge,
) -> Result<rustls::ServerConfig> {
    let verifier = Arc::new(SelfSignedVerifier::new());
    match cert_paths {
        Some((cert_path, key_path, is_acme)) => {
            let renewal = if *is_acme {
                config.acme_domain.as_ref().map(|domain| AcmeRenewalConfig {
                    domain: domain.clone(),
                    email: config.acme_email.clone(),
                    staging: config.acme_staging,
                    creds_path: config.acme_creds_path.clone(),
                    cert_path: cert_path.clone(),
                    key_path: key_path.clone(),
                    server_challenge: server_challenge.clone(),
                    renew_before_secs: config.acme_renew_days_before_expiry as i64 * 86400,
                })
            } else {
                None
            };
            Ok(rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_cert_resolver(Arc::new(DiskCertResolver::new(
                    cert_path, key_path, renewal,
                ))))
        }
        None => {
            let (c, k) = tunnel_common::cert("tunnel");
            Ok(rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(vec![c], k)?)
        }
    }
}

use tunnel_common::SelfSignedVerifier;
