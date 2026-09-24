use anyhow::Result;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, Order,
};
use log::{info, warn};
use std::{
    collections::HashMap,
    path::Path,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, watch};

pub struct AlpnPending {
    pub key_authorization: String,
    challenge_url: String,
    pub order: Order,
    /// Broadcast the issued cert PEM to any concurrent followers waiting on this order.
    tx: watch::Sender<Option<String>>,
}

pub enum PrepareResult {
    /// Cert is already cached — use it directly, no challenge needed.
    Cached(String),
    /// This caller owns the LE order. Send `key_authorization` to the server,
    /// run an ALPN acceptor, then call `finalize()`.
    LeaderChallenge(AlpnPending),
    /// Another caller owns the LE order. Send the shared `key_authorization`
    /// to the server (so this relay's pending entry is registered), run an
    /// ALPN acceptor (LE may pick this relay's IP), and await the cert PEM
    /// on `cert_rx` instead of calling `finalize()`.
    FollowerChallenge {
        key_authorization: String,
        cert_rx: watch::Receiver<Option<String>>,
    },
}

struct CacheEntry {
    cert_pem: String,
    renew_at: Instant,
}

/// Fallback renewal point for an issued cert whose validity cannot be read.
const DEFAULT_RENEW_AFTER: Duration = Duration::from_secs(60 * 24 * 3600);

/// When the leaf in `pem` is due for renewal: once a third of its lifetime is left.
fn renew_at(pem: &str) -> Result<Instant> {
    let der = rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .ok_or_else(|| anyhow::anyhow!("no certificate in PEM"))??;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)?;
    let validity = cert.validity();
    let (not_before, not_after) = (
        validity.not_before.timestamp(),
        validity.not_after.timestamp(),
    );
    let due = not_after - (not_after - not_before) / 3;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    Ok(Instant::now() + Duration::from_secs(due.saturating_sub(now).max(0) as u64))
}

/// Why the leaf in `pem` cannot serve `domain` under `public_key`, if it cannot.
fn seed_mismatch(domain: &str, public_key: &[u8], pem: &str) -> Option<String> {
    let der = match rustls_pemfile::certs(&mut pem.as_bytes()).next() {
        Some(Ok(der)) => der,
        _ => return Some("no certificate in PEM".into()),
    };
    let cert = match x509_parser::parse_x509_certificate(&der) {
        Ok((_, cert)) => cert,
        Err(e) => return Some(format!("unparseable certificate: {e}")),
    };
    let names_domain = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .is_some_and(|san| {
            san.value.general_names.iter().any(|n| {
                matches!(n, x509_parser::extensions::GeneralName::DNSName(d)
                    if d.eq_ignore_ascii_case(domain))
            })
        });
    if !names_domain {
        return Some(format!("certificate does not name {domain}"));
    }
    if !same_public_key(&cert.public_key().subject_public_key.data, public_key) {
        return Some("certificate is for a different key".into());
    }
    None
}

/// Compares SEC1 points regardless of compression; other keys byte-for-byte.
fn same_public_key(a: &[u8], b: &[u8]) -> bool {
    use p256::ecdsa::VerifyingKey;
    match (
        VerifyingKey::from_sec1_bytes(a),
        VerifyingKey::from_sec1_bytes(b),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

#[derive(Clone)]
struct InFlightEntry {
    /// `Some(key_auth)` once the leader has it from LE. Followers await this
    /// before they can register pending on their relay with the same value.
    key_auth_rx: watch::Receiver<Option<String>>,
    /// `Some(pem)` once the leader's `finalize()` succeeds. Followers return
    /// this PEM as their tunnel cert.
    cert_rx: watch::Receiver<Option<String>>,
}

pub struct CertProvisioner {
    /// Established on the first cache miss, not up front: a client started with
    /// an already-issued cert (seeded via `seed()`) never places an order, and
    /// must not need Let's Encrypt — or any connectivity — in order to boot.
    account: tokio::sync::OnceCell<Account>,
    contact_email: Option<String>,
    staging: bool,
    credentials_path: String,
    cache: Mutex<HashMap<String, CacheEntry>>,
    /// Tracks in-progress ACME orders. Holds the watch receivers that drive
    /// the leader/follower coordination across concurrent `prepare()` callers
    /// for the same domain. The leader's senders live in [`AlpnPending`].
    in_flight: Mutex<HashMap<String, InFlightEntry>>,
    on_cert_issued: Option<Arc<dyn Fn(String) + Send + Sync>>,
}

impl CertProvisioner {
    /// Synchronous and offline. The ACME account is established lazily — see
    /// [`CertProvisioner::account`].
    pub fn new(
        contact_email: Option<&str>,
        staging: bool,
        credentials_path: &str,
        on_cert_issued: Option<Arc<dyn Fn(String) + Send + Sync>>,
    ) -> Self {
        Self {
            account: tokio::sync::OnceCell::new(),
            contact_email: contact_email.map(str::to_string),
            staging,
            credentials_path: credentials_path.to_string(),
            cache: Mutex::new(HashMap::new()),
            in_flight: Mutex::new(HashMap::new()),
            on_cert_issued,
        }
    }

    /// Loads the ACME account, creating and persisting one on first call.
    /// Reached only when a cert actually has to be ordered.
    async fn account(&self) -> Result<&Account> {
        self.account
            .get_or_try_init(|| {
                load_or_create_account(
                    self.contact_email.as_deref(),
                    self.staging,
                    &self.credentials_path,
                )
            })
            .await
    }

    /// Pre-seeds the cache with an already-issued cert PEM, skipping ACME on the
    /// next `prepare()`. Ignored unless it names `domain`, carries `public_key`
    /// and is not yet due for renewal.
    pub async fn seed(&self, domain: &str, public_key: &[u8], pem: String) {
        if let Some(why) = seed_mismatch(domain, public_key, &pem) {
            return warn!("ACME: ignoring seeded cert for {domain}: {why}");
        }
        let renew_at = match renew_at(&pem) {
            Ok(t) if t > Instant::now() => t,
            Ok(_) => return warn!("ACME: ignoring seeded cert for {domain}: due for renewal"),
            Err(e) => return warn!("ACME: ignoring seeded cert for {domain}: {e}"),
        };
        self.cache.lock().await.insert(
            domain.to_string(),
            CacheEntry {
                cert_pem: pem,
                renew_at,
            },
        );
    }

    /// Phase 1: returns a cached cert, becomes leader of a fresh LE order, or
    /// joins as follower of an in-flight order. With multiple relay-connections
    /// driving the same domain concurrently, only one caller becomes leader —
    /// followers receive the SAME `key_authorization` so every relay registers
    /// pending server-side with matching state. Whichever IP LE picks for the
    /// TLS-ALPN-01 validator works.
    ///
    /// Leader contract: send `key_authorization` to the server, run an ALPN
    /// acceptor, then call `finalize()`.
    /// Follower contract: send the shared `key_authorization` to the server,
    /// run an ALPN acceptor, then await the cert PEM on `cert_rx`.
    pub async fn prepare(&self, domain: &str) -> Result<PrepareResult> {
        loop {
            // Fast path: cache hit (don't hold lock across the ACME I/O below)
            {
                let cache = self.cache.lock().await;
                if let Some(e) = cache.get(domain) {
                    if Instant::now() < e.renew_at {
                        return Ok(PrepareResult::Cached(e.cert_pem.clone()));
                    }
                }
            }

            // Check in_flight under the lock; if a leader exists, become a
            // follower. Receivers are cloned so we can wait outside the lock.
            let existing = {
                let in_flight = self.in_flight.lock().await;
                in_flight.get(domain).cloned()
            };
            if let Some(InFlightEntry {
                mut key_auth_rx,
                cert_rx,
            }) = existing
            {
                // If the leader's `cert_tx` is already gone (finalize errored
                // or panicked), the entry is stale. Drop it and retry the loop
                // so this caller can claim leader instead of becoming a
                // follower of a dead sender.
                if cert_rx.has_changed().is_err() {
                    self.in_flight.lock().await.remove(domain);
                    continue;
                }
                // Fast path: leader has already published key_auth.
                let cached = key_auth_rx.borrow().clone();
                if let Some(key_authorization) = cached {
                    return Ok(PrepareResult::FollowerChallenge {
                        key_authorization,
                        cert_rx,
                    });
                }
                // Wait for the leader to publish key_auth. If the sender is
                // dropped without publishing, the leader's LE setup failed —
                // drop the stale entry and retry as a fresh leader.
                match key_auth_rx.changed().await {
                    Ok(_) => {
                        let key_authorization = key_auth_rx.borrow().clone();
                        match key_authorization {
                            Some(key_authorization) => {
                                return Ok(PrepareResult::FollowerChallenge {
                                    key_authorization,
                                    cert_rx,
                                });
                            }
                            None => {
                                // Shouldn't normally happen — leader sent None.
                                // Treat as failure and retry.
                                self.in_flight.lock().await.remove(domain);
                                continue;
                            }
                        }
                    }
                    Err(_) => {
                        self.in_flight.lock().await.remove(domain);
                        continue;
                    }
                }
            }

            // Claim leader by atomically inserting under the lock. Re-check to
            // close the race window between the existing-entry probe and here.
            let (key_auth_tx, key_auth_rx) = watch::channel(None::<String>);
            let (cert_tx, cert_rx) = watch::channel(None::<String>);
            {
                let mut in_flight = self.in_flight.lock().await;
                if in_flight.contains_key(domain) {
                    // Lost the race; retry the loop to become a follower.
                    continue;
                }
                in_flight.insert(
                    domain.to_string(),
                    InFlightEntry {
                        key_auth_rx,
                        cert_rx,
                    },
                );
            }

            // Leader: drive the LE order. On failure, remove the in_flight
            // entry and drop the senders so any concurrent followers wake up
            // with `Err` and can retry from scratch.
            info!("ACME: provisioning cert for {}", domain);
            let setup = async {
                let mut order = self
                    .account()
                    .await?
                    .new_order(&NewOrder::new(&[Identifier::Dns(domain.to_string())]))
                    .await?;

                let mut challenge_url = String::new();
                let mut key_authorization = String::new();
                let mut authorizations = order.authorizations();
                while let Some(result) = authorizations.next().await {
                    let mut authz = result?;
                    if authz.status == AuthorizationStatus::Valid {
                        continue;
                    }
                    let challenge = authz.challenge(ChallengeType::TlsAlpn01).ok_or_else(|| {
                        anyhow::anyhow!("no TLS-ALPN-01 challenge for {}", domain)
                    })?;
                    key_authorization = challenge.key_authorization().as_str().to_string();
                    challenge_url = challenge.url.clone();
                }
                Ok::<_, anyhow::Error>((order, key_authorization, challenge_url))
            };

            match setup.await {
                Ok((order, key_authorization, challenge_url)) => {
                    // Publish key_auth to any followers blocked on `changed()`.
                    let _ = key_auth_tx.send(Some(key_authorization.clone()));
                    return Ok(PrepareResult::LeaderChallenge(AlpnPending {
                        key_authorization,
                        challenge_url,
                        order,
                        tx: cert_tx,
                    }));
                }
                Err(e) => {
                    self.in_flight.lock().await.remove(domain);
                    drop(key_auth_tx);
                    drop(cert_tx);
                    return Err(e);
                }
            }
        } // end loop
    }

    /// Phase 2: signal challenge ready, poll until validated, finalize, cache.
    /// Call only after ALPN challenge streams are being served.
    ///
    /// The `in_flight` HashMap entry for `domain` is removed on every exit
    /// path (success or error). This is critical: without it, a failed
    /// finalize would leave a stale entry whose `key_auth_rx` still reports
    /// `Some(key_authorization)`, causing subsequent `prepare()` calls to
    /// take the follower fast path and immediately fail on the
    /// already-dropped `cert_tx`.
    pub async fn finalize(
        &self,
        domain: &str,
        mut pending: AlpnPending,
        csr_der: &[u8],
    ) -> Result<String> {
        let result: Result<String> = async {
            if !pending.challenge_url.is_empty() {
                let mut authorizations = pending.order.authorizations();
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

            let cert_pem =
                tunnel_common::acme::finalize_order(&mut pending.order, domain, csr_der).await?;

            info!("ACME: cert issued for {}", domain);
            if let Some(cb) = &self.on_cert_issued {
                cb(cert_pem.clone());
            }
            self.cache.lock().await.insert(
                domain.to_string(),
                CacheEntry {
                    cert_pem: cert_pem.clone(),
                    renew_at: renew_at(&cert_pem)
                        .unwrap_or_else(|_| Instant::now() + DEFAULT_RENEW_AFTER),
                },
            );

            // Notify waiting concurrent callers. The in_flight cleanup runs
            // unconditionally after this async block, regardless of outcome.
            let _ = pending.tx.send(Some(cert_pem.clone()));

            Ok(cert_pem)
        }
        .await;

        self.in_flight.lock().await.remove(domain);

        result
    }
}

async fn load_or_create_account(email: Option<&str>, staging: bool, path: &str) -> Result<Account> {
    if Path::new(path).exists() {
        let json = tokio::fs::read_to_string(path).await?;
        let creds: AccountCredentials = serde_json::from_str(&json)?;
        return Ok(Account::builder_with_http(make_acme_http_client())
            .from_credentials(creds)
            .await?);
    }

    let contact = email.map(|e| format!("mailto:{}", e));
    let contact_refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();
    let url = if staging {
        LetsEncrypt::Staging.url().to_owned()
    } else {
        LetsEncrypt::Production.url().to_owned()
    };
    let (account, credentials) = Account::builder_with_http(make_acme_http_client())
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

/// Builds an HTTP client for the ACME flow backed by the Mozilla CA bundle
/// (`webpki-roots`). No OS-level trust store or revocation checking — the
/// ACME surface is narrow (one host, one CA chain) and LE end-entity certs
/// are short-lived enough that pinned roots are an acceptable trade-off.
fn make_acme_http_client() -> Box<dyn instant_acme::HttpClient> {
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .enable_http2()
        .build();

    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build(connector);

    Box::new(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN: &str = "abc.localhost";

    fn cert(names: &[&str], key: &rcgen::KeyPair, days_left: i64, lifetime_days: i64) -> String {
        let mut params =
            rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        let now = rcgen::date_time_ymd(1970, 1, 1)
            + SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        params.not_after = now + Duration::from_secs(days_left as u64 * 86400);
        params.not_before = now - Duration::from_secs((lifetime_days - days_left) as u64 * 86400);
        params.self_signed(key).unwrap().pem()
    }

    fn provisioner() -> CertProvisioner {
        CertProvisioner::new(None, true, "unused.json", None)
    }

    async fn cached(p: &CertProvisioner) -> bool {
        p.cache.lock().await.contains_key(DOMAIN)
    }

    #[tokio::test]
    async fn seed_accepts_a_matching_fresh_cert() {
        let key = rcgen::KeyPair::generate().unwrap();
        let p = provisioner();
        p.seed(DOMAIN, key.public_key_raw(), cert(&[DOMAIN], &key, 80, 90))
            .await;
        assert!(cached(&p).await);
    }

    #[tokio::test]
    async fn seed_ignores_a_cert_for_another_key() {
        let (key, other) = (
            rcgen::KeyPair::generate().unwrap(),
            rcgen::KeyPair::generate().unwrap(),
        );
        let p = provisioner();
        p.seed(
            DOMAIN,
            other.public_key_raw(),
            cert(&[DOMAIN], &key, 80, 90),
        )
        .await;
        assert!(!cached(&p).await);
    }

    #[tokio::test]
    async fn seed_ignores_a_cert_for_another_domain() {
        let key = rcgen::KeyPair::generate().unwrap();
        let p = provisioner();
        p.seed(
            DOMAIN,
            key.public_key_raw(),
            cert(&["other.localhost"], &key, 80, 90),
        )
        .await;
        assert!(!cached(&p).await);
    }

    #[tokio::test]
    async fn seed_ignores_a_cert_due_for_renewal() {
        let key = rcgen::KeyPair::generate().unwrap();
        let p = provisioner();
        p.seed(DOMAIN, key.public_key_raw(), cert(&[DOMAIN], &key, 20, 90))
            .await;
        assert!(!cached(&p).await);
    }

    #[test]
    fn same_public_key_ignores_point_compression() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let raw = rcgen::KeyPair::generate()
            .unwrap()
            .public_key_raw()
            .to_vec();
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&raw).unwrap();
        assert!(same_public_key(
            vk.to_encoded_point(false).as_bytes(),
            vk.to_encoded_point(true).as_bytes()
        ));
    }
}
