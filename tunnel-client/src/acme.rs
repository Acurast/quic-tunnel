use anyhow::{bail, Result};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, Order, OrderStatus,
};
use log::info;
use std::{
    collections::HashMap,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{watch, Mutex};

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
    issued_at: Instant,
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
    account: Account,
    cache: Mutex<HashMap<String, CacheEntry>>,
    /// Tracks in-progress ACME orders. Holds the watch receivers that drive
    /// the leader/follower coordination across concurrent `prepare()` callers
    /// for the same domain. The leader's senders live in [`AlpnPending`].
    in_flight: Mutex<HashMap<String, InFlightEntry>>,
    on_cert_issued: Option<Arc<dyn Fn(String) + Send + Sync>>,
}

impl CertProvisioner {
    pub async fn new(
        contact_email: Option<&str>,
        staging: bool,
        credentials_path: &str,
        on_cert_issued: Option<Arc<dyn Fn(String) + Send + Sync>>,
    ) -> Result<Self> {
        let account = load_or_create_account(contact_email, staging, credentials_path).await?;
        Ok(Self {
            account,
            cache: Mutex::new(HashMap::new()),
            in_flight: Mutex::new(HashMap::new()),
            on_cert_issued,
        })
    }

    /// Pre-seed the cache with an already-obtained cert PEM, skipping ACME on next `prepare()`.
    pub async fn seed(&self, domain: &str, pem: String) {
        self.cache.lock().await.insert(
            domain.to_string(),
            CacheEntry {
                cert_pem: pem,
                issued_at: Instant::now(),
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
                    if e.issued_at.elapsed() < Duration::from_secs(60 * 24 * 3600) {
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
                    .account
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
                    let challenge = authz.challenge(ChallengeType::TlsAlpn01).ok_or_else(
                        || anyhow::anyhow!("no TLS-ALPN-01 challenge for {}", domain),
                    )?;
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

            let mut delay = Duration::from_secs(2);
            for _ in 0..12 {
                tokio::time::sleep(delay).await;
                let state = pending.order.refresh().await?;
                match state.status {
                    OrderStatus::Ready | OrderStatus::Valid => break,
                    OrderStatus::Invalid => bail!("ACME order invalid for {}", domain),
                    _ => {}
                }
                delay = (delay * 2).min(Duration::from_secs(15));
            }

            pending.order.finalize_csr(csr_der).await?;

            let cert_pem = loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                if let Some(cert) = pending.order.certificate().await? {
                    break cert;
                }
            };

            info!("ACME: cert issued for {}", domain);
            if let Some(cb) = &self.on_cert_issued {
                cb(cert_pem.clone());
            }
            self.cache.lock().await.insert(
                domain.to_string(),
                CacheEntry {
                    cert_pem: cert_pem.clone(),
                    issued_at: Instant::now(),
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
        return Ok(
            Account::builder_with_http(make_acme_http_client())
                .from_credentials(creds)
                .await?,
        );
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

    let client = hyper_util::client::legacy::Client::builder(
        hyper_util::rt::TokioExecutor::new(),
    )
    .build(connector);

    Box::new(client)
}
