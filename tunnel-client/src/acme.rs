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
    /// Broadcast the issued cert PEM to any concurrent callers waiting on this order.
    tx: watch::Sender<Option<String>>,
}

pub enum PrepareResult {
    /// Cert is already cached — use it directly, no challenge needed.
    Cached(String),
    /// ACME order started. Set up the ALPN proxy then call `finalize()`.
    Challenge(AlpnPending),
}

struct CacheEntry {
    cert_pem: String,
    issued_at: Instant,
}

pub struct CertProvisioner {
    account: Account,
    cache: Mutex<HashMap<String, CacheEntry>>,
    /// Tracks in-progress ACME orders. Value is a receiver that yields `Some(pem)`
    /// when the order completes, or closes (sender dropped) on failure.
    in_flight: Mutex<HashMap<String, watch::Receiver<Option<String>>>>,
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

    /// Phase 1: returns cached cert or starts an ACME TLS-ALPN-01 order.
    /// If `Challenge` is returned, the caller must:
    ///   1. Send `key_authorization` to the server.
    ///   2. Handle incoming ALPN challenge streams from the server.
    ///   3. Call `finalize()`.
    ///
    /// Concurrent calls for the same domain while an order is in progress will
    /// block until the first caller's `finalize()` completes, then return `Cached`.
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

            // Check in_flight without holding the lock across network calls.
            // If a stale entry is found (sender already dropped), remove it and retry.
            {
                let maybe_rx = self.in_flight.lock().await.get(domain).cloned();
                if let Some(mut rx) = maybe_rx {
                    match rx.changed().await {
                        Ok(_) => {
                            let pem = rx.borrow().clone();
                            return match pem {
                                Some(pem) => Ok(PrepareResult::Cached(pem)),
                                None => bail!("in-flight ACME order failed for {}", domain),
                            };
                        }
                        Err(_) => {
                            // Sender was dropped (order failed/cancelled) — remove stale
                            // entry and fall through to start a fresh order.
                            self.in_flight.lock().await.remove(domain);
                            continue;
                        }
                    }
                }
            }

            // No in_flight entry. Run the ACME network calls before inserting into the
            // map so a failure never leaves a stale entry behind.
            info!("ACME: provisioning cert for {}", domain);
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
                let challenge = authz
                    .challenge(ChallengeType::TlsAlpn01)
                    .ok_or_else(|| anyhow::anyhow!("no TLS-ALPN-01 challenge for {}", domain))?;
                key_authorization = challenge.key_authorization().as_str().to_string();
                challenge_url = challenge.url.clone();
            }

            let (tx, rx) = watch::channel(None::<String>);

            // Insert only after successful order setup. If another task raced us and
            // already inserted an entry, loop back and wait for theirs.
            {
                let mut in_flight = self.in_flight.lock().await;
                if in_flight.contains_key(domain) {
                    continue;
                }
                in_flight.insert(domain.to_string(), rx);
            }

            return Ok(PrepareResult::Challenge(AlpnPending {
                key_authorization,
                challenge_url,
                order,
                tx,
            }));
        } // end loop
    }

    /// Phase 2: signal challenge ready, poll until validated, finalize, cache.
    /// Call only after ALPN challenge streams are being served.
    pub async fn finalize(
        &self,
        domain: &str,
        mut pending: AlpnPending,
        csr_der: &[u8],
    ) -> Result<String> {
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

        // Notify waiting concurrent callers and clean up in_flight entry
        let _ = pending.tx.send(Some(cert_pem.clone()));
        self.in_flight.lock().await.remove(domain);

        Ok(cert_pem)
    }
}

async fn load_or_create_account(email: Option<&str>, staging: bool, path: &str) -> Result<Account> {
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
