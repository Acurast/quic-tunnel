use crate::acme::{CertProvisioner, PrepareResult};
use crate::key::{KeyAlgorithm, RcgenRemoteKey, RustlsRemoteKey, TunnelKey};
use anyhow::Result;
use log::{debug, error, info, warn};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rustls::pki_types::CertificateDer;
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{net::TcpStream, sync::Notify};
use tunnel_common::{
    CUSTOM_DATA_EXT_OID, H2Recv, H2Send, IO, NoVerify, build_alpn_acceptor, ctrl_read, ctrl_write,
};

/// Maximum number of consecutive failed reconnect attempts before the
/// per-connection task gives up and returns an error. The counter resets
/// after a connection successfully completes the control exchange.
const RECONNECT_MAX_ATTEMPTS: u32 = 5;
/// First backoff interval; doubles after each failed attempt, capped at
/// [`RECONNECT_MAX_BACKOFF`]. Sequence: 2s, 4s, 8s, 16s, 32s, then bail.
const RECONNECT_BASE_BACKOFF: Duration = Duration::from_secs(2);
const RECONNECT_MAX_BACKOFF: Duration = Duration::from_secs(32);

/// Per-connection identity: the signing key and an optional custom X.509
/// extension embedded in the self-signed agent certificate the server sees
/// during mTLS.
pub struct TunnelIdentityConfig {
    /// Signing key. The private key material stays behind the trait
    /// boundary; the client only calls `sign`.
    pub keypair: Arc<dyn TunnelKey>,
    /// Opaque bytes embedded as a custom X.509 extension in the self-signed
    /// agent certificate. The server can extract these after mTLS handshake.
    /// `None` omits the extension.
    pub cert_extension: Option<Vec<u8>>,
}

pub struct TunnelConfig {
    pub server_addrs: Vec<String>,
    pub local_addr: String,
    /// Local address the secondary (self-signed) connection forwards to.
    /// `None` → falls back to `local_addr` (same target as primary).
    pub secondary_local_addr: Option<String>,
    pub domain_suffix: String,
    pub force_h2: bool,
    pub pool_size: usize,
    pub acme_email: Option<String>,
    pub acme_creds_path: String,
    pub acme_staging: bool,
    /// Pre-seeded LE cert PEM for the primary connection's domain. Skips ACME if supplied.
    pub cert_pem: Option<String>,
    /// Called with the cert PEM when a new cert is freshly issued via ACME.
    pub on_cert_issued: Option<Arc<dyn Fn(String) + Send + Sync>>,
    /// Primary connection identity. Drives the ACME-issued tunnel cert.
    pub primary_identity: TunnelIdentityConfig,
    /// Optional self-signed connection identity. When present, the client
    /// opens a second connection per server address using this identity;
    /// that connection uses a plain self-signed cert to terminate tunnel
    /// TLS (no ACME).
    pub self_signed_identity: Option<TunnelIdentityConfig>,
}

pub struct TunnelClient {
    config: TunnelConfig,
    primary: Connection,
    secondary: Option<Connection>,
    stop: Arc<Notify>,
    stopped: Arc<AtomicBool>,
}

struct Connection {
    client_id: String,
    domain: String,
    url: String,
    /// Self-signed cert presented during mTLS to the server. Signed by
    /// `agent_keypair`. On the secondary connection this cert is also reused
    /// to terminate user-facing tunnel TLS.
    agent_cert_der: Vec<u8>,
    /// Keypair signing the mTLS agent cert and driving TLS handshakes
    /// (client auth + secondary user TLS termination).
    agent_keypair: Arc<dyn TunnelKey>,
    /// Keypair whose pubkey derives `client_id` and signs the domain
    /// proof-of-possession sent to the server. Also signs the ACME CSR on
    /// the primary connection. Must be ECDSA P-256.
    identity_keypair: Arc<dyn TunnelKey>,
    /// CSR used to request an ACME-issued tunnel cert. Present only on the
    /// primary connection. Signed by `identity_keypair`.
    csr_der: Option<Vec<u8>>,
}

impl TunnelClient {
    /// Creates a new client. Synchronous — no network operations.
    /// `client_id` and `url` are available immediately.
    pub fn new(config: TunnelConfig) -> Result<Self> {
        // Multiple rustls crypto providers (ring + aws-lc-rs) can be pulled in by
        // transitive deps, leaving no auto-detected default. Install ring explicitly;
        // ignore Err (already installed by another caller).
        let _ = rustls::crypto::ring::default_provider().install_default();

        // The identity-recovery protocol requires P-256 on both keypairs (server
        // recovers the pubkey from a recoverable ECDSA signature).
        if config.primary_identity.keypair.algorithm() != crate::key::KeyAlgorithm::EcdsaP256 {
            anyhow::bail!("primary_identity keypair must be ECDSA P-256");
        }
        if let Some(sec) = &config.self_signed_identity {
            if sec.keypair.algorithm() != crate::key::KeyAlgorithm::EcdsaP256 {
                anyhow::bail!("self_signed_identity keypair must be ECDSA P-256");
            }
        }

        // Primary connection: identity = primary_identity (drives id, ACME CSR,
        // domain signature). Agent cert is signed by self_signed_identity when
        // configured, otherwise by primary_identity.
        let primary_agent_keypair = match &config.self_signed_identity {
            Some(sec) => Arc::clone(&sec.keypair),
            None => Arc::clone(&config.primary_identity.keypair),
        };
        let primary = build_connection(
            primary_agent_keypair,
            Arc::clone(&config.primary_identity.keypair),
            &config.domain_suffix,
            config.primary_identity.cert_extension.as_deref(),
            /* need_csr */ true,
        )?;
        // Secondary connection: only exists when self_signed_identity is
        // configured. Both the agent cert and the identity (id derivation +
        // domain signature) are bound to self_signed_identity, so the secondary
        // gets a distinct client_id from the primary and routes to its own URL.
        let secondary = match &config.self_signed_identity {
            Some(sec) => Some(build_connection(
                Arc::clone(&sec.keypair),
                Arc::clone(&sec.keypair),
                &config.domain_suffix,
                sec.cert_extension.as_deref(),
                /* need_csr */ false,
            )?),
            None => None,
        };

        Ok(Self {
            config,
            primary,
            secondary,
            stop: Arc::new(Notify::new()),
            stopped: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn client_id(&self) -> &str {
        &self.primary.client_id
    }
    pub fn url(&self) -> &str {
        &self.primary.url
    }
    pub fn secondary_client_id(&self) -> Option<&str> {
        self.secondary.as_ref().map(|s| s.client_id.as_str())
    }
    pub fn secondary_url(&self) -> Option<&str> {
        self.secondary.as_ref().map(|s| s.url.as_str())
    }

    /// Signal the running tunnel to stop. Safe to call from any thread or task.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.stop.notify_waiters();
    }

    /// Runs the tunnel. Resolves when `stop()` is called.
    /// Must be called on an `Arc<TunnelClient>` (the call site already uses Arc).
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let provisioner = Arc::new(
            CertProvisioner::new(
                self.config.acme_email.as_deref(),
                self.config.acme_staging,
                &self.config.acme_creds_path,
                self.config.on_cert_issued.clone(),
            )
            .await?,
        );

        if let Some(pem) = &self.config.cert_pem {
            provisioner.seed(&self.primary.domain, pem.clone()).await;
        }

        let mut handles = Vec::new();
        for server_addr in &self.config.server_addrs {
            // Primary connection (ACME-backed tunnel cert). Forwards to local_addr.
            {
                let server_addr = server_addr.clone();
                let provisioner = provisioner.clone();
                let this = Arc::clone(&self);
                handles.push(tokio::spawn(async move {
                    let target = &this.config.local_addr;
                    this.connection_run(
                        &this.primary,
                        &server_addr,
                        Some(provisioner),
                        "PRI",
                        target,
                    )
                    .await
                }));
            }
            // Secondary connection (self-signed tunnel cert, no ACME). Forwards to
            // secondary_local_addr when set, else falls back to local_addr.
            if self.secondary.is_some() {
                let server_addr = server_addr.clone();
                let this = Arc::clone(&self);
                handles.push(tokio::spawn(async move {
                    let sec = this.secondary.as_ref().expect("secondary present");
                    let target = this
                        .config
                        .secondary_local_addr
                        .as_deref()
                        .unwrap_or(&this.config.local_addr);
                    this.connection_run(sec, &server_addr, None, "SEC", target)
                        .await
                }));
            }
        }

        self.stop.notified().await;
        for h in handles {
            h.abort();
        }
        Ok(())
    }

    /// Drives a single connection (either primary or secondary) to one server.
    /// `provisioner = Some(_)` enables the ACME flow; `None` uses the pre-built
    /// self-signed agent cert for tunnel TLS termination.
    async fn connection_run(
        &self,
        conn_m: &Connection,
        server_addr: &str,
        provisioner: Option<Arc<CertProvisioner>>,
        tag: &str,
        target_addr: &str,
    ) -> Result<()> {
        if !self.config.force_h2 {
            self.quic_run(conn_m, server_addr, provisioner, tag, target_addr)
                .await
        } else {
            info!(
                "H2[{}/{}]: FORCE_HTTP2 set, skipping QUIC",
                tag, server_addr
            );
            self.h2_pool(conn_m, server_addr, provisioner, tag, target_addr)
                .await
        }
    }

    async fn quic_run(
        &self,
        conn_m: &Connection,
        server_addr: &str,
        provisioner: Option<Arc<CertProvisioner>>,
        tag: &str,
        target_addr: &str,
    ) -> Result<()> {
        let mut attempts: u32 = 0;
        let mut backoff = RECONNECT_BASE_BACKOFF;
        while !self.stopped.load(Ordering::SeqCst) {
            info!(
                "QUIC[{}/{}]: connecting (attempt {}/{})",
                tag,
                server_addr,
                attempts + 1,
                RECONNECT_MAX_ATTEMPTS
            );
            match self.quic_connect(conn_m, server_addr).await {
                Err(e) => {
                    warn!(
                        "QUIC[{}/{}]: connection failed ({}), falling back to H2",
                        tag, server_addr, e
                    );
                    return self
                        .h2_pool(conn_m, server_addr, provisioner, tag, target_addr)
                        .await;
                }
                Ok(conn) => {
                    info!("QUIC[{}/{}]: connected", tag, server_addr);
                    let ctrl_completed = Arc::new(AtomicBool::new(false));
                    if let Err(e) = self
                        .quic_loop(
                            conn_m,
                            conn,
                            server_addr,
                            provisioner.clone(),
                            tag,
                            target_addr,
                            Arc::clone(&ctrl_completed),
                        )
                        .await
                    {
                        warn!("QUIC[{}/{}]: error ({})", tag, server_addr, e);
                    }
                    if self.stopped.load(Ordering::SeqCst) {
                        return Ok(());
                    }
                    if ctrl_completed.load(Ordering::SeqCst) {
                        attempts = 0;
                        backoff = RECONNECT_BASE_BACKOFF;
                    } else {
                        attempts += 1;
                        if attempts >= RECONNECT_MAX_ATTEMPTS {
                            anyhow::bail!(
                                "QUIC[{}/{}]: giving up after {} failed attempts",
                                tag,
                                server_addr,
                                attempts
                            );
                        }
                    }
                    info!(
                        "QUIC[{}/{}]: reconnecting in {:?} (next attempt {}/{})",
                        tag,
                        server_addr,
                        backoff,
                        attempts + 1,
                        RECONNECT_MAX_ATTEMPTS
                    );
                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => {}
                        _ = self.stop.notified() => return Ok(()),
                    }
                    backoff = (backoff * 2).min(RECONNECT_MAX_BACKOFF);
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn quic_loop(
        &self,
        conn_m: &Connection,
        conn: quinn::Connection,
        server_addr: &str,
        provisioner: Option<Arc<CertProvisioner>>,
        tag: &str,
        target_addr: &str,
        ctrl_completed: Arc<AtomicBool>,
    ) -> Result<()> {
        let (mut ctrl_send, mut ctrl_recv) = conn.open_bi().await?;

        // Step 1: send domain
        ctrl_write(&mut ctrl_send, conn_m.domain.as_bytes()).await?;

        // Step 2: send recoverable ECDSA P-256 signature over the domain so the
        // server can recover the identity pubkey and verify it hashes to the id
        // portion of the domain.
        let sig = sign_recoverable(conn_m.identity_keypair.as_ref(), conn_m.domain.as_bytes())?;
        ctrl_write(&mut ctrl_send, &sig).await?;

        // Step 3: obtain the tunnel-terminating cert material.
        let provisioner_was_some = provisioner.is_some();
        let tunnel_certs: Vec<CertificateDer<'static>> = match provisioner {
            None => {
                // No ACME on this connection: send empty key_auth; reuse agent
                // cert for user-facing TLS termination.
                ctrl_write(&mut ctrl_send, b"").await?;
                vec![conn_m.agent_cert_der.clone().into()]
            }
            Some(provisioner) => {
                let cert_pem = match provisioner.prepare(&conn_m.domain).await? {
                    PrepareResult::Cached(pem) => {
                        debug!("QUIC[{}]: cert cached, no challenge needed", tag);
                        ctrl_write(&mut ctrl_send, b"").await?;
                        pem
                    }
                    PrepareResult::LeaderChallenge(alpn_pending) => {
                        let ka = alpn_pending.key_authorization.clone();
                        debug!(
                            "QUIC[{}]: leader, building ALPN acceptor for challenge",
                            tag
                        );
                        let alpn_acceptor = build_alpn_acceptor(&conn_m.domain, &ka)?;

                        // Send key_auth, wait for server ACK (server registers pending_alpn)
                        ctrl_write(&mut ctrl_send, ka.as_bytes()).await?;
                        ctrl_read(&mut ctrl_recv).await?;

                        // Finalize concurrently while serving ALPN challenge streams
                        let csr_der = conn_m
                            .csr_der
                            .clone()
                            .ok_or_else(|| anyhow::anyhow!("ACME path requires csr_der"))?;
                        let prov = provisioner.clone();
                        let dom = conn_m.domain.clone();
                        let mut finalize_task = tokio::spawn(async move {
                            prov.finalize(&dom, alpn_pending, &csr_der).await
                        });

                        let cert_pem = loop {
                            tokio::select! {
                                res = conn.accept_bi() => match res {
                                    Ok((send, recv)) => {
                                        debug!("QUIC[{}]: challenge stream received, terminating TLS-ALPN-01", tag);
                                        let acc = alpn_acceptor.clone();
                                        tokio::spawn(async move {
                                            let _ = acc.accept(IO::new(recv, send)).await;
                                        });
                                    }
                                    Err(e) => return Err(e.into()),
                                },
                                result = &mut finalize_task => {
                                    break result??;
                                }
                            }
                        };

                        // Signal done to server (server removes from pending_alpn)
                        ctrl_write(&mut ctrl_send, b"done").await?;
                        cert_pem
                    }
                    PrepareResult::FollowerChallenge {
                        key_authorization,
                        mut cert_rx,
                    } => {
                        let ka = key_authorization;
                        debug!(
                            "QUIC[{}]: follower, sharing leader's key_auth for ALPN challenge",
                            tag
                        );
                        let alpn_acceptor = build_alpn_acceptor(&conn_m.domain, &ka)?;

                        // Register pending on the server with the shared key_auth so
                        // LE can land on this relay's IP and still validate.
                        ctrl_write(&mut ctrl_send, ka.as_bytes()).await?;
                        ctrl_read(&mut ctrl_recv).await?;

                        // Serve ALPN challenge streams until the leader broadcasts
                        // the issued cert (or the leader's order fails).
                        let cert_pem = loop {
                            tokio::select! {
                                res = conn.accept_bi() => match res {
                                    Ok((send, recv)) => {
                                        debug!("QUIC[{}]: challenge stream received (follower), terminating TLS-ALPN-01", tag);
                                        let acc = alpn_acceptor.clone();
                                        tokio::spawn(async move {
                                            let _ = acc.accept(IO::new(recv, send)).await;
                                        });
                                    }
                                    Err(e) => return Err(e.into()),
                                },
                                res = cert_rx.changed() => {
                                    res.map_err(|_| anyhow::anyhow!(
                                        "ACME leader for {} dropped before cert issuance",
                                        conn_m.domain
                                    ))?;
                                    let pem = cert_rx.borrow().clone().ok_or_else(|| {
                                        anyhow::anyhow!(
                                            "ACME leader for {} signalled empty cert",
                                            conn_m.domain
                                        )
                                    })?;
                                    break pem;
                                }
                            }
                        };

                        // Signal done to server (server removes from pending_alpn)
                        ctrl_write(&mut ctrl_send, b"done").await?;
                        cert_pem
                    }
                };
                parse_cert_chain_pem(&cert_pem)?
            }
        };

        drop((ctrl_send, ctrl_recv));
        ctrl_completed.store(true, Ordering::SeqCst);
        info!(
            "QUIC[{}/{}]: tunnel ready at {}",
            tag, server_addr, conn_m.url
        );

        // User-TLS keypair must match the cert chain: on the ACME path the
        // chain belongs to the identity key (CSR was signed by it); without
        // ACME we reuse the agent cert + agent key.
        let user_tls_keypair = if provisioner_was_some {
            Arc::clone(&conn_m.identity_keypair)
        } else {
            Arc::clone(&conn_m.agent_keypair)
        };
        let acceptor = build_tls_acceptor(user_tls_keypair, tunnel_certs)?;
        let local_addr = target_addr.to_string();

        loop {
            tokio::select! {
                res = conn.accept_bi() => match res {
                    Ok((send, recv)) => {
                        debug!("QUIC[{}]: new tunnel stream, forwarding to {}", tag, local_addr);
                        pipe(acceptor.clone(), IO::new(recv, send), local_addr.clone());
                    }
                    Err(e) => {
                        warn!("QUIC[{}]: connection closed ({})", tag, e);
                        return Ok(());
                    }
                },
                _ = self.stop.notified() => return Ok(()),
            }
        }
    }

    async fn h2_pool(
        &self,
        conn_m: &Connection,
        server_addr: &str,
        provisioner: Option<Arc<CertProvisioner>>,
        tag: &str,
        target_addr: &str,
    ) -> Result<()> {
        info!(
            "H2[{}/{}]: starting pool of {} connections",
            tag, server_addr, self.config.pool_size
        );
        let handles: Vec<_> = (0..self.config.pool_size)
            .map(|i| {
                let server_addr = server_addr.to_string();
                let local_addr = target_addr.to_string();
                let agent_cert_der = conn_m.agent_cert_der.clone();
                let agent_keypair = Arc::clone(&conn_m.agent_keypair);
                let identity_keypair = Arc::clone(&conn_m.identity_keypair);
                let csr_der = conn_m.csr_der.clone();
                let url = conn_m.url.clone();
                let domain = conn_m.domain.clone();
                let provisioner = provisioner.clone();
                let tag = tag.to_string();
                let acme_staging = self.config.acme_staging;
                tokio::spawn(async move {
                    let mut attempts: u32 = 0;
                    let mut backoff = RECONNECT_BASE_BACKOFF;
                    loop {
                        debug!(
                            "H2[{}/{}]: connecting (attempt {}/{})",
                            tag,
                            i,
                            attempts + 1,
                            RECONNECT_MAX_ATTEMPTS
                        );
                        let cert: CertificateDer<'static> = agent_cert_der.clone().into();
                        match connect_h2(
                            &server_addr,
                            cert,
                            Arc::clone(&agent_keypair),
                            acme_staging,
                        )
                        .await
                        {
                            Err(e) => {
                                error!("H2[{}/{}]: connection failed: {}", tag, i, e);
                            }
                            Ok(mut h2) => {
                                info!("H2[{}/{}]: connected", tag, i);
                                let ctrl_res = h2_ctrl_exchange(
                                    &mut h2,
                                    &domain,
                                    identity_keypair.as_ref(),
                                    csr_der.as_deref(),
                                    provisioner.clone(),
                                    &agent_cert_der,
                                )
                                .await;
                                let provisioner_was_some = provisioner.is_some();
                                match ctrl_res {
                                    Err(e) => {
                                        error!("H2[{}/{}]: control exchange failed: {}", tag, i, e);
                                    }
                                        Ok(tunnel_certs) => {
                                        info!("H2[{}/{}]: tunnel ready at {}", tag, i, url);
                                        // Successful ctrl exchange → reset retry budget.
                                        attempts = 0;
                                        backoff = RECONNECT_BASE_BACKOFF;
                                        let user_tls_keypair = if provisioner_was_some {
                                            Arc::clone(&identity_keypair)
                                        } else {
                                            Arc::clone(&agent_keypair)
                                        };
                                        match build_tls_acceptor(user_tls_keypair, tunnel_certs) {
                                            Err(e) => {
                                                error!("H2[{}/{}]: failed to build TLS acceptor: {}", tag, i, e);
                                            }
                                            Ok(acceptor) => {
                                                while let Some(Ok((req, mut resp))) = h2.accept().await {
                                                    debug!("H2[{}/{}]: new tunnel stream, forwarding to {}", tag, i, local_addr);
                                                    if let Ok(send) =
                                                        resp.send_response(http::Response::new(()), false)
                                                    {
                                                        let recv = H2Recv {
                                                            r: req.into_body(),
                                                            buf: bytes::Bytes::new(),
                                                        };
                                                        pipe(
                                                            acceptor.clone(),
                                                            IO::new(recv, H2Send(send)),
                                                            local_addr.clone(),
                                                        );
                                                    }
                                                }
                                                warn!("H2[{}/{}]: connection dropped, reconnecting", tag, i);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        attempts += 1;
                        if attempts >= RECONNECT_MAX_ATTEMPTS {
                            error!(
                                "H2[{}/{}]: giving up after {} failed attempts",
                                tag, i, attempts
                            );
                            return;
                        }
                        debug!(
                            "H2[{}/{}]: retrying in {:?} (next attempt {}/{})",
                            tag,
                            i,
                            backoff,
                            attempts + 1,
                            RECONNECT_MAX_ATTEMPTS
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(RECONNECT_MAX_BACKOFF);
                    }
                })
            })
            .collect();

        self.stop.notified().await;
        info!("H2[{}]: stop signal received, shutting down pool", tag);
        for h in handles {
            h.abort();
        }
        Ok(())
    }

    async fn quic_connect(
        &self,
        conn_m: &Connection,
        server_addr: &str,
    ) -> Result<quinn::Connection> {
        let cert: CertificateDer<'static> = conn_m.agent_cert_der.clone().into();
        connect_quic(
            server_addr,
            cert,
            Arc::clone(&conn_m.agent_keypair),
            self.config.acme_staging,
        )
        .await
    }
}

fn pipe(acceptor: tokio_rustls::TlsAcceptor, tunnel: IO, target: String) {
    tokio::spawn(async move {
        let mut tls = match acceptor.accept(tunnel).await {
            Ok(s) => s,
            Err(e) => {
                error!("pipe: TLS accept failed: {}", e);
                return None;
            }
        };
        let mut local = match TcpStream::connect(&target).await {
            Ok(s) => s,
            Err(e) => {
                error!("pipe: connect to {} failed: {}", target, e);
                return None;
            }
        };
        tokio::io::copy_bidirectional(&mut tls, &mut local)
            .await
            .ok()
    });
}

fn build_tls_acceptor(
    keypair: Arc<dyn TunnelKey>,
    certs: Vec<CertificateDer<'static>>,
) -> Result<tokio_rustls::TlsAcceptor> {
    let signing_key = Arc::new(RustlsRemoteKey::new(keypair));
    let resolver = Arc::new(SingleCertAndKey::from(CertifiedKey::new(
        certs,
        signing_key,
    )));
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

fn parse_cert_chain_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    Ok(rustls_pemfile::certs(&mut pem.as_bytes())
        .map(|r| r.map(|c| c.to_owned()))
        .collect::<Result<_, _>>()?)
}

/// Builds a `Connection` with split agent/identity roles.
///
/// `agent_keypair` signs the self-signed mTLS agent cert and drives TLS
/// handshakes. `identity_keypair` (must be P-256) derives `client_id` from
/// its pubkey and signs the ACME CSR when `need_csr` is true.
fn build_connection(
    agent_keypair: Arc<dyn TunnelKey>,
    identity_keypair: Arc<dyn TunnelKey>,
    domain_suffix: &str,
    cert_extension: Option<&[u8]>,
    need_csr: bool,
) -> Result<Connection> {
    let identity_pub_raw = identity_keypair.public_key_raw();
    // Hash the SEC1-COMPRESSED point (33 bytes: 0x02/0x03 || X) for P-256, not
    // the uncompressed 65-byte form, so client_id matches the Acurast on-chain
    // pubkey hash convention (Substrate ecdsa::Public is compressed-33).
    // public_key_raw() still returns uncompressed because rcgen / rustls /
    // X.509 SPKI for P-256 all want the uncompressed point.
    let id_bytes: Vec<u8> = match identity_keypair.algorithm() {
        KeyAlgorithm::Ed25519 => {
            anyhow::ensure!(
                identity_pub_raw.len() == 32,
                "Ed25519 identity public_key_raw() returned {} bytes (expected 32)",
                identity_pub_raw.len(),
            );
            identity_pub_raw.clone()
        }
        KeyAlgorithm::EcdsaP256 => {
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&identity_pub_raw)
                .map_err(|e| anyhow::anyhow!("parse identity pubkey for client_id: {e}"))?;
            vk.to_encoded_point(true).as_bytes().to_vec()
        }
    };
    let client_id = hex::encode(&Sha256::digest(&id_bytes)[0..8]);
    let domain = format!("{}.{}", client_id, domain_suffix);
    let url = format!("https://{}:8443", domain);

    let agent_rcgen_key = RcgenRemoteKey::new(Arc::clone(&agent_keypair));

    let mut params = rcgen::CertificateParams::new(vec!["agent".into()])?;
    if let Some(ext_bytes) = cert_extension {
        let content = yasna::construct_der(|writer| {
            writer.write_bytes(ext_bytes);
        });
        params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
            CUSTOM_DATA_EXT_OID,
            content,
        )];
    }
    let agent_cert_der = params.self_signed(&agent_rcgen_key)?.der().to_vec();

    let csr_der = if need_csr {
        let identity_rcgen_key = RcgenRemoteKey::new(Arc::clone(&identity_keypair));
        let mut csr_params = rcgen::CertificateParams::new(vec![domain.clone()])?;
        csr_params.distinguished_name = rcgen::DistinguishedName::new();
        csr_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, domain.clone());
        Some(
            csr_params
                .serialize_request(&identity_rcgen_key)?
                .der()
                .as_ref()
                .to_vec(),
        )
    } else {
        None
    };

    Ok(Connection {
        client_id,
        domain,
        url,
        agent_cert_der,
        agent_keypair,
        identity_keypair,
        csr_der,
    })
}

/// Sign a message with `identity_keypair` and produce a 65-byte recoverable
/// ECDSA P-256 signature (`r || s || v`). The signer's pubkey is encoded
/// SEC1-uncompressed (matches `keypair.public_key_raw()` for P-256), used
/// for the trial-recovery step to pin the correct recovery id.
fn sign_recoverable(identity_keypair: &dyn TunnelKey, msg: &[u8]) -> Result<[u8; 65]> {
    use p256::ecdsa::{Signature, VerifyingKey, recoverable};
    let der = identity_keypair.sign(msg)?;
    let sig = Signature::from_der(&der)
        .map_err(|e| anyhow::anyhow!("parse identity signature DER: {e}"))?;
    // Trial-recovery only matches against the canonical low-s form. Android
    // Keystore's `SHA256withECDSA` can emit high-s signatures, which DER-parse
    // fine but won't recover to the expected pubkey. Normalize defensively;
    // ring-backed signers (rcgen LocalKey) are already low-s, so this is a
    // no-op there.
    let sig = sig.normalize_s().unwrap_or(sig);
    let vk = VerifyingKey::from_sec1_bytes(&identity_keypair.public_key_raw())
        .map_err(|e| anyhow::anyhow!("identity pubkey: {e}"))?;
    let rec = recoverable::Signature::from_trial_recovery(&vk, msg, &sig)
        .map_err(|e| anyhow::anyhow!("trial-recovery for identity signature: {e}"))?;
    let bytes: &[u8] = rec.as_ref();
    let mut out = [0u8; 65];
    if bytes.len() != 65 {
        anyhow::bail!("recoverable signature length {} (expected 65)", bytes.len());
    }
    out.copy_from_slice(bytes);
    Ok(out)
}

async fn h2_ctrl_exchange(
    h2_conn: &mut h2::server::Connection<tokio_rustls::client::TlsStream<TcpStream>, bytes::Bytes>,
    domain: &str,
    identity_keypair: &dyn TunnelKey,
    csr_der: Option<&[u8]>,
    provisioner: Option<Arc<CertProvisioner>>,
    agent_cert_der: &[u8],
) -> Result<Vec<CertificateDer<'static>>> {
    // Step 1: GET /_ctrl/domain — respond with domain
    let (req, mut resp) = h2_conn
        .accept()
        .await
        .ok_or_else(|| anyhow::anyhow!("closed before /_ctrl/domain"))??;
    anyhow::ensure!(req.uri().path() == "/_ctrl/domain");
    let mut send = resp.send_response(http::Response::new(()), false)?;
    send.send_data(bytes::Bytes::from(domain.as_bytes().to_vec()), true)?;

    // Step 2: GET /_ctrl/sig — respond with 65-byte recoverable ECDSA P-256
    // signature over the domain so the server can recover the identity pubkey.
    let (req, mut resp) = h2_conn
        .accept()
        .await
        .ok_or_else(|| anyhow::anyhow!("closed before /_ctrl/sig"))??;
    anyhow::ensure!(req.uri().path() == "/_ctrl/sig");
    let sig = sign_recoverable(identity_keypair, domain.as_bytes())?;
    let mut send = resp.send_response(http::Response::new(()), false)?;
    send.send_data(bytes::Bytes::copy_from_slice(&sig), true)?;

    // Step 3: GET /_ctrl/key_auth — run ACME prepare, respond with key_auth
    let (req, mut resp) = h2_conn
        .accept()
        .await
        .ok_or_else(|| anyhow::anyhow!("closed before /_ctrl/key_auth"))??;
    anyhow::ensure!(req.uri().path() == "/_ctrl/key_auth");

    // Non-ACME path: respond empty and reuse agent cert for tunnel TLS.
    let Some(provisioner) = provisioner else {
        debug!("H2: no provisioner (self-signed path), responding with empty key_auth");
        let mut send = resp.send_response(http::Response::new(()), false)?;
        send.send_data(bytes::Bytes::new(), true)?;
        return Ok(vec![agent_cert_der.to_vec().into()]);
    };

    let cert_pem = match provisioner.prepare(domain).await? {
        PrepareResult::Cached(pem) => {
            debug!("H2: cert cached, responding with empty key_auth");
            let mut send = resp.send_response(http::Response::new(()), false)?;
            send.send_data(bytes::Bytes::new(), true)?;
            pem
        }
        PrepareResult::LeaderChallenge(alpn_pending) => {
            let ka = alpn_pending.key_authorization.clone();
            debug!("H2: leader, building ALPN acceptor for challenge");
            let alpn_acceptor = build_alpn_acceptor(domain, &ka)?;

            // Send key_auth in response body
            let mut send = resp.send_response(http::Response::new(()), false)?;
            send.send_data(bytes::Bytes::from(ka.into_bytes()), true)?;

            // Spawn finalize concurrently
            let csr_der = csr_der
                .ok_or_else(|| anyhow::anyhow!("ACME path requires csr_der"))?
                .to_vec();
            let prov = provisioner.clone();
            let dom = domain.to_string();
            let mut finalize_task =
                tokio::spawn(async move { prov.finalize(&dom, alpn_pending, &csr_der).await });

            // Loop: handle /_ctrl/alpn streams and wait for /_ctrl/done
            loop {
                let (req, mut resp) = h2_conn
                    .accept()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("connection closed during challenge"))??;
                match req.uri().path() {
                    "/_ctrl/alpn" => {
                        debug!("H2: challenge stream received, terminating TLS-ALPN-01");
                        let send = resp.send_response(http::Response::new(()), false)?;
                        let stream = IO::new(
                            H2Recv {
                                r: req.into_body(),
                                buf: bytes::Bytes::new(),
                            },
                            H2Send(send),
                        );
                        let acc = alpn_acceptor.clone();
                        tokio::spawn(async move {
                            let _ = acc.accept(stream).await;
                        });
                    }
                    "/_ctrl/done" => {
                        // Server signals it's done proxying challenges; await finalize
                        let cert_pem = loop {
                            tokio::select! {
                                // Keep handling any last challenge streams
                                inner = h2_conn.accept() => {
                                    if let Some(Ok((inner_req, mut inner_resp))) = inner {
                                        if inner_req.uri().path() == "/_ctrl/alpn" {
                                            let send = inner_resp.send_response(http::Response::new(()), false)?;
                                            let stream = IO::new(
                                                H2Recv { r: inner_req.into_body(), buf: bytes::Bytes::new() },
                                                H2Send(send),
                                            );
                                            let acc = alpn_acceptor.clone();
                                            tokio::spawn(async move { let _ = acc.accept(stream).await; });
                                        }
                                    }
                                }
                                result = &mut finalize_task => {
                                    break result??;
                                }
                            }
                        };
                        resp.send_response(http::Response::builder().status(200).body(())?, true)?;
                        break cert_pem;
                    }
                    path => anyhow::bail!("unexpected ctrl path: {}", path),
                }
            }
        }
        PrepareResult::FollowerChallenge {
            key_authorization,
            mut cert_rx,
        } => {
            let ka = key_authorization;
            debug!("H2: follower, sharing leader's key_auth for ALPN challenge");
            let alpn_acceptor = build_alpn_acceptor(domain, &ka)?;

            // Register pending on the server with the shared key_auth so LE
            // can land on this relay's IP and still validate.
            let mut send = resp.send_response(http::Response::new(()), false)?;
            send.send_data(bytes::Bytes::from(ka.into_bytes()), true)?;

            // Loop: handle /_ctrl/alpn streams and wait for /_ctrl/done; the
            // leader's broadcast on `cert_rx` decides when we have the PEM.
            loop {
                let (req, mut resp) = h2_conn
                    .accept()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("connection closed during challenge"))??;
                match req.uri().path() {
                    "/_ctrl/alpn" => {
                        debug!("H2: challenge stream received (follower), terminating TLS-ALPN-01");
                        let send = resp.send_response(http::Response::new(()), false)?;
                        let stream = IO::new(
                            H2Recv {
                                r: req.into_body(),
                                buf: bytes::Bytes::new(),
                            },
                            H2Send(send),
                        );
                        let acc = alpn_acceptor.clone();
                        tokio::spawn(async move {
                            let _ = acc.accept(stream).await;
                        });
                    }
                    "/_ctrl/done" => {
                        let cert_pem = loop {
                            tokio::select! {
                                inner = h2_conn.accept() => {
                                    if let Some(Ok((inner_req, mut inner_resp))) = inner {
                                        if inner_req.uri().path() == "/_ctrl/alpn" {
                                            let send = inner_resp.send_response(http::Response::new(()), false)?;
                                            let stream = IO::new(
                                                H2Recv { r: inner_req.into_body(), buf: bytes::Bytes::new() },
                                                H2Send(send),
                                            );
                                            let acc = alpn_acceptor.clone();
                                            tokio::spawn(async move { let _ = acc.accept(stream).await; });
                                        }
                                    }
                                }
                                res = cert_rx.changed() => {
                                    res.map_err(|_| anyhow::anyhow!(
                                        "ACME leader for {} dropped before cert issuance",
                                        domain
                                    ))?;
                                    let pem = cert_rx.borrow().clone().ok_or_else(|| {
                                        anyhow::anyhow!(
                                            "ACME leader for {} signalled empty cert",
                                            domain
                                        )
                                    })?;
                                    break pem;
                                }
                            }
                        };
                        resp.send_response(http::Response::builder().status(200).body(())?, true)?;
                        break cert_pem;
                    }
                    path => anyhow::bail!("unexpected ctrl path: {}", path),
                }
            }
        }
    };

    parse_cert_chain_pem(&cert_pem)
}

fn server_name_from_addr(addr: &str) -> Option<String> {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    if host.parse::<std::net::IpAddr>().is_ok() {
        None
    } else {
        Some(host.to_string())
    }
}

fn client_cert_resolver(
    cert: Vec<CertificateDer<'static>>,
    keypair: Arc<dyn TunnelKey>,
) -> Arc<SingleCertAndKey> {
    let signing_key = Arc::new(RustlsRemoteKey::new(keypair));
    Arc::new(SingleCertAndKey::from(CertifiedKey::new(cert, signing_key)))
}

/// Let's Encrypt staging roots, bundled so a client running in `acme_staging`
/// mode can verify a relay whose own cert was issued by LE staging.
/// Source: https://letsencrypt.org/docs/staging-environment/
const LE_STAGING_ROOTS_PEM: &str = concat!(
    include_str!("../certs/letsencrypt-stg-root-x1.pem"),
    "\n",
    include_str!("../certs/letsencrypt-stg-root-x2.pem"),
);

fn ca_roots_client_config(
    cert: Vec<CertificateDer<'static>>,
    keypair: Arc<dyn TunnelKey>,
    acme_staging: bool,
) -> Result<rustls::ClientConfig> {
    // Mozilla CA bundle (`webpki-roots`). Android's `rustls-native-certs`
    // can't reliably load the system trust store on all OS versions — ISRG
    // Root X1 ends up missing on stock-relay devices, causing
    // `invalid peer certificate: UnknownIssuer` for Let's Encrypt-signed
    // relay certs. The Mozilla bundle is pinned at compile time and matches
    // the ACME HTTPS path in `acme.rs`.
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if acme_staging {
        for c in parse_cert_chain_pem(LE_STAGING_ROOTS_PEM)? {
            roots.add(c).ok();
        }
    }
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_cert_resolver(client_cert_resolver(cert, keypair)))
}

async fn connect_quic(
    addr: &str,
    cert: CertificateDer<'static>,
    keypair: Arc<dyn TunnelKey>,
    acme_staging: bool,
) -> Result<quinn::Connection> {
    let (tls_config, sni) = match server_name_from_addr(addr) {
        Some(name) => (
            ca_roots_client_config(vec![cert], keypair, acme_staging)?,
            name,
        ),
        None => (
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_client_cert_resolver(client_cert_resolver(vec![cert], keypair)),
            "localhost".to_string(),
        ),
    };

    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(1000u32.into());
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    ));
    client_config.transport_config(Arc::new(transport));

    let socket_addr = tokio::net::lookup_host(addr)
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve {}", addr))?;

    let endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    Ok(endpoint
        .connect_with(client_config, socket_addr, &sni)?
        .await?)
}

async fn connect_h2(
    addr: &str,
    cert: CertificateDer<'static>,
    keypair: Arc<dyn TunnelKey>,
    acme_staging: bool,
) -> Result<h2::server::Connection<tokio_rustls::client::TlsStream<TcpStream>, bytes::Bytes>> {
    let (tls_config, sni) = match server_name_from_addr(addr) {
        Some(name) => (
            ca_roots_client_config(vec![cert], keypair, acme_staging)?,
            name,
        ),
        None => (
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_client_cert_resolver(client_cert_resolver(vec![cert], keypair)),
            "localhost".to_string(),
        ),
    };

    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;
    let server_name = rustls::pki_types::ServerName::try_from(sni.as_str())
        .map_err(|e| anyhow::anyhow!("invalid server name: {e}"))?
        .to_owned();
    let tls = connector.connect(server_name, tcp).await?;
    Ok(h2::server::Builder::new()
        .initial_window_size(10_000_000)
        .initial_connection_window_size(10_000_000)
        .handshake(tls)
        .await?)
}
