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
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{net::TcpStream, sync::watch};
use tunnel_common::{
    CTRL_REJECT_PATH, CUSTOM_DATA_EXT_OID, H2_DATA_CONN_WINDOW, H2_DATA_STREAM_WINDOW, H2KeepAlive,
    H2Recv, H2Send, IO, MAX_CTRL_FRAME, NoVerify, QUIC_KEEP_ALIVE_INTERVAL, QUIC_MAX_IDLE_TIMEOUT,
    REJECT_UNAUTHORIZED, build_alpn_acceptor, collect_h2_body, ctrl_read, ctrl_write, h2_ping_loop,
};

/// Retry budget of a single connection's reconnect loop. [`Default`] is what
/// production runs with; tests shrink it so the give-up path is reachable in
/// milliseconds instead of a minute.
#[derive(Debug, Clone, Copy)]
pub struct ReconnectPolicy {
    /// Maximum number of *consecutive failed* attempts before the
    /// per-connection task gives up and returns an error. `0` means unlimited.
    pub max_attempts: u32,
    /// First backoff interval; doubles after each failed attempt, capped at
    /// [`ReconnectPolicy::max_backoff`]. Default sequence: 2s, 4s, 8s, 16s,
    /// 32s, then bail.
    pub base_backoff: Duration,
    /// Ceiling the doubling backoff saturates at.
    pub max_backoff: Duration,
    /// Bounds one connect attempt end-to-end (DNS + transport + TLS
    /// handshake) on either transport. Without it a UDP blackhole costs the
    /// full QUIC idle timeout before the H2 fallback even starts.
    pub connect_timeout: Duration,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            base_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(32),
            connect_timeout: Duration::from_secs(10),
        }
    }
}

impl ReconnectPolicy {
    /// Budget for a mobile client: unlimited attempts with a 60s backoff ceiling.
    pub fn mobile() -> Self {
        Self {
            max_attempts: 0,
            base_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(10),
        }
    }

    /// True once `attempts` consecutive failures have used the budget up.
    /// Always false for an unlimited policy (`max_attempts == 0`).
    fn exhausted(&self, attempts: u32) -> bool {
        self.max_attempts != 0 && attempts >= self.max_attempts
    }

    /// Budget as it appears in log lines; `0` reads as "unlimited" rather
    /// than as a budget of zero attempts.
    fn budget_label(&self) -> String {
        if self.max_attempts == 0 {
            "unlimited".to_string()
        } else {
            self.max_attempts.to_string()
        }
    }

    /// Rejects a policy the reconnect loops cannot honour: a zero
    /// `base_backoff`, a `max_backoff` below it, or a zero `connect_timeout`.
    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            !self.base_backoff.is_zero(),
            "reconnect.base_backoff must be greater than zero"
        );
        anyhow::ensure!(
            self.base_backoff <= self.max_backoff,
            "reconnect.base_backoff ({:?}) must not exceed max_backoff ({:?})",
            self.base_backoff,
            self.max_backoff
        );
        anyhow::ensure!(
            !self.connect_timeout.is_zero(),
            "reconnect.connect_timeout must be greater than zero"
        );
        Ok(())
    }
}

/// Transport a connection ended up using. QUIC is tried first unless
/// [`TunnelConfig::force_h2`] is set; a failed QUIC connect falls back to the
/// H2 pool for that attempt, so one `(tag, server_addr)` can report either.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Quic,
    H2,
}

impl Transport {
    /// Wire name of the transport, as reported to consumers.
    pub fn as_str(&self) -> &'static str {
        match self {
            Transport::Quic => "quic",
            Transport::H2 => "h2",
        }
    }
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle of a single logical connection — one `(tag, server_addr)` pair.
/// The H2 pool reports at pool level: its `pool_size` sockets share one
/// `(tag, server_addr)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionEvent {
    /// Control exchange completed on this `(tag, server_addr)` connection;
    /// tunnel traffic can flow.
    Established {
        tag: String,
        server_addr: String,
        transport: Transport,
    },
    /// A previously established connection dropped; its reconnect loop will
    /// retry. Suppressed for a connection torn down by `stop()`, though a
    /// teardown racing a graceful close can still emit one.
    Lost {
        tag: String,
        server_addr: String,
        transport: Transport,
        cause: String,
    },
    /// This connection's task ended for good (reconnect budget exhausted, or
    /// panic). No further retries.
    ///
    /// Carries no `transport`: one connection's task can span both, since a
    /// failed QUIC connect falls back to the H2 pool for that attempt.
    GaveUp {
        tag: String,
        server_addr: String,
        cause: String,
    },
}

/// Hands one event to the configured sink, if there is one. Free-standing
/// because the H2 pool's tasks own a clone of the callback rather than a
/// borrow of `self`.
fn emit_to(sink: &Option<Arc<dyn Fn(ConnectionEvent) + Send + Sync>>, ev: ConnectionEvent) {
    debug!("connection event: {ev:?}");
    if let Some(f) = sink {
        f(ev);
    }
}

/// Pool-level `Established`/`Lost` for the H2 pool: only the 0→1 and 1→0
/// transitions are reported, each under the lock that made it.
struct PoolLiveness {
    state: Mutex<PoolState>,
    /// Fired on every 1→0 transition.
    went_down: tokio::sync::Notify,
    /// Bumped on every 0→1 transition; wakes parked members.
    came_up: watch::Sender<u64>,
    /// Fired once every member is parked with none up.
    all_parked: tokio::sync::Notify,
    size: usize,
    sink: Option<Arc<dyn Fn(ConnectionEvent) + Send + Sync>>,
    tag: String,
    server_addr: String,
}

/// Pool liveness, shared by the members and the session loop under one lock.
#[derive(Default)]
struct PoolState {
    /// Members that have completed the control exchange and not yet dropped.
    live: usize,
    /// Whether the pool was ever up during this session.
    ever_up: bool,
    /// Members waiting for a sibling to come up after a failed attempt.
    parked: usize,
}

impl PoolLiveness {
    fn new(
        sink: Option<Arc<dyn Fn(ConnectionEvent) + Send + Sync>>,
        tag: &str,
        server_addr: &str,
        size: usize,
    ) -> Self {
        Self {
            state: Mutex::new(PoolState::default()),
            went_down: tokio::sync::Notify::new(),
            came_up: watch::Sender::new(0),
            all_parked: tokio::sync::Notify::new(),
            size,
            sink,
            tag: tag.to_string(),
            server_addr: server_addr.to_string(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PoolState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// One pooled connection completed its control exchange.
    fn up(&self) {
        let mut state = self.lock();
        state.live += 1;
        state.ever_up = true;
        if state.live == 1 {
            self.came_up.send_modify(|n| *n += 1);
            emit_to(
                &self.sink,
                ConnectionEvent::Established {
                    tag: self.tag.clone(),
                    server_addr: self.server_addr.clone(),
                    transport: Transport::H2,
                },
            );
        }
    }

    /// One pooled connection that had been up went away. `stopped` suppresses
    /// the event for a pool being torn down on request — that is a shutdown,
    /// not a loss (see [`ConnectionEvent::Lost`] for the race this leaves).
    fn down(&self, cause: String, stopped: bool) {
        let mut state = self.lock();
        state.live = state.live.saturating_sub(1);
        if state.live == 0 {
            if !stopped {
                emit_to(
                    &self.sink,
                    ConnectionEvent::Lost {
                        tag: self.tag.clone(),
                        server_addr: self.server_addr.clone(),
                        transport: Transport::H2,
                        cause,
                    },
                );
            }
            // Signalled on the stopped path too; whichever fires first ends it.
            self.went_down.notify_one();
        }
    }

    /// Parks a member whose attempt failed while no sibling is up. Returns a
    /// receiver that changes when the pool next comes up, or `None` when a
    /// sibling is already up.
    fn park(&self) -> Option<watch::Receiver<u64>> {
        let mut state = self.lock();
        if state.live > 0 {
            return None;
        }
        state.parked += 1;
        if state.parked >= self.size {
            self.all_parked.notify_one();
        }
        Some(self.came_up.subscribe())
    }

    fn unpark(&self) {
        let mut state = self.lock();
        state.parked = state.parked.saturating_sub(1);
    }

    /// Resolves once every member is parked, i.e. none could come up.
    async fn wait_all_parked(&self) {
        self.all_parked.notified().await;
    }

    /// Whether the pool ever came up during this session.
    fn ever_up(&self) -> bool {
        self.lock().ever_up
    }

    /// Resolves once the pool has gone from up to fully down.
    async fn wait_down(&self) {
        self.went_down.notified().await;
    }
}

/// Latest relay rejection seen by one connection's current session; the
/// reconnect loop takes it after each session.
type RejectSlot = watch::Sender<Option<String>>;

/// How one session — a QUIC connection or an H2 pool run — ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionOutcome {
    /// `stop()` was called. Terminal: the connection task returns `Ok(())`.
    Stopped,
    /// The session carried traffic and then went down. Resets the retry budget.
    Lost,
    /// Nothing ever completed the control exchange. Counts as one failed attempt.
    NeverUp,
}

/// Attempts-and-backoff bookkeeping shared by both transports of one connection.
struct RetryState {
    policy: ReconnectPolicy,
    /// Consecutive attempts that never carried traffic.
    attempts: u32,
    backoff: Duration,
}

impl RetryState {
    fn new(policy: ReconnectPolicy) -> Self {
        Self {
            backoff: policy.base_backoff,
            attempts: 0,
            policy,
        }
    }

    /// Number the attempt about to start carries in the logs.
    fn next_attempt(&self) -> u32 {
        self.attempts.saturating_add(1)
    }

    /// One attempt the relay rejected: counts as failed and backs off the most.
    fn rejected(&mut self) -> u32 {
        self.backoff = self.policy.max_backoff;
        self.failed()
    }

    /// A session that carried traffic went down; clears the budget.
    fn recovered(&mut self) {
        self.attempts = 0;
        self.backoff = self.policy.base_backoff;
    }

    /// One attempt that never carried traffic; returns the running count.
    fn failed(&mut self) -> u32 {
        self.attempts = self.attempts.saturating_add(1);
        self.attempts
    }

    fn exhausted(&self) -> bool {
        self.policy.exhausted(self.attempts)
    }

    /// Sleeps the current backoff, then doubles it. `false` means `stop()` was
    /// signalled and the caller must not loop again.
    async fn wait(&mut self, stop: &mut watch::Receiver<bool>) -> bool {
        tokio::select! {
            _ = tokio::time::sleep(self.backoff) => {}
            _ = stop.wait_for(|stopped| *stopped) => return false,
        }
        self.backoff = self.backoff.saturating_mul(2).min(self.policy.max_backoff);
        true
    }
}

/// Identity of the connection a finished task was driving, `"?"` when the task
/// never registered one.
fn owner_of(
    owners: &mut std::collections::HashMap<tokio::task::Id, (String, String)>,
    id: tokio::task::Id,
) -> (String, String) {
    owners.remove(&id).unwrap_or_else(|| {
        error!("tunnel connection task {id} ended without a registered owner");
        debug_assert!(
            false,
            "every spawned connection task must register an owner"
        );
        ("?".to_string(), "?".to_string())
    })
}

/// Log prefix and [`ConnectionEvent`] `tag` for the two connections the client
/// opens per relay address: the ACME-backed primary and the self-signed
/// secondary.
const PRIMARY_TAG: &str = "PRI";
const SECONDARY_TAG: &str = "SEC";

/// Bounds the two setup steps of a forwarded stream: the tunnel-side TLS
/// handshake and the connection to the local target. An established stream is
/// never timed out.
const PIPE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const PIPE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Bounds the wait for the relay to accept a QUIC agent; above the relay's own
/// 30s authentication budget.
const QUIC_ACCEPT_TIMEOUT: Duration = Duration::from_secs(40);

/// Closes the endpoint when dropped, so peers get a close frame rather than a
/// silent timeout, and the UDP socket is released promptly.
struct CloseOnDrop(quinn::Endpoint);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.close(quinn::VarInt::from_u32(0), b"tunnel stopped");
    }
}

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
    /// Called for every [`ConnectionEvent`]. Runs inline on the connection's
    /// task, so it must not block.
    pub on_connection_event: Option<Arc<dyn Fn(ConnectionEvent) + Send + Sync>>,
    /// Primary connection identity. Drives the ACME-issued tunnel cert.
    pub primary_identity: TunnelIdentityConfig,
    /// Retry budget for each connection's reconnect loop.
    pub reconnect: ReconnectPolicy,
    /// PING liveness for pooled H2 connections. The QUIC path uses the
    /// transport's own keep-alive instead.
    pub h2_keepalive: H2KeepAlive,
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
    /// Level-triggered stop signal: a subscriber that arrives after `stop()`
    /// still sees it.
    stop_tx: watch::Sender<bool>,
}

struct Connection {
    client_id: String,
    domain: String,
    url: String,
    /// Self-signed cert presented during mTLS to the server. Signed by
    /// `agent_keypair`. On the secondary connection this cert is also reused
    /// to terminate user-facing tunnel TLS.
    agent_cert: CertificateDer<'static>,
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
    /// Client TLS for both transports, built once for every attempt this
    /// connection makes.
    tls: Arc<ClientTls>,
}

impl TunnelClient {
    /// Creates a new client. Synchronous — no network operations.
    /// `client_id` and `url` are available immediately.
    pub fn new(config: TunnelConfig) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        if config.primary_identity.keypair.algorithm() != crate::key::KeyAlgorithm::EcdsaP256 {
            anyhow::bail!("primary_identity keypair must be ECDSA P-256");
        }
        if let Some(sec) = &config.self_signed_identity {
            if sec.keypair.algorithm() != crate::key::KeyAlgorithm::EcdsaP256 {
                anyhow::bail!("self_signed_identity keypair must be ECDSA P-256");
            }
        }
        if config.server_addrs.is_empty() {
            anyhow::bail!("server_addrs must contain at least one relay address");
        }
        if config.pool_size == 0 {
            anyhow::bail!("pool_size must be at least 1");
        }
        config.reconnect.validate()?;
        config.h2_keepalive.validate()?;

        let primary_agent_keypair = match &config.self_signed_identity {
            Some(sec) => Arc::clone(&sec.keypair),
            None => Arc::clone(&config.primary_identity.keypair),
        };
        let primary = build_connection(
            primary_agent_keypair,
            Arc::clone(&config.primary_identity.keypair),
            &config.domain_suffix,
            config.primary_identity.cert_extension.as_deref(),
            config.acme_staging,
            /* need_csr */ true,
        )?;
        let secondary = match &config.self_signed_identity {
            Some(sec) => Some(build_connection(
                Arc::clone(&sec.keypair),
                Arc::clone(&sec.keypair),
                &config.domain_suffix,
                sec.cert_extension.as_deref(),
                config.acme_staging,
                /* need_csr */ false,
            )?),
            None => None,
        };

        Ok(Self {
            config,
            primary,
            secondary,
            stop_tx: watch::Sender::new(false),
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
        self.stop_tx.send_replace(true);
    }

    /// True once `stop()` has been called.
    fn stopped(&self) -> bool {
        *self.stop_tx.borrow()
    }

    /// Publish a connection lifecycle event to the configured sink.
    fn emit(&self, ev: ConnectionEvent) {
        emit_to(&self.config.on_connection_event, ev);
    }

    /// Runs the tunnel. Resolves when `stop()` is called.
    /// Must be called on an `Arc<TunnelClient>` (the call site already uses Arc).
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let provisioner = Arc::new(CertProvisioner::new(
            self.config.acme_email.as_deref(),
            self.config.acme_staging,
            &self.config.acme_creds_path,
            self.config.on_cert_issued.clone(),
        ));

        if let Some(pem) = &self.config.cert_pem {
            let public_key = self.primary.identity_keypair.public_key_raw();
            provisioner
                .seed(&self.primary.domain, &public_key, pem.clone())
                .await;
        }

        let mut tasks = tokio::task::JoinSet::new();
        // Task id → the connection it drives, so even a panicking task can be
        // named in a `GaveUp`.
        let mut owners: std::collections::HashMap<tokio::task::Id, (String, String)> =
            std::collections::HashMap::new();
        for server_addr in &self.config.server_addrs {
            // Primary connection (ACME-backed tunnel cert). Forwards to local_addr.
            {
                let server_addr = server_addr.clone();
                let provisioner = provisioner.clone();
                let this = Arc::clone(&self);
                let owner_addr = server_addr.clone();
                let handle = tasks.spawn(async move {
                    let target = &this.config.local_addr;
                    this.connection_run(
                        &this.primary,
                        &server_addr,
                        Some(provisioner),
                        PRIMARY_TAG,
                        target,
                    )
                    .await
                });
                owners.insert(handle.id(), (PRIMARY_TAG.to_string(), owner_addr));
            }
            // Secondary connection (self-signed tunnel cert, no ACME). Forwards to
            // secondary_local_addr when set, else falls back to local_addr.
            if self.secondary.is_some() {
                let server_addr = server_addr.clone();
                let this = Arc::clone(&self);
                let owner_addr = server_addr.clone();
                let handle = tasks.spawn(async move {
                    let sec = this.secondary.as_ref().expect("secondary present");
                    let target = this
                        .config
                        .secondary_local_addr
                        .as_deref()
                        .unwrap_or(&this.config.local_addr);
                    this.connection_run(sec, &server_addr, None, SECONDARY_TAG, target)
                        .await
                });
                owners.insert(handle.id(), (SECONDARY_TAG.to_string(), owner_addr));
            }
        }

        let mut stop = self.stop_tx.subscribe();
        let mut all_gave_up = false;
        let mut last_err: Option<anyhow::Error> = None;
        while !self.stopped() {
            tokio::select! {
                _ = stop.changed() => break,
                joined = tasks.join_next_with_id() => match joined {
                    None => {
                        all_gave_up = true;
                        break;
                    }
                    Some(Ok((id, Err(e)))) => {
                        warn!("tunnel connection ended: {e:#}");
                        let (tag, addr) = owner_of(&mut owners, id);
                        self.emit(ConnectionEvent::GaveUp {
                            tag,
                            server_addr: addr,
                            cause: format!("{e:#}"),
                        });
                        last_err = Some(e);
                    }
                    Some(Err(e)) if e.is_panic() => {
                        error!("tunnel connection panicked: {e}");
                        let (tag, addr) = owner_of(&mut owners, e.id());
                        self.emit(ConnectionEvent::GaveUp {
                            tag,
                            server_addr: addr,
                            cause: format!("tunnel connection panicked: {e}"),
                        });
                        last_err = Some(anyhow::anyhow!("tunnel connection panicked: {e}"));
                    }
                    // A task that returned `Ok` stopped on request, not for
                    // good: no `GaveUp`. Same for a cancelled one.
                    Some(Ok((id, Ok(())))) => {
                        owners.remove(&id);
                    }
                    Some(Err(e)) => {
                        owners.remove(&e.id());
                    }
                },
            }
        }
        if all_gave_up {
            return Err(match last_err {
                Some(cause) => cause.context("all tunnel connections gave up"),
                None => anyhow::anyhow!("all tunnel connections gave up"),
            });
        }
        Ok(())
    }

    /// Drives a single connection (either primary or secondary) to one server.
    /// `provisioner = Some(_)` enables the ACME flow; `None` uses the pre-built
    /// self-signed agent cert for tunnel TLS termination.
    ///
    /// One reconnect loop covers both transports: a failed QUIC attempt falls
    /// back to a single H2 pool session, and both draw on one [`RetryState`].
    async fn connection_run(
        &self,
        conn_m: &Connection,
        server_addr: &str,
        provisioner: Option<Arc<CertProvisioner>>,
        tag: &str,
        target_addr: &str,
    ) -> Result<()> {
        let mut stop = self.stop_tx.subscribe();
        let mut retry = RetryState::new(self.config.reconnect);
        let rejected: RejectSlot = watch::Sender::new(None);
        // One UDP socket for every QUIC attempt, rebound lazily, closed on drop.
        let mut endpoint: Option<CloseOnDrop> = None;

        if self.config.force_h2 {
            info!(
                "H2[{}/{}]: FORCE_HTTP2 set, skipping QUIC",
                tag, server_addr
            );
        }

        while !self.stopped() {
            let outcome = match self
                .quic_attempt(
                    &mut endpoint,
                    &retry,
                    &rejected,
                    conn_m,
                    server_addr,
                    &provisioner,
                    tag,
                    target_addr,
                )
                .await
            {
                Some(outcome) => outcome,
                None => {
                    // Release the socket: the H2 session owns this attempt.
                    endpoint = None;
                    self.h2_pool(
                        conn_m,
                        server_addr,
                        provisioner.clone(),
                        tag,
                        target_addr,
                        &rejected,
                    )
                    .await
                }
            };

            if outcome == SessionOutcome::Stopped {
                return Ok(());
            }
            if let Some(reason) = rejected.send_replace(None) {
                let attempts = retry.rejected();
                if retry.exhausted() {
                    anyhow::bail!(
                        "TUNNEL[{tag}/{server_addr}]: giving up after {attempts} failed attempts, \
                         last one rejected by relay: {reason}"
                    );
                }
            } else if outcome == SessionOutcome::Lost {
                retry.recovered();
            } else {
                let attempts = retry.failed();
                if retry.exhausted() {
                    anyhow::bail!(
                        "TUNNEL[{}/{}]: giving up after {} failed attempts",
                        tag,
                        server_addr,
                        attempts
                    );
                }
            }

            info!(
                "TUNNEL[{}/{}]: reconnecting in {:?} (next attempt {}/{})",
                tag,
                server_addr,
                retry.backoff,
                retry.next_attempt(),
                retry.policy.budget_label()
            );
            if !retry.wait(&mut stop).await {
                return Ok(());
            }
        }
        Ok(())
    }

    /// One QUIC attempt: binds the endpoint if it is not bound yet, then runs a
    /// session on it. `None` means QUIC did not take this attempt and the
    /// caller owes it an H2 fallback.
    #[allow(clippy::too_many_arguments)]
    async fn quic_attempt(
        &self,
        endpoint: &mut Option<CloseOnDrop>,
        retry: &RetryState,
        rejected: &RejectSlot,
        conn_m: &Connection,
        server_addr: &str,
        provisioner: &Option<Arc<CertProvisioner>>,
        tag: &str,
        target_addr: &str,
    ) -> Option<SessionOutcome> {
        if self.config.force_h2 {
            return None;
        }
        if endpoint.is_none() {
            // A bind failure falls back to H2 for this attempt, not fatally.
            match quinn::Endpoint::client(std::net::SocketAddr::from(([0, 0, 0, 0], 0))) {
                Ok(ep) => *endpoint = Some(CloseOnDrop(ep)),
                Err(e) => warn!(
                    "QUIC[{tag}/{server_addr}]: UDP bind failed ({e}), \
                     falling back to H2 for this attempt"
                ),
            }
        }
        let ep = endpoint.as_ref()?;
        info!(
            "QUIC[{}/{}]: connecting (attempt {}/{})",
            tag,
            server_addr,
            retry.next_attempt(),
            retry.policy.budget_label()
        );
        self.quic_session(
            &ep.0,
            rejected,
            conn_m,
            server_addr,
            provisioner.clone(),
            tag,
            target_addr,
        )
        .await
    }

    /// One QUIC session: connect, then serve streams until the connection ends.
    /// `None` means the connect failed and the caller owes this attempt an H2
    /// fallback.
    #[allow(clippy::too_many_arguments)]
    async fn quic_session(
        &self,
        endpoint: &quinn::Endpoint,
        rejected: &RejectSlot,
        conn_m: &Connection,
        server_addr: &str,
        provisioner: Option<Arc<CertProvisioner>>,
        tag: &str,
        target_addr: &str,
    ) -> Option<SessionOutcome> {
        let connected = connect_within(
            self.config.reconnect.connect_timeout,
            server_addr,
            connect_quic(endpoint, server_addr, &conn_m.tls),
        )
        .await;
        let conn = match connected {
            Err(e) => {
                warn!(
                    "QUIC[{}/{}]: connection failed ({}), falling back to H2 for this attempt",
                    tag, server_addr, e
                );
                return None;
            }
            Ok(conn) => conn,
        };
        info!("QUIC[{}/{}]: connected", tag, server_addr);
        let ctrl_completed = Arc::new(AtomicBool::new(false));
        let ended = self
            .quic_loop(
                rejected,
                conn_m,
                conn,
                server_addr,
                provisioner,
                tag,
                target_addr,
                Arc::clone(&ctrl_completed),
            )
            .await;
        let cause = match &ended {
            Err(e) => {
                warn!("QUIC[{}/{}]: error ({})", tag, server_addr, e);
                format!("{e:#}")
            }
            Ok(()) => "connection closed".to_string(),
        };
        if self.stopped() {
            return Some(SessionOutcome::Stopped);
        }
        if ctrl_completed.load(Ordering::SeqCst) {
            // Only a connection that was *up* can be lost.
            self.emit(ConnectionEvent::Lost {
                tag: tag.to_string(),
                server_addr: server_addr.to_string(),
                transport: Transport::Quic,
                cause,
            });
            Some(SessionOutcome::Lost)
        } else {
            Some(SessionOutcome::NeverUp)
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn quic_loop(
        &self,
        rejected: &RejectSlot,
        conn_m: &Connection,
        conn: quinn::Connection,
        server_addr: &str,
        provisioner: Option<Arc<CertProvisioner>>,
        tag: &str,
        target_addr: &str,
        ctrl_completed: Arc<AtomicBool>,
    ) -> Result<()> {
        let result = self
            .quic_loop_inner(
                conn_m,
                &conn,
                server_addr,
                provisioner,
                tag,
                target_addr,
                ctrl_completed,
            )
            .await;
        if let Some(quinn::ConnectionError::ApplicationClosed(close)) = conn.close_reason() {
            if close.error_code == quinn::VarInt::from_u32(REJECT_UNAUTHORIZED) {
                let reason = String::from_utf8_lossy(&close.reason).into_owned();
                warn!("QUIC[{tag}/{server_addr}]: rejected by relay: {reason}");
                rejected.send_replace(Some(reason));
            }
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn quic_loop_inner(
        &self,
        conn_m: &Connection,
        conn: &quinn::Connection,
        server_addr: &str,
        provisioner: Option<Arc<CertProvisioner>>,
        tag: &str,
        target_addr: &str,
        ctrl_completed: Arc<AtomicBool>,
    ) -> Result<()> {
        let mut stop = self.stop_tx.subscribe();

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
                vec![conn_m.agent_cert.clone()]
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
                        let mut finalize = tokio::task::JoinSet::new();
                        finalize.spawn(
                            async move { prov.finalize(&dom, alpn_pending, &csr_der).await },
                        );
                        let mut challenges = tokio::task::JoinSet::new();

                        let cert_pem = quic_serve_challenges_until(
                            conn,
                            &alpn_acceptor,
                            &mut challenges,
                            tag,
                            "",
                            async {
                                match finalize.join_next().await {
                                    Some(r) => Ok(r??),
                                    None => anyhow::bail!(
                                        "ACME finalize task for {} disappeared",
                                        conn_m.domain
                                    ),
                                }
                            },
                        )
                        .await?;

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
                        // the issued cert (or the leader's order fails). Owned
                        // in a `JoinSet` so they die with this frame.
                        let mut challenges = tokio::task::JoinSet::new();
                        let cert_pem = quic_serve_challenges_until(
                            conn,
                            &alpn_acceptor,
                            &mut challenges,
                            tag,
                            " (follower)",
                            async {
                                cert_rx.changed().await.map_err(|_| {
                                    anyhow::anyhow!(
                                        "ACME leader for {} dropped before cert issuance",
                                        conn_m.domain
                                    )
                                })?;
                                cert_rx.borrow().clone().ok_or_else(|| {
                                    anyhow::anyhow!(
                                        "ACME leader for {} signalled empty cert",
                                        conn_m.domain
                                    )
                                })
                            },
                        )
                        .await?;

                        // Signal done to server (server removes from pending_alpn)
                        ctrl_write(&mut ctrl_send, b"done").await?;
                        cert_pem
                    }
                };
                parse_cert_chain_pem(&cert_pem)?
            }
        };

        // The relay finishes the control stream once it accepts this agent; a
        // rejection closes the connection instead.
        tokio::time::timeout(QUIC_ACCEPT_TIMEOUT, ctrl_recv.read_to_end(MAX_CTRL_FRAME))
            .await
            .map_err(|_| {
                anyhow::anyhow!("relay did not accept within {QUIC_ACCEPT_TIMEOUT:?}")
            })??;
        drop((ctrl_send, ctrl_recv));

        // User-TLS keypair must match the cert chain: on the ACME path the
        // chain belongs to the identity key (CSR was signed by it); without
        // ACME we reuse the agent cert + agent key.
        let user_tls_keypair = if provisioner_was_some {
            Arc::clone(&conn_m.identity_keypair)
        } else {
            Arc::clone(&conn_m.agent_keypair)
        };
        // Before the session counts as up: a session that cannot terminate
        // tunnel TLS never served traffic.
        let acceptor = build_tls_acceptor(user_tls_keypair, tunnel_certs)?;

        ctrl_completed.store(true, Ordering::SeqCst);
        self.emit(ConnectionEvent::Established {
            tag: tag.to_string(),
            server_addr: server_addr.to_string(),
            transport: Transport::Quic,
        });
        info!(
            "QUIC[{}/{}]: tunnel ready at {}",
            tag, server_addr, conn_m.url
        );
        let local_addr = target_addr.to_string();
        let mut pipes = tokio::task::JoinSet::new();

        if self.stopped() {
            return Ok(());
        }

        loop {
            tokio::select! {
                res = conn.accept_bi() => match res {
                    Ok((send, recv)) => {
                        debug!("QUIC[{}]: new tunnel stream, forwarding to {}", tag, local_addr);
                        pipes.spawn(pipe(acceptor.clone(), IO::new(recv, send), local_addr.clone()));
                    }
                    // Surfaced as the `Lost` cause, carrying the close reason.
                    Err(e) => return Err(e.into()),
                },
                // Reaps finished forwards so the set does not grow for the life
                // of the connection.
                _ = pipes.join_next(), if !pipes.is_empty() => {}
                _ = stop.changed() => return Ok(()),
            }
        }
    }

    /// One H2 pool session: brings `pool_size` members up and runs until the pool
    /// goes fully down, every member's attempt has ended, or `stop()`.
    async fn h2_pool(
        &self,
        conn_m: &Connection,
        server_addr: &str,
        provisioner: Option<Arc<CertProvisioner>>,
        tag: &str,
        target_addr: &str,
        rejected: &RejectSlot,
    ) -> SessionOutcome {
        info!(
            "H2[{}/{}]: starting pool of {} connections",
            tag, server_addr, self.config.pool_size
        );
        let mut tasks = tokio::task::JoinSet::new();
        // Shared by every pooled task: the pool is one logical connection, so
        // `Established`/`Lost` track whether *any* member is up, not each one.
        let live = Arc::new(PoolLiveness::new(
            self.config.on_connection_event.clone(),
            tag,
            server_addr,
            self.config.pool_size,
        ));
        let shared = Arc::new(H2Shared {
            tag: tag.to_string(),
            server_addr: server_addr.to_string(),
            local_addr: target_addr.to_string(),
            url: conn_m.url.clone(),
            domain: conn_m.domain.clone(),
            agent_cert: conn_m.agent_cert.clone(),
            agent_keypair: Arc::clone(&conn_m.agent_keypair),
            identity_keypair: Arc::clone(&conn_m.identity_keypair),
            csr_der: conn_m.csr_der.clone(),
            provisioner,
            tls: Arc::clone(&conn_m.tls),
            policy: self.config.reconnect,
            keepalive: self.config.h2_keepalive,
            rejected: rejected.clone(),
        });
        for i in 0..self.config.pool_size {
            let pooled = H2Pooled {
                index: i,
                shared: Arc::clone(&shared),
                live: Arc::clone(&live),
                stop: self.stop_tx.subscribe(),
            };
            tasks.spawn(pooled.drive());
        }

        let mut stop = self.stop_tx.subscribe();
        let mut rejection = rejected.subscribe();
        loop {
            tokio::select! {
                _ = stop.wait_for(|stopped| *stopped) => {
                    info!("H2[{}/{}]: shutting down pool", tag, server_addr);
                    return SessionOutcome::Stopped;
                }
                _ = rejection.wait_for(|r| r.is_some()) => return SessionOutcome::NeverUp,
                _ = live.wait_down() => {
                    warn!(
                        "H2[{}/{}]: pool is fully down, ending the session",
                        tag, server_addr
                    );
                    return SessionOutcome::Lost;
                }
                _ = live.wait_all_parked() => {
                    if live.ever_up() {
                        warn!("H2[{}/{}]: pool drained after being up", tag, server_addr);
                        return SessionOutcome::Lost;
                    }
                    warn!(
                        "H2[{}/{}]: all {} pooled connections failed to come up",
                        tag,
                        server_addr,
                        self.config.pool_size
                    );
                    return SessionOutcome::NeverUp;
                }
                joined = tasks.join_next() => {
                    if joined.is_none() {
                        // Every member has stopped trying.
                        if live.ever_up() {
                            warn!("H2[{}/{}]: pool drained after being up", tag, server_addr);
                            return SessionOutcome::Lost;
                        }
                        warn!(
                            "H2[{}/{}]: all {} pooled connections failed to come up",
                            tag,
                            server_addr,
                            self.config.pool_size
                        );
                        return SessionOutcome::NeverUp;
                    }
                }
            }
        }
    }
}

/// Everything one pooled H2 connection needs, cloned out of `&self` and the
/// `Connection` once per pool: `h2_pool` holds `&self`, not `Arc<Self>`, so
/// nothing can be borrowed into a `'static` task.
struct H2Shared {
    tag: String,
    server_addr: String,
    local_addr: String,
    url: String,
    domain: String,
    agent_cert: CertificateDer<'static>,
    agent_keypair: Arc<dyn TunnelKey>,
    identity_keypair: Arc<dyn TunnelKey>,
    csr_der: Option<Vec<u8>>,
    provisioner: Option<Arc<CertProvisioner>>,
    tls: Arc<ClientTls>,
    policy: ReconnectPolicy,
    keepalive: H2KeepAlive,
    /// Where a member records a relay rejection; ends the pool session.
    rejected: RejectSlot,
}

/// One member of an H2 pool.
struct H2Pooled {
    /// Position in the pool. Log-only — every member shares one identity.
    index: usize,
    shared: Arc<H2Shared>,
    live: Arc<PoolLiveness>,
    stop: watch::Receiver<bool>,
}

impl H2Pooled {
    /// Log prefix naming the relay and this member: `H2[tag/server_addr#index]`.
    fn prefix(&self) -> String {
        format!(
            "H2[{}/{}#{}]",
            self.shared.tag, self.shared.server_addr, self.index
        )
    }

    /// Connect, control exchange, serve streams, repeat. After a failed attempt
    /// with no sibling up, parks until one comes up; the pool ends the session
    /// once every member is parked.
    async fn drive(mut self) {
        let policy = self.shared.policy;
        let mut backoff = policy.base_backoff;
        loop {
            debug!("{}: connecting", self.prefix());
            let served = self.attempt().await;
            if served {
                backoff = policy.base_backoff;
            } else if let Some(mut came_up) = self.live.park() {
                debug!(
                    "{}: attempt failed with no live sibling, waiting for one",
                    self.prefix()
                );
                let woke = tokio::select! {
                    r = came_up.changed() => r.is_ok(),
                    _ = self.stop.wait_for(|stopped| *stopped) => false,
                };
                self.live.unpark();
                if !woke {
                    return;
                }
            }
            if self.stopped() {
                return;
            }
            debug!("{}: retrying in {:?}", self.prefix(), backoff);
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {}
                _ = self.stop.wait_for(|stopped| *stopped) => return,
            }
            backoff = backoff.saturating_mul(2).min(policy.max_backoff);
        }
    }

    /// One connect-and-serve pass. Returns whether the control exchange
    /// completed, which is what decides whether this counted as a failed
    /// attempt against the retry budget.
    async fn attempt(&self) -> bool {
        let shared = &self.shared;
        let prefix = self.prefix();
        let connected = connect_within(
            shared.policy.connect_timeout,
            &shared.server_addr,
            connect_h2(&shared.server_addr, &shared.tls),
        )
        .await;
        let (mut h2, ping_pong) = match connected {
            Err(e) => {
                warn!("{prefix}: connection failed: {e}");
                return false;
            }
            Ok(h2) => h2,
        };
        info!("{prefix}: connected");

        // Pinned across the control exchange and the accept loop below, which
        // are what drive the connection the pings travel on. It resolves only
        // when the relay stops answering.
        let keepalive = shared.keepalive;
        let ping = async move {
            match ping_pong {
                Some(pp) => h2_ping_loop(pp, keepalive).await,
                None => std::future::pending().await,
            }
        };
        tokio::pin!(ping);

        let provisioner_was_some = shared.provisioner.is_some();
        let exchanged = tokio::select! {
            r = h2_ctrl_exchange(
                &mut h2,
                &shared.domain,
                shared.identity_keypair.as_ref(),
                shared.csr_der.as_deref(),
                shared.provisioner.clone(),
                &shared.agent_cert,
            ) => r,
            cause = &mut ping => Err(anyhow::anyhow!(cause)),
        };
        let tunnel_certs = match exchanged {
            Err(e) => {
                match e.downcast_ref::<RelayRejected>() {
                    Some(rejected) => {
                        warn!("{prefix}: rejected by relay: {}", rejected.0);
                        shared.rejected.send_replace(Some(rejected.0.clone()));
                    }
                    None => warn!("{prefix}: control exchange failed: {e}"),
                }
                return false;
            }
            Ok(certs) => certs,
        };

        // User-TLS keypair must match the cert chain, same as the QUIC path.
        let user_tls_keypair = if provisioner_was_some {
            Arc::clone(&shared.identity_keypair)
        } else {
            Arc::clone(&shared.agent_keypair)
        };
        // Before the member counts as up: a member that cannot terminate tunnel
        // TLS never served traffic.
        let acceptor = match build_tls_acceptor(user_tls_keypair, tunnel_certs) {
            Err(e) => {
                error!("{prefix}: failed to build TLS acceptor: {e}");
                return false;
            }
            Ok(acceptor) => acceptor,
        };
        info!("{prefix}: tunnel ready at {}", shared.url);
        self.live.up();

        // Owned for the same reason as the QUIC path: dropping this loop
        // reclaims the forwards it started.
        let mut pipes = tokio::task::JoinSet::new();
        let cause = loop {
            let accepted = tokio::select! {
                accepted = h2.accept() => accepted,
                cause = &mut ping => break cause,
            };
            let Some(Ok((req, mut resp))) = accepted else {
                break "connection dropped".to_string();
            };
            reap(&mut pipes);
            debug!(
                "{prefix}: new tunnel stream, forwarding to {}",
                shared.local_addr
            );
            if let Ok(send) = resp.send_response(http::Response::new(()), false) {
                pipes.spawn(pipe(
                    acceptor.clone(),
                    IO::new(H2Recv::new(req.into_body()), H2Send(send)),
                    shared.local_addr.clone(),
                ));
            }
        };
        warn!("{prefix}: {cause}, reconnecting");
        self.live.down(cause, self.stopped());
        true
    }

    /// Whether the tunnel has been asked to stop. Read, not awaited: see
    /// [`ConnectionEvent::Lost`] for what that leaves racy.
    fn stopped(&self) -> bool {
        *self.stop.borrow()
    }
}

/// Forwards one tunnel stream to `target` until either side closes. Carries no
/// stop signal: the caller owns the future and drops it to end the forward.
async fn pipe(acceptor: tokio_rustls::TlsAcceptor, tunnel: IO, target: String) {
    let mut tls = match tokio::time::timeout(PIPE_HANDSHAKE_TIMEOUT, acceptor.accept(tunnel)).await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return debug!("pipe: TLS accept failed: {}", e),
        Err(_) => {
            return warn!(
                "pipe: TLS handshake timed out after {:?}",
                PIPE_HANDSHAKE_TIMEOUT
            );
        }
    };
    let mut local =
        match tokio::time::timeout(PIPE_CONNECT_TIMEOUT, TcpStream::connect(&target)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return error!("pipe: connect to {} failed: {}", target, e),
            Err(_) => {
                return warn!(
                    "pipe: connect to {} timed out after {:?}",
                    target, PIPE_CONNECT_TIMEOUT
                );
            }
        };
    let _ = tokio::io::copy_bidirectional(&mut tls, &mut local).await;
}

/// Terminates one TLS-ALPN-01 challenge stream on behalf of the ACME
/// validator.
async fn serve_alpn_challenge(acceptor: tokio_rustls::TlsAcceptor, stream: IO) {
    match tokio::time::timeout(PIPE_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => debug!("ALPN challenge: TLS accept failed: {}", e),
        Err(_) => warn!(
            "ALPN challenge: TLS handshake timed out after {:?}",
            PIPE_HANDSHAKE_TIMEOUT
        ),
    }
}

/// Drops the tasks of a long-lived set that have already finished.
fn reap(set: &mut tokio::task::JoinSet<()>) {
    while set.try_join_next().is_some() {}
}

/// Reaps finished challenge tasks, then serves `stream` in the same set.
fn spawn_challenge(
    set: &mut tokio::task::JoinSet<()>,
    acceptor: &tokio_rustls::TlsAcceptor,
    stream: IO,
) {
    reap(set);
    set.spawn(serve_alpn_challenge(acceptor.clone(), stream));
}

/// Serves ALPN challenge streams off a QUIC connection until `done` yields the
/// cert PEM. `role` distinguishes the leader's log line from the follower's.
async fn quic_serve_challenges_until<F>(
    conn: &quinn::Connection,
    acceptor: &tokio_rustls::TlsAcceptor,
    challenges: &mut tokio::task::JoinSet<()>,
    tag: &str,
    role: &str,
    done: F,
) -> Result<String>
where
    F: std::future::Future<Output = Result<String>>,
{
    tokio::pin!(done);
    loop {
        tokio::select! {
            res = conn.accept_bi() => match res {
                Ok((send, recv)) => {
                    debug!("QUIC[{tag}]: challenge stream received{role}, terminating TLS-ALPN-01");
                    spawn_challenge(challenges, acceptor, IO::new(recv, send));
                }
                Err(e) => return Err(e.into()),
            },
            pem = &mut done => return pem,
        }
    }
}

/// Serves `/_ctrl/alpn` streams off an H2 connection until `done` yields the
/// cert PEM. `what` names what the wait was for.
async fn h2_serve_challenges_until<F>(
    h2_conn: &mut H2Conn,
    acceptor: &tokio_rustls::TlsAcceptor,
    challenges: &mut tokio::task::JoinSet<()>,
    domain: &str,
    what: &str,
    done: F,
) -> Result<String>
where
    F: std::future::Future<Output = Result<String>>,
{
    tokio::pin!(done);
    loop {
        tokio::select! {
            // A closed connection is ready forever, so it must end the loop
            // instead of spinning it.
            inner = h2_conn.accept() => match inner {
                None => anyhow::bail!("H2: connection closed while awaiting {what} for {domain}"),
                Some(Err(e)) => {
                    return Err(anyhow::Error::new(e)
                        .context(format!("H2: connection lost while awaiting {what}")));
                }
                Some(Ok((req, resp))) => {
                    let (req, mut resp) = check_reject(req, resp).await?;
                    if req.uri().path() == "/_ctrl/alpn" {
                        let send = resp.send_response(http::Response::new(()), false)?;
                        let stream = IO::new(H2Recv::new(req.into_body()), H2Send(send));
                        spawn_challenge(challenges, acceptor, stream);
                    }
                }
            },
            pem = &mut done => return pem,
        }
    }
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
fn build_connection(
    agent_keypair: Arc<dyn TunnelKey>,
    identity_keypair: Arc<dyn TunnelKey>,
    domain_suffix: &str,
    cert_extension: Option<&[u8]>,
    acme_staging: bool,
    need_csr: bool,
) -> Result<Connection> {
    let identity_pub_raw = identity_keypair.public_key_raw();
    // Hash the SEC1-compressed point, matching the Acurast on-chain pubkey hash.
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
    let url = format!("https://{}", domain);

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
    let agent_cert: CertificateDer<'static> =
        params.self_signed(&agent_rcgen_key)?.der().to_vec().into();
    let tls = Arc::new(ClientTls::new(
        agent_cert.clone(),
        Arc::clone(&agent_keypair),
        acme_staging,
    )?);

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
        agent_cert,
        agent_keypair,
        identity_keypair,
        csr_der,
        tls,
    })
}

/// Signs `msg` with `identity_keypair`, producing a 65-byte recoverable ECDSA
/// P-256 signature (`r || s || v`).
fn sign_recoverable(identity_keypair: &dyn TunnelKey, msg: &[u8]) -> Result<[u8; 65]> {
    use p256::ecdsa::{Signature, VerifyingKey, recoverable};
    let der = identity_keypair.sign(msg)?;
    let sig = Signature::from_der(&der)
        .map_err(|e| anyhow::anyhow!("parse identity signature DER: {e}"))?;
    // Trial-recovery only matches the canonical low-s form.
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

/// The H2 control connection to one relay, on which this crate is the server.
type H2Conn = h2::server::Connection<tokio_rustls::client::TlsStream<TcpStream>, bytes::Bytes>;

/// One accepted control request and the handle answering it.
type CtrlReq = (
    http::Request<h2::RecvStream>,
    h2::server::SendResponse<bytes::Bytes>,
);

/// The relay refused this agent. Retried at maximum backoff.
#[derive(Debug)]
struct RelayRejected(String);

impl std::fmt::Display for RelayRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rejected by relay: {}", self.0)
    }
}

impl std::error::Error for RelayRejected {}

/// Passes a control request through unless it is the relay's rejection, which
/// is answered `200` and raised as [`RelayRejected`] carrying the reason body.
async fn check_reject(
    req: http::Request<h2::RecvStream>,
    mut resp: h2::server::SendResponse<bytes::Bytes>,
) -> Result<CtrlReq> {
    if req.uri().path() != CTRL_REJECT_PATH {
        return Ok((req, resp));
    }
    let reason = collect_h2_body(req.into_body(), MAX_CTRL_FRAME)
        .await
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let _ = resp.send_response(http::Response::new(()), true);
    Err(RelayRejected(reason).into())
}

/// Accepts the next control request, or fails with `closed` if the relay hung
/// up first.
async fn accept_ctrl(h2_conn: &mut H2Conn, closed: &str) -> Result<CtrlReq> {
    let (req, resp) = h2_conn
        .accept()
        .await
        .ok_or_else(|| anyhow::anyhow!("{closed}"))??;
    check_reject(req, resp).await
}

async fn h2_ctrl_exchange(
    h2_conn: &mut H2Conn,
    domain: &str,
    identity_keypair: &dyn TunnelKey,
    csr_der: Option<&[u8]>,
    provisioner: Option<Arc<CertProvisioner>>,
    agent_cert: &CertificateDer<'static>,
) -> Result<Vec<CertificateDer<'static>>> {
    // Step 1: GET /_ctrl/domain — respond with domain
    let (req, mut resp) = accept_ctrl(h2_conn, "closed before /_ctrl/domain").await?;
    anyhow::ensure!(req.uri().path() == "/_ctrl/domain");
    let mut send = resp.send_response(http::Response::new(()), false)?;
    send.send_data(bytes::Bytes::from(domain.as_bytes().to_vec()), true)?;

    // Step 2: GET /_ctrl/sig — respond with 65-byte recoverable ECDSA P-256
    // signature over the domain so the server can recover the identity pubkey.
    let (req, mut resp) = accept_ctrl(h2_conn, "closed before /_ctrl/sig").await?;
    anyhow::ensure!(req.uri().path() == "/_ctrl/sig");
    let sig = sign_recoverable(identity_keypair, domain.as_bytes())?;
    let mut send = resp.send_response(http::Response::new(()), false)?;
    send.send_data(bytes::Bytes::copy_from_slice(&sig), true)?;

    // Step 3: GET /_ctrl/key_auth — run ACME prepare, respond with key_auth
    let (req, mut resp) = accept_ctrl(h2_conn, "closed before /_ctrl/key_auth").await?;
    anyhow::ensure!(req.uri().path() == "/_ctrl/key_auth");

    // Non-ACME path: respond empty and reuse agent cert for tunnel TLS.
    let Some(provisioner) = provisioner else {
        debug!("H2: no provisioner (self-signed path), responding with empty key_auth");
        let mut send = resp.send_response(http::Response::new(()), false)?;
        send.send_data(bytes::Bytes::new(), true)?;
        return Ok(vec![agent_cert.clone()]);
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
            let mut finalize = tokio::task::JoinSet::new();
            finalize.spawn(async move { prov.finalize(&dom, alpn_pending, &csr_der).await });
            let mut challenges = tokio::task::JoinSet::new();

            // Loop: handle /_ctrl/alpn streams and wait for /_ctrl/done
            loop {
                let (req, mut resp) =
                    accept_ctrl(h2_conn, "connection closed during challenge").await?;
                match req.uri().path() {
                    "/_ctrl/alpn" => {
                        debug!("H2: challenge stream received, terminating TLS-ALPN-01");
                        let send = resp.send_response(http::Response::new(()), false)?;
                        let stream = IO::new(H2Recv::new(req.into_body()), H2Send(send));
                        spawn_challenge(&mut challenges, &alpn_acceptor, stream);
                    }
                    "/_ctrl/done" => {
                        // Server signals it's done proxying challenges; await finalize
                        let cert_pem = h2_serve_challenges_until(
                            h2_conn,
                            &alpn_acceptor,
                            &mut challenges,
                            domain,
                            "ACME finalize",
                            async {
                                match finalize.join_next().await {
                                    Some(r) => Ok(r??),
                                    None => anyhow::bail!(
                                        "ACME finalize task for {} disappeared",
                                        domain
                                    ),
                                }
                            },
                        )
                        .await?;
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
            // Acceptors are owned so they die with this frame.
            let mut challenges = tokio::task::JoinSet::new();
            loop {
                let (req, mut resp) =
                    accept_ctrl(h2_conn, "connection closed during challenge").await?;
                match req.uri().path() {
                    "/_ctrl/alpn" => {
                        debug!("H2: challenge stream received (follower), terminating TLS-ALPN-01");
                        let send = resp.send_response(http::Response::new(()), false)?;
                        let stream = IO::new(H2Recv::new(req.into_body()), H2Send(send));
                        spawn_challenge(&mut challenges, &alpn_acceptor, stream);
                    }
                    "/_ctrl/done" => {
                        let cert_pem = h2_serve_challenges_until(
                            h2_conn,
                            &alpn_acceptor,
                            &mut challenges,
                            domain,
                            "leader cert",
                            async {
                                cert_rx.changed().await.map_err(|_| {
                                    anyhow::anyhow!(
                                        "ACME leader for {} dropped before cert issuance",
                                        domain
                                    )
                                })?;
                                cert_rx.borrow().clone().ok_or_else(|| {
                                    anyhow::anyhow!(
                                        "ACME leader for {} signalled empty cert",
                                        domain
                                    )
                                })
                            },
                        )
                        .await?;
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
    // Mozilla's pinned bundle: Android's system store misses ISRG Root X1.
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

/// rustls and quinn client configs for one server-verification mode.
struct TlsMode {
    tls: Arc<rustls::ClientConfig>,
    quic: quinn::ClientConfig,
}

impl TlsMode {
    fn new(tls: rustls::ClientConfig) -> Result<Self> {
        let tls = Arc::new(tls);
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(1000u32.into());
        transport.keep_alive_interval(Some(QUIC_KEEP_ALIVE_INTERVAL));
        transport.max_idle_timeout(Some(QUIC_MAX_IDLE_TIMEOUT.try_into()?));
        let mut quic = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(Arc::clone(&tls))?,
        ));
        quic.transport_config(Arc::new(transport));
        Ok(Self { tls, quic })
    }
}

/// Client TLS for outbound relay connections, built once per [`Connection`]:
/// CA-verified for a named relay, unverified for a bare IP.
struct ClientTls {
    named: TlsMode,
    ip: TlsMode,
}

impl ClientTls {
    fn new(
        cert: CertificateDer<'static>,
        keypair: Arc<dyn TunnelKey>,
        acme_staging: bool,
    ) -> Result<Self> {
        let named = ca_roots_client_config(vec![cert.clone()], Arc::clone(&keypair), acme_staging)?;
        let ip = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_client_cert_resolver(client_cert_resolver(vec![cert], keypair));
        Ok(Self {
            named: TlsMode::new(named)?,
            ip: TlsMode::new(ip)?,
        })
    }

    /// Config and SNI to use for one relay address.
    fn for_addr(&self, addr: &str) -> (&TlsMode, String) {
        match server_name_from_addr(addr) {
            Some(name) => (&self.named, name),
            None => (&self.ip, "localhost".to_string()),
        }
    }
}

/// Bounds one connect attempt; a timeout reads as a connect failure.
async fn connect_within<T>(
    timeout: Duration,
    addr: &str,
    fut: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout(timeout, fut)
        .await
        .unwrap_or_else(|_| {
            Err(anyhow::anyhow!(
                "connect to {} timed out after {:?}",
                addr,
                timeout
            ))
        })
}

async fn connect_quic(
    endpoint: &quinn::Endpoint,
    addr: &str,
    tls: &ClientTls,
) -> Result<quinn::Connection> {
    let (mode, sni) = tls.for_addr(addr);
    let socket_addr = tokio::net::lookup_host(addr)
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve {}", addr))?;

    Ok(endpoint
        .connect_with(mode.quic.clone(), socket_addr, &sni)?
        .await?)
}

/// Connects one pooled member. The [`h2::PingPong`] comes back with the
/// connection because it can only be taken before the connection is driven.
async fn connect_h2(
    addr: &str,
    tls: &ClientTls,
) -> Result<(
    h2::server::Connection<tokio_rustls::client::TlsStream<TcpStream>, bytes::Bytes>,
    Option<h2::PingPong>,
)> {
    let (mode, sni) = tls.for_addr(addr);
    let connector = tokio_rustls::TlsConnector::from(Arc::clone(&mode.tls));
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;
    let server_name = rustls::pki_types::ServerName::try_from(sni.as_str())
        .map_err(|e| anyhow::anyhow!("invalid server name: {e}"))?
        .to_owned();
    let stream = connector.connect(server_name, tcp).await?;
    let mut conn = h2::server::Builder::new()
        .initial_window_size(H2_DATA_STREAM_WINDOW)
        .initial_connection_window_size(H2_DATA_CONN_WINDOW)
        .handshake(stream)
        .await?;
    let ping_pong = conn.ping_pong();
    Ok((conn, ping_pong))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::RcgenKey;
    use tokio::time::timeout;

    const WAIT: Duration = Duration::from_secs(5);

    fn liveness(size: usize) -> Arc<PoolLiveness> {
        Arc::new(PoolLiveness::new(None, "PRI", "127.0.0.1:1", size))
    }

    /// A loopback address that refuses connections.
    fn refused_addr() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        drop(listener);
        addr.to_string()
    }

    fn pooled_member(
        server_addr: &str,
        live: Arc<PoolLiveness>,
        stop: &watch::Sender<bool>,
    ) -> H2Pooled {
        let key = || -> Arc<dyn TunnelKey> {
            Arc::new(RcgenKey::generate(KeyAlgorithm::EcdsaP256).expect("key"))
        };
        let conn =
            build_connection(key(), key(), "localhost", None, false, false).expect("connection");
        let shared = Arc::new(H2Shared {
            tag: "PRI".into(),
            server_addr: server_addr.into(),
            local_addr: "127.0.0.1:1".into(),
            url: conn.url,
            domain: conn.domain,
            agent_cert: conn.agent_cert,
            agent_keypair: conn.agent_keypair,
            identity_keypair: conn.identity_keypair,
            csr_der: conn.csr_der,
            provisioner: None,
            tls: conn.tls,
            policy: ReconnectPolicy {
                max_attempts: 0,
                base_backoff: Duration::from_millis(10),
                max_backoff: Duration::from_millis(20),
                connect_timeout: Duration::from_secs(1),
            },
            keepalive: H2KeepAlive::default(),
            rejected: watch::Sender::new(None),
        });
        H2Pooled {
            index: 0,
            shared,
            live,
            stop: stop.subscribe(),
        }
    }

    #[test]
    fn park_is_refused_while_a_member_is_up() {
        let live = liveness(2);
        live.up();
        assert!(live.park().is_none());
    }

    #[tokio::test]
    async fn all_parked_fires_only_once_every_member_is_parked() {
        let live = liveness(2);
        let _first = live.park().expect("nothing up");
        assert!(
            timeout(Duration::from_millis(100), live.wait_all_parked())
                .await
                .is_err()
        );
        let _second = live.park().expect("nothing up");
        timeout(WAIT, live.wait_all_parked())
            .await
            .expect("every member parked");
    }

    #[tokio::test]
    async fn pool_coming_up_wakes_a_parked_member() {
        let live = liveness(2);
        let mut parked = live.park().expect("nothing up");
        live.up();
        timeout(WAIT, parked.changed())
            .await
            .expect("woken by the 0 to 1 transition")
            .expect("sender alive");
    }

    #[tokio::test]
    async fn failed_member_parks_and_retries_once_a_sibling_comes_up() {
        let live = liveness(1);
        let (stop, _) = watch::channel(false);
        let member = pooled_member(&refused_addr(), Arc::clone(&live), &stop);
        let task = tokio::spawn(member.drive());

        timeout(WAIT, live.wait_all_parked())
            .await
            .expect("member parked after failing with no sibling up");
        assert!(
            !task.is_finished(),
            "member left the pool instead of parking"
        );

        // A sibling comes up and drops again: the member must retry, fail and park anew.
        live.up();
        live.down("sibling lost".into(), false);
        timeout(WAIT, live.wait_all_parked())
            .await
            .expect("woken member retried and parked again");
        assert!(!task.is_finished(), "member left the pool after retrying");

        stop.send_replace(true);
        timeout(WAIT, task)
            .await
            .expect("member honours stop")
            .expect("member task");
    }
}
