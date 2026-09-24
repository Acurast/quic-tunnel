//! Foreign-language surface for the tunnel client.
//!
//! Exposes a [`TunnelClient`] uniffi object with an idiomatic shape: sync
//! constructor + getter, async [`TunnelClient::run`] driven by the foreign
//! coroutine runtime, and sync [`TunnelClient::stop`]. Lifecycle,
//! per-connection and ACME cert events are pushed to the foreign side through
//! a [`Handler`] trait.
//! The optional secondary signing key is implemented foreign-side as a
//! [`TunnelKey`] callback object (typically backed by Android Keystore).

use std::fmt::Debug;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use tunnel_client as tc;

/// Upper bound on one foreign `sign` round-trip. Past this the Keystore or the
/// foreign dispatcher is stuck, and waiting forever would strand the caller.
const SIGN_TIMEOUT: Duration = Duration::from_secs(10);

/// Lazily built runtime that caches successes only, so a build that failed
/// under thread exhaustion is retried by the next caller instead of poisoning
/// the process.
struct LazyRuntime {
    cell: OnceLock<tokio::runtime::Runtime>,
    building: Mutex<()>,
}

impl LazyRuntime {
    const fn new() -> Self {
        Self {
            cell: OnceLock::new(),
            building: Mutex::new(()),
        }
    }

    /// Returns the runtime, building it on first use. `building` serialises
    /// attempts so a burst of callers doesn't spawn a burst of doomed runtimes.
    fn get(
        &'static self,
        build: impl FnOnce() -> Result<tokio::runtime::Runtime, String>,
    ) -> Result<&'static tokio::runtime::Runtime, String> {
        if let Some(rt) = self.cell.get() {
            return Ok(rt);
        }
        let _serialised = self.building.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(rt) = self.cell.get() {
            return Ok(rt);
        }
        let rt = build()?;
        Ok(self.cell.get_or_init(|| rt))
    }
}

/// Dedicated runtime for driving foreign-side async sign callbacks, isolated
/// so a `sign` blocking inside a rustls handshake can't stall the tunnel and
/// so neither the no-runtime nor the runtime-already-entered caller needs care.
fn foreign_key_runtime() -> Result<&'static tokio::runtime::Runtime, String> {
    static RT: LazyRuntime = LazyRuntime::new();
    RT.get(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("tunnel-foreign-key")
            .build()
            .map_err(|e| format!("foreign key runtime unavailable: {e}"))
    })
}

/// Runtime the tunnel itself runs on, in place of the single-threaded runtime
/// `async_compat` falls back to when no tokio handle is entered.
fn tunnel_runtime() -> Result<&'static tokio::runtime::Runtime, String> {
    static RT: LazyRuntime = LazyRuntime::new();
    RT.get(|| {
        tokio::runtime::Builder::new_multi_thread()
            // A floor, not the isolation mechanism: `recv_blocking` blocks in place.
            .worker_threads(2)
            .enable_all()
            .thread_name("tunnel")
            .build()
            .map_err(|e| format!("tunnel runtime unavailable: {e}"))
    })
}

/// Block the calling thread on `rx` for at most `timeout`, telling tokio about
/// the block on a multi-thread worker, where `block_in_place` is allowed.
fn recv_blocking<T>(
    rx: std::sync::mpsc::Receiver<T>,
    timeout: Duration,
) -> Result<T, std::sync::mpsc::RecvTimeoutError> {
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current() {
        Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| rx.recv_timeout(timeout))
        }
        _ => rx.recv_timeout(timeout),
    }
}

#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Ed25519,
    EcdsaP256,
}

impl From<KeyAlgorithm> for tc::KeyAlgorithm {
    fn from(a: KeyAlgorithm) -> Self {
        match a {
            KeyAlgorithm::Ed25519 => tc::KeyAlgorithm::Ed25519,
            KeyAlgorithm::EcdsaP256 => tc::KeyAlgorithm::EcdsaP256,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct PrimaryKey {
    pub algorithm: KeyAlgorithm,
    /// Ed25519: 32-byte seed or PKCS#8 DER. EcdsaP256: PKCS#8 DER.
    pub bytes: Vec<u8>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct PrimaryConnection {
    pub key: PrimaryKey,
    pub cert_extension: Option<Vec<u8>>,
}

#[derive(uniffi::Record, Clone, Debug, Default)]
pub struct SecondaryConnection {
    pub cert_extension: Option<Vec<u8>>,
    pub local_addr: Option<String>,
}

/// Retry budget for each connection's reconnect loop. `max_attempts: 0` means
/// unlimited; the defaults are the mobile ones, see `ReconnectPolicy::mobile()`.
/// A non-zero budget yields `ConnectionGaveUp`, then `Failed` once all have.
#[derive(uniffi::Record, Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconnectConfig {
    /// Consecutive failed attempts before a connection gives up. `0` is unlimited.
    /// A relay rejection counts as one, retried at `max_backoff_ms`.
    #[uniffi(default = 0)]
    pub max_attempts: u32,
    /// First backoff interval; doubles after each failed attempt.
    #[uniffi(default = 2000)]
    pub base_backoff_ms: u64,
    /// Ceiling the doubling backoff saturates at.
    #[uniffi(default = 60000)]
    pub max_backoff_ms: u64,
    /// Bounds one connect attempt end-to-end (DNS + transport + TLS).
    #[uniffi(default = 10000)]
    pub connect_timeout_ms: u64,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        let p = tc::ReconnectPolicy::mobile();
        Self {
            max_attempts: p.max_attempts,
            base_backoff_ms: p.base_backoff.as_millis() as u64,
            max_backoff_ms: p.max_backoff.as_millis() as u64,
            connect_timeout_ms: p.connect_timeout.as_millis() as u64,
        }
    }
}

impl From<ReconnectConfig> for tc::ReconnectPolicy {
    fn from(c: ReconnectConfig) -> Self {
        // Verbatim: `tc::TunnelClient::new` validates and reports InvalidConfig.
        Self {
            max_attempts: c.max_attempts,
            base_backoff: Duration::from_millis(c.base_backoff_ms),
            max_backoff: Duration::from_millis(c.max_backoff_ms),
            connect_timeout: Duration::from_millis(c.connect_timeout_ms),
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct TunnelConfig {
    pub server_addrs: Vec<String>,
    pub local_addr: String,
    pub domain_suffix: String,
    pub primary: PrimaryConnection,
    pub secondary: Option<SecondaryConnection>,
    pub force_h2: bool,
    pub pool_size: u32,
    pub acme_email: Option<String>,
    pub acme_creds_path: String,
    pub acme_staging: bool,
    /// Pre-seeded LE cert PEM for the primary domain. Skips ACME if supplied.
    pub cert_pem: Option<String>,
    /// Reconnect budget. Unset → [`ReconnectConfig::default`] (retry forever,
    /// 2s → 60s backoff, 10s connect timeout).
    #[uniffi(default = None)]
    pub reconnect: Option<ReconnectConfig>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct TunnelInfo {
    pub url: String,
    pub client_id: String,
    pub secondary_url: Option<String>,
    pub secondary_client_id: Option<String>,
}

/// What the foreign side observes. See [`TunnelClient::run`] for the order
/// these arrive in.
///
/// `transport` is `"quic"` or `"h2"` — a string rather than an enum so the
/// Kotlin surface stays a plain `when` on a value nobody has to import.
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum TunnelEvent {
    /// The first connection completed its control exchange. Not "run() was
    /// called": a tunnel that never reaches a relay never reports this.
    Started,
    Stopped,
    CertIssued {
        pem: String,
    },
    /// One connection is carrying traffic. `tag` is `"PRI"` or `"SEC"`.
    ///
    /// `transport` is per session: it can differ between sessions of one connection.
    ConnectionEstablished {
        tag: String,
        server_addr: String,
        transport: String,
    },
    /// One established connection dropped. Its reconnect loop will retry, so
    /// this is not terminal.
    ConnectionLost {
        tag: String,
        server_addr: String,
        transport: String,
        cause: String,
    },
    /// One connection exhausted its reconnect budget and will not retry. The
    /// tunnel as a whole may still be up on other connections.
    ConnectionGaveUp {
        tag: String,
        server_addr: String,
        cause: String,
    },
    Failed {
        cause: String,
    },
}

/// Everything `run()` delivers, in one queue, so the foreign side sees certs
/// and connection events in the order they happened.
enum Inner {
    Cert(String),
    Conn(tc::ConnectionEvent),
}

impl From<tc::ConnectionEvent> for TunnelEvent {
    fn from(ev: tc::ConnectionEvent) -> Self {
        match ev {
            tc::ConnectionEvent::Established {
                tag,
                server_addr,
                transport,
            } => TunnelEvent::ConnectionEstablished {
                tag,
                server_addr,
                transport: transport.to_string(),
            },
            tc::ConnectionEvent::Lost {
                tag,
                server_addr,
                transport,
                cause,
            } => TunnelEvent::ConnectionLost {
                tag,
                server_addr,
                transport: transport.to_string(),
                cause,
            },
            tc::ConnectionEvent::GaveUp {
                tag,
                server_addr,
                cause,
            } => TunnelEvent::ConnectionGaveUp {
                tag,
                server_addr,
                cause,
            },
        }
    }
}

/// Delivers one queued item, emitting `Started` immediately before the first
/// `ConnectionEstablished`.
async fn deliver(handler: &dyn Handler, announced: &AtomicBool, item: Inner) {
    let ev = match item {
        Inner::Cert(pem) => TunnelEvent::CertIssued { pem },
        Inner::Conn(conn) => {
            if matches!(conn, tc::ConnectionEvent::Established { .. })
                && !announced.load(Ordering::SeqCst)
            {
                handler.on_event(TunnelEvent::Started).await;
                announced.store(true, Ordering::SeqCst);
            }
            conn.into()
        }
    };
    handler.on_event(ev).await;
}

/// Delivers everything already queued, without waiting for more.
async fn drain(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<Inner>,
    handler: &dyn Handler,
    announced: &AtomicBool,
) {
    while let Ok(item) = rx.try_recv() {
        deliver(handler, announced, item).await;
    }
}

#[derive(uniffi::Error, thiserror::Error, Debug)]
pub enum TunnelError {
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("runtime error: {0}")]
    Runtime(String),
}

/// Foreign-implemented signing key for the optional secondary connection.
/// `sign` is async on the foreign side; the rust adapter bridges back to
/// the sync `tc::TunnelKey` interface required by rustls/rcgen.
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait TunnelKey: Send + Sync + Debug {
    fn algorithm(&self) -> KeyAlgorithm;
    fn public_key_raw(&self) -> Vec<u8>;
    async fn sign(&self, msg: Vec<u8>) -> Vec<u8>;
}

/// Foreign-implemented event sink. Receives lifecycle, per-connection and
/// ACME events; see [`TunnelClient::run`] for the order they arrive in.
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait Handler: Send + Sync + Debug {
    async fn on_event(&self, event: TunnelEvent);
}

#[derive(uniffi::Object)]
pub struct TunnelClient {
    inner: Arc<tc::TunnelClient>,
    info: TunnelInfo,
    handler: Arc<dyn Handler>,
    /// Certs and connection events in the order they happened. [`TunnelClient::run`]
    /// hands the receiver to its [`TerminalGuard`].
    events_rx: Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<Inner>>>,
    /// Set by the first `run()`; a second call is rejected.
    started: AtomicBool,
    /// Set once `Started` has been delivered, on the first `Established`.
    /// Shared with the guard so the cancelled path emits it too.
    announced: Arc<AtomicBool>,
    /// Set by `stop()`. A `run()` that finds it already set emits `Stopped`
    /// without starting anything.
    stopped: AtomicBool,
    /// Set once a terminal event (`Stopped` or `Failed`) has been fully
    /// delivered, so the cancellation guard doesn't emit a second one.
    terminal: Arc<AtomicBool>,
}

/// Drains whatever is still queued and then emits `Stopped` if
/// [`TunnelClient::run`]'s future is dropped before a terminal event was
/// delivered. Owns the receiver and the tunnel task so it can flush both.
struct TerminalGuard {
    terminal: Arc<AtomicBool>,
    announced: Arc<AtomicBool>,
    handler: Arc<dyn Handler>,
    events_rx: Option<tokio::sync::mpsc::UnboundedReceiver<Inner>>,
    tunnel: tokio::task::JoinSet<Result<()>>,
}

impl TerminalGuard {
    /// Emits the terminal event, marking it delivered only once `on_event`
    /// returns, so a cancel mid-delivery still leaves `drop` one to emit.
    async fn deliver_terminal(&self, event: TunnelEvent) {
        self.handler.on_event(event).await;
        self.terminal.store(true, Ordering::SeqCst);
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.terminal.load(Ordering::SeqCst) {
            return;
        }
        let handler = Arc::clone(&self.handler);
        let announced = Arc::clone(&self.announced);
        let terminal = Arc::clone(&self.terminal);
        let mut events_rx = self.events_rx.take();
        let mut tunnel = std::mem::take(&mut self.tunnel);
        // `on_event` is async and `drop` is not, so the tail of the stream goes
        // to a runtime; one task keeps it ordered before `Stopped`.
        let tail = async move {
            // Aborts *and waits*: a still-running task may have one more event
            // to send, and it would die with the receiver.
            tunnel.shutdown().await;
            if let Some(rx) = events_rx.as_mut() {
                drain(rx, handler.as_ref(), &announced).await;
            }
            handler.on_event(TunnelEvent::Stopped).await;
            terminal.store(true, Ordering::SeqCst);
        };
        if let Err(e) = spawn_detached(tail) {
            log::error!("cannot deliver trailing tunnel events: {e}");
        }
    }
}

/// Runs `fut` to completion off the caller: on the tunnel runtime, else on the
/// current runtime, else on a dedicated thread.
fn spawn_detached(fut: impl Future<Output = ()> + Send + 'static) -> Result<(), String> {
    let rt_err = match tunnel_runtime() {
        Ok(rt) => {
            rt.spawn(fut);
            return Ok(());
        }
        Err(e) => e,
    };
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(fut);
        return Ok(());
    }
    std::thread::Builder::new()
        .name("tunnel-terminal".into())
        .spawn(move || {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt.block_on(fut),
                Err(e) => log::error!("cannot deliver trailing tunnel events: {e}"),
            }
        })
        .map(drop)
        .map_err(|e| format!("{rt_err}; no thread either: {e}"))
}

#[uniffi::export(async_runtime = "tokio")]
impl TunnelClient {
    /// Builds the client and binds its identities.
    ///
    /// **Do not construct this on `Dispatchers.Default`.** The constructor
    /// generates the secondary CSR, which calls the foreign `sign` and blocks
    /// the calling thread until it answers — while uniffi dispatches that
    /// foreign `sign` onto `Dispatchers.Default`. On a small-core device the
    /// two can be the same, very small, pool, and the call self-deadlocks until
    /// [`SIGN_TIMEOUT`] expires and construction fails. Construct on
    /// `Dispatchers.IO` (the Kotlin wrapper does this for you).
    #[uniffi::constructor]
    pub fn new(
        config: TunnelConfig,
        secondary_key: Option<Arc<dyn TunnelKey>>,
        handler: Arc<dyn Handler>,
    ) -> Result<Arc<Self>, TunnelError> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let primary_local = primary_key(&config.primary.key).map_err(|e| {
            let chain = format_error_chain(&e);
            log::error!("TunnelClient::new primary key error: {chain}");
            TunnelError::InvalidConfig(chain)
        })?;
        let primary = tc::TunnelIdentityConfig {
            keypair: Arc::new(primary_local),
            cert_extension: config.primary.cert_extension.clone(),
        };

        let secondary = match (config.secondary.clone(), secondary_key) {
            (Some(sec_cfg), Some(sec_foreign)) => Some(tc::TunnelIdentityConfig {
                keypair: Arc::new(ForeignKey::new(sec_foreign)),
                cert_extension: sec_cfg.cert_extension,
            }),
            _ => None,
        };

        // Unbounded because both senders are sync `Fn(..)` and must not block.
        let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel::<Inner>();
        let cert_tx = events_tx.clone();
        let on_cert_issued: Arc<dyn Fn(String) + Send + Sync> = Arc::new(move |pem: String| {
            if cert_tx.send(Inner::Cert(pem)).is_err() {
                log::error!("fresh ACME certificate dropped: event channel closed");
            }
        });
        let on_connection_event: Arc<dyn Fn(tc::ConnectionEvent) + Send + Sync> =
            Arc::new(move |ev: tc::ConnectionEvent| {
                if events_tx.send(Inner::Conn(ev)).is_err() {
                    log::error!("connection event dropped: event channel closed");
                }
            });

        let inner_cfg = tc::TunnelConfig {
            server_addrs: config.server_addrs,
            local_addr: config.local_addr,
            secondary_local_addr: config.secondary.as_ref().and_then(|s| s.local_addr.clone()),
            domain_suffix: config.domain_suffix,
            force_h2: config.force_h2,
            pool_size: config.pool_size as usize,
            acme_email: config.acme_email,
            acme_creds_path: config.acme_creds_path,
            acme_staging: config.acme_staging,
            cert_pem: config.cert_pem,
            on_cert_issued: Some(on_cert_issued),
            on_connection_event: Some(on_connection_event),
            primary_identity: primary,
            reconnect: config.reconnect.unwrap_or_default().into(),
            h2_keepalive: Default::default(),
            self_signed_identity: secondary,
        };

        let inner = tc::TunnelClient::new(inner_cfg).map_err(|e| {
            let chain = format_error_chain(&e);
            log::error!("TunnelClient::new failed: {chain}");
            TunnelError::InvalidConfig(chain)
        })?;
        let info = TunnelInfo {
            url: inner.url().to_string(),
            client_id: inner.client_id().to_string(),
            secondary_url: inner.secondary_url().map(str::to_string),
            secondary_client_id: inner.secondary_client_id().map(str::to_string),
        };

        Ok(Arc::new(Self {
            inner: Arc::new(inner),
            info,
            handler,
            events_rx: Mutex::new(Some(events_rx)),
            started: AtomicBool::new(false),
            announced: Arc::new(AtomicBool::new(false)),
            stopped: AtomicBool::new(false),
            terminal: Arc::new(AtomicBool::new(false)),
        }))
    }

    pub fn info(&self) -> TunnelInfo {
        self.info.clone()
    }

    /// Drives the tunnel until it stops or fails.
    ///
    /// Emits `Started` once the first connection completes its control
    /// exchange, then connection and cert events in the order they happened,
    /// then exactly one terminal event — `Stopped` or `Failed`. `Failed` or
    /// `Stopped` may arrive without a prior `Started` if no connection was
    /// ever established.
    ///
    /// The terminal event is emitted even if the foreign side cancels this
    /// future, and so is anything still queued when it does — including a
    /// pending `Started`.
    ///
    /// One-shot: a second call returns [`TunnelError::Runtime`]. A *first* call
    /// that loses the race with [`TunnelClient::stop`] is not an error — the
    /// foreign wrapper legitimately constructs and immediately closes — so it
    /// emits `Stopped` and returns `Ok`.
    pub async fn run(&self) -> Result<(), TunnelError> {
        if self.started.swap(true, Ordering::SeqCst) {
            return Err(TunnelError::Runtime(
                "run() already called on this TunnelClient".into(),
            ));
        }

        // Before anything can be emitted, so no event is produced without a
        // guard in place to finish the stream if the foreign side cancels.
        let mut guard = TerminalGuard {
            terminal: Arc::clone(&self.terminal),
            announced: Arc::clone(&self.announced),
            handler: Arc::clone(&self.handler),
            events_rx: self
                .events_rx
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take(),
            // A `JoinSet` aborts on drop, so a cancelled `run()` reclaims the
            // tunnel instead of detaching it onto the runtime.
            tunnel: tokio::task::JoinSet::new(),
        };

        // `close()` before the run coroutine got to dispatch. Don't start a
        // tunnel that is already told to stop, but do close out the event
        // stream so the foreign side isn't left waiting.
        if self.stopped.load(Ordering::SeqCst) {
            guard.deliver_terminal(TunnelEvent::Stopped).await;
            return Ok(());
        }

        let rt = match tunnel_runtime() {
            Ok(rt) => rt,
            Err(cause) => {
                log::error!("tunnel run failed: {cause}");
                guard.deliver_terminal(TunnelEvent::Failed { cause }).await;
                return Ok(());
            }
        };
        let inner = Arc::clone(&self.inner);
        guard.tunnel.spawn_on(inner.run(), rt.handle());

        let outcome = loop {
            // Split borrow: the select needs the queue and the task set at the
            // same time, and `&mut guard` twice is not allowed.
            let TerminalGuard {
                events_rx, tunnel, ..
            } = &mut guard;
            let next_event = async {
                match events_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                // Queued events first: a PEM or a `GaveUp` is worth delivering
                // even on the turn the tunnel ends.
                biased;
                item = next_event => match item {
                    Some(item) => deliver(self.handler.as_ref(), &self.announced, item).await,
                    // Every sender is gone; stop polling this arm.
                    None => *events_rx = None,
                },
                joined = tunnel.join_next() => break joined,
            }
        };

        if let Some(rx) = guard.events_rx.as_mut() {
            drain(rx, self.handler.as_ref(), &self.announced).await;
        }

        let event = match outcome {
            Some(Ok(Ok(()))) => TunnelEvent::Stopped,
            Some(Ok(Err(e))) => {
                let chain = format_error_chain(&e);
                log::error!("tunnel run failed: {chain}");
                TunnelEvent::Failed { cause: chain }
            }
            // Only reachable on a panic: the abort happens on drop, by which
            // point nobody is awaiting this.
            Some(Err(e)) => {
                log::error!("tunnel run panicked: {e}");
                TunnelEvent::Failed {
                    cause: e.to_string(),
                }
            }
            None => unreachable!("exactly one task was spawned"),
        };
        guard.deliver_terminal(event).await;
        Ok(())
    }

    /// Signals the tunnel to shut down. Idempotent, callable from any thread.
    ///
    /// One-shot: the client is spent afterwards. A later [`TunnelClient::run`]
    /// will not start a tunnel — it emits `Stopped` and returns `Ok` — so build
    /// a new client to reconnect.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.inner.stop();
    }
}

/// Builds the primary key from job-supplied raw bytes. An Ed25519 32-byte
/// input is a raw seed; everything else is PKCS#8 DER.
fn primary_key(primary: &PrimaryKey) -> Result<tc::RcgenKey> {
    let algorithm: tc::KeyAlgorithm = primary.algorithm.into();
    match algorithm {
        tc::KeyAlgorithm::Ed25519 if primary.bytes.len() == 32 => {
            tc::RcgenKey::from_ed25519_seed(&primary.bytes)
                .map_err(|e| anyhow::anyhow!("ed25519 keypair: {e}"))
        }
        tc::KeyAlgorithm::Ed25519 => tc::RcgenKey::from_pkcs8_der(&primary.bytes)
            .map_err(|e| anyhow::anyhow!("ed25519 keypair: {e}")),
        tc::KeyAlgorithm::EcdsaP256 => tc::RcgenKey::from_pkcs8_der(&primary.bytes)
            .map_err(|e| anyhow::anyhow!("p256 keypair (expect PKCS#8 DER): {e}")),
    }
}

/// Bridge from a foreign async [`TunnelKey`] to the sync `tc::TunnelKey`
/// trait that rustls/rcgen call from Tokio worker threads.
struct ForeignKey {
    foreign: Arc<dyn TunnelKey>,
    algorithm: tc::KeyAlgorithm,
    public_key: Vec<u8>,
}

impl Debug for ForeignKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForeignKey")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl ForeignKey {
    fn new(foreign: Arc<dyn TunnelKey>) -> Self {
        let algorithm: tc::KeyAlgorithm = foreign.algorithm().into();
        let public_key = foreign.public_key_raw();
        Self {
            foreign,
            algorithm,
            public_key,
        }
    }
}

impl tc::TunnelKey for ForeignKey {
    fn algorithm(&self) -> tc::KeyAlgorithm {
        self.algorithm
    }
    fn public_key_raw(&self) -> Vec<u8> {
        self.public_key.clone()
    }
    /// Drives the foreign `async sign()` on [`foreign_key_runtime`] and blocks
    /// here until it answers or [`SIGN_TIMEOUT`] elapses.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        use std::sync::mpsc::RecvTimeoutError;

        let rt = foreign_key_runtime().map_err(|e| anyhow::anyhow!("{e}"))?;
        let foreign = Arc::clone(&self.foreign);
        let msg = msg.to_vec();
        // Buffered, so a timed-out caller doesn't leave the worker blocked.
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);
        rt.spawn(async move {
            let sig = foreign.sign(msg).await;
            let _ = tx.send(sig);
        });
        recv_blocking(rx, SIGN_TIMEOUT).map_err(|e| match e {
            RecvTimeoutError::Timeout => {
                anyhow::anyhow!("foreign sign timed out after {SIGN_TIMEOUT:?}")
            }
            RecvTimeoutError::Disconnected => anyhow::anyhow!("foreign sign worker died"),
        })
    }
}

/// Render an `anyhow::Error` plus its full source chain in a single string,
/// suitable for crossing the FFI boundary and showing up in `adb logcat`.
/// Format: `top: cause1: cause2: ...`.
fn format_error_chain(err: &anyhow::Error) -> String {
    let mut parts = err.chain().map(|c| c.to_string());
    let mut out = parts.next().unwrap_or_default();
    for cause in parts {
        out.push_str(": ");
        out.push_str(&cause);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};

    /// Records everything `run()` delivers, in order. Rust implementations of
    /// an `#[uniffi::export(with_foreign)]` trait are ordinary implementations,
    /// so the foreign event contract is testable without a JVM.
    #[derive(Debug, Clone, Default)]
    struct Recorder(Arc<Mutex<Vec<TunnelEvent>>>);

    impl Recorder {
        fn events(&self) -> Vec<TunnelEvent> {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }
    }

    #[async_trait]
    impl Handler for Recorder {
        async fn on_event(&self, event: TunnelEvent) {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).push(event);
        }
    }

    /// A port nothing listens on. Bound and released, so it is a real address
    /// that refuses TCP at once rather than a black hole.
    fn dead_addr() -> String {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let addr = l.local_addr().expect("local_addr");
        drop(l);
        addr.to_string()
    }

    fn config(server_addr: String) -> TunnelConfig {
        let der = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("keypair")
            .serialize_der();
        TunnelConfig {
            server_addrs: vec![server_addr],
            local_addr: "127.0.0.1:1".to_string(),
            domain_suffix: "localhost".to_string(),
            primary: PrimaryConnection {
                key: PrimaryKey {
                    algorithm: KeyAlgorithm::EcdsaP256,
                    bytes: der,
                },
                cert_extension: None,
            },
            secondary: None,
            // Straight to the H2 pool: a refused TCP connect fails instantly,
            // where a QUIC attempt would have to wait out `connect_timeout`.
            force_h2: true,
            pool_size: 1,
            acme_email: None,
            // Never reached: no connection here completes a control exchange.
            acme_creds_path: std::env::temp_dir()
                .join("tunnel-client-ffi-tests-acme-should-not-exist.json")
                .to_string_lossy()
                .into_owned(),
            acme_staging: true,
            cert_pem: None,
            reconnect: Some(ReconnectConfig {
                max_attempts: 1,
                base_backoff_ms: 50,
                max_backoff_ms: 50,
                connect_timeout_ms: 200,
            }),
        }
    }

    /// A tunnel that never reaches a relay must not report itself as started.
    #[tokio::test(flavor = "multi_thread")]
    async fn never_started_tunnel_fails_without_reporting_started() {
        let addr = dead_addr();
        let recorder = Recorder::default();
        let client = TunnelClient::new(config(addr.clone()), None, Arc::new(recorder.clone()))
            .expect("build client");

        client.run().await.expect("run() reports failure by event");

        let events = recorder.events();
        assert!(
            !events.contains(&TunnelEvent::Started),
            "nothing was ever established, so Started must not be emitted: {events:?}"
        );
        assert!(
            events.iter().any(|e| matches!(
                e,
                TunnelEvent::ConnectionGaveUp { tag, server_addr, .. }
                    if tag == "PRI" && server_addr == &addr
            )),
            "the dead connection should be named: {events:?}"
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, TunnelEvent::Failed { .. } | TunnelEvent::Stopped))
                .count(),
            1,
            "exactly one terminal event: {events:?}"
        );
        assert!(
            matches!(events.last(), Some(TunnelEvent::Failed { .. })),
            "the terminal event is Failed and comes last: {events:?}"
        );
    }

    /// Records an event only once `on_event` returns, and never returns from
    /// the first terminal one, so a cancel can land mid-delivery.
    #[derive(Debug, Default)]
    struct BlockingHandler {
        events: Mutex<Vec<TunnelEvent>>,
        entered: tokio::sync::Notify,
        blocking: AtomicBool,
    }

    impl BlockingHandler {
        fn events(&self) -> Vec<TunnelEvent> {
            self.events
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }

        fn terminals(&self) -> usize {
            self.events()
                .iter()
                .filter(|e| matches!(e, TunnelEvent::Failed { .. } | TunnelEvent::Stopped))
                .count()
        }
    }

    #[async_trait]
    impl Handler for BlockingHandler {
        async fn on_event(&self, event: TunnelEvent) {
            if matches!(event, TunnelEvent::Failed { .. } | TunnelEvent::Stopped)
                && !self.blocking.swap(true, Ordering::SeqCst)
            {
                self.entered.notify_one();
                std::future::pending::<()>().await;
            }
            self.events
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(event);
        }
    }

    /// Cancelling `run()` while the handler is still inside the terminal
    /// `on_event` must still end the stream with exactly one terminal event.
    #[tokio::test(flavor = "multi_thread")]
    async fn cancel_during_terminal_delivery_still_ends_the_stream() {
        let handler = Arc::new(BlockingHandler::default());
        let client =
            TunnelClient::new(config(dead_addr()), None, handler.clone()).expect("build client");

        let mut run = Box::pin(client.run());
        tokio::select! {
            _ = &mut run => panic!("run() returned instead of blocking in the terminal event"),
            _ = handler.entered.notified() => {}
        }
        drop(run);

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while handler.terminals() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "cancelled mid-delivery, so the guard owes a terminal event: {:?}",
                handler.events()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;

        let events = handler.events();
        assert_eq!(
            handler.terminals(),
            1,
            "exactly one terminal event, never two: {events:?}"
        );
        assert!(
            matches!(events.last(), Some(TunnelEvent::Stopped)),
            "the guard's terminal event comes last: {events:?}"
        );
    }

    /// Pins [`Default`] to `tc::ReconnectPolicy::mobile()` and to the
    /// `#[uniffi(default = ...)]` literals, which uniffi only takes as literals.
    #[test]
    fn reconnect_defaults_are_the_mobile_defaults() {
        assert_eq!(
            ReconnectConfig::default(),
            ReconnectConfig {
                max_attempts: 0,
                base_backoff_ms: 2_000,
                max_backoff_ms: 60_000,
                connect_timeout_ms: 10_000,
            },
            "keep the #[uniffi(default = ...)] literals on ReconnectConfig equal to these"
        );
        let policy: tc::ReconnectPolicy = ReconnectConfig::default().into();
        let mobile = tc::ReconnectPolicy::mobile();
        assert_eq!(policy.max_attempts, mobile.max_attempts);
        assert_eq!(policy.base_backoff, mobile.base_backoff);
        assert_eq!(policy.max_backoff, mobile.max_backoff);
        assert_eq!(policy.connect_timeout, mobile.connect_timeout);
    }
}
