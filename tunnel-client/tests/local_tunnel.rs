//! End-to-end tests against an in-process relay, with no ACME and no real
//! certificates: the relay serves an in-memory self-signed cert, an agent
//! pointed at an IP literal skips relay certificate verification, and the relay
//! forwards bytes untouched, so TLS terminates inside the client under test.
//!
//! Every assertion that a connection was released names the *specific*
//! connection (see [`EchoTarget`]), since the readiness probe opens and closes
//! tunnel sessions of its own.

use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket},
    sync::{
        Arc, Mutex, Once, OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use anyhow::Result;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::timeout,
};
use tunnel_client::{
    ConnectionEvent, H2KeepAlive, KeyAlgorithm, RcgenKey, ReconnectPolicy, Transport, TunnelClient,
    TunnelConfig, TunnelIdentityConfig, TunnelKey, key::RcgenRemoteKey,
};

/// How long to wait for the tunnel to come up before declaring the test failed.
const READY_TIMEOUT: Duration = Duration::from_secs(20);

/// Bounds one readiness probe and every session-level read/write. Without it a
/// stalled tunnel hangs the test binary (and CI) instead of failing.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a released connection may take to show up as EOF on the local
/// target.
const RELEASE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bounds the give-up tests: well above the ~300ms budget [`unreachable_policy`]
/// hands the client, well below quinn's 30s idle timeout.
const GAVE_UP_TIMEOUT: Duration = Duration::from_secs(5);

/// Installs the crypto provider the rustls configs built here need. `run()` and
/// the relay both do this too; all three are idempotent.
fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

// ---------------------------------------------------------------------------
// Log capture
// ---------------------------------------------------------------------------

/// Log lines captured from every test in this binary, filtered by the calling
/// test's relay address. The give-up tests match the per-connection reason here,
/// which `TunnelClient::run` logs rather than chains.
static LOGS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

fn logs() -> &'static Mutex<Vec<String>> {
    LOGS.get_or_init(|| Mutex::new(Vec::new()))
}

struct CaptureLogger;

impl log::Log for CaptureLogger {
    fn enabled(&self, _meta: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        let line = format!("{}", record.args());
        eprintln!("[{}] {}", record.level(), line);
        logs().lock().unwrap_or_else(|e| e.into_inner()).push(line);
    }
    fn flush(&self) {}
}

fn init_logging() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        static LOGGER: CaptureLogger = CaptureLogger;
        if log::set_logger(&LOGGER).is_ok() {
            // Info: `assert_no_acme_activity` matches ACME's own `info!` line.
            log::set_max_level(log::LevelFilter::Info);
        }
    });
}

/// Asserts some captured log line mentions both `addr` (which pins the line to
/// the calling test) and `needle`.
fn assert_logged(addr: &str, needle: &str) {
    let lines = logs().lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(
        lines.iter().any(|l| l.contains(addr) && l.contains(needle)),
        "no log line for {addr} contains {needle:?}; lines for this address: {:?}",
        lines
            .iter()
            .filter(|l| l.contains(addr))
            .collect::<Vec<_>>()
    );
}

/// Polls `f` every `every` until it yields a value, failing after `within`.
async fn poll_until<T>(
    within: Duration,
    every: Duration,
    what: &str,
    mut f: impl FnMut() -> Option<T>,
) -> Result<T> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if let Some(found) = f() {
            return Ok(found);
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("no {what} within {within:?}")
        }
        tokio::time::sleep(every).await;
    }
}

/// [`assert_logged`] for a line that has not been written yet.
async fn wait_logged(addr: &str, needle: &str, within: Duration) -> Result<()> {
    let what = format!("log line for {addr} contains {needle:?}");
    poll_until(within, Duration::from_millis(50), &what, || {
        let lines = logs().lock().unwrap_or_else(|e| e.into_inner());
        lines
            .iter()
            .any(|l| l.contains(addr) && l.contains(needle))
            .then_some(())
    })
    .await
}

/// Asserts no test reached Let's Encrypt. `ACME:` is logged immediately before
/// the first network call `CertProvisioner::prepare` would make, so its absence
/// is the proof.
fn assert_no_acme_activity() {
    let lines = logs().lock().unwrap_or_else(|e| e.into_inner()).clone();
    let acme: Vec<&String> = lines.iter().filter(|l| l.contains("ACME:")).collect();
    assert!(
        acme.is_empty(),
        "tests must not reach Let's Encrypt, but ACME provisioning ran: {acme:?}"
    );
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

/// Reserves a port free for **both** TCP and UDP (the relay binds an H2 listener
/// and a QUIC endpoint on the same port), never handing the same port to two
/// callers in this process. Still racy against other processes.
fn free_port() -> u16 {
    static TAKEN: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    let taken = TAKEN.get_or_init(|| Mutex::new(HashSet::new()));

    for _ in 0..100 {
        let tcp = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral tcp");
        let port = tcp.local_addr().expect("local_addr").port();
        {
            let mut taken = taken.lock().unwrap_or_else(|e| e.into_inner());
            if !taken.insert(port) {
                continue;
            }
        }
        if let Ok(udp) = StdUdpSocket::bind((Ipv4Addr::LOCALHOST, port)) {
            drop(udp);
            drop(tcp);
            return port;
        }
    }
    panic!("no port free on both TCP and UDP after 100 tries");
}

// ---------------------------------------------------------------------------
// Local target
// ---------------------------------------------------------------------------

/// First bytes a caller writes into a session, used to tell one connection to
/// the echo target from another.
type Tag = [u8; 8];

const PROBE_TAG: Tag = *b"probe___";

/// A tag unique to one session, so a test can name the connection it opened
/// rather than trusting that no other connection is in flight.
fn session_tag() -> Tag {
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed) % 100_000;
    let s = format!("sess{n:04}");
    s.as_bytes().try_into().expect("8-byte tag")
}

/// Local service the tunnel forwards to: echoes back whatever it is sent, and
/// reports each connection's start (with the first bytes it saw) and end over
/// channels, so a test can observe *its own* forwarding task being torn down.
struct EchoTarget {
    addr: SocketAddr,
    opened: mpsc::UnboundedReceiver<(u64, Vec<u8>)>,
    closed: mpsc::UnboundedReceiver<u64>,
}

impl EchoTarget {
    async fn start() -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let (open_tx, opened) = mpsc::unbounded_channel();
        let (close_tx, closed) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            let mut next_id: u64 = 0;
            while let Ok((mut sock, _)) = listener.accept().await {
                let id = next_id;
                next_id += 1;
                let open_tx = open_tx.clone();
                let close_tx = close_tx.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let mut announced = false;
                    loop {
                        match sock.read(&mut buf).await {
                            // EOF: the tunnel side let go of this connection.
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if !announced {
                                    announced = true;
                                    let _ = open_tx.send((id, buf[..n].to_vec()));
                                }
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    let _ = close_tx.send(id);
                });
            }
        });

        Ok(Self {
            addr,
            opened,
            closed,
        })
    }

    /// Forgets connections opened or closed so far (readiness probes, mostly).
    fn drain(&mut self) {
        while self.opened.try_recv().is_ok() {}
        while self.closed.try_recv().is_ok() {}
    }

    /// Id of the connection whose first bytes start with `tag`.
    async fn opened_with(&mut self, tag: &Tag) -> Result<u64> {
        timeout(IO_TIMEOUT, async {
            while let Some((id, first)) = self.opened.recv().await {
                if first.starts_with(tag) {
                    return Ok(id);
                }
            }
            anyhow::bail!("echo target stopped accepting")
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "no local connection tagged {:?}",
                String::from_utf8_lossy(tag)
            )
        })?
    }

    /// Waits for *this* connection to be released, ignoring any other.
    async fn wait_closed(&mut self, id: u64, within: Duration) -> Result<()> {
        timeout(within, async {
            while let Some(closed) = self.closed.recv().await {
                if closed == id {
                    return Ok(());
                }
            }
            anyhow::bail!("echo target stopped before connection {id} closed")
        })
        .await
        .map_err(|_| anyhow::anyhow!("local connection {id} was not released within {within:?}"))?
    }
}

// ---------------------------------------------------------------------------
// Relay
// ---------------------------------------------------------------------------

/// Reason the relay task exited, if it did. The readiness loop reports it
/// instead of spinning until its own timeout with nothing to say.
type RelayErr = Arc<Mutex<Option<String>>>;

/// Starts a relay on loopback with an in-memory self-signed cert and no ACME.
/// Returns `(api_port, pub_port, relay_error_slot)`.
fn start_relay() -> (u16, u16, RelayErr) {
    let api_port = free_port();
    let (pub_port, err) = start_relay_on(api_port);
    (api_port, pub_port, err)
}

/// [`start_relay`] on a caller-chosen API port. Returns `(pub_port, relay_error_slot)`.
fn start_relay_on(api_port: u16) -> (u16, RelayErr) {
    start_relay_with(api_port, H2KeepAlive::default(), None)
}

/// [`start_relay_on`] with an auth handler that denies every agent.
fn start_relay_denying(api_port: u16) -> (u16, RelayErr) {
    start_relay_with(
        api_port,
        H2KeepAlive::default(),
        Some(Arc::new(|_pubkey: &[u8], _custom: Option<&[u8]>| {
            anyhow::bail!("denied by test auth handler")
        })),
    )
}

/// [`start_relay_on`] with the relay's H2 PING liveness shortened, so a test
/// does not have to wait out the production 10s/20s pair.
fn start_relay_with(
    api_port: u16,
    h2_keepalive: H2KeepAlive,
    auth_handler: Option<tunnel_server::AuthHandler>,
) -> (u16, RelayErr) {
    let (pub_port, err, shutdown) = start_relay_until(api_port, h2_keepalive, auth_handler);
    // Kept alive for the process: this relay is never asked to stop.
    std::mem::forget(shutdown);
    (pub_port, err)
}

/// [`start_relay_with`] on [`tunnel_server::run_until`], returning the trigger
/// that shuts the relay down the way a SIGTERM does.
fn start_relay_until(
    api_port: u16,
    h2_keepalive: H2KeepAlive,
    auth_handler: Option<tunnel_server::AuthHandler>,
) -> (u16, RelayErr, tokio::sync::oneshot::Sender<()>) {
    let pub_port = free_port();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let err: RelayErr = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&err);

    tokio::spawn(async move {
        let config = tunnel_server::ServerConfig {
            bind_addr: Ipv4Addr::LOCALHOST.to_string(),
            api_port,
            pub_port,
            // Empty: accept any client domain, so the test needs no allowlist.
            domain_suffixes: Vec::new(),
            cert_path: None,
            key_path: None,
            acme_domain: None,
            acme_email: None,
            acme_creds_path: "unused_in_tests.json".to_string(),
            acme_staging: false,
            acme_directory_url: None,
            acme_root_ca_path: None,
            acme_renew_days_before_expiry: 30,
            auth_handler,
            h2_keepalive,
        };
        // Records why the relay stopped, so dependent tests fail with a reason.
        let shutdown = async {
            let _ = shutdown_rx.await;
        };
        let msg = match tunnel_server::run_until(config, shutdown).await {
            Ok(()) => format!("relay api={api_port} pub={pub_port} shut down"),
            Err(e) => format!("relay api={api_port} pub={pub_port} failed: {e:#}"),
        };
        eprintln!("{msg}");
        *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(msg);
    });

    (pub_port, err, shutdown_tx)
}

/// A TCP-only front: proxies its port to the relay's API port, binds nothing on
/// UDP. [`TcpFront::close`] drops the proxied connections and frees the port,
/// [`TcpFront::freeze`] stops the bytes without closing anything.
struct TcpFront {
    port: u16,
    close_tx: tokio::sync::watch::Sender<bool>,
    freeze_tx: tokio::sync::watch::Sender<bool>,
    closed: tokio::sync::oneshot::Receiver<()>,
}

/// Waits for `want`, returning `false` if the sender is gone. Wrapped so the
/// borrow of the watched value never crosses an await.
async fn watch_for(rx: &mut tokio::sync::watch::Receiver<bool>, want: bool) -> bool {
    rx.wait_for(|v| *v == want).await.is_ok()
}

impl TcpFront {
    async fn start(upstream_api_port: u16) -> Result<Self> {
        let port = free_port();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
        let (close_tx, mut close_rx) = tokio::sync::watch::channel(false);
        let (freeze_tx, freeze_rx) = tokio::sync::watch::channel(false);
        let (closed_tx, closed) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let mut conns = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = close_rx.changed() => break,
                    accepted = listener.accept() => match accepted {
                        Ok((mut downstream, _)) => {
                            let mut frozen = freeze_rx.clone();
                            conns.spawn(async move {
                                let up = TcpStream::connect((Ipv4Addr::LOCALHOST, upstream_api_port)).await;
                                if let Ok(mut upstream) = up {
                                    // Both sockets stay open while frozen, so
                                    // neither peer sees an EOF or an error —
                                    // the bytes simply stop.
                                    loop {
                                        let paused = tokio::select! {
                                            _ = tokio::io::copy_bidirectional(
                                                &mut downstream,
                                                &mut upstream,
                                            ) => false,
                                            paused = watch_for(&mut frozen, true) => paused,
                                        };
                                        if !paused || !watch_for(&mut frozen, false).await {
                                            break;
                                        }
                                    }
                                }
                            });
                        }
                        Err(_) => break,
                    },
                    // Reaps finished proxies so the set does not grow.
                    _ = conns.join_next(), if !conns.is_empty() => {}
                }
            }
            // Connections die, then the port frees, then `close()` returns.
            drop(conns);
            drop(listener);
            let _ = closed_tx.send(());
        });

        Ok(Self {
            port,
            close_tx,
            freeze_tx,
            closed,
        })
    }

    /// Stops forwarding in both directions, leaving every socket open.
    fn freeze(&self) {
        self.freeze_tx.send_replace(true);
    }

    fn unfreeze(&self) {
        self.freeze_tx.send_replace(false);
    }

    async fn close(self) {
        self.close_tx.send_replace(true);
        let _ = timeout(IO_TIMEOUT, self.closed).await;
    }
}

/// A relay that completes the QUIC handshake and then closes without ever
/// granting stream credit, so the client's control exchange fails on `open_bi()`
/// every time and every failed attempt stays on the QUIC side.
fn start_stream_starved_relay() -> Result<u16> {
    install_crypto();

    let key = rcgen::KeyPair::generate()?;
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])?.self_signed(&key)?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der());

    let tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(tunnel_common::NoVerify))
        .with_single_cert(vec![cert_der], key_der.into())?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(0u32.into());
    server_config.transport_config(Arc::new(transport));

    let endpoint =
        quinn::Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let port = endpoint.local_addr()?.port();

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                if let Ok(conn) = incoming.await {
                    conn.close(quinn::VarInt::from_u32(7), b"starved on purpose");
                }
            });
        }
    });

    Ok(port)
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// A syntactically valid cert PEM seeding the primary connection's provisioner
/// cache, so `CertProvisioner::prepare` returns `Cached` and the ACME path is
/// never walked.
fn seeded_cert_pem(identity: &Arc<dyn TunnelKey>) -> String {
    let point = p256::ecdsa::VerifyingKey::from_sec1_bytes(&identity.public_key_raw())
        .expect("identity pubkey")
        .to_encoded_point(true);
    let client_id = hex::encode(&Sha256::digest(point.as_bytes())[..8]);
    rcgen::CertificateParams::new(vec![format!("{client_id}.localhost")])
        .expect("seed cert params")
        .self_signed(&RcgenRemoteKey::new(Arc::clone(identity)))
        .expect("seed cert")
        .pem()
}

/// Credentials path for the ACME account. Nothing should ever write it, and it
/// points outside the repo so a regression leaves its evidence in the temp dir.
fn acme_creds_path() -> String {
    std::env::temp_dir()
        .join(format!(
            "tunnel-client-tests-{}-acme-should-not-exist.json",
            std::process::id()
        ))
        .to_string_lossy()
        .into_owned()
}

/// A client with a secondary identity only in any meaningful sense: the primary
/// is present because the config requires it, but every assertion here runs
/// against the secondary, which never touches ACME.
fn tunnel_config(
    server_addr: String,
    local_addr: String,
    force_h2: bool,
    reconnect: ReconnectPolicy,
) -> TunnelConfig {
    let primary: Arc<dyn TunnelKey> =
        Arc::new(RcgenKey::generate(KeyAlgorithm::EcdsaP256).expect("primary key"));
    let secondary = RcgenKey::generate(KeyAlgorithm::EcdsaP256).expect("secondary key");

    TunnelConfig {
        server_addrs: vec![server_addr],
        local_addr,
        secondary_local_addr: None,
        domain_suffix: "localhost".to_string(),
        force_h2,
        pool_size: 1,
        acme_email: None,
        // Seeded by `cert_pem` below; a cache miss here would reach LE staging.
        acme_creds_path: acme_creds_path(),
        acme_staging: true,
        cert_pem: Some(seeded_cert_pem(&primary)),
        on_cert_issued: None,
        on_connection_event: None,
        primary_identity: TunnelIdentityConfig {
            keypair: primary,
            cert_extension: None,
        },
        reconnect,
        h2_keepalive: H2KeepAlive::default(),
        self_signed_identity: Some(TunnelIdentityConfig {
            keypair: Arc::new(secondary),
            cert_extension: None,
        }),
    }
}

fn build_client(
    server_addr: String,
    local_addr: String,
    force_h2: bool,
    reconnect: ReconnectPolicy,
) -> Arc<TunnelClient> {
    build_client_with(server_addr, local_addr, force_h2, reconnect, |_| {})
}

/// [`build_client`] with a hook for the fields only a couple of tests care
/// about (`pool_size`, extra `server_addrs`, the event sink), so the common
/// helpers keep their short signatures.
fn build_client_with(
    server_addr: String,
    local_addr: String,
    force_h2: bool,
    reconnect: ReconnectPolicy,
    customize: impl FnOnce(&mut TunnelConfig),
) -> Arc<TunnelClient> {
    let mut config = tunnel_config(server_addr, local_addr, force_h2, reconnect);
    customize(&mut config);
    Arc::new(TunnelClient::new(config).expect("build client"))
}

// ---------------------------------------------------------------------------
// Connection events
// ---------------------------------------------------------------------------

/// Records every [`ConnectionEvent`] the client under test emits.
///
/// The sink runs inline on the connection's own task, so it only pushes.
#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<ConnectionEvent>>>);

impl Events {
    fn sink(&self) -> Arc<dyn Fn(ConnectionEvent) + Send + Sync> {
        let seen = Arc::clone(&self.0);
        Arc::new(move |ev| {
            seen.lock().unwrap_or_else(|e| e.into_inner()).push(ev);
        })
    }

    fn all(&self) -> Vec<ConnectionEvent> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn count(&self, pred: impl Fn(&ConnectionEvent) -> bool) -> usize {
        self.all().iter().filter(|e| pred(e)).count()
    }

    /// Waits for a matching event, or fails with everything seen so far —
    /// which is the part worth reading when this times out.
    async fn wait_for(
        &self,
        within: Duration,
        what: &str,
        pred: impl Fn(&ConnectionEvent) -> bool,
    ) -> Result<ConnectionEvent> {
        poll_until(within, Duration::from_millis(50), what, || {
            self.all().into_iter().find(|e| pred(e))
        })
        .await
        .map_err(|e| anyhow::anyhow!("{e}; events seen: {:?}", self.all()))
    }
}

fn is_established(ev: &ConnectionEvent, want_tag: &str, want_transport: Transport) -> bool {
    matches!(
        ev,
        ConnectionEvent::Established { tag, transport, .. }
            if tag == want_tag && *transport == want_transport
    )
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

/// Opens a user connection through the relay to `sni`, terminating TLS against
/// the tunnel client's self-signed cert (hence no verification here).
async fn connect_through_tunnel(
    pub_port: u16,
    sni: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    install_crypto();
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(tunnel_common::NoVerify))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    let tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, pub_port)).await?;
    let name = rustls::pki_types::ServerName::try_from(sni.to_string())?;
    Ok(connector.connect(name, tcp).await?)
}

/// Writes `tag` and reads it back, proving the session reaches the echo target.
async fn round_trip(tls: &mut tokio_rustls::client::TlsStream<TcpStream>, tag: &Tag) -> Result<()> {
    tls.write_all(tag).await?;
    let mut buf = [0u8; 8];
    tls.read_exact(&mut buf).await?;
    anyhow::ensure!(&buf == tag, "tunnel should forward to the local target");
    Ok(())
}

/// One readiness attempt, bounded so a stalled tunnel cannot park the loop.
async fn probe(pub_port: u16, sni: &str) -> Result<()> {
    timeout(IO_TIMEOUT, async {
        let mut tls = connect_through_tunnel(pub_port, sni).await?;
        round_trip(&mut tls, &PROBE_TAG).await
    })
    .await
    .map_err(|_| anyhow::anyhow!("probe timed out after {IO_TIMEOUT:?}"))?
}

/// Retries until the tunnel is carrying traffic, so tests don't race startup.
async fn wait_until_ready(pub_port: u16, sni: &str, relay_err: &RelayErr) -> Result<()> {
    let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
    let mut last: Option<anyhow::Error> = None;

    while tokio::time::Instant::now() < deadline {
        if let Some(e) = relay_err.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            anyhow::bail!("relay is not running: {e}");
        }
        match probe(pub_port, sni).await {
            Ok(()) => return Ok(()),
            Err(e) => last = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    anyhow::bail!("tunnel never became ready: {last:?}")
}

/// Relay + echo target + a running tunnel, ready to carry traffic. `force_h2`
/// picks the transport: `false` the QUIC path, `true` the HTTP/2 pool.
async fn setup(
    force_h2: bool,
) -> Result<(
    EchoTarget,
    Arc<TunnelClient>,
    u16,
    String,
    tokio::task::JoinHandle<Result<()>>,
)> {
    setup_with(force_h2, |_| {}).await
}

/// [`setup`] with a hook on the client's config, and the relay address it
/// dialled — the address the event tests match `server_addr` against.
async fn setup_with(
    force_h2: bool,
    customize: impl FnOnce(&mut TunnelConfig),
) -> Result<(
    EchoTarget,
    Arc<TunnelClient>,
    u16,
    String,
    tokio::task::JoinHandle<Result<()>>,
)> {
    init_logging();
    let (api_port, pub_port, relay_err) = start_relay();
    let echo = EchoTarget::start().await?;
    let client = build_client_with(
        format!("127.0.0.1:{api_port}"),
        echo.addr.to_string(),
        force_h2,
        ReconnectPolicy::default(),
        customize,
    );
    let sni = client
        .secondary_url()
        .expect("secondary configured")
        .trim_start_matches("https://")
        .to_string();

    let run = tokio::spawn(Arc::clone(&client).run());
    wait_until_ready(pub_port, &sni, &relay_err).await?;
    Ok((echo, client, pub_port, sni, run))
}

/// Opens a session and proves it forwards, leaving it open for the caller.
/// Returns the stream plus the echo target's id for *this* connection, so the
/// caller can assert on that connection's release specifically.
async fn open_session(
    pub_port: u16,
    sni: &str,
    echo: &mut EchoTarget,
) -> Result<(tokio_rustls::client::TlsStream<TcpStream>, u64)> {
    // Everything before this point (probing, mostly) is another test's business.
    echo.drain();

    let tag = session_tag();
    let mut tls = timeout(IO_TIMEOUT, connect_through_tunnel(pub_port, sni))
        .await
        .map_err(|_| anyhow::anyhow!("opening a session timed out after {IO_TIMEOUT:?}"))??;
    timeout(IO_TIMEOUT, round_trip(&mut tls, &tag))
        .await
        .map_err(|_| anyhow::anyhow!("session round trip timed out after {IO_TIMEOUT:?}"))??;

    let id = echo.opened_with(&tag).await?;
    Ok((tls, id))
}

// ---------------------------------------------------------------------------
// Tests: forwarding and release
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn forwards_traffic_and_releases_it_when_run_is_dropped() -> Result<()> {
    let (mut echo, _client, pub_port, sni, run) = setup(false).await?;
    let (_session, id) = open_session(pub_port, &sni, &mut echo).await?;

    // Cancellation alone, with no `stop()` first — what the foreign side does
    // when it drops the `run()` future.
    run.abort();

    // The local target seeing EOF proves the forwarding task let go of both its
    // TCP connection and its tunnel streams.
    echo.wait_closed(id, RELEASE_TIMEOUT).await?;
    assert_no_acme_activity();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_alone_releases_forwarded_connections() -> Result<()> {
    let (mut echo, client, pub_port, sni, run) = setup(false).await?;
    let (_session, id) = open_session(pub_port, &sni, &mut echo).await?;

    // No abort: `stop()` on its own has to reach the forwarding tasks.
    client.stop();

    echo.wait_closed(id, RELEASE_TIMEOUT).await?;

    timeout(RELEASE_TIMEOUT, run)
        .await
        .expect("run() should return after stop()")
        .expect("run() should not panic")
        .expect("run() should return Ok after stop()");
    assert_no_acme_activity();
    Ok(())
}

/// The HTTP/2 pool has its own accept loop, its own `JoinSet` of forwards, and
/// its own shutdown loop — none of which the QUIC tests reach.
#[tokio::test(flavor = "multi_thread")]
async fn h2_pool_forwards_and_releases_on_stop() -> Result<()> {
    let (mut echo, client, pub_port, sni, run) = setup(true).await?;
    let (_session, id) = open_session(pub_port, &sni, &mut echo).await?;

    client.stop();

    echo.wait_closed(id, RELEASE_TIMEOUT).await?;

    timeout(RELEASE_TIMEOUT, run)
        .await
        .expect("run() should return after stop() on the H2 path")
        .expect("run() should not panic on the H2 path")
        .expect("run() should return Ok after stop() on the H2 path");
    assert_no_acme_activity();
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests: connection events
// ---------------------------------------------------------------------------

/// Both connections report `Established` once the tunnel carries traffic, and a
/// stop on request reports neither `Lost` nor `GaveUp`.
#[tokio::test(flavor = "multi_thread")]
async fn quic_reports_established_and_stays_quiet_on_a_clean_stop() -> Result<()> {
    let events = Events::default();
    let sink = events.sink();
    let (_echo, client, _pub_port, _sni, run) =
        setup_with(false, move |c| c.on_connection_event = Some(sink)).await?;

    let ev = events
        .wait_for(READY_TIMEOUT, "Established for PRI over QUIC", |e| {
            is_established(e, "PRI", Transport::Quic)
        })
        .await?;
    let ConnectionEvent::Established { server_addr, .. } = &ev else {
        unreachable!("matched above")
    };
    assert!(
        server_addr.starts_with("127.0.0.1:"),
        "Established should name the relay it connected to, got {server_addr:?}"
    );
    // The secondary carries the traffic in these tests, so it has to report too.
    events
        .wait_for(READY_TIMEOUT, "Established for SEC over QUIC", |e| {
            is_established(e, "SEC", Transport::Quic)
        })
        .await?;

    client.stop();
    timeout(RELEASE_TIMEOUT, run)
        .await
        .expect("run() should return after stop()")
        .expect("run() should not panic")
        .expect("run() should return Ok after stop()");

    let seen = events.all();
    assert!(
        !seen
            .iter()
            .any(|e| matches!(e, ConnectionEvent::Lost { .. })),
        "a tunnel stopped on request must not report a lost connection: {seen:?}"
    );
    assert!(
        !seen
            .iter()
            .any(|e| matches!(e, ConnectionEvent::GaveUp { .. })),
        "nothing gave up here: {seen:?}"
    );
    assert_no_acme_activity();
    Ok(())
}

/// The H2 pool is `pool_size` sockets behind one logical connection. A
/// consumer wants "the pool is up", not one event per socket — and certainly
/// not a `Lost` every time a single member of a live pool reconnects.
#[tokio::test(flavor = "multi_thread")]
async fn h2_pool_reports_one_established_for_the_whole_pool() -> Result<()> {
    let events = Events::default();
    let sink = events.sink();
    let (_echo, client, _pub_port, _sni, run) = setup_with(true, move |c| {
        c.pool_size = 3;
        c.on_connection_event = Some(sink);
    })
    .await?;

    events
        .wait_for(READY_TIMEOUT, "Established for SEC over H2", |e| {
            is_established(e, "SEC", Transport::H2)
        })
        .await?;

    client.stop();
    timeout(RELEASE_TIMEOUT, run)
        .await
        .expect("run() should return after stop() on the H2 path")
        .expect("run() should not panic on the H2 path")
        .expect("run() should return Ok after stop() on the H2 path");

    for tag in ["PRI", "SEC"] {
        assert_eq!(
            events.count(|e| is_established(e, tag, Transport::H2)),
            1,
            "a pool of 3 is one logical connection, so {tag} should report exactly one \
             Established: {:?}",
            events.all()
        );
    }
    assert!(
        !events
            .all()
            .iter()
            .any(|e| matches!(e, ConnectionEvent::Lost { .. })),
        "stopping the pool is not losing it: {:?}",
        events.all()
    );
    assert_no_acme_activity();
    Ok(())
}

/// One reachable relay and one that answers nothing: the dead address reports
/// `GaveUp` on its own while `run()` keeps going and the live tunnel keeps
/// forwarding.
#[tokio::test(flavor = "multi_thread")]
async fn partial_death_reports_gave_up_while_the_live_tunnel_keeps_serving() -> Result<()> {
    one_bad_relay_leaves_the_tunnel_serving(format!("127.0.0.1:{}", free_port())).await
}

/// One reachable relay and one that rejects every agent: the rejection costs
/// only that relay's connections, not the tunnel.
#[tokio::test(flavor = "multi_thread")]
async fn a_rejecting_relay_leaves_the_tunnel_serving() -> Result<()> {
    init_logging();
    let api_port = free_port();
    let (_pub_port, _relay_err) = start_relay_denying(api_port);
    let denying = format!("127.0.0.1:{api_port}");
    one_bad_relay_leaves_the_tunnel_serving(denying.clone()).await?;
    assert_logged(&denying, "rejected by relay");
    Ok(())
}

/// A client on one working relay plus `dead`: `dead` reports `GaveUp` for both
/// connections while `run()` keeps going and the working tunnel keeps forwarding.
async fn one_bad_relay_leaves_the_tunnel_serving(dead: String) -> Result<()> {
    let events = Events::default();
    let sink = events.sink();
    let dead_for_cfg = dead.clone();
    let (mut echo, client, pub_port, sni, run) = setup_with(false, move |c| {
        c.server_addrs.push(dead_for_cfg);
        // Bounded, so the dead address spends its budget in ~300ms. The live
        // one never fails a connect, so its attempt counter stays at zero.
        c.reconnect = unreachable_policy();
        c.on_connection_event = Some(sink);
    })
    .await?;

    for tag in ["PRI", "SEC"] {
        events
            .wait_for(GAVE_UP_TIMEOUT, "GaveUp for the unreachable relay", |e| {
                matches!(e, ConnectionEvent::GaveUp { tag: t, server_addr, .. }
                    if t == tag && server_addr == &dead)
            })
            .await?;
    }

    assert!(
        !run.is_finished(),
        "run() must keep going while one relay is still connected"
    );
    // The point of the event: the reachable half is still a working tunnel.
    let (_session, id) = open_session(pub_port, &sni, &mut echo).await?;

    client.stop();
    echo.wait_closed(id, RELEASE_TIMEOUT).await?;
    timeout(RELEASE_TIMEOUT, run)
        .await
        .expect("run() should return after stop()")
        .expect("run() should not panic")
        .expect("run() should return Ok after stop()");

    // Either transport: a slow local QUIC handshake may legitimately fall back
    // to the H2 pool. What matters is that the reachable relay came up at all.
    assert!(
        events.all().iter().any(|e| matches!(
            e,
            ConnectionEvent::Established { tag, server_addr, .. }
                if tag == "SEC" && server_addr != &dead
        )),
        "the reachable relay should still have reported Established: {:?}",
        events.all()
    );
    assert_no_acme_activity();
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests: giving up
// ---------------------------------------------------------------------------

/// Spends its whole budget in ~300ms of sleeping, so the give-up path is
/// reachable inside a test instead of a minute later.
fn unreachable_policy() -> ReconnectPolicy {
    ReconnectPolicy {
        max_attempts: 3,
        base_backoff: Duration::from_millis(100),
        max_backoff: Duration::from_millis(200),
        connect_timeout: Duration::from_millis(200),
    }
}

/// Backoff a client on [`unreachable_policy`] must sleep through before it may
/// give up: 100ms after the first failed attempt, 200ms after the second. A
/// "gave up" that arrives sooner than this did not actually spend its budget.
const MIN_GIVE_UP_ELAPSED: Duration = Duration::from_millis(290);

/// A client pointed at a real but unbound loopback port on the tiny retry budget
/// above, so every attempt fails at connect on both transports and both
/// connections run out of attempts. Covers [`ReconnectPolicy::connect_timeout`].
fn build_unreachable_client(force_h2: bool) -> (Arc<TunnelClient>, String, Events) {
    let server_addr = format!("127.0.0.1:{}", free_port());
    let events = Events::default();
    let sink = events.sink();
    let client = build_client_with(
        server_addr.clone(),
        format!("127.0.0.1:{}", free_port()),
        force_h2,
        unreachable_policy(),
        move |c| c.on_connection_event = Some(sink),
    );
    (client, server_addr, events)
}

/// Runs the client and asserts it ends by giving up rather than hanging: the
/// elapsed time shows the retry budget was really spent, and the logged
/// per-connection `reason` names why each connection gave up.
async fn run_until_gave_up(
    client: Arc<TunnelClient>,
    server_addr: &str,
    reason: &str,
    events: &Events,
) {
    let started = std::time::Instant::now();
    let ended = timeout(GAVE_UP_TIMEOUT, client.run())
        .await
        .unwrap_or_else(|_| panic!("run() should give up within {GAVE_UP_TIMEOUT:?}"));
    let elapsed = started.elapsed();
    let err = ended.expect_err("run() should fail once every connection has given up");
    eprintln!("gave up after {elapsed:?}: {err:#}");
    assert!(
        err.chain()
            .any(|c| c.to_string().contains("all tunnel connections gave up")),
        "run() should report that every connection gave up, got: {err:#}"
    );
    assert!(
        elapsed >= MIN_GIVE_UP_ELAPSED,
        "gave up after {elapsed:?}, sooner than the {MIN_GIVE_UP_ELAPSED:?} of backoff the \
         configured attempts require — the connections cannot have spent their budget"
    );
    assert_logged(server_addr, reason);
    // The error says only that everything gave up; the event names which.
    for tag in ["PRI", "SEC"] {
        assert!(
            events.all().iter().any(|e| matches!(
                e,
                ConnectionEvent::GaveUp { tag: t, server_addr: a, .. }
                    if t == tag && a == server_addr
            )),
            "{tag} should have reported GaveUp for {server_addr}: {:?}",
            events.all()
        );
    }
    assert_no_acme_activity();
}

fn assert_never_established(events: &Events) {
    assert!(
        !events
            .all()
            .iter()
            .any(|e| matches!(e, ConnectionEvent::Established { .. })),
        "nothing was ever established here: {:?}",
        events.all()
    );
}

/// Each failed attempt but the last, which gives up instead, was reported with
/// its number and backoff, and a cause containing `cause`.
fn assert_attempts_reported(events: &Events, tag: &str, retry_in: &[Duration], cause: &str) {
    let seen: Vec<(u32, Duration)> = events
        .all()
        .into_iter()
        .filter_map(|e| match e {
            ConnectionEvent::AttemptFailed {
                tag: t,
                attempt,
                cause: c,
                retry_in,
                ..
            } if t == tag => {
                assert!(c.contains(cause), "cause {c:?} lacks {cause:?}");
                Some((attempt, retry_in))
            }
            _ => None,
        })
        .collect();
    let expected: Vec<(u32, Duration)> = (1..).zip(retry_in.iter().copied()).collect();
    assert_eq!(seen, expected, "{tag} attempt reports");
}

/// The default transport: QUIC cannot connect, the H2 fallback cannot come up
/// either, and once the shared budget is spent `run()` has to surface that.
#[tokio::test(flavor = "multi_thread")]
async fn run_gives_up_when_relay_is_unreachable() -> Result<()> {
    init_logging();
    let (client, addr, events) = build_unreachable_client(false);
    // The whole line: a transport-prefixed `giving up` would mean one of the two
    // had taken the connection over for good.
    let reason = format!("TUNNEL[SEC/{addr}]: giving up after 3 failed attempts");
    run_until_gave_up(client, &addr, &reason, &events).await;
    assert_never_established(&events);
    assert_attempts_reported(
        &events,
        "SEC",
        &[Duration::from_millis(100), Duration::from_millis(200)],
        "",
    );
    assert_logged(&addr, "falling back to H2 for this attempt");
    Ok(())
}

/// The `force_h2` path: a pool that never comes up drains, costs an attempt, and
/// eventually bails out to `run()` instead of parking on the stop signal.
#[tokio::test(flavor = "multi_thread")]
async fn h2_only_gives_up_when_relay_is_unreachable() -> Result<()> {
    init_logging();
    let (client, addr, events) = build_unreachable_client(true);
    let reason = format!("TUNNEL[SEC/{addr}]: giving up after 3 failed attempts");
    run_until_gave_up(client, &addr, &reason, &events).await;
    assert_never_established(&events);
    Ok(())
}

/// Giving up with every attempt spent on QUIC alone: only a connect that
/// succeeds and then fails the control exchange keeps the budget purely QUIC's.
#[tokio::test(flavor = "multi_thread")]
async fn quic_gives_up_when_control_exchange_keeps_failing() -> Result<()> {
    init_logging();
    let port = start_stream_starved_relay()?;
    let server_addr = format!("127.0.0.1:{port}");
    let events = Events::default();
    let sink = events.sink();
    let client = build_client_with(
        server_addr.clone(),
        format!("127.0.0.1:{}", free_port()),
        false,
        unreachable_policy(),
        move |c| c.on_connection_event = Some(sink),
    );
    let reason = format!("TUNNEL[SEC/{server_addr}]: giving up after 3 failed attempts");
    run_until_gave_up(client, &server_addr, &reason, &events).await;
    assert_never_established(&events);
    // An exhausted budget must not restart the retry story on the other transport.
    assert_logged(&server_addr, "QUIC[");
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests: rejection by the relay
// ---------------------------------------------------------------------------

/// A client the relay's auth handler denies, on either transport: each rejection
/// costs one attempt at the maximum backoff, and the budget still runs out.
async fn rejected_by_relay_retries_then_gives_up(force_h2: bool) -> Result<()> {
    init_logging();
    let api_port = free_port();
    let (_pub_port, _relay_err) = start_relay_denying(api_port);
    let server_addr = format!("127.0.0.1:{api_port}");
    let events = Events::default();
    let sink = events.sink();
    let client = build_client_with(
        server_addr.clone(),
        format!("127.0.0.1:{}", free_port()),
        force_h2,
        unreachable_policy(),
        move |c| c.on_connection_event = Some(sink),
    );

    let started = std::time::Instant::now();
    let reason = format!(
        "TUNNEL[SEC/{server_addr}]: giving up after 3 failed attempts, \
         last one rejected by relay: unauthorized: auth handler rejected"
    );
    run_until_gave_up(client, &server_addr, &reason, &events).await;
    assert_never_established(&events);
    for tag in ["PRI", "SEC"] {
        assert_attempts_reported(
            &events,
            tag,
            &[Duration::from_millis(200), Duration::from_millis(200)],
            "rejected by relay: unauthorized",
        );
    }
    let needle = if force_h2 {
        format!("H2[SEC/{server_addr}#0]: rejected by relay")
    } else {
        format!("QUIC[SEC/{server_addr}]: rejected by relay")
    };
    assert_logged(&server_addr, &needle);
    // Two waits at max_backoff, not the 100ms + 200ms a plain failure costs.
    assert!(
        started.elapsed() >= Duration::from_millis(390),
        "rejections should back off at max_backoff, gave up after {:?}",
        started.elapsed()
    );

    let rejections = logs()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|l| l.contains(&server_addr) && l.contains("rejected by relay:"))
        .filter(|l| !l.contains("giving up"))
        .count();
    assert!(
        rejections >= 6,
        "each of PRI and SEC should have been rejected on all 3 attempts, saw {rejections}"
    );
    assert_no_acme_activity();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn h2_rejected_by_relay_retries_then_gives_up() -> Result<()> {
    rejected_by_relay_retries_then_gives_up(true).await
}

#[tokio::test(flavor = "multi_thread")]
async fn quic_rejected_by_relay_retries_then_gives_up() -> Result<()> {
    rejected_by_relay_retries_then_gives_up(false).await
}

// ---------------------------------------------------------------------------
// Tests: the H2 fallback is per attempt, not for good
// ---------------------------------------------------------------------------

/// [`Events::wait_for`], reporting the relay's own bind failure if it has one.
async fn wait_for_event(
    events: &Events,
    relay_err: &RelayErr,
    what: &str,
    pred: impl Fn(&ConnectionEvent) -> bool,
) -> Result<ConnectionEvent> {
    match events.wait_for(READY_TIMEOUT, what, pred).await {
        Ok(ev) => Ok(ev),
        Err(e) => match relay_err.lock().unwrap_or_else(|p| p.into_inner()).clone() {
            Some(msg) => anyhow::bail!("{e:#}; relay is not running: {msg}"),
            None => Err(e),
        },
    }
}

/// A QUIC connect that fails once must cost the current attempt only, not the
/// lifetime of the client. Staged on one port: a [`TcpFront`] serves TCP with
/// nothing on UDP, then a real relay with a QUIC endpoint takes the port over.
#[tokio::test(flavor = "multi_thread")]
async fn quic_is_retried_after_an_h2_fallback_session() -> Result<()> {
    init_logging();
    let (api_port, _pub_port, relay_err) = start_relay();
    let echo = EchoTarget::start().await?;

    // Phase 1: TCP reaches the relay, UDP reaches nothing.
    let front = TcpFront::start(api_port).await?;
    let front_port = front.port;
    let addr = format!("127.0.0.1:{front_port}");

    let events = Events::default();
    let sink = events.sink();
    let client = build_client_with(
        addr.clone(),
        echo.addr.to_string(),
        /* force_h2 */ false,
        // Unlimited attempts, as on mobile, with short waits.
        ReconnectPolicy {
            max_attempts: 0,
            base_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(200),
            connect_timeout: Duration::from_millis(500),
        },
        move |c| c.on_connection_event = Some(sink),
    );
    let run = tokio::spawn(Arc::clone(&client).run());

    wait_for_event(&events, &relay_err, "Established for SEC over H2", |e| {
        is_established(e, "SEC", Transport::H2)
    })
    .await?;
    assert_logged(&addr, "falling back to H2 for this attempt");

    // Phase 2: a real relay, UDP included, takes the port.
    front.close().await;
    let (_pub_port2, relay2_err) = start_relay_on(front_port);

    wait_for_event(&events, &relay2_err, "Lost on the H2 transport", |e| {
        matches!(
            e,
            ConnectionEvent::Lost {
                transport: Transport::H2,
                ..
            }
        )
    })
    .await?;
    wait_for_event(&events, &relay2_err, "Established for SEC over QUIC", |e| {
        is_established(e, "SEC", Transport::Quic)
    })
    .await?;

    client.stop();
    timeout(RELEASE_TIMEOUT, run)
        .await
        .expect("run() should return after stop()")
        .expect("run() should not panic")
        .expect("run() should return Ok after stop()");
    assert_no_acme_activity();
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests: H2 liveness
// ---------------------------------------------------------------------------

/// PING liveness short enough to run in a test on both ends.
const FAST_KEEPALIVE: H2KeepAlive = H2KeepAlive {
    interval: Duration::from_millis(100),
    timeout: Duration::from_millis(300),
};

/// How long the two ends may take to notice a frozen connection, generously
/// above [`FAST_KEEPALIVE`] and far below the 20s an unnoticed one would cost.
const LIVENESS_TIMEOUT: Duration = Duration::from_secs(2);

/// A connection whose bytes stop moving while both sockets stay open is
/// invisible to TCP; only the PINGs notice. Asserts both ends react: the agent
/// leaves the pool and reconnects, the relay evicts it.
#[tokio::test(flavor = "multi_thread")]
async fn a_frozen_h2_connection_is_dropped_by_both_ends() -> Result<()> {
    init_logging();
    let api_port = free_port();
    let (pub_port, relay_err) = start_relay_with(api_port, FAST_KEEPALIVE, None);
    let echo = EchoTarget::start().await?;

    let front = TcpFront::start(api_port).await?;
    let addr = format!("127.0.0.1:{}", front.port);
    let events = Events::default();
    let sink = events.sink();
    let client = build_client_with(
        addr.clone(),
        echo.addr.to_string(),
        /* force_h2 */ true,
        ReconnectPolicy {
            max_attempts: 0,
            base_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(200),
            connect_timeout: Duration::from_millis(500),
        },
        move |c| {
            c.on_connection_event = Some(sink);
            c.h2_keepalive = FAST_KEEPALIVE;
        },
    );
    let sni = client
        .secondary_url()
        .expect("secondary configured")
        .trim_start_matches("https://")
        .to_string();
    let client_id = sni.split('.').next().expect("client_id label").to_string();
    let run = tokio::spawn(Arc::clone(&client).run());

    wait_for_event(&events, &relay_err, "Established for SEC over H2", |e| {
        is_established(e, "SEC", Transport::H2)
    })
    .await?;
    wait_until_ready(pub_port, &sni, &relay_err).await?;

    front.freeze();

    // Agent side: the pool goes down, which is what drives the reconnect.
    events
        .wait_for(LIVENESS_TIMEOUT, "Lost on the H2 transport", |e| {
            matches!(
                e,
                ConnectionEvent::Lost {
                    transport: Transport::H2,
                    ..
                }
            )
        })
        .await?;

    // Relay side: the agent is evicted, so a user connection is refused rather
    // than parked on a dead agent for the open timeout.
    wait_logged(&client_id, "no H2 PONG", LIVENESS_TIMEOUT).await?;
    let refused = timeout(LIVENESS_TIMEOUT, probe(pub_port, &sni))
        .await
        .map_err(|_| anyhow::anyhow!("the relay parked a user connection on a frozen agent"))?;
    assert!(
        refused.is_err(),
        "a probe through an evicted agent should fail, not forward"
    );

    // And the agent comes back once the bytes move again.
    front.unfreeze();
    wait_until_ready(pub_port, &sni, &relay_err).await?;
    assert!(
        events.count(|e| is_established(e, "SEC", Transport::H2)) >= 2,
        "the pool should report Established again after recovering: {:?}",
        events.all()
    );

    client.stop();
    timeout(RELEASE_TIMEOUT, run)
        .await
        .expect("run() should return after stop()")
        .expect("run() should not panic")
        .expect("run() should return Ok after stop()");
    front.close().await;
    assert_no_acme_activity();
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests: relay shutdown
// ---------------------------------------------------------------------------

/// How long a QUIC agent may take to notice a relay that shut down gracefully.
/// Far below the idle timeout it would otherwise wait out.
const SHUTDOWN_NOTICE_TIMEOUT: Duration = Duration::from_secs(3);

/// A relay that closes its QUIC endpoint on the way out must be noticed at once,
/// the way an H2 agent notices the TCP reset — not after the idle timeout.
#[tokio::test(flavor = "multi_thread")]
async fn a_graceful_relay_shutdown_is_seen_by_a_quic_agent_at_once() -> Result<()> {
    init_logging();
    let api_port = free_port();
    let (pub_port, relay_err, shutdown) = start_relay_until(api_port, H2KeepAlive::default(), None);
    let echo = EchoTarget::start().await?;

    let addr = format!("127.0.0.1:{api_port}");
    let events = Events::default();
    let sink = events.sink();
    let client = build_client_with(
        addr.clone(),
        echo.addr.to_string(),
        /* force_h2 */ false,
        ReconnectPolicy {
            max_attempts: 0,
            base_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(200),
            connect_timeout: Duration::from_millis(500),
        },
        move |c| c.on_connection_event = Some(sink),
    );
    let sni = client
        .secondary_url()
        .expect("secondary configured")
        .trim_start_matches("https://")
        .to_string();
    let run = tokio::spawn(Arc::clone(&client).run());

    wait_for_event(&events, &relay_err, "Established for SEC over QUIC", |e| {
        is_established(e, "SEC", Transport::Quic)
    })
    .await?;
    wait_until_ready(pub_port, &sni, &relay_err).await?;

    shutdown.send(()).expect("relay should still be running");

    let lost = events
        .wait_for(SHUTDOWN_NOTICE_TIMEOUT, "Lost on the QUIC transport", |e| {
            matches!(
                e,
                ConnectionEvent::Lost {
                    transport: Transport::Quic,
                    ..
                }
            )
        })
        .await?;
    let ConnectionEvent::Lost { cause, .. } = &lost else {
        unreachable!("the predicate matched a Lost event")
    };
    assert!(
        cause.contains("relay shutting down"),
        "the loss should carry the relay's close reason, got {cause:?}"
    );

    client.stop();
    timeout(RELEASE_TIMEOUT, run)
        .await
        .expect("run() should return after stop()")
        .expect("run() should not panic")
        .expect("run() should return Ok after stop()");
    assert_no_acme_activity();
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests: stop before run, config validation
// ---------------------------------------------------------------------------

/// `stop()` called before `run()` is even spawned has to stick: the foreign side
/// can close a client while the runtime is still getting around to the task, and
/// a stop signal that only reaches consumers subscribed at the time is lost.
#[tokio::test(flavor = "multi_thread")]
async fn stop_before_run_returns_without_connecting() -> Result<()> {
    init_logging();
    // A listener that answers nothing but counts: the H2 pool would reach it on
    // its first attempt, so a zero count is proof the tunnel never started.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(sock);
        }
    });

    let client = build_client(
        format!("127.0.0.1:{port}"),
        format!("127.0.0.1:{}", free_port()),
        /* force_h2 */ true,
        // Default policy on purpose: if the stop is lost, the first retry sleeps
        // for seconds and the timeout below fires instead of passing by luck.
        ReconnectPolicy::default(),
    );

    client.stop();

    timeout(Duration::from_secs(2), Arc::clone(&client).run())
        .await
        .expect("run() should return at once when stop() preceded it")
        .expect("run() should return Ok after a stop() that preceded it");

    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "a client stopped before run() must not connect to the relay"
    );
    assert_no_acme_activity();
    Ok(())
}

/// A zero PING interval would spin the liveness loop; a zero timeout would
/// declare every connection dead on the first ping.
#[test]
fn a_degenerate_h2_keepalive_is_rejected() {
    for keepalive in [
        H2KeepAlive {
            interval: Duration::ZERO,
            timeout: Duration::from_secs(1),
        },
        H2KeepAlive {
            interval: Duration::from_secs(1),
            timeout: Duration::ZERO,
        },
    ] {
        let mut config = tunnel_config(
            "127.0.0.1:1".to_string(),
            "127.0.0.1:2".to_string(),
            true,
            unreachable_policy(),
        );
        config.h2_keepalive = keepalive;
        assert!(
            TunnelClient::new(config).is_err(),
            "{keepalive:?} should be rejected by TunnelClient::new"
        );
    }
}

/// A pool of zero connections can never carry traffic and never gives up either
/// (the `JoinSet` is empty from the start), so it has to be refused up front.
#[test]
fn zero_pool_size_is_rejected() {
    let mut config = tunnel_config(
        "127.0.0.1:1".to_string(),
        "127.0.0.1:2".to_string(),
        true,
        unreachable_policy(),
    );
    config.pool_size = 0;
    assert!(
        TunnelClient::new(config).is_err(),
        "pool_size 0 should be rejected by TunnelClient::new"
    );
}
