mod admission;
mod alpn;
mod cert;
mod h2_listener;
mod public;
mod quic;
mod util;

use anyhow::Result;
use dashmap::DashMap;
use log::info;
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

/// Handler invoked after TLS handshake to authenticate a connecting client.
/// Receives the raw public key bytes
/// and the optional custom extension data (decoded from its OCTET STRING wrapper)
/// from the client's self-signed certificate.
///
/// Return values:
/// - `Ok(None)` — allow the connection, no DNS TXT verification.
/// - `Ok(Some(deployment_source))` — allow the connection; the server verifies
///   that a DNS TXT record at `_acu.<host>` matches
///   `base64(sha256(deployment_source || host))` before completing the control
///   exchange.
/// - `Err(...)` — deny the connection (the error message is logged).
pub type AuthHandler = Arc<dyn Fn(&[u8], Option<&[u8]>) -> Result<Option<Vec<u8>>> + Send + Sync>;
use tokio::net::TcpListener;
pub use tunnel_common::H2KeepAlive;
use tunnel_common::{QUIC_KEEP_ALIVE_INTERVAL, QUIC_MAX_IDLE_TIMEOUT};

type ServerChallenge = Arc<tokio::sync::Mutex<Option<(String, tokio_rustls::TlsAcceptor)>>>;

type AgentMap = Arc<DashMap<String, AgentPool>>;

#[derive(Clone)]
enum Agent {
    Quic(quinn::Connection),
    H2(h2::client::SendRequest<bytes::Bytes>),
}

struct AgentPool {
    counter: AtomicUsize,
    agents: Vec<(u64, Agent)>,
}

impl AgentPool {
    fn push(&mut self, uid: u64, agent: Agent) {
        self.agents.push((uid, agent));
    }
    fn remove(&mut self, uid: u64) {
        self.agents.retain(|(u, _)| *u != uid);
    }
    fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }
    fn next_agent(&self) -> Option<Agent> {
        if self.agents.is_empty() {
            return None;
        }
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.agents.len();
        Some(self.agents[idx].1.clone())
    }
}

impl Default for AgentPool {
    fn default() -> Self {
        Self {
            counter: AtomicUsize::new(0),
            agents: Vec::new(),
        }
    }
}

/// Tracks in-progress ACME TLS-ALPN-01 challenges. When Let's Encrypt connects
/// to port 443, we proxy the raw TCP bytes through the registered tunnel to the
/// client, which terminates the TLS handshake and presents the ALPN cert.
type PendingAlpnMap = Arc<DashMap<String, PendingAlpn>>;

/// One registered challenge connection, tagged so a reconnecting client's entry
/// is never removed by the cleanup of the connection it replaced.
struct PendingAlpn {
    token: u64,
    conn: PendingAlpnConn,
}

#[derive(Clone)]
enum PendingAlpnConn {
    Quic(quinn::Connection),
    H2(h2::client::SendRequest<bytes::Bytes>),
}

static PENDING_ALPN_TOKEN: AtomicU64 = AtomicU64::new(0);

/// Registers `conn` for `client_id`, returning the token identifying this entry.
fn pending_alpn_insert(pending: &PendingAlpnMap, client_id: &str, conn: PendingAlpnConn) -> u64 {
    let token = PENDING_ALPN_TOKEN.fetch_add(1, Ordering::Relaxed);
    pending.insert(client_id.to_string(), PendingAlpn { token, conn });
    token
}

/// Removes `client_id`'s entry only while it is still the one `token` identifies.
fn pending_alpn_remove(pending: &PendingAlpnMap, client_id: &str, token: u64) {
    pending.remove_if(client_id, |_, entry| entry.token == token);
}

/// State every accepted agent connection needs, shared by both listeners.
#[derive(Clone)]
struct ListenerCtx {
    agents: AgentMap,
    pending: PendingAlpnMap,
    domain_suffixes: Arc<Vec<String>>,
    auth_handler: Option<AuthHandler>,
    resolver: Arc<hickory_resolver::TokioAsyncResolver>,
}

pub struct ServerConfig {
    pub bind_addr: String,
    pub api_port: u16,
    /// Public traffic port. Must be reachable as port 443 so Let's Encrypt can
    /// complete TLS-ALPN-01 challenges; the same listener serves public user
    /// traffic and ACME challenges, dispatched by ALPN.
    pub pub_port: u16,
    /// Allowed domain suffixes (e.g. `["yourserver.com"]`). Clients whose domain
    /// does not end with one of these suffixes are rejected. If empty, the
    /// allowlist is disabled and all client domains are accepted.
    pub domain_suffixes: Vec<String>,
    /// Path to PEM certificate chain. When `acme_domain` is set this is where the
    /// provisioned cert is written/read (defaults to `"server_cert.pem"`); without
    /// `acme_domain` the cert is used as-is with no auto-renewal.
    pub cert_path: Option<String>,
    /// Path to PEM private key matching `cert_path` (defaults to `"server.key"` when
    /// `acme_domain` is set and `cert_path` is `None`).
    pub key_path: Option<String>,
    /// Server domain for ACME TLS-ALPN-01 provisioning (e.g. `"relay.example.com"`).
    /// When set, the cert at `cert_path` is server-managed and auto-renewed.
    pub acme_domain: Option<String>,
    /// Contact email for ACME account registration.
    pub acme_email: Option<String>,
    /// Path to persist ACME account credentials. Default: `"server_acme_creds.json"`.
    pub acme_creds_path: String,
    /// Use Let's Encrypt staging environment.
    pub acme_staging: bool,
    /// ACME directory URL to use instead of Let's Encrypt (e.g. a Pebble test server).
    pub acme_directory_url: Option<String>,
    /// PEM root CA to trust for the ACME server's HTTPS API instead of the default roots.
    pub acme_root_ca_path: Option<String>,
    /// Renew the server ACME cert this many days before expiry (default 30).
    /// Only applies when `acme_domain` is set; externally managed certs are unaffected.
    pub acme_renew_days_before_expiry: u32,
    /// Optional callback for client authentication, called before the control
    /// exchange; an `Err` denies the connection. `None` accepts all clients.
    pub auth_handler: Option<AuthHandler>,
    /// PING liveness for H2 agent connections; QUIC agents have the transport's
    /// own keep-alive.
    pub h2_keepalive: H2KeepAlive,
}

/// Bounds the memory an unauthenticated QUIC peer can park; the client itself
/// opens only the control stream toward the server.
const QUIC_MAX_BIDI_STREAMS: u32 = 256;
/// No uni streams are used by this protocol in either direction.
const QUIC_MAX_UNI_STREAMS: u32 = 0;
const QUIC_STREAM_RECEIVE_WINDOW: u32 = 1024 * 1024;
/// Total in-flight bytes a single connection may buffer; ~16 MB is >1 Gbit/s at
/// a 100 ms RTT, so it never throttles legitimate tunnel data.
const QUIC_RECEIVE_WINDOW: u32 = 16 * 1024 * 1024;

/// How long a shutdown waits for queued CONNECTION_CLOSE frames to reach peers.
const SHUTDOWN_FLUSH: Duration = Duration::from_secs(2);
/// Close reason peers see when the relay shuts down.
const SHUTDOWN_REASON: &[u8] = b"relay shutting down";

/// Aborts the task when dropped, so no exit path of `run_until` detaches it.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Closes the endpoint when dropped, so agents get a close frame rather than
/// waiting out their idle timeout.
struct CloseOnDrop(quinn::Endpoint);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.close(quinn::VarInt::from_u32(0), SHUTDOWN_REASON);
    }
}

fn quic_transport_config() -> Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(QUIC_MAX_BIDI_STREAMS.into());
    transport.max_concurrent_uni_streams(QUIC_MAX_UNI_STREAMS.into());
    transport.stream_receive_window(QUIC_STREAM_RECEIVE_WINDOW.into());
    transport.receive_window(QUIC_RECEIVE_WINDOW.into());
    transport.max_idle_timeout(Some(QUIC_MAX_IDLE_TIMEOUT.try_into()?));
    transport.keep_alive_interval(Some(QUIC_KEEP_ALIVE_INTERVAL));
    Ok(transport)
}

/// Runs the relay until its public listener ends.
pub async fn run(config: ServerConfig) -> Result<()> {
    run_until(config, std::future::pending()).await
}

/// [`run`] that also returns once `shutdown` resolves, closing the QUIC
/// endpoint first so agents fail over at once instead of timing out.
pub async fn run_until(config: ServerConfig, shutdown: impl Future<Output = ()>) -> Result<()> {
    // Err means another caller already installed a provider.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let api_addr = format!("{}:{}", config.bind_addr, config.api_port);
    let pub_addr = format!("{}:{}", config.bind_addr, config.pub_port);
    info!("ROUTER: API {} | PUB {}", api_addr, pub_addr);
    if config.domain_suffixes.is_empty() {
        info!("ROUTER: domain suffix allowlist disabled (accepting all domains)");
    } else {
        info!(
            "ROUTER: allowed domain suffixes: {:?}",
            config.domain_suffixes
        );
    }

    let domain_suffixes: Arc<Vec<String>> = Arc::new(config.domain_suffixes.clone());
    let pending_alpn: PendingAlpnMap = Arc::new(DashMap::new());
    let agents: AgentMap = Arc::new(DashMap::new());
    let server_challenge: ServerChallenge = Arc::new(tokio::sync::Mutex::new(None));

    // Accept before cert selection: the server's own challenge must be serviced
    // while provision_acme_cert() runs, or a cold provision deadlocks.
    let pub_listener = TcpListener::bind(&pub_addr).await?;
    let mut pub_handle = AbortOnDrop(tokio::spawn(public::run_public_listener(
        pub_listener,
        agents.clone(),
        pending_alpn.clone(),
        server_challenge.clone(),
    )));

    let cert_paths = cert::determine_cert(&config, &server_challenge).await?;
    let server_tls = cert::build_server_tls_config(&config, &cert_paths, &server_challenge)?;

    let mut quic_server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_tls.clone())?,
    ));
    quic_server_config.transport_config(Arc::new(quic_transport_config()?));
    let quic_endpoint = quinn::Endpoint::server(quic_server_config, api_addr.parse()?)?;
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));
    let tcp_listener = TcpListener::bind(&api_addr).await?;

    let resolver = Arc::new(hickory_resolver::TokioAsyncResolver::tokio(
        hickory_resolver::config::ResolverConfig::default(),
        hickory_resolver::config::ResolverOpts::default(),
    ));
    let ctx = ListenerCtx {
        agents: agents.clone(),
        pending: pending_alpn.clone(),
        domain_suffixes,
        auth_handler: config.auth_handler.clone(),
        resolver,
    };
    let _quic_handle = AbortOnDrop(tokio::spawn(quic::run_quic_listener(
        quic_endpoint.clone(),
        ctx.clone(),
    )));
    let _h2_handle = AbortOnDrop(tokio::spawn(h2_listener::run_h2_listener(
        tcp_listener,
        tls_acceptor,
        ctx,
        config.h2_keepalive,
    )));
    // Also covers a caller that simply drops this future.
    let endpoint = CloseOnDrop(quic_endpoint);

    tokio::pin!(shutdown);
    tokio::select! {
        joined = &mut pub_handle.0 => joined?,
        () = &mut shutdown => {
            info!("ROUTER: shutting down");
            endpoint.0.close(quinn::VarInt::from_u32(0), SHUTDOWN_REASON);
            let _ = tokio::time::timeout(SHUTDOWN_FLUSH, endpoint.0.wait_idle()).await;
            Ok(())
        }
    }
}
