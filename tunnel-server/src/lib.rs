mod alpn;
mod cert;
mod h2_listener;
mod public;
mod quic;
mod util;

use anyhow::Result;
use dashmap::DashMap;
use log::info;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
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
type PendingAlpnMap = Arc<DashMap<String, PendingAlpnConn>>;

#[derive(Clone)]
enum PendingAlpnConn {
    Quic(quinn::Connection),
    H2(h2::client::SendRequest<bytes::Bytes>),
}

pub struct ServerConfig {
    pub bind_addr: String,
    pub api_port: u16,
    pub pub_port: u16,
    pub alpn_port: u16,
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
    /// Renew the server ACME cert this many days before expiry (default 30).
    /// Only applies when `acme_domain` is set; externally managed certs are unaffected.
    pub acme_renew_days_before_expiry: u32,
    /// Optional callback for client authentication. Called after extracting the
    /// client certificate's public key and custom extension data but before the
    /// control exchange. If the handler returns `Err`, the connection is denied.
    /// When `None`, all clients are accepted (current behavior).
    pub auth_handler: Option<AuthHandler>,
}

pub async fn run(config: ServerConfig) -> Result<()> {
    // Multiple rustls crypto providers (ring + aws-lc-rs) can be pulled in by
    // transitive deps, leaving no auto-detected default. Install ring explicitly;
    // ignore Err (already installed by another caller).
    let _ = rustls::crypto::ring::default_provider().install_default();
    let api_addr = format!("{}:{}", config.bind_addr, config.api_port);
    let pub_addr = format!("{}:{}", config.bind_addr, config.pub_port);
    let alpn_addr = format!("{}:{}", config.bind_addr, config.alpn_port);
    info!(
        "ROUTER: API {} | PUB {} | ALPN {}",
        api_addr, pub_addr, alpn_addr
    );
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

    // Bind and start ALPN listener before cert selection: the server's own ACME
    // TLS-ALPN-01 challenge must be handled here while provision_acme_cert() runs.
    let alpn_listener = TcpListener::bind(&alpn_addr).await?;
    tokio::spawn(alpn::run_alpn_listener(
        alpn_listener,
        pending_alpn.clone(),
        server_challenge.clone(),
    ));

    let cert_paths = cert::determine_cert(&config, &server_challenge).await?;
    let server_tls = cert::build_server_tls_config(&config, &cert_paths, &server_challenge)?;

    let quic_endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls.clone())?,
        )),
        api_addr.parse()?,
    )?;
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));
    let tcp_listener = TcpListener::bind(&api_addr).await?;
    let pub_listener = TcpListener::bind(&pub_addr).await?;

    let resolver = Arc::new(hickory_resolver::TokioAsyncResolver::tokio(
        hickory_resolver::config::ResolverConfig::default(),
        hickory_resolver::config::ResolverOpts::default(),
    ));
    let auth_handler = config.auth_handler.clone();
    tokio::spawn(quic::run_quic_listener(
        quic_endpoint,
        agents.clone(),
        pending_alpn.clone(),
        domain_suffixes.clone(),
        auth_handler.clone(),
        resolver.clone(),
    ));
    tokio::spawn(h2_listener::run_h2_listener(
        tcp_listener,
        tls_acceptor,
        agents.clone(),
        pending_alpn,
        domain_suffixes,
        auth_handler,
        resolver,
    ));

    public::run_public_listener(pub_listener, agents).await
}
