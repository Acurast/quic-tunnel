//! Foreign-language surface for the tunnel client.
//!
//! Exposes a [`TunnelClient`] uniffi object with an idiomatic shape: sync
//! constructor + getter, async [`TunnelClient::run`] driven by the foreign
//! coroutine runtime, and sync [`TunnelClient::stop`]. Lifecycle and ACME
//! cert events are pushed to the foreign side through a [`Handler`] trait.
//! The optional secondary signing key is implemented foreign-side as a
//! [`TunnelKey`] callback object (typically backed by Android Keystore).

use std::fmt::Debug;
use std::sync::{Arc, OnceLock};

use anyhow::Result;
use async_trait::async_trait;
use tunnel_client as tc;

/// Dedicated tokio runtime for driving foreign-side async sign callbacks.
///
/// `tc::TunnelKey::sign` is invoked synchronously by rustls/rcgen from two
/// distinct contexts: (1) the uniffi constructor (no runtime entered), and
/// (2) the uniffi async `run()` (already on a tokio worker). A foreign
/// `async sign()` future therefore can't be driven via
/// `Handle::current().block_on(...)` reliably. Using an isolated multi-threaded
/// runtime + `spawn` + a sync channel sidesteps both the no-runtime case and
/// the runtime-already-entered case.
fn foreign_key_runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("tunnel-foreign-key")
            .build()
            .expect("foreign key runtime")
    })
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
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct TunnelInfo {
    pub url: String,
    pub client_id: String,
    pub secondary_url: Option<String>,
    pub secondary_client_id: Option<String>,
}

#[derive(uniffi::Enum, Clone, Debug)]
pub enum TunnelEvent {
    Started,
    Stopped,
    CertIssued { pem: String },
    Failed { cause: String },
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

/// Foreign-implemented event sink. Receives lifecycle and ACME events.
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
}

#[uniffi::export(async_runtime = "tokio")]
impl TunnelClient {
    #[uniffi::constructor]
    pub fn new(
        config: TunnelConfig,
        secondary_key: Option<Arc<dyn TunnelKey>>,
        handler: Arc<dyn Handler>,
    ) -> Result<Arc<Self>, TunnelError> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let primary_local = LocalKey::from_primary(&config.primary.key).map_err(|e| {
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

        let handler_for_cert = Arc::clone(&handler);
        let on_cert_issued: Arc<dyn Fn(String) + Send + Sync> = Arc::new(move |pem: String| {
            let h = Arc::clone(&handler_for_cert);
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    h.on_event(TunnelEvent::CertIssued { pem }).await;
                });
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
            primary_identity: primary,
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
        }))
    }

    pub fn info(&self) -> TunnelInfo {
        self.info.clone()
    }

    pub async fn run(&self) {
        self.handler.on_event(TunnelEvent::Started).await;
        let inner = Arc::clone(&self.inner);
        match inner.run().await {
            Ok(()) => self.handler.on_event(TunnelEvent::Stopped).await,
            Err(e) => {
                let chain = format_error_chain(&e);
                log::error!("tunnel run failed: {chain}");
                self.handler
                    .on_event(TunnelEvent::Failed { cause: chain })
                    .await
            }
        }
    }

    pub fn stop(&self) {
        self.inner.stop();
    }
}

/// In-process key built from job-supplied raw bytes (primary connection).
struct LocalKey {
    keypair: rcgen::KeyPair,
    algorithm: tc::KeyAlgorithm,
    raw_pub: Vec<u8>,
}

impl Debug for LocalKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalKey")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl LocalKey {
    fn from_primary(primary: &PrimaryKey) -> Result<Self> {
        let algorithm: tc::KeyAlgorithm = primary.algorithm.into();
        let keypair = match algorithm {
            tc::KeyAlgorithm::Ed25519 => {
                if primary.bytes.len() == 32 {
                    let pkcs8 = ed25519_seed_to_pkcs8(&primary.bytes);
                    let der = rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8);
                    rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&der, &rcgen::PKCS_ED25519)
                        .map_err(|e| anyhow::anyhow!("ed25519 keypair: {e}"))?
                } else {
                    rcgen::KeyPair::try_from(primary.bytes.as_slice())
                        .map_err(|e| anyhow::anyhow!("ed25519 keypair: {e}"))?
                }
            }
            tc::KeyAlgorithm::EcdsaP256 => rcgen::KeyPair::try_from(primary.bytes.as_slice())
                .map_err(|e| anyhow::anyhow!("p256 keypair (expect PKCS#8 DER): {e}"))?,
        };
        let raw_pub = keypair.public_key_raw().to_vec();
        Ok(Self {
            keypair,
            algorithm,
            raw_pub,
        })
    }
}

impl tc::TunnelKey for LocalKey {
    fn algorithm(&self) -> tc::KeyAlgorithm {
        self.algorithm
    }
    fn public_key_raw(&self) -> Vec<u8> {
        self.raw_pub.clone()
    }
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        use rcgen::SigningKey;
        self.keypair
            .sign(msg)
            .map_err(|e| anyhow::anyhow!("local sign failed: {e}"))
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
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let foreign = Arc::clone(&self.foreign);
        let msg = msg.to_vec();
        // The caller may be on a tokio worker (run() path) or on no runtime at
        // all (constructor path during cert/CSR generation). Drive the foreign
        // future on a dedicated runtime and block the calling thread on a sync
        // channel — independent of any ambient tokio context.
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);
        foreign_key_runtime().spawn(async move {
            let sig = foreign.sign(msg).await;
            let _ = tx.send(sig);
        });
        rx.recv()
            .map_err(|e| anyhow::anyhow!("foreign sign worker died: {e}"))
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

/// Wraps a raw 32-byte Ed25519 seed in a PKCS#8 DER blob suitable for rcgen.
fn ed25519_seed_to_pkcs8(seed: &[u8]) -> Vec<u8> {
    use yasna::models::ObjectIdentifier;
    let oid = ObjectIdentifier::from_slice(&[1, 3, 101, 112]);
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_u8(0);
            w.next().write_sequence(|w| {
                w.next().write_oid(&oid);
            });
            let inner = yasna::construct_der(|w| w.write_bytes(seed));
            w.next().write_bytes(&inner);
        });
    })
}
