use anyhow::Result;
use clap::Parser;
use log::{error, info};
use std::{path::Path, sync::Arc};
use tunnel_client::key::KeyAlgorithm;
use tunnel_client::{TunnelClient, TunnelConfig, TunnelIdentityConfig, TunnelKey};

#[derive(Parser)]
struct Args {
    /// Relay server address(es); repeat the flag to connect to multiple servers
    #[arg(long, required = true)]
    server: Vec<String>,

    /// Local service address to forward traffic to
    #[arg(long, default_value = "127.0.0.1:3000")]
    local: String,

    /// Local service address the secondary (self-signed) connection forwards to.
    /// When unset, the secondary reuses `--local`. Only relevant with `--secondary-key`.
    #[arg(long)]
    secondary_local: Option<String>,

    /// Domain suffix for the tunnel URL (e.g. "yourserver.com")
    #[arg(long, default_value = "localhost")]
    domain_suffix: String,

    /// Path to the persistent primary keypair file (generated if absent)
    #[arg(long, default_value = "client.key")]
    primary_key: String,

    /// Skip QUIC and use HTTP/2 pool only
    #[arg(long)]
    force_h2: bool,

    /// Number of H2 connections in the pool
    #[arg(long, default_value_t = 4)]
    pool_size: usize,

    /// Email address for Let's Encrypt account registration (optional)
    #[arg(long)]
    acme_email: Option<String>,

    /// Path to persist ACME account credentials
    #[arg(long, default_value = "acme_credentials.json")]
    acme_creds_path: String,

    /// Use Let's Encrypt staging environment
    #[arg(long)]
    acme_staging: bool,

    /// Hex-encoded bytes to embed in the primary agent certificate
    #[arg(long)]
    primary_cert_extension_hex: Option<String>,

    /// Path to store/load the LE certificate PEM (loaded if present, written on fresh issuance)
    #[arg(long, default_value = "acme_cert.pem")]
    cert_pem: String,

    /// Optional path to a second persistent keypair. When set, the client opens
    /// a second connection per server that uses a plain self-signed cert (no
    /// ACME) to terminate user-facing tunnel TLS.
    #[arg(long)]
    secondary_key: Option<String>,

    /// Hex-encoded bytes to embed in the secondary agent certificate
    #[arg(long)]
    secondary_cert_extension_hex: Option<String>,
}

/// CLI-local `TunnelKey` backed by a file-system PKCS#8 keypair.
#[derive(Debug)]
struct LocalKey {
    keypair: rcgen::KeyPair,
    raw_pub: Vec<u8>,
    algorithm: KeyAlgorithm,
}

impl LocalKey {
    fn from_der(der: Vec<u8>) -> Result<Self> {
        let keypair = rcgen::KeyPair::try_from(der.as_slice())?;
        let raw_pub = keypair.public_key_raw().to_vec();
        let algorithm = if keypair.is_compatible(&rcgen::PKCS_ECDSA_P256_SHA256) {
            KeyAlgorithm::EcdsaP256
        } else if keypair.is_compatible(&rcgen::PKCS_ED25519) {
            KeyAlgorithm::Ed25519
        } else {
            anyhow::bail!("unsupported keypair algorithm in PKCS#8 file");
        };
        Ok(Self {
            keypair,
            raw_pub,
            algorithm,
        })
    }
}

impl TunnelKey for LocalKey {
    fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }
    fn public_key_raw(&self) -> Vec<u8> {
        self.raw_pub.clone()
    }
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        use rcgen::SigningKey;
        self.keypair
            .sign(msg)
            .map_err(|e| anyhow::anyhow!("rcgen sign failed: {e}"))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let primary_der = load_or_generate_keypair(&args.primary_key)?;
    let secondary_der = match &args.secondary_key {
        Some(path) => Some(load_or_generate_keypair(path)?),
        None => None,
    };
    let primary_identity: Arc<dyn TunnelKey> = Arc::new(LocalKey::from_der(primary_der)?);
    let self_signed_identity: Option<Arc<dyn TunnelKey>> = match secondary_der {
        Some(der) => Some(Arc::new(LocalKey::from_der(der)?)),
        None => None,
    };

    let primary_cert_extension = args
        .primary_cert_extension_hex
        .map(|h| hex::decode(&h))
        .transpose()?;
    let secondary_cert_extension = args
        .secondary_cert_extension_hex
        .map(|h| hex::decode(&h))
        .transpose()?;

    if self_signed_identity.is_none() && secondary_cert_extension.is_some() {
        log::warn!(
            "--secondary-cert-extension-hex ignored because --secondary-key was not provided"
        );
    }
    if self_signed_identity.is_none() && args.secondary_local.is_some() {
        log::warn!("--secondary-local ignored because --secondary-key was not provided");
    }

    let self_signed_identity_config = self_signed_identity.map(|keypair| TunnelIdentityConfig {
        keypair,
        cert_extension: secondary_cert_extension,
    });

    let config = TunnelConfig {
        server_addrs: args.server,
        local_addr: args.local,
        secondary_local_addr: args.secondary_local,
        domain_suffix: args.domain_suffix,
        force_h2: args.force_h2,
        pool_size: args.pool_size,
        acme_email: args.acme_email,
        acme_creds_path: args.acme_creds_path,
        acme_staging: args.acme_staging,
        cert_pem: load_cert_pem(&args.cert_pem)?,
        on_cert_issued: {
            let path = args.cert_pem.clone();
            Some(Arc::new(move |pem: String| {
                if let Err(e) = std::fs::write(&path, &pem) {
                    log::error!("failed to write cert to {}: {}", path, e);
                } else {
                    log::info!("certificate saved to {}", path);
                }
            }))
        },
        primary_identity: TunnelIdentityConfig {
            keypair: primary_identity,
            cert_extension: primary_cert_extension,
        },
        self_signed_identity: self_signed_identity_config,
    };

    let client = Arc::new(TunnelClient::new(config)?);
    info!("ID: {}", client.client_id());
    info!("URL: {}", client.url());
    if let (Some(id), Some(url)) = (client.secondary_client_id(), client.secondary_url()) {
        info!("secondary ID: {}", id);
        info!("secondary URL: {}", url);
    }

    let c = Arc::clone(&client);
    let tunnel = tokio::spawn(async move { c.run().await });

    // Exit on Ctrl-C, or when the tunnel ends on its own (e.g. a terminal
    // rejection by the relay) — surfacing its error so the process fails fast
    // instead of hanging.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            client.stop();
            Ok(())
        }
        res = tunnel => match res {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                error!("tunnel stopped: {e:#}");
                Err(e)
            }
            Err(e) => Err(anyhow::anyhow!("tunnel task join error: {e}")),
        },
    }
}

fn load_cert_pem(path: &str) -> Result<Option<String>> {
    if Path::new(path).exists() {
        Ok(Some(std::fs::read_to_string(path)?))
    } else {
        Ok(None)
    }
}

fn load_or_generate_keypair(path: &str) -> Result<Vec<u8>> {
    if Path::new(path).exists() {
        return Ok(std::fs::read(path)?);
    }
    let keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let der = keypair.serialize_der();
    std::fs::write(path, &der)?;
    Ok(der)
}
