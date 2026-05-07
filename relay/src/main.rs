use anyhow::Result;
use clap::Parser;
use tunnel_server::ServerConfig;

#[derive(Parser)]
struct Args {
    /// Bind address for all tunnel ports
    #[arg(long, default_value = "0.0.0.0")]
    bind_addr: String,

    /// API port for QUIC + H2 agent connections
    #[arg(long, default_value_t = 4433)]
    api_port: u16,

    /// Public port for user connections
    #[arg(long, default_value_t = 8443)]
    pub_port: u16,

    /// TLS-ALPN-01 challenge port (must be reachable as port 443)
    #[arg(long, default_value_t = 443)]
    alpn_port: u16,

    /// Allowed domain suffixes; clients with other suffixes are rejected.
    /// Repeat the flag for multiple suffixes: --domain-suffix a.com --domain-suffix b.com.
    /// If omitted, all client domains are accepted.
    #[arg(long)]
    domain_suffix: Vec<String>,

    /// Path to PEM certificate chain. When --acme-domain is set, this is where the
    /// provisioned cert is written/read (default: server_cert.pem). Without --acme-domain,
    /// the cert is used as-is with no auto-renewal. If omitted and --acme-domain is unset,
    /// a self-signed cert is generated.
    #[arg(long)]
    tls_cert: Option<String>,

    /// Path to PEM private key matching --tls-cert (default: server.key when --acme-domain is set).
    #[arg(long)]
    tls_key: Option<String>,

    /// Domain for ACME TLS-ALPN-01 certificate provisioning. When set, the cert at
    /// --tls-cert is server-managed and auto-renewed before expiry.
    #[arg(long)]
    acme_domain: Option<String>,

    /// Contact email for ACME account registration.
    #[arg(long)]
    acme_email: Option<String>,

    /// Path to persist ACME account credentials.
    #[arg(long, default_value = "server_acme_creds.json")]
    acme_creds_path: String,

    /// Use Let's Encrypt staging environment (for testing).
    #[arg(long)]
    acme_staging: bool,

    /// Trigger background ACME cert renewal this many days before expiry.
    /// Only applies when --acme-domain is set.
    #[arg(long, default_value_t = 30)]
    acme_renew_days: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let config = ServerConfig {
        bind_addr: args.bind_addr,
        api_port: args.api_port,
        pub_port: args.pub_port,
        alpn_port: args.alpn_port,
        domain_suffixes: args.domain_suffix,
        cert_path: args.tls_cert,
        key_path: args.tls_key,
        acme_domain: args.acme_domain,
        acme_email: args.acme_email,
        acme_creds_path: args.acme_creds_path,
        acme_staging: args.acme_staging,
        acme_renew_days_before_expiry: args.acme_renew_days,
        auth_handler: None,
    };
    tunnel_server::run(config).await
}
