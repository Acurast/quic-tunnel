//! Public connections for a passthrough hostname reach another TLS server on the
//! same host unchanged, while other hostnames are still routed to tunnel agents.

use std::{
    net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket},
    sync::Arc,
    time::Duration,
};

use rustls::pki_types::ServerName;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tunnel_common::NoVerify;
use tunnel_server::{ServerConfig, SniPassthrough};

const RELAY_HOST: &str = "relay.example.com";
const STEP_TIMEOUT: Duration = Duration::from_secs(5);

/// A port free for both TCP and UDP, since the server binds both on the API port.
fn free_port() -> u16 {
    for _ in 0..100 {
        let tcp = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind tcp");
        let port = tcp.local_addr().expect("local_addr").port();
        if StdUdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return port;
        }
    }
    panic!("no port free on both TCP and UDP");
}

fn server_config(api_port: u16, pub_port: u16, target: SocketAddr) -> ServerConfig {
    ServerConfig {
        bind_addr: "127.0.0.1".into(),
        api_port,
        pub_port,
        domain_suffixes: vec![],
        cert_path: None,
        key_path: None,
        acme_domain: None,
        acme_email: None,
        acme_creds_path: std::env::temp_dir()
            .join("sni_passthrough_unused_creds.json")
            .to_string_lossy()
            .into_owned(),
        acme_staging: true,
        acme_directory_url: None,
        acme_root_ca_path: None,
        acme_renew_days_before_expiry: 30,
        auth_handler: None,
        h2_keepalive: Default::default(),
        sni_passthrough: vec![SniPassthrough {
            hostname: RELAY_HOST.into(),
            target,
        }],
    }
}

/// A TLS server for `RELAY_HOST` that answers every connection with "relay: " and
/// the first message it receives, as the iroh relay terminating TLS would.
async fn spawn_relay() -> SocketAddr {
    let (cert, key) = tunnel_common::cert(RELAY_HOST);
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = acceptor.accept(stream).await.unwrap();
                let mut buf = [0u8; 64];
                let n = tls.read(&mut buf).await.unwrap();
                tls.write_all(&[b"relay: ".as_slice(), &buf[..n]].concat())
                    .await
                    .unwrap();
                tls.shutdown().await.unwrap();
            });
        }
    });
    addr
}

async fn connect_retrying(port: u16) -> TcpStream {
    for _ in 0..50 {
        if let Ok(stream) = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await {
            return stream;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("server did not start listening on {port}");
}

/// Sends "hello" over TLS with `sni` to the public port and returns the reply.
async fn exchange(pub_port: u16, sni: &str) -> std::io::Result<Vec<u8>> {
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let stream = connect_retrying(pub_port).await;
    let name = ServerName::try_from(sni.to_owned()).unwrap();
    let mut tls = connector.connect(name, stream).await?;
    tls.write_all(b"hello").await?;
    let mut reply = Vec::new();
    tls.read_to_end(&mut reply).await?;
    Ok(reply)
}

#[tokio::test]
async fn passthrough_hostname_reaches_its_target_and_others_do_not() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let target = spawn_relay().await;
    let (api_port, pub_port) = (free_port(), free_port());
    tokio::spawn(tunnel_server::run(server_config(
        api_port, pub_port, target,
    )));

    let reply = timeout(STEP_TIMEOUT, exchange(pub_port, RELAY_HOST))
        .await
        .expect("passthrough in time")
        .expect("passthrough");
    assert_eq!(reply, b"relay: hello");

    // Same check with the case changed: DNS names are case-insensitive.
    let reply = timeout(STEP_TIMEOUT, exchange(pub_port, "Relay.Example.Com"))
        .await
        .expect("passthrough in time")
        .expect("passthrough");
    assert_eq!(reply, b"relay: hello");

    // Another hostname goes to the tunnel agents; there is none, so it is closed.
    let other = timeout(STEP_TIMEOUT, exchange(pub_port, "abc.example.com"))
        .await
        .expect("closed in time");
    assert!(other.is_err() || other.unwrap().is_empty());
}
