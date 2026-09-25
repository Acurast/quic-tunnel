//! The relay's H2 ACME wait against a hand-rolled agent: a live agent stays
//! registered for challenges, a silent one is dropped by PING liveness.

use std::{
    net::{Ipv4Addr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use p256::ecdsa::{Signature, VerifyingKey, recoverable};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rcgen::SigningKey;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use sha2::{Digest, Sha256};
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tunnel_common::{H2KeepAlive, NoVerify};
use tunnel_server::ServerConfig;

const KEEPALIVE: H2KeepAlive = H2KeepAlive {
    interval: Duration::from_millis(200),
    timeout: Duration::from_millis(300),
};
const STEP_TIMEOUT: Duration = Duration::from_secs(5);

type AgentConn = h2::server::Connection<TlsStream<TcpStream>, Bytes>;
type CtrlReq = (
    http::Request<h2::RecvStream>,
    h2::server::SendResponse<Bytes>,
);

/// A port free for both TCP and UDP, since the relay binds both on the API port.
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

fn relay_config(api_port: u16, pub_port: u16) -> ServerConfig {
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
            .join("h2_acme_wait_unused_creds.json")
            .to_string_lossy()
            .into_owned(),
        acme_staging: true,
        acme_directory_url: None,
        acme_root_ca_path: None,
        acme_renew_days_before_expiry: 30,
        auth_handler: None,
        h2_keepalive: KEEPALIVE,
    }
}

fn tls_connector(cert_key: Option<&rcgen::KeyPair>, alpn: &[u8]) -> TlsConnector {
    let builder = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify));
    let mut config = match cert_key {
        Some(key) => {
            let cert = rcgen::CertificateParams::new(vec!["agent".to_string()])
                .expect("cert params")
                .self_signed(key)
                .expect("self-signed agent cert");
            let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
            builder
                .with_client_auth_cert(vec![cert.der().clone()], key_der)
                .expect("client auth cert")
        }
        None => builder.with_no_client_auth(),
    };
    if !alpn.is_empty() {
        config.alpn_protocols = vec![alpn.to_vec()];
    }
    TlsConnector::from(Arc::new(config))
}

async fn connect_retrying(port: u16) -> TcpStream {
    for _ in 0..100 {
        if let Ok(tcp) = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await {
            return tcp;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("relay never accepted on port {port}");
}

/// Domain and 65-byte recoverable signature binding it to `identity`.
fn identity_proof(identity: &rcgen::KeyPair) -> (String, Vec<u8>) {
    let vk = VerifyingKey::from_sec1_bytes(identity.public_key_raw()).expect("identity pubkey");
    let compressed = vk.to_encoded_point(true);
    let id = hex::encode(&Sha256::digest(compressed.as_bytes())[0..8]);
    let domain = format!("{id}.localhost");
    let der = identity.sign(domain.as_bytes()).expect("sign domain");
    let sig = Signature::from_der(&der).expect("DER signature");
    let sig = sig.normalize_s().unwrap_or(sig);
    let rec = recoverable::Signature::from_trial_recovery(&vk, domain.as_bytes(), &sig)
        .expect("trial recovery");
    let bytes: &[u8] = rec.as_ref();
    (domain, bytes.to_vec())
}

async fn next_request(conn: &mut AgentConn, expected: &str) -> CtrlReq {
    let (req, resp) = timeout(STEP_TIMEOUT, conn.accept())
        .await
        .unwrap_or_else(|_| panic!("relay never sent {expected}"))
        .unwrap_or_else(|| panic!("connection closed before {expected}"))
        .expect("accept stream");
    assert_eq!(req.uri().path(), expected);
    (req, resp)
}

fn reply(mut resp: h2::server::SendResponse<Bytes>, body: &[u8]) {
    let mut send = resp
        .send_response(http::Response::new(()), false)
        .expect("send response");
    send.send_data(Bytes::copy_from_slice(body), true)
        .expect("send body");
}

/// Connects an agent and walks it into the ACME wait: authenticated, a
/// non-empty key_auth sent, `/_ctrl/done` received and left unanswered.
async fn agent_in_acme_wait(api_port: u16) -> (AgentConn, String, h2::server::SendResponse<Bytes>) {
    let tls_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("tls key");
    let identity =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("identity key");
    let (domain, sig) = identity_proof(&identity);

    let tcp = connect_retrying(api_port).await;
    let tls = tls_connector(Some(&tls_key), b"")
        .connect(ServerName::try_from("localhost").expect("name"), tcp)
        .await
        .expect("agent TLS handshake");
    let mut conn: AgentConn = h2::server::handshake(tls).await.expect("h2 handshake");

    let (_, resp) = next_request(&mut conn, "/_ctrl/domain").await;
    reply(resp, domain.as_bytes());
    let (_, resp) = next_request(&mut conn, "/_ctrl/sig").await;
    reply(resp, &sig);
    let (_, resp) = next_request(&mut conn, "/_ctrl/key_auth").await;
    reply(resp, b"test-key-authorization");
    let (_, done) = next_request(&mut conn, "/_ctrl/done").await;
    (conn, domain, done)
}

#[tokio::test]
async fn relay_drops_an_agent_that_goes_silent_during_the_acme_wait() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (api_port, pub_port) = (free_port(), free_port());
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let relay = tokio::spawn(tunnel_server::run_until(
        relay_config(api_port, pub_port),
        async {
            let _ = stop_rx.await;
        },
    ));

    let (mut conn, domain, _done) = agent_in_acme_wait(api_port).await;

    // Live agent: polling answers the PINGs, so several intervals pass unharmed.
    let idle = timeout(Duration::from_secs(1), conn.accept()).await;
    assert!(idle.is_err(), "relay dropped a live agent: {idle:?}");

    // Still registered for challenges: an acme-tls/1 hello reaches the agent.
    let probe = tokio::spawn(async move {
        let tcp = connect_retrying(pub_port).await;
        let name = ServerName::try_from(domain).expect("name");
        let _ = tls_connector(None, b"acme-tls/1").connect(name, tcp).await;
    });
    let (_, resp) = next_request(&mut conn, "/_ctrl/alpn").await;
    drop(resp);
    probe.abort();

    // Silent agent: socket open, nothing polled, PINGs unanswered.
    tokio::time::sleep(Duration::from_secs(2)).await;
    match timeout(STEP_TIMEOUT, conn.accept()).await {
        Ok(None) | Ok(Some(Err(_))) => {}
        Ok(Some(Ok((req, _)))) => panic!("unexpected request {}", req.uri()),
        Err(_) => panic!("relay kept a silent agent in the ACME wait"),
    }

    let _ = stop_tx.send(());
    timeout(STEP_TIMEOUT, relay)
        .await
        .expect("relay shuts down")
        .expect("relay task")
        .expect("relay result");
}
