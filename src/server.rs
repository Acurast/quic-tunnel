use anyhow::Result;
use dashmap::DashMap;
use rand::seq::SliceRandom;
use sha2::{Digest, Sha256};
use std::{any::Any, io::Write, sync::Arc};
use tls_parser::{parse_tls_extensions, parse_tls_plaintext, TlsExtension, TlsMessage, TlsMessageHandshake};
use tokio::net::TcpListener;
use tunnel::{cert, H2Recv, H2Send, NoVerify, IO};

type AgentMap = Arc<DashMap<String, Vec<(u64, Agent)>>>;

#[derive(Clone)]
enum Agent {
    Quic(quinn::Connection),
    H2(h2::client::SendRequest<bytes::Bytes>),
}

#[tokio::main]
async fn main() -> Result<()> {
    let api_addr = std::env::var("BIND_API").unwrap_or("0.0.0.0:4433".into());
    let pub_addr = std::env::var("BIND_PUB").unwrap_or("0.0.0.0:8443".into());
    println!("ROUTER: API {} | PUB {}", api_addr, pub_addr);
    std::io::stdout().flush().unwrap();

    let agents: AgentMap = Arc::new(DashMap::new());
    let (cert, key) = cert("tunnel");
    let verifier = Arc::new(NoVerify);

    // Configure QUIC server
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(1000u32.into());

    let quic_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(
            rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier.clone())
                .with_single_cert(vec![cert.clone()], key.clone_key())?,
        )?,
    ));

    let quic_endpoint = quinn::Endpoint::server(quic_config, api_addr.parse()?)?;

    // Configure TLS acceptor for HTTP/2
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![cert], key)?,
    ));

    let tcp_listener = TcpListener::bind(&api_addr).await?;
    let pub_listener = TcpListener::bind(&pub_addr).await?;

    // Accept QUIC connections
    let quic_agents = agents.clone();
    tokio::spawn(async move {
        while let Some(incoming) = quic_endpoint.accept().await {
            let agents = quic_agents.clone();
            tokio::spawn(async move {
                let conn = incoming.await.ok()?;
                let id = id_from_peer_identity(conn.peer_identity()?)?;
                register(&agents, id, Agent::Quic(conn), None).await;
                Some(())
            });
        }
    });

    // Accept HTTP/2 connections
    let h2_agents = agents.clone();
    tokio::spawn(async move {
        while let Ok((tcp_stream, _)) = tcp_listener.accept().await {
            let (acceptor, agents) = (tls_acceptor.clone(), h2_agents.clone());
            tokio::spawn(async move {
                let _ = tcp_stream.set_nodelay(true);
                let tls_stream = acceptor.accept(tcp_stream).await.ok()?;
                let peer_cert = tls_stream.get_ref().1.peer_certificates()?.first()?.as_ref();
                let id = id_from_cert(peer_cert)?;

                let (h2_sender, h2_conn) = h2::client::Builder::new()
                    .initial_window_size(10_000_000)
                    .initial_connection_window_size(10_000_000)
                    .handshake(tls_stream)
                    .await
                    .ok()?;

                register(&agents, id, Agent::H2(h2_sender), Some(h2_conn)).await;
                Some(())
            });
        }
    });

    // Accept public connections and route to agents
    while let Ok((mut user_stream, _)) = pub_listener.accept().await {
        let _ = user_stream.set_nodelay(true);
        let agents = agents.clone();

        tokio::spawn(async move {
            // Peek at TLS ClientHello to extract SNI
            let mut peek_buf = [0u8; 4096];
            let n = user_stream.peek(&mut peek_buf).await.ok()?;
            let host = extract_sni(&peek_buf[..n])?;
            let client_id = host.split('.').next()?;

            // Select random agent for this client
            let agent = {
                let agent_list = agents.get(client_id)?;
                if agent_list.is_empty() {
                    return None;
                }
                agent_list.choose(&mut rand::thread_rng())?.1.clone()
            };

            // Open tunnel to agent
            let mut tunnel = match agent {
                Agent::Quic(conn) => {
                    let (send, recv) = conn.open_bi().await.ok()?;
                    IO::new(recv, send)
                }
                Agent::H2(mut sender) => {
                    let req = http::Request::builder().uri("/").body(()).unwrap();
                    let (response, send_stream) = sender.send_request(req, false).ok()?;
                    let recv = H2Recv { r: response.await.ok()?.into_body(), buf: bytes::Bytes::new() };
                    IO::new(recv, H2Send(send_stream))
                }
            };

            tokio::io::copy_bidirectional(&mut user_stream, &mut tunnel).await.ok();
            Some(())
        });
    }

    Ok(())
}

async fn register(
    agents: &AgentMap,
    id: String,
    agent: Agent,
    h2_conn: Option<h2::client::Connection<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, bytes::Bytes>>,
) {
    let uid: u64 = rand::random();
    println!("LINK ADD: {} (uid: {})", id, uid);
    std::io::stdout().flush().unwrap();
    agents.entry(id).or_default().push((uid, agent));

    if let Some(conn) = h2_conn {
        tokio::spawn(async move { let _ = conn.await; });
    }
}

fn id_from_peer_identity(any: Box<dyn Any>) -> Option<String> {
    let certs: Vec<rustls::pki_types::CertificateDer> = *any.downcast().ok()?;
    id_from_cert(certs.first()?.as_ref())
}

fn id_from_cert(cert: &[u8]) -> Option<String> {
    Some(hex::encode(&Sha256::digest(cert)[0..8]))
}

fn extract_sni(data: &[u8]) -> Option<&str> {
    let (_, plaintext) = parse_tls_plaintext(data).ok()?;
    let hello = match plaintext.msg.first()? {
        TlsMessage::Handshake(TlsMessageHandshake::ClientHello(h)) => h,
        _ => return None,
    };
    let (_, extensions) = parse_tls_extensions(hello.ext?).ok()?;
    extensions.iter().find_map(|ext| match ext {
        TlsExtension::SNI(names) => names.first().and_then(|(_, name)| std::str::from_utf8(name).ok()),
        _ => None,
    })
}
