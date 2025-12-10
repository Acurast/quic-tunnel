use anyhow::Result;
use futures::future::join_all;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::net::TcpStream;
use tunnel::{cert, H2Recv, H2Send, NoVerify, IO};

#[tokio::main]
async fn main() -> Result<()> {
    let server_addr = std::env::var("SERVER_ADDR").unwrap_or("127.0.0.1:4433".into());
    let local_addr = std::env::var("LOCAL_ADDR").unwrap_or("127.0.0.1:3000".into());

    // Generate client identity
    let (agent_cert, agent_key) = cert("agent");
    let client_id = hex::encode(&Sha256::digest(&agent_cert)[0..8]);
    println!("ID: {}\nURL: https://{}.localhost:8443", client_id, client_id);

    // TLS acceptor for incoming tunnel connections
    let (wildcard_cert, wildcard_key) = cert(&format!("{}.localhost", client_id));
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![wildcard_cert], wildcard_key)?,
    ));

    // Try QUIC first unless HTTP/2 is forced
    if std::env::var("FORCE_HTTP2").is_err() {
        if let Ok(conn) = connect_quic(&server_addr, agent_cert.clone(), agent_key.clone_key()).await {
            println!("MODE: QUIC");
            while let Ok((send, recv)) = conn.accept_bi().await {
                pipe(tls_acceptor.clone(), IO::new(recv, send), local_addr.clone());
            }
            return Ok(());
        }
    }

    // Fall back to HTTP/2 connection pool
    println!("MODE: TCP/H2 (Pool)");
    let pool_size: usize = std::env::var("POOL_SIZE").ok().and_then(|s| s.parse().ok()).unwrap_or(4);

    join_all((0..pool_size).map(|_| {
        let (cert, key, acceptor, server, local) = (
            agent_cert.clone(),
            agent_key.clone_key(),
            tls_acceptor.clone(),
            server_addr.clone(),
            local_addr.clone(),
        );
        tokio::spawn(async move {
            loop {
                if let Ok(mut h2_conn) = connect_h2(&server, cert.clone(), key.clone_key()).await {
                    while let Some(Ok((req, mut resp))) = h2_conn.accept().await {
                        if let Ok(send_stream) = resp.send_response(http::Response::new(()), false) {
                            let recv = H2Recv { r: req.into_body(), buf: bytes::Bytes::new() };
                            pipe(acceptor.clone(), IO::new(recv, H2Send(send_stream)), local.clone());
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })
    }))
    .await;

    Ok(())
}

/// Pipe tunnel traffic to local service
fn pipe(acceptor: tokio_rustls::TlsAcceptor, tunnel: IO, target: String) {
    tokio::spawn(async move {
        let mut tls_stream = acceptor.accept(tunnel).await.ok()?;
        let mut local_stream = TcpStream::connect(&target).await.ok()?;
        tokio::io::copy_bidirectional(&mut tls_stream, &mut local_stream).await.ok()
    });
}

/// Connect to server via QUIC
async fn connect_quic(
    addr: &str,
    cert: rustls::pki_types::CertificateDer<'static>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<quinn::Connection> {
    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_client_auth_cert(vec![cert], key)?;

    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(1000u32.into());

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    ));
    client_config.transport_config(Arc::new(transport));

    let endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    Ok(endpoint.connect_with(client_config, addr.parse()?, "localhost")?.await?)
}

/// Connect to server via HTTP/2 over TLS
async fn connect_h2(
    addr: &str,
    cert: rustls::pki_types::CertificateDer<'static>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<h2::server::Connection<tokio_rustls::client::TlsStream<TcpStream>, bytes::Bytes>> {
    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_client_auth_cert(vec![cert], key)?;

    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;

    let tls_stream = connector.connect("localhost".try_into()?, tcp).await?;
    Ok(h2::server::Builder::new()
        .initial_window_size(10_000_000)
        .initial_connection_window_size(10_000_000)
        .handshake(tls_stream)
        .await?)
}
