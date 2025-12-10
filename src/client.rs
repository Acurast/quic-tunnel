use anyhow::Result;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::net::TcpStream;
use futures::future::join_all;
use tunnel::{IO, H2Send, H2Recv, cert, NoVerify};

#[tokio::main]
async fn main() -> Result<()> {
    let svr = std::env::var("SERVER_ADDR").unwrap_or("127.0.0.1:4433".into());
    let loc = std::env::var("LOCAL_ADDR").unwrap_or("127.0.0.1:3000".into());
    let (ac, ak) = cert("agent");
    let id = hex::encode(&Sha256::digest(&ac)[0..8]);
    println!("ID: {}\nURL: https://{}.localhost:8443", id, id);

    let (wc, wk) = cert(&format!("{}.localhost", id));
    let term = tokio_rustls::TlsAcceptor::from(Arc::new(rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![wc], wk)?));

    if !std::env::var("FORCE_HTTP2").is_ok() {
        if let Ok(c) = connect_q(&svr, ac.clone(), ak.clone_key()).await {
            println!("MODE: QUIC");
            while let Ok((t, r)) = c.accept_bi().await { pipe(term.clone(), IO::new(r, t), loc.clone()); }
            return Ok(());
        }
    }

    println!("MODE: TCP/H2 (Pool)");
    join_all((0..std::env::var("POOL_SIZE").ok().and_then(|s| s.parse().ok()).unwrap_or(4)).map(|_| {
        let (c, k, t, sa, la) = (ac.clone(), ak.clone_key(), term.clone(), svr.clone(), loc.clone());
        tokio::spawn(async move { loop {
            if let Ok(mut s) = connect_h(&sa, c.clone(), k.clone_key()).await {
                while let Some(Ok((req, mut res))) = s.accept().await {
                    if let Ok(tx) = res.send_response(http::Response::new(()), false) {
                        pipe(t.clone(), IO::new(H2Recv{r: req.into_body(), b: bytes::Bytes::new()}, H2Send(tx)), la.clone());
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }})
    })).await;
    Ok(())
}

fn pipe(acc: tokio_rustls::TlsAcceptor, tun: IO, target: String) {
    tokio::spawn(async move {
        let mut s = acc.accept(tun).await.ok()?;
        let mut l = TcpStream::connect(&target).await.ok()?;
        let _ = tokio::io::copy_bidirectional(&mut s, &mut l).await;
        Some(())
    });
}

async fn connect_q(addr: &str, c: rustls::pki_types::CertificateDer<'static>, k: rustls::pki_types::PrivateKeyDer<'static>) -> Result<quinn::Connection> {
    let mut cfg = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(Arc::new(NoVerify)).with_client_auth_cert(vec![c], k)?)?));
    cfg.transport_config(Arc::new({ let mut t = quinn::TransportConfig::default(); t.max_concurrent_bidi_streams(1000u32.into()); t }));
    Ok(quinn::Endpoint::client("0.0.0.0:0".parse()?)?.connect_with(cfg, addr.parse()?, "localhost")?.await?)
}

async fn connect_h(addr: &str, c: rustls::pki_types::CertificateDer<'static>, k: rustls::pki_types::PrivateKeyDer<'static>) -> Result<h2::server::Connection<tokio_rustls::client::TlsStream<TcpStream>, bytes::Bytes>> {
    let tls = tokio_rustls::TlsConnector::from(Arc::new(rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(Arc::new(NoVerify)).with_client_auth_cert(vec![c], k)?));
    let tcp = TcpStream::connect(addr).await?; tcp.set_nodelay(true)?;
    Ok(h2::server::Builder::new().initial_window_size(10_000_000).initial_connection_window_size(10_000_000).handshake(tls.connect("localhost".try_into()?, tcp).await?).await?)
}
