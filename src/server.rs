use anyhow::Result;
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::{sync::Arc, any::Any, io::Write};
use tokio::net::TcpListener;
use tls_parser::{parse_tls_plaintext, parse_tls_extensions, TlsMessage, TlsMessageHandshake, TlsExtension};
use rand::seq::SliceRandom;
use tunnel::{IO, H2Send, H2Recv, cert, NoVerify};

type Map = Arc<DashMap<String, Vec<(u64, Agent)>>>;
#[derive(Clone)] enum Agent { Quic(quinn::Connection), H2(h2::client::SendRequest<bytes::Bytes>) }

#[tokio::main]
async fn main() -> Result<()> {
    let api = std::env::var("BIND_API").unwrap_or("0.0.0.0:4433".into());
    let pub_addr = std::env::var("BIND_PUB").unwrap_or("0.0.0.0:8443".into());
    println!("ROUTER: API {} | PUB {}", api, pub_addr);
    std::io::stdout().flush().unwrap();

    let map: Map = Arc::new(DashMap::new());
    let (c, k) = cert("tunnel");
    let v = Arc::new(NoVerify);

    let mut qc = quinn::ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(rustls::ServerConfig::builder().with_client_cert_verifier(v.clone()).with_single_cert(vec![c.clone()], k.clone_key())?)?));
    qc.transport_config(Arc::new({ let mut t = quinn::TransportConfig::default(); t.max_concurrent_bidi_streams(1000u32.into()); t }));
    let q_ep = quinn::Endpoint::server(qc, api.parse()?)?;

    let t_acc = tokio_rustls::TlsAcceptor::from(Arc::new(rustls::ServerConfig::builder().with_client_cert_verifier(v).with_single_cert(vec![c], k)?));
    let t_list = TcpListener::bind(&api).await?;
    let pub_list = TcpListener::bind(&pub_addr).await?;

    // QUIC Acceptor
    let m1 = map.clone();
    tokio::spawn(async move {
        while let Some(c) = q_ep.accept().await {
            let m = m1.clone();
            tokio::spawn(async move {
                let c = c.await.ok()?;
                let id = id_any(c.peer_identity()?)?;
                register(m, id, Agent::Quic(c), None).await;
                Some(())
            });
        }
    });

    // H2 Acceptor
    let m2 = map.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = t_list.accept().await {
            let (acc, m) = (t_acc.clone(), m2.clone());
            tokio::spawn(async move {
                let _ = s.set_nodelay(true);
                let s = acc.accept(s).await.ok()?;
                let id = id_raw(s.get_ref().1.peer_certificates()?.first()?.as_ref())?;
                let (h2, c) = h2::client::Builder::new().initial_window_size(10_000_000).initial_connection_window_size(10_000_000).handshake(s).await.ok()?;
                register(m, id, Agent::H2(h2), Some(c)).await;
                Some(())
            });
        }
    });

    // Public Acceptor
    while let Ok((mut usr, _)) = pub_list.accept().await {
        let _ = usr.set_nodelay(true);
        let map = map.clone();
        tokio::spawn(async move {
            let mut b = [0u8; 4096];
            let n = usr.peek(&mut b).await.ok()?;
            let host = sni(&b[..n])?;
            
            let agent = {
                let vec = map.get(host.split('.').next()?)?;
                if vec.is_empty() { return None; }
                vec.choose(&mut rand::thread_rng())?.1.clone()
            };

            let mut tun = match agent {
                Agent::Quic(c) => { let (s, r) = c.open_bi().await.ok()?; IO::new(r, s) },
                Agent::H2(c) => {
                    let (res, tx) = c.clone().send_request(http::Request::builder().uri("/").body(()).unwrap(), false).ok()?;
                    IO::new(H2Recv{r: res.await.ok()?.into_body(), b: bytes::Bytes::new()}, H2Send(tx))
                }
            };

            tokio::io::copy_bidirectional(&mut usr, &mut tun).await.ok();
            Some(())
        });
    }
    Ok(())
}

async fn register(m: Map, id: String, agent: Agent, conn: Option<h2::client::Connection<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, bytes::Bytes>>) {
    let uid: u64 = rand::random();
    println!("LINK ADD: {} (uid: {})", id, uid);
    std::io::stdout().flush().unwrap();
    m.entry(id).or_default().push((uid, agent));
    if let Some(c) = conn {
        tokio::spawn(async move { let _ = c.await; });
    }
}

fn id_any(any: Box<dyn Any>) -> Option<String> {
    let certs: Vec<rustls::pki_types::CertificateDer> = *any.downcast().ok()?;
    id_raw(certs.first()?.as_ref())
}

fn id_raw(cert: &[u8]) -> Option<String> {
    Some(hex::encode(&Sha256::digest(cert)[0..8]))
}

fn sni(b: &[u8]) -> Option<&str> {
    let (_, p) = parse_tls_plaintext(b).ok()?;
    let h = match p.msg.first()? { TlsMessage::Handshake(TlsMessageHandshake::ClientHello(h)) => h, _ => return None };
    let (_, exts) = parse_tls_extensions(h.ext?).ok()?;
    exts.iter().find_map(|e| match e { TlsExtension::SNI(v) => v.first().and_then(|(_, n)| std::str::from_utf8(n).ok()), _ => None })
}
