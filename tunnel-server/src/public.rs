use anyhow::Result;
use log::{debug, error, warn};
use tokio::net::{TcpListener, TcpStream};
use tunnel_common::{H2Recv, H2Send, IO};

use crate::alpn::handle_acme;
use crate::util::extract_sni_alpn;
use crate::{Agent, AgentMap, PendingAlpnMap, ServerChallenge};

/// Single public listener on port 443. Peeks the TLS ClientHello and dispatches:
/// ACME TLS-ALPN-01 challenges (ALPN `acme-tls/1`) go to [`handle_acme`], all
/// other traffic is routed to the tunnel agent for the SNI's `client_id`. The
/// server never terminates TLS for either — it proxies raw bytes to the client.
pub(crate) async fn run_public_listener(
    listener: TcpListener,
    agents: AgentMap,
    pending_alpn: PendingAlpnMap,
    server_challenge: ServerChallenge,
) -> Result<()> {
    while let Ok((stream, remote)) = listener.accept().await {
        let _ = stream.set_nodelay(true);
        let agents = agents.clone();
        let pending_alpn = pending_alpn.clone();
        let server_challenge = server_challenge.clone();
        tokio::spawn(async move {
            let mut peek_buf = [0u8; 4096];
            let n = stream.peek(&mut peek_buf).await.ok()?;
            let (host, is_acme) = match extract_sni_alpn(&peek_buf[..n]) {
                Some(h) => h,
                None => {
                    warn!("PUB: no SNI in ClientHello from {}", remote);
                    return None;
                }
            };
            if is_acme {
                debug!("PUB: ACME challenge from {} for {}", remote, host);
                let host = host.to_owned();
                return handle_acme(stream, &host, pending_alpn, server_challenge).await;
            }
            let host = host.to_owned();
            handle_public(stream, &host, remote, agents).await
        });
    }
    Ok(())
}

/// Proxy a public user connection to the tunnel agent for `host`'s `client_id`.
async fn handle_public(
    mut user_stream: TcpStream,
    host: &str,
    remote: std::net::SocketAddr,
    agents: AgentMap,
) -> Option<()> {
    let client_id = host.split('.').next()?;
    debug!("PUB: {} -> client_id={}", remote, client_id);

    let agent = {
        let pool = agents.get(client_id)?;
        if pool.is_empty() {
            warn!(
                "PUB: no agent registered for client_id={} (from {})",
                client_id, remote
            );
            return None;
        }
        pool.next_agent()?
    };

    let mut tunnel = match agent {
        Agent::Quic(conn) => {
            debug!("PUB: opening QUIC stream to client_id={}", client_id);
            let (send, recv) = match conn.open_bi().await {
                Ok(s) => s,
                Err(e) => {
                    error!(
                        "PUB: failed to open QUIC stream for client_id={}: {}",
                        client_id, e
                    );
                    return None;
                }
            };
            IO::new(recv, send)
        }
        Agent::H2(mut sender) => {
            debug!("PUB: opening H2 stream to client_id={}", client_id);
            let req = http::Request::builder().uri("/").body(()).unwrap();
            let (response, send_stream) = match sender.send_request(req, false) {
                Ok(r) => r,
                Err(e) => {
                    error!(
                        "PUB: failed to open H2 stream for client_id={}: {}",
                        client_id, e
                    );
                    return None;
                }
            };
            let recv = H2Recv {
                r: response.await.ok()?.into_body(),
                buf: bytes::Bytes::new(),
            };
            IO::new(recv, H2Send(send_stream))
        }
    };

    debug!(
        "PUB: tunnel established {} -> client_id={}",
        remote, client_id
    );
    if let Err(e) = tokio::io::copy_bidirectional(&mut user_stream, &mut tunnel).await {
        debug!(
            "PUB: tunnel closed {} -> client_id={}: {}",
            remote, client_id, e
        );
    }
    Some(())
}
