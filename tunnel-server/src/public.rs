use anyhow::Result;
use log::{debug, error, warn};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tunnel_common::{H2Recv, H2Send, IO};

use crate::alpn::handle_acme;
use crate::util::extract_sni_alpn;
use crate::{Agent, AgentMap, PendingAlpnMap, ServerChallenge};

/// Single public listener on port 443. Peeks the TLS ClientHello and dispatches
/// ACME TLS-ALPN-01 challenges to [`handle_acme`] and everything else to the
/// tunnel agent for the SNI's `client_id`, proxying raw bytes either way.
pub(crate) async fn run_public_listener(
    listener: TcpListener,
    agents: AgentMap,
    pending_alpn: PendingAlpnMap,
    server_challenge: ServerChallenge,
) -> Result<()> {
    loop {
        let (stream, remote) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("PUB: accept failed: {e}");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let agents = agents.clone();
        let pending_alpn = pending_alpn.clone();
        let server_challenge = server_challenge.clone();
        tokio::spawn(async move {
            let (host, is_acme) =
                match tokio::time::timeout(PEEK_TIMEOUT, peek_sni_alpn(&stream)).await {
                    Ok(Some(v)) => v,
                    Ok(None) => {
                        warn!("PUB: no SNI in ClientHello from {}", remote);
                        return None;
                    }
                    Err(_) => {
                        warn!(
                            "PUB: timed out after {:?} waiting for a ClientHello from {}",
                            PEEK_TIMEOUT, remote
                        );
                        return None;
                    }
                };
            if is_acme {
                debug!("PUB: ACME challenge from {} for {}", remote, host);
                return handle_acme(stream, &host, pending_alpn, server_challenge).await;
            }
            handle_public(stream, &host, remote, agents).await
        });
    }
}

/// Buffer for sniffing the ClientHello: grown only when the parser wants more
/// than was peeked. TLS caps a handshake record at 16 KiB.
const PEEK_BUF_INIT: usize = 4096;
const PEEK_BUF_MAX: usize = 16 * 1024;
/// Pause after a failed `accept`, so a persistent error cannot spin the loop.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);
/// Total budget for a peer to deliver a complete ClientHello.
const PEEK_TIMEOUT: Duration = Duration::from_secs(10);
/// Budget for the agent to accept a tunnel stream. An agent whose socket is
/// still open but whose peer is gone answers neither, and without this the user
/// connection waits on it forever.
pub(crate) const TUNNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const PEEK_POLL_MIN: Duration = Duration::from_millis(1);
const PEEK_POLL_MAX: Duration = Duration::from_millis(50);

/// Sniff SNI/ALPN from the ClientHello without consuming it, returning
/// `(sni_host, is_acme_tls_alpn)`.
async fn peek_sni_alpn(stream: &TcpStream) -> Option<(String, bool)> {
    let mut buf = vec![0u8; PEEK_BUF_INIT];
    let mut seen = 0usize;
    let mut backoff = PEEK_POLL_MIN;
    loop {
        let n = stream.peek(&mut buf).await.ok()?;
        if n == 0 {
            // Peer closed before sending a hello.
            return None;
        }
        if n > seen {
            if let Some((host, is_acme)) = extract_sni_alpn(&buf[..n]) {
                return Some((host.to_owned(), is_acme));
            }
            seen = n;
            backoff = PEEK_POLL_MIN;
            if n >= buf.len() {
                // The record needs more than we asked the socket for: grow, then
                // re-peek at once rather than waiting for new bytes.
                if buf.len() >= PEEK_BUF_MAX {
                    // A full buffer that still does not parse is not a hello we route.
                    return None;
                }
                buf.resize((buf.len() * 2).min(PEEK_BUF_MAX), 0);
                seen = 0;
                continue;
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(PEEK_POLL_MAX);
    }
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
            let (send, recv) = match tokio::time::timeout(TUNNEL_OPEN_TIMEOUT, conn.open_bi()).await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    error!(
                        "PUB: failed to open QUIC stream for client_id={}: {}",
                        client_id, e
                    );
                    return None;
                }
                Err(_) => {
                    warn!(
                        "PUB: opening a QUIC stream for client_id={} timed out after {:?}",
                        client_id, TUNNEL_OPEN_TIMEOUT
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
            let body = match tokio::time::timeout(TUNNEL_OPEN_TIMEOUT, response).await {
                Ok(Ok(r)) => r.into_body(),
                Ok(Err(e)) => {
                    error!("PUB: H2 stream for client_id={} failed: {}", client_id, e);
                    return None;
                }
                Err(_) => {
                    warn!(
                        "PUB: opening an H2 stream for client_id={} timed out after {:?}",
                        client_id, TUNNEL_OPEN_TIMEOUT
                    );
                    return None;
                }
            };
            IO::new(H2Recv::new(body), H2Send(send_stream))
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
