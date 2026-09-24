use log::{debug, error, warn};
use tokio::net::TcpStream;
use tunnel_common::{H2Recv, H2Send, IO};

use crate::public::TUNNEL_OPEN_TIMEOUT;
use crate::{PendingAlpnConn, PendingAlpnMap, ServerChallenge};

/// Handles one ACME TLS-ALPN-01 challenge connection for the already-extracted
/// SNI `host`: serves the server's own challenge when it matches, otherwise
/// proxies the raw TLS bytes to the tunnel client registered for it.
pub(crate) async fn handle_acme(
    mut tcp: TcpStream,
    host: &str,
    pending: PendingAlpnMap,
    server_challenge: ServerChallenge,
) -> Option<()> {
    // Check for server's own ACME challenge before routing to a client.
    {
        let guard = server_challenge.lock().await;
        if let Some((domain, acceptor)) = guard.as_ref() {
            if host == domain.as_str() {
                let acceptor = acceptor.clone();
                drop(guard);
                debug!("ALPN: serving server's own challenge for {}", host);
                let _ = acceptor.accept(tcp).await;
                return Some(());
            }
        }
    }

    let client_id = host.split('.').next()?;
    debug!("ALPN: challenge for client_id={}", client_id);

    let conn = pending.get(client_id)?.conn.clone();
    match conn {
        PendingAlpnConn::Quic(qconn) => {
            let (send, recv) =
                match tokio::time::timeout(TUNNEL_OPEN_TIMEOUT, qconn.open_bi()).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        error!("ALPN: failed to open QUIC stream for {}: {}", client_id, e);
                        return None;
                    }
                    Err(_) => {
                        warn!(
                            "ALPN: opening a QUIC stream for {} timed out after {:?}",
                            client_id, TUNNEL_OPEN_TIMEOUT
                        );
                        return None;
                    }
                };
            let mut tunnel = IO::new(recv, send);
            let _ = tokio::io::copy_bidirectional(&mut tcp, &mut tunnel).await;
        }
        PendingAlpnConn::H2(mut sender) => {
            let req = http::Request::builder()
                .method("POST")
                .uri("/_ctrl/alpn")
                .body(())
                .unwrap();
            let (resp_future, send) = match sender.send_request(req, false) {
                Ok(r) => r,
                Err(e) => {
                    error!("ALPN: H2 send_request failed for {}: {}", client_id, e);
                    return None;
                }
            };
            let body = match tokio::time::timeout(TUNNEL_OPEN_TIMEOUT, resp_future).await {
                Ok(Ok(r)) => r.into_body(),
                Ok(Err(e)) => {
                    error!("ALPN: H2 stream for {} failed: {}", client_id, e);
                    return None;
                }
                Err(_) => {
                    warn!(
                        "ALPN: opening an H2 stream for {} timed out after {:?}",
                        client_id, TUNNEL_OPEN_TIMEOUT
                    );
                    return None;
                }
            };
            let mut h2_stream = IO::new(H2Recv::new(body), H2Send(send));
            let _ = tokio::io::copy_bidirectional(&mut tcp, &mut h2_stream).await;
        }
    }
    Some(())
}
