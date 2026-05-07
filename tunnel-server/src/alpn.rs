use log::{debug, error};
use tokio::net::TcpListener;
use tunnel_common::{H2Recv, H2Send, IO};

use crate::util::extract_sni;
use crate::{PendingAlpnConn, PendingAlpnMap, ServerChallenge};

pub(crate) async fn run_alpn_listener(
    listener: TcpListener,
    pending: PendingAlpnMap,
    server_challenge: ServerChallenge,
) {
    while let Ok((mut tcp, remote)) = listener.accept().await {
        debug!("ALPN: incoming connection from {}", remote);
        let pending = pending.clone();
        let server_challenge = server_challenge.clone();
        tokio::spawn(async move {
            let mut peek_buf = [0u8; 4096];
            let n = tcp.peek(&mut peek_buf).await.ok()?;
            let host = extract_sni(&peek_buf[..n])?;

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

            let conn = pending.get(client_id)?.clone();
            match conn {
                PendingAlpnConn::Quic(qconn) => {
                    let (send, recv) = match qconn.open_bi().await {
                        Ok(s) => s,
                        Err(e) => {
                            error!("ALPN: failed to open QUIC stream for {}: {}", client_id, e);
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
                    let mut h2_stream = IO::new(
                        H2Recv {
                            r: resp_future.await.ok()?.into_body(),
                            buf: bytes::Bytes::new(),
                        },
                        H2Send(send),
                    );
                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut h2_stream).await;
                }
            }
            Some(())
        });
    }
}
