use log::{debug, warn};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::OwnedSemaphorePermit;
use tunnel_common::{
    CTRL_REJECT_PATH, H2_DATA_CONN_WINDOW, H2_DATA_STREAM_WINDOW, H2KeepAlive, MAX_CTRL_FRAME,
    collect_h2_body, h2_ping_loop,
};

use crate::admission::{AUTH_EXCHANGE_TIMEOUT, Admission, KEY_AUTH_TIMEOUT};
use crate::util::{
    allowed_suffix, custom_data_from_cert, pubkey_from_cert, recover_identity_pubkey, register,
    txt_authorizes,
};
use crate::{
    Agent, ListenerCtx, PendingAlpnConn, PendingAlpnMap, pending_alpn_insert, pending_alpn_remove,
};

/// Per-stage deadlines for bringing up a connection; a peer that stalls at any of
/// them would otherwise pin a task, a socket and its flow-control windows forever.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const H2_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Flow-control windows advertised to a peer that is not yet authenticated; a
/// control body is at most `MAX_CTRL_FRAME`. Raised on the live connection once
/// the identity signature checks out.
const CTRL_STREAM_WINDOW: u32 = 16 * 1024;
const CTRL_CONN_WINDOW: u32 = 64 * 1024;
/// Retry schedule for the post-authentication SETTINGS update: ~10s in total.
const WINDOW_RAISE_RETRY: Duration = Duration::from_millis(50);
const WINDOW_RAISE_ATTEMPTS: u32 = 200;
/// Budget for delivering a rejection reason before the connection is dropped.
const REJECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Pause after a failed `accept`, so a persistent error cannot spin the loop.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

type H2Conn = h2::client::Connection<tokio_rustls::server::TlsStream<TcpStream>, bytes::Bytes>;

pub(crate) async fn run_h2_listener(
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    ctx: ListenerCtx,
    keepalive: H2KeepAlive,
) {
    let mut admission = Admission::new("H2");
    loop {
        let (tcp_stream, remote) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("H2: accept failed: {e}");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        let Some(permit) = admission.try_admit(remote) else {
            drop(tcp_stream);
            continue;
        };
        debug!("H2: incoming connection from {}", remote);
        tokio::spawn(handle_h2_connection(
            tcp_stream,
            remote,
            acceptor.clone(),
            ctx.clone(),
            permit,
            keepalive,
        ));
    }
}

async fn handle_h2_connection(
    tcp_stream: TcpStream,
    remote: SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    ctx: ListenerCtx,
    permit: OwnedSemaphorePermit,
    keepalive: H2KeepAlive,
) -> Option<()> {
    let _ = tcp_stream.set_nodelay(true);
    let tls_stream =
        match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp_stream)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                warn!("H2: TLS handshake failed from {}: {}", remote, e);
                return None;
            }
            Err(_) => {
                warn!(
                    "H2: TLS handshake from {} timed out after {:?}",
                    remote, TLS_HANDSHAKE_TIMEOUT
                );
                return None;
            }
        };
    let peer_cert = tls_stream
        .get_ref()
        .1
        .peer_certificates()?
        .first()?
        .as_ref();
    let custom_data = custom_data_from_cert(peer_cert);
    if let Some(ref bytes) = custom_data {
        debug!("H2: {} custom data ({} bytes)", remote, bytes.len());
    }
    let auth_token: Option<Vec<u8>> = if let Some(ref handler) = ctx.auth_handler {
        let pubkey = match pubkey_from_cert(peer_cert) {
            Some(pk) => pk,
            None => {
                warn!("H2: could not extract pubkey from {}", remote);
                h2_reject(tls_stream, remote, "unauthorized: client certificate").await;
                return None;
            }
        };
        match handler(&pubkey, custom_data.as_deref()) {
            Ok(token) => token,
            Err(e) => {
                warn!("H2: auth denied for {}: {}", remote, e);
                h2_reject(tls_stream, remote, "unauthorized: auth handler rejected").await;
                return None;
            }
        }
    } else {
        None
    };
    debug!("H2: {} starting control exchange", remote);

    let (mut h2_sender, mut h2_conn) = match tokio::time::timeout(
        H2_HANDSHAKE_TIMEOUT,
        h2::client::Builder::new()
            .initial_window_size(CTRL_STREAM_WINDOW)
            .initial_connection_window_size(CTRL_CONN_WINDOW)
            .handshake(tls_stream),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            warn!("H2: handshake failed for {}: {}", remote, e);
            return None;
        }
        Err(_) => {
            warn!(
                "H2: handshake for {} timed out after {:?}",
                remote, H2_HANDSHAKE_TIMEOUT
            );
            return None;
        }
    };

    // Must be taken before the driver task owns the connection.
    let ping_pong = h2_conn.ping_pong();

    let (raise_tx, mut raise_rx) = tokio::sync::oneshot::channel::<()>();
    let conn_task = tokio::spawn(async move {
        let mut h2_conn = h2_conn;
        tokio::select! {
            _ = &mut h2_conn => return,
            signal = &mut raise_rx => {
                // Never authenticated: keep the control-sized windows.
                if signal.is_err() {
                    let _ = h2_conn.await;
                    return;
                }
            }
        }
        if !raise_windows(&mut h2_conn).await {
            warn!(
                "H2: {} could not raise the stream window to {} within {:?}, dropping the connection",
                remote,
                H2_DATA_STREAM_WINDOW,
                WINDOW_RAISE_RETRY * WINDOW_RAISE_ATTEMPTS
            );
            return;
        }
        let _ = h2_conn.await;
    });

    let id = match tokio::time::timeout(
        AUTH_EXCHANGE_TIMEOUT,
        h2_auth_exchange(
            &mut h2_sender,
            remote,
            &ctx.domain_suffixes,
            auth_token,
            &ctx.resolver,
        ),
    )
    .await
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            conn_task.abort();
            return None;
        }
        Err(_) => {
            warn!(
                "H2: authentication exchange with {} timed out after {:?}",
                remote, AUTH_EXCHANGE_TIMEOUT
            );
            conn_task.abort();
            return None;
        }
    };

    // Authenticated: restore data-sized flow control and release the budget.
    let _ = raise_tx.send(());
    drop(permit);

    // Liveness from here on, including the ACME wait: a dead peer fails the PING
    // and aborting the driver fails every pending request.
    let conn_abort = conn_task.abort_handle();
    let agent_id = id.clone();
    let supervisor = tokio::spawn(async move {
        let mut conn_task = conn_task;
        let Some(ping_pong) = ping_pong else {
            let _ = conn_task.await;
            return;
        };
        tokio::select! {
            _ = &mut conn_task => {}
            cause = h2_ping_loop(ping_pong, keepalive) => {
                warn!("H2: {} ({}): {}, dropping the connection", agent_id, remote, cause);
                conn_task.abort();
            }
        }
    });

    let key_auth =
        match tokio::time::timeout(KEY_AUTH_TIMEOUT, h2_read_key_auth(&mut h2_sender, &id)).await {
            Ok(Some(k)) => k,
            Ok(None) => {
                conn_abort.abort();
                return None;
            }
            Err(_) => {
                warn!(
                    "H2: {} did not answer /_ctrl/key_auth within {:?}",
                    id, KEY_AUTH_TIMEOUT
                );
                conn_abort.abort();
                return None;
            }
        };

    // Outside every deadline above: blocks for as long as ACME finalize takes.
    if !key_auth.is_empty()
        && h2_acme_wait(&mut h2_sender, &id, &ctx.pending)
            .await
            .is_none()
    {
        conn_abort.abort();
        return None;
    }

    // Awaiting the supervisor is what unregisters the agent on disconnect.
    register(&ctx.agents, id, Agent::H2(h2_sender), async move {
        let _ = supervisor.await;
    })
    .await;
    Some(())
}

/// Delivers a rejection on a connection that has not been handshaken,
/// driving the H2 connection until the agent answers or the budget runs out.
async fn h2_reject(
    tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    remote: SocketAddr,
    reason: &'static str,
) {
    let handshake = h2::client::Builder::new()
        .initial_window_size(CTRL_STREAM_WINDOW)
        .initial_connection_window_size(CTRL_CONN_WINDOW)
        .handshake(tls_stream);
    let (mut sender, conn): (_, H2Conn) =
        match tokio::time::timeout(H2_HANDSHAKE_TIMEOUT, handshake).await {
            Ok(Ok(r)) => r,
            _ => {
                debug!("H2: could not reject {}: handshake failed", remote);
                return;
            }
        };
    tokio::select! {
        _ = h2_send_reject(&mut sender, reason) => {}
        _ = conn => {}
    }
}

/// Sends `GET /_ctrl/reject` with `reason` as the body and waits briefly for the
/// agent's response. The caller drives the H2 connection.
async fn h2_send_reject(sender: &mut h2::client::SendRequest<bytes::Bytes>, reason: &'static str) {
    let exchange = async {
        let req = http::Request::builder()
            .method("GET")
            .uri(CTRL_REJECT_PATH)
            .body(())
            .ok()?;
        let (resp, mut body) = sender.send_request(req, false).ok()?;
        body.send_data(bytes::Bytes::from_static(reason.as_bytes()), true)
            .ok()?;
        resp.await.ok()
    };
    let _ = tokio::time::timeout(REJECT_TIMEOUT, exchange).await;
}

/// Raises the connection and stream flow-control windows to data size. Returns
/// `false` when every attempt failed while the connection was still alive.
async fn raise_windows(conn: &mut H2Conn) -> bool {
    conn.set_target_window_size(H2_DATA_CONN_WINDOW);
    for attempt in 0..WINDOW_RAISE_ATTEMPTS {
        match conn.set_initial_window_size(H2_DATA_STREAM_WINDOW) {
            Ok(()) => return true,
            Err(e) => {
                if attempt == 0 {
                    debug!("H2: stream window raise deferred ({}), retrying", e);
                }
            }
        }
        tokio::select! {
            r = &mut *conn => {
                let _ = r;
                return true;
            }
            _ = tokio::time::sleep(WINDOW_RAISE_RETRY) => {}
        }
    }
    false
}

/// Reads and verifies the peer's identity: the announced domain, the recoverable
/// signature binding it, the suffix allowlist and the DNS TXT authorization.
/// Returns the `client_id`.
async fn h2_auth_exchange(
    sender: &mut h2::client::SendRequest<bytes::Bytes>,
    remote: SocketAddr,
    domain_suffixes: &[String],
    auth_token: Option<Vec<u8>>,
    resolver: &hickory_resolver::TokioAsyncResolver,
) -> Option<String> {
    // Step 1: GET /_ctrl/domain — client responds with domain in body
    let domain = {
        let req = http::Request::builder()
            .method("GET")
            .uri("/_ctrl/domain")
            .body(())
            .unwrap();
        let (resp_future, _) = match sender.send_request(req, true) {
            Ok(r) => r,
            Err(e) => {
                warn!("H2: failed to send /_ctrl/domain for {}: {}", remote, e);
                return None;
            }
        };
        let body = match collect_h2_body(resp_future.await.ok()?.into_body(), MAX_CTRL_FRAME).await
        {
            Ok(b) => b,
            Err(e) => {
                warn!("H2: failed to read domain body from {}: {}", remote, e);
                return None;
            }
        };
        match String::from_utf8(body.to_vec()) {
            Ok(d) => d,
            Err(e) => {
                warn!("H2: invalid domain encoding from {}: {}", remote, e);
                return None;
            }
        }
    };

    // Step 2: GET /_ctrl/sig — client responds with 65-byte recoverable ECDSA P-256 signature over the domain
    let sig_bytes = {
        let req = http::Request::builder()
            .method("GET")
            .uri("/_ctrl/sig")
            .body(())
            .unwrap();
        let (resp_future, _) = match sender.send_request(req, true) {
            Ok(r) => r,
            Err(e) => {
                warn!("H2: failed to send /_ctrl/sig for {}: {}", remote, e);
                return None;
            }
        };
        match collect_h2_body(resp_future.await.ok()?.into_body(), MAX_CTRL_FRAME).await {
            Ok(b) => b.to_vec(),
            Err(e) => {
                warn!("H2: failed to read sig body from {}: {}", remote, e);
                return None;
            }
        }
    };
    let pubkey = match recover_identity_pubkey(&domain, &sig_bytes) {
        Some(pk) => pk,
        None => {
            warn!(
                "H2: identity signature does not bind to id in domain {} from {}",
                domain, remote
            );
            h2_send_reject(sender, "unauthorized: identity signature").await;
            return None;
        }
    };
    let id = domain.split('.').next()?.to_string();
    debug!(
        "H2: {} id={} recovered identity pubkey ({} bytes)",
        remote,
        id,
        pubkey.len()
    );

    if !allowed_suffix(&domain, domain_suffixes) {
        warn!(
            "H2: domain {} has no allowed suffix (allowed: {:?})",
            domain, domain_suffixes
        );
        h2_send_reject(sender, "unauthorized: domain suffix not allowed").await;
        return None;
    }
    debug!("H2: domain={}", domain);

    // Step 2b: DNS TXT validation (only when auth_handler returned a deployment_source)
    if let Some(ref deployment_source) = auth_token {
        let host = domain.split_once('.').map(|x| x.1).unwrap_or("");
        let txt_name = format!("_acu.{}.", host);
        match resolver.txt_lookup(&txt_name).await {
            Ok(lookup) => {
                let values: Vec<&[u8]> = lookup
                    .iter()
                    .flat_map(|r| r.txt_data().iter().map(|d| d.as_ref()))
                    .collect();
                if !txt_authorizes(&values, deployment_source, host) {
                    warn!(
                        "H2: TXT record mismatch for {} (client_id={})",
                        txt_name, id
                    );
                    h2_send_reject(
                        sender,
                        "unauthorized: deployment source not authorized by TXT",
                    )
                    .await;
                    return None;
                }
            }
            Err(e) => {
                warn!("H2: TXT lookup failed for {}: {}", txt_name, e);
                return None;
            }
        }
    }

    Some(id)
}

/// Step 3: `GET /_ctrl/key_auth` — empty means the client's cert is cached,
/// non-empty means an ACME challenge is in progress.
async fn h2_read_key_auth(
    sender: &mut h2::client::SendRequest<bytes::Bytes>,
    id: &str,
) -> Option<Vec<u8>> {
    let req = http::Request::builder()
        .method("GET")
        .uri("/_ctrl/key_auth")
        .body(())
        .unwrap();
    let (resp_future, _) = match sender.send_request(req, true) {
        Ok(r) => r,
        Err(e) => {
            warn!("H2: failed to send /_ctrl/key_auth for {}: {}", id, e);
            return None;
        }
    };
    match collect_h2_body(resp_future.await.ok()?.into_body(), MAX_CTRL_FRAME).await {
        Ok(b) => Some(b.to_vec()),
        Err(e) => {
            warn!("H2: failed to read key_auth body from {}: {}", id, e);
            None
        }
    }
}

/// Services the client's TLS-ALPN-01 challenge: registers the connection so
/// `handle_acme` can proxy Let's Encrypt's port-443 connections through it, then
/// long-polls `GET /_ctrl/done`, held open until ACME finalize completes.
async fn h2_acme_wait(
    sender: &mut h2::client::SendRequest<bytes::Bytes>,
    id: &str,
    pending: &PendingAlpnMap,
) -> Option<()> {
    let token = pending_alpn_insert(pending, id, PendingAlpnConn::H2(sender.clone()));
    let req = http::Request::builder()
        .method("GET")
        .uri("/_ctrl/done")
        .body(())
        .unwrap();
    let (resp_future, _) = match sender.send_request(req, true) {
        Ok(r) => r,
        Err(e) => {
            warn!("H2: failed to send /_ctrl/done for {}: {}", id, e);
            pending_alpn_remove(pending, id, token);
            return None;
        }
    };
    if let Err(e) = resp_future.await {
        warn!("H2: /_ctrl/done response failed for {}: {}", id, e);
    }
    pending_alpn_remove(pending, id, token);
    Some(())
}
