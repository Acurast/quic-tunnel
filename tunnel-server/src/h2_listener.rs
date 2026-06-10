use log::{debug, error, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tunnel_common::collect_h2_body;

use crate::util::{
    allowed_suffix, custom_data_from_cert, pubkey_from_cert, recover_identity_pubkey, register,
    txt_authorizes,
};
use crate::{Agent, AgentMap, AuthHandler, PendingAlpnConn, PendingAlpnMap};

pub(crate) async fn run_h2_listener(
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    agents: AgentMap,
    pending: PendingAlpnMap,
    domain_suffixes: Arc<Vec<String>>,
    auth_handler: Option<AuthHandler>,
    resolver: Arc<hickory_resolver::TokioAsyncResolver>,
) {
    while let Ok((tcp_stream, remote)) = listener.accept().await {
        debug!("H2: incoming connection from {}", remote);
        let (acceptor, agents, pending, domain_suffixes, auth_handler, resolver) = (
            acceptor.clone(),
            agents.clone(),
            pending.clone(),
            domain_suffixes.clone(),
            auth_handler.clone(),
            resolver.clone(),
        );
        tokio::spawn(handle_h2_connection(
            tcp_stream,
            remote,
            acceptor,
            agents,
            pending,
            domain_suffixes,
            auth_handler,
            resolver,
        ));
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_h2_connection(
    tcp_stream: TcpStream,
    remote: SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    agents: AgentMap,
    pending: PendingAlpnMap,
    domain_suffixes: Arc<Vec<String>>,
    auth_handler: Option<AuthHandler>,
    resolver: Arc<hickory_resolver::TokioAsyncResolver>,
) -> Option<()> {
    let _ = tcp_stream.set_nodelay(true);
    let tls_stream = match acceptor.accept(tcp_stream).await {
        Ok(s) => s,
        Err(e) => {
            warn!("H2: TLS handshake failed from {}: {}", remote, e);
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
    let auth_token: Option<Vec<u8>> = if let Some(ref handler) = auth_handler {
        let pubkey = match pubkey_from_cert(peer_cert) {
            Some(pk) => pk,
            None => {
                warn!("H2: could not extract pubkey from {}", remote);
                drop(tls_stream);
                return None;
            }
        };
        match handler(&pubkey, custom_data.as_deref()) {
            Ok(token) => token,
            Err(e) => {
                warn!("H2: auth denied for {}: {}", remote, e);
                drop(tls_stream);
                return None;
            }
        }
    } else {
        None
    };
    debug!("H2: {} starting control exchange", remote);

    let (mut h2_sender, h2_conn) = match h2::client::Builder::new()
        .initial_window_size(10_000_000)
        .initial_connection_window_size(10_000_000)
        .handshake(tls_stream)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("H2: handshake failed for {}: {}", remote, e);
            return None;
        }
    };

    // `SendRequest` only queues frames; the `Connection` future performs the actual
    // socket I/O and must be polled for the control exchange below to make progress
    // (and for the ACME `/_ctrl/alpn` proxying that reuses the sender via `pending`).
    // Drive it for the connection's whole lifetime starting now — spawning it only
    // after the exchange deadlocks step 1.
    let conn_task = tokio::spawn(async move {
        let _ = h2_conn.await;
    });

    let id = match h2_ctrl_exchange(
        &mut h2_sender,
        remote,
        &pending,
        &domain_suffixes,
        auth_token,
        &resolver,
    )
    .await
    {
        Some(id) => id,
        None => {
            conn_task.abort();
            return None;
        }
    };

    // register() spawns a task that awaits `done` then unregisters the agent;
    // awaiting the driver handle preserves that "remove on disconnect" contract.
    register(&agents, id, Agent::H2(h2_sender), async move {
        let _ = conn_task.await;
    })
    .await;
    Some(())
}

async fn h2_ctrl_exchange(
    sender: &mut h2::client::SendRequest<bytes::Bytes>,
    remote: SocketAddr,
    pending: &PendingAlpnMap,
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
                error!("H2: failed to send /_ctrl/domain for {}: {}", remote, e);
                return None;
            }
        };
        let body = match collect_h2_body(resp_future.await.ok()?.into_body()).await {
            Ok(b) => b,
            Err(e) => {
                error!("H2: failed to read domain body from {}: {}", remote, e);
                return None;
            }
        };
        match String::from_utf8(body.to_vec()) {
            Ok(d) => d,
            Err(e) => {
                error!("H2: invalid domain encoding from {}: {}", remote, e);
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
                error!("H2: failed to send /_ctrl/sig for {}: {}", remote, e);
                return None;
            }
        };
        match collect_h2_body(resp_future.await.ok()?.into_body()).await {
            Ok(b) => b.to_vec(),
            Err(e) => {
                error!("H2: failed to read sig body from {}: {}", remote, e);
                return None;
            }
        }
    };
    let pubkey = match recover_identity_pubkey(&domain, &sig_bytes) {
        Some(pk) => pk,
        None => {
            error!(
                "H2: identity signature does not bind to id in domain {} from {}",
                domain, remote
            );
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
        error!(
            "H2: domain {} has no allowed suffix (allowed: {:?})",
            domain, domain_suffixes
        );
        return None;
    }
    debug!("H2: domain={}", domain);

    // Step 1b: DNS TXT validation (only when auth_handler returned a deployment_source)
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
                    return None;
                }
            }
            Err(e) => {
                warn!("H2: TXT lookup failed for {}: {}", txt_name, e);
                return None;
            }
        }
    }

    // Step 3: GET /_ctrl/key_auth — empty means cert cached, non-empty means ACME in progress
    let key_auth = {
        let req = http::Request::builder()
            .method("GET")
            .uri("/_ctrl/key_auth")
            .body(())
            .unwrap();
        let (resp_future, _) = match sender.send_request(req, true) {
            Ok(r) => r,
            Err(e) => {
                error!("H2: failed to send /_ctrl/key_auth for {}: {}", id, e);
                return None;
            }
        };
        let body = match collect_h2_body(resp_future.await.ok()?.into_body()).await {
            Ok(b) => b,
            Err(e) => {
                error!("H2: failed to read key_auth body from {}: {}", id, e);
                return None;
            }
        };
        body.to_vec()
    };

    if !key_auth.is_empty() {
        // Register so handle_acme can proxy LE's port-443 connections to this client
        pending.insert(id.clone(), PendingAlpnConn::H2(sender.clone()));
        // Long-poll GET /_ctrl/done — client holds the response until ACME finalize completes,
        // while concurrently handling /_ctrl/alpn challenge streams from handle_acme.
        let req = http::Request::builder()
            .method("GET")
            .uri("/_ctrl/done")
            .body(())
            .unwrap();
        let (resp_future, _) = match sender.send_request(req, true) {
            Ok(r) => r,
            Err(e) => {
                error!("H2: failed to send /_ctrl/done for {}: {}", id, e);
                pending.remove(&id);
                return None;
            }
        };
        if let Err(e) = resp_future.await {
            error!("H2: /_ctrl/done response failed for {}: {}", id, e);
        }
        pending.remove(&id);
    }

    Some(id)
}
