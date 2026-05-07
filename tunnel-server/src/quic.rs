use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use tunnel_common::{ctrl_read, ctrl_write};

use crate::util::{
    allowed_suffix, compute_txt_expected, custom_data_from_cert, id_from_cert, pubkey_from_cert,
    register,
};
use crate::{Agent, AgentMap, AuthHandler, PendingAlpnConn, PendingAlpnMap};

pub(crate) async fn run_quic_listener(
    endpoint: quinn::Endpoint,
    agents: AgentMap,
    pending: PendingAlpnMap,
    domain_suffixes: Arc<Vec<String>>,
    auth_handler: Option<AuthHandler>,
    resolver: Arc<hickory_resolver::TokioAsyncResolver>,
) {
    while let Some(incoming) = endpoint.accept().await {
        let remote = incoming.remote_address();
        debug!("QUIC: incoming connection from {}", remote);
        tokio::spawn(handle_quic_connection(
            incoming,
            remote,
            agents.clone(),
            pending.clone(),
            domain_suffixes.clone(),
            auth_handler.clone(),
            resolver.clone(),
        ));
    }
}

async fn handle_quic_connection(
    incoming: quinn::Incoming,
    remote: SocketAddr,
    agents: AgentMap,
    pending: PendingAlpnMap,
    domain_suffixes: Arc<Vec<String>>,
    auth_handler: Option<AuthHandler>,
    resolver: Arc<hickory_resolver::TokioAsyncResolver>,
) -> Option<()> {
    let conn = match incoming.await {
        Ok(c) => c,
        Err(e) => {
            warn!("QUIC: handshake failed from {}: {}", remote, e);
            return None;
        }
    };
    let peer_certs: Vec<rustls::pki_types::CertificateDer> =
        *conn.peer_identity()?.downcast().ok()?;
    let first_cert = peer_certs.first()?.as_ref();
    let id = match id_from_cert(first_cert) {
        Some(id) => id,
        None => {
            warn!("QUIC: could not derive client_id from {}", remote);
            return None;
        }
    };
    let custom_data = custom_data_from_cert(first_cert);
    if let Some(ref att) = custom_data {
        info!("QUIC: client_id={} custom data ({} bytes)", id, att.len());
    }
    let auth_token: Option<Vec<u8>> = if let Some(ref handler) = auth_handler {
        let pubkey = match pubkey_from_cert(first_cert) {
            Some(pk) => pk,
            None => {
                warn!("QUIC: could not extract pubkey from {}", remote);
                conn.close(quinn::VarInt::from_u32(1), b"");
                return None;
            }
        };
        match handler(&pubkey, custom_data.as_deref()) {
            Ok(token) => token,
            Err(e) => {
                warn!("QUIC: auth denied for client_id={} ({}): {}", id, remote, e);
                conn.close(quinn::VarInt::from_u32(1), b"");
                return None;
            }
        }
    } else {
        None
    };
    debug!(
        "QUIC: client_id={} ({}), starting control exchange",
        id, remote
    );

    let (mut ctrl_send, mut ctrl_recv) = match conn.accept_bi().await {
        Ok(s) => s,
        Err(e) => {
            error!("QUIC: failed to accept control stream from {}: {}", id, e);
            return None;
        }
    };

    quic_ctrl_exchange(
        &conn,
        &mut ctrl_send,
        &mut ctrl_recv,
        &id,
        &pending,
        &domain_suffixes,
        auth_token,
        &resolver,
    )
    .await?;
    drop((ctrl_send, ctrl_recv));

    let done = {
        let conn = conn.clone();
        async move {
            let _ = conn.closed().await;
        }
    };
    register(&agents, id, Agent::Quic(conn), done).await;
    Some(())
}

#[allow(clippy::too_many_arguments)]
async fn quic_ctrl_exchange(
    conn: &quinn::Connection,
    ctrl_send: &mut quinn::SendStream,
    ctrl_recv: &mut quinn::RecvStream,
    id: &str,
    pending: &PendingAlpnMap,
    domain_suffixes: &[String],
    auth_token: Option<Vec<u8>>,
    resolver: &hickory_resolver::TokioAsyncResolver,
) -> Option<()> {
    // Step 1: read domain from client
    let domain_bytes = match ctrl_read(ctrl_recv).await {
        Ok(d) => d,
        Err(e) => {
            error!("QUIC: failed to read domain from {}: {}", id, e);
            return None;
        }
    };
    let domain = match std::str::from_utf8(&domain_bytes) {
        Ok(d) => d.to_string(),
        Err(e) => {
            error!("QUIC: invalid domain from {}: {}", id, e);
            return None;
        }
    };
    if domain.split('.').next() != Some(id) {
        error!("QUIC: domain {} does not match client_id {}", domain, id);
        return None;
    }
    if !allowed_suffix(&domain, domain_suffixes) {
        error!(
            "QUIC: domain {} has no allowed suffix (allowed: {:?})",
            domain, domain_suffixes
        );
        return None;
    }
    debug!("QUIC: domain={}", domain);

    // Step 1b: DNS TXT validation (only when auth_handler returned a deployment_source)
    if let Some(ref deployment_source) = auth_token {
        let host = domain.split_once('.').map(|x| x.1).unwrap_or("");
        let txt_name = format!("_acu.{}.", host);
        let expected = compute_txt_expected(deployment_source, host);
        match resolver.txt_lookup(&txt_name).await {
            Ok(lookup) => {
                let matched = lookup.iter().any(|r| {
                    r.txt_data()
                        .iter()
                        .any(|d| d.as_ref() == expected.as_bytes())
                });
                if !matched {
                    warn!(
                        "QUIC: TXT record mismatch for {} (client_id={})",
                        txt_name, id
                    );
                    return None;
                }
            }
            Err(e) => {
                warn!("QUIC: TXT lookup failed for {}: {}", txt_name, e);
                return None;
            }
        }
    }

    // Step 2: read key_auth — empty means cert is cached, non-empty means ACME challenge in progress
    let key_auth = match ctrl_read(ctrl_recv).await {
        Ok(k) => k,
        Err(e) => {
            error!("QUIC: failed to read key_auth from {}: {}", id, e);
            return None;
        }
    };

    if !key_auth.is_empty() {
        // Register this connection so run_alpn_listener can proxy LE's port-443 connections
        pending.insert(id.to_string(), PendingAlpnConn::Quic(conn.clone()));
        // ACK so client knows it can start handling ALPN challenge streams
        if let Err(e) = ctrl_write(ctrl_send, b"ack").await {
            error!("QUIC: failed to send ACK to {}: {}", id, e);
            pending.remove(id);
            return None;
        }
        // Wait for client to signal ACME finalize is complete
        if let Err(e) = ctrl_read(ctrl_recv).await {
            error!("QUIC: failed to read done signal from {}: {}", id, e);
        }
        pending.remove(id);
    }

    Some(())
}
