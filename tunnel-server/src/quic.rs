use log::{debug, warn};
use std::net::SocketAddr;
use tokio::sync::OwnedSemaphorePermit;
use tunnel_common::{CLOSE_TIMEOUT, REJECT_UNAUTHORIZED, ctrl_read, ctrl_write};

use crate::admission::{AUTH_EXCHANGE_TIMEOUT, Admission, KEY_AUTH_TIMEOUT};
use crate::util::{
    allowed_suffix, custom_data_from_cert, pubkey_from_cert, recover_identity_pubkey, register,
    txt_authorizes,
};
use crate::{
    Agent, ListenerCtx, PendingAlpnConn, PendingAlpnMap, pending_alpn_insert, pending_alpn_remove,
};

pub(crate) async fn run_quic_listener(endpoint: quinn::Endpoint, ctx: ListenerCtx) {
    let mut admission = Admission::new("QUIC");
    while let Some(incoming) = endpoint.accept().await {
        let remote = incoming.remote_address();
        let Some(permit) = admission.try_admit(remote) else {
            incoming.refuse();
            continue;
        };
        debug!("QUIC: incoming connection from {}", remote);
        tokio::spawn(handle_quic_connection(
            incoming,
            remote,
            ctx.clone(),
            permit,
        ));
    }
}

async fn handle_quic_connection(
    incoming: quinn::Incoming,
    remote: SocketAddr,
    ctx: ListenerCtx,
    permit: OwnedSemaphorePermit,
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
    let custom_data = custom_data_from_cert(first_cert);
    if let Some(ref att) = custom_data {
        debug!("QUIC: {} custom data ({} bytes)", remote, att.len());
    }
    let auth_token: Option<Vec<u8>> = if let Some(ref handler) = ctx.auth_handler {
        let pubkey = match pubkey_from_cert(first_cert) {
            Some(pk) => pk,
            None => {
                warn!("QUIC: could not extract pubkey from {}", remote);
                conn.close(
                    quinn::VarInt::from_u32(REJECT_UNAUTHORIZED),
                    b"unauthorized: client certificate",
                );
                return None;
            }
        };
        match handler(&pubkey, custom_data.as_deref()) {
            Ok(token) => token,
            Err(e) => {
                warn!("QUIC: auth denied for {}: {}", remote, e);
                conn.close(
                    quinn::VarInt::from_u32(REJECT_UNAUTHORIZED),
                    b"unauthorized: auth handler rejected",
                );
                return None;
            }
        }
    } else {
        None
    };
    debug!("QUIC: {} starting control exchange", remote);

    let (mut ctrl_send, mut ctrl_recv, id) =
        match tokio::time::timeout(AUTH_EXCHANGE_TIMEOUT, async {
            let (ctrl_send, mut ctrl_recv) = match conn.accept_bi().await {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        "QUIC: failed to accept control stream from {}: {}",
                        remote, e
                    );
                    return None;
                }
            };
            let id = quic_auth_exchange(
                &conn,
                &mut ctrl_recv,
                remote,
                &ctx.domain_suffixes,
                auth_token,
                &ctx.resolver,
            )
            .await?;
            Some((ctrl_send, ctrl_recv, id))
        })
        .await
        {
            Ok(Some(v)) => v,
            Ok(None) => return None,
            Err(_) => {
                warn!(
                    "QUIC: authentication exchange from {} timed out after {:?}",
                    remote, AUTH_EXCHANGE_TIMEOUT
                );
                conn.close(
                    quinn::VarInt::from_u32(CLOSE_TIMEOUT),
                    b"authentication exchange timeout",
                );
                return None;
            }
        };

    // Authenticated: stop counting against the unauthenticated budget.
    drop(permit);

    // Step 3: key_auth — empty means the cert is cached, non-empty means an ACME
    // challenge is in progress.
    let key_auth = match tokio::time::timeout(KEY_AUTH_TIMEOUT, ctrl_read(&mut ctrl_recv)).await {
        Ok(Ok(k)) => k,
        Ok(Err(e)) => {
            warn!("QUIC: failed to read key_auth from {}: {}", id, e);
            return None;
        }
        Err(_) => {
            warn!(
                "QUIC: {} did not send key_auth within {:?}",
                id, KEY_AUTH_TIMEOUT
            );
            return None;
        }
    };

    if !key_auth.is_empty() {
        quic_acme_wait(&conn, &mut ctrl_send, &mut ctrl_recv, &id, &ctx.pending).await?;
    }
    drop((ctrl_send, ctrl_recv));

    let done = {
        let conn = conn.clone();
        async move {
            let _ = conn.closed().await;
        }
    };
    register(&ctx.agents, id, Agent::Quic(conn), done).await;
    Some(())
}

/// Reads and verifies the peer's identity: the announced domain, the recoverable
/// signature binding it, the suffix allowlist and the DNS TXT authorization.
/// Returns the `client_id`. The key-auth frame is read by the caller.
async fn quic_auth_exchange(
    conn: &quinn::Connection,
    ctrl_recv: &mut quinn::RecvStream,
    remote: SocketAddr,
    domain_suffixes: &[String],
    auth_token: Option<Vec<u8>>,
    resolver: &hickory_resolver::TokioAsyncResolver,
) -> Option<String> {
    // Step 1: read domain from client
    let domain_bytes = match ctrl_read(ctrl_recv).await {
        Ok(d) => d,
        Err(e) => {
            warn!("QUIC: failed to read domain from {}: {}", remote, e);
            return None;
        }
    };
    let domain = match std::str::from_utf8(&domain_bytes) {
        Ok(d) => d.to_string(),
        Err(e) => {
            warn!("QUIC: invalid domain from {}: {}", remote, e);
            return None;
        }
    };

    // Step 2: read identity signature over the domain (P-256 recoverable, 65 bytes)
    let sig_bytes = match ctrl_read(ctrl_recv).await {
        Ok(s) => s,
        Err(e) => {
            warn!(
                "QUIC: failed to read identity signature from {}: {}",
                remote, e
            );
            return None;
        }
    };
    let pubkey = match recover_identity_pubkey(&domain, &sig_bytes) {
        Some(pk) => pk,
        None => {
            warn!(
                "QUIC: identity signature does not bind to id in domain {} from {}",
                domain, remote
            );
            conn.close(
                quinn::VarInt::from_u32(REJECT_UNAUTHORIZED),
                b"unauthorized: identity signature",
            );
            return None;
        }
    };
    let id = domain.split('.').next()?.to_string();
    debug!(
        "QUIC: {} id={} recovered identity pubkey ({} bytes)",
        remote,
        id,
        pubkey.len()
    );

    if !allowed_suffix(&domain, domain_suffixes) {
        warn!(
            "QUIC: domain {} has no allowed suffix (allowed: {:?})",
            domain, domain_suffixes
        );
        conn.close(
            quinn::VarInt::from_u32(REJECT_UNAUTHORIZED),
            b"unauthorized: domain suffix not allowed",
        );
        return None;
    }
    debug!("QUIC: domain={}", domain);

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
                        "QUIC: TXT record mismatch for {} (client_id={})",
                        txt_name, id
                    );
                    conn.close(
                        quinn::VarInt::from_u32(REJECT_UNAUTHORIZED),
                        b"unauthorized: deployment source not authorized by TXT",
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

    Some(id)
}

/// Services the client's TLS-ALPN-01 challenge: registers the connection so
/// `handle_acme` can proxy Let's Encrypt's port-443 connections through it, then
/// blocks — unbounded, the ACME server drives it — until the client reports done.
async fn quic_acme_wait(
    conn: &quinn::Connection,
    ctrl_send: &mut quinn::SendStream,
    ctrl_recv: &mut quinn::RecvStream,
    id: &str,
    pending: &PendingAlpnMap,
) -> Option<()> {
    let token = pending_alpn_insert(pending, id, PendingAlpnConn::Quic(conn.clone()));
    // ACK so client knows it can start handling ALPN challenge streams
    if let Err(e) = ctrl_write(ctrl_send, b"ack").await {
        warn!("QUIC: failed to send ACK to {}: {}", id, e);
        pending_alpn_remove(pending, id, token);
        return None;
    }
    // Wait for client to signal ACME finalize is complete
    if let Err(e) = ctrl_read(ctrl_recv).await {
        warn!("QUIC: failed to read done signal from {}: {}", id, e);
    }
    pending_alpn_remove(pending, id, token);
    Some(())
}
