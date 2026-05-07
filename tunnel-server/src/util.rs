use log::info;
use sha2::{Digest, Sha256};
use tls_parser::{
    parse_tls_extensions, parse_tls_plaintext, TlsExtension, TlsMessage, TlsMessageHandshake,
};
use tunnel_common::CUSTOM_DATA_EXT_OID_STR;

use crate::{Agent, AgentMap};

pub(crate) async fn register(
    agents: &AgentMap,
    id: String,
    agent: Agent,
    done: impl std::future::Future<Output = ()> + Send + 'static,
) {
    let uid: u64 = rand::random();
    info!("LINK ADD: {} (uid: {})", id, uid);
    agents.entry(id.clone()).or_default().push(uid, agent);

    let agents = agents.clone();
    tokio::spawn(async move {
        done.await;
        info!("LINK REMOVE: {} (uid: {})", id, uid);
        if let Some(mut pool) = agents.get_mut(&id) {
            pool.remove(uid);
        }
    });
}

pub(crate) fn allowed_suffix(domain: &str, suffixes: &[String]) -> bool {
    if suffixes.is_empty() {
        return true;
    }
    suffixes
        .iter()
        .any(|s| domain.ends_with(&format!(".{}", s)))
}

pub(crate) fn id_from_cert(cert_der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    let pubkey_bytes = &cert.public_key().subject_public_key.data;
    Some(hex::encode(&Sha256::digest(pubkey_bytes)[0..8]))
}

pub(crate) fn pubkey_from_cert(cert_der: &[u8]) -> Option<Vec<u8>> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    Some(cert.public_key().subject_public_key.data.to_vec())
}

pub(crate) fn custom_data_from_cert(cert_der: &[u8]) -> Option<Vec<u8>> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    for ext in cert.extensions() {
        if ext.oid.to_id_string() == CUSTOM_DATA_EXT_OID_STR {
            // ext.value is the DER-encoded ASN.1 value (an OCTET STRING wrapping the raw bytes)
            return yasna::parse_der(ext.value, |reader| reader.read_bytes()).ok();
        }
    }
    None
}

/// Computes the expected DNS TXT value: `base64(sha256(deployment_source || host))`.
pub(crate) fn compute_txt_expected(deployment_source: &[u8], host: &str) -> String {
    use base64::{engine::general_purpose, Engine};
    let digest = Sha256::digest([deployment_source, host.as_bytes()].concat());
    general_purpose::STANDARD.encode(digest)
}

pub(crate) fn extract_sni(data: &[u8]) -> Option<&str> {
    let (_, plaintext) = parse_tls_plaintext(data).ok()?;
    let hello = match plaintext.msg.first()? {
        TlsMessage::Handshake(TlsMessageHandshake::ClientHello(h)) => h,
        _ => return None,
    };
    let (_, extensions) = parse_tls_extensions(hello.ext?).ok()?;
    extensions.iter().find_map(|ext| match ext {
        TlsExtension::SNI(names) => names
            .first()
            .and_then(|(_, name)| std::str::from_utf8(name).ok()),
        _ => None,
    })
}
