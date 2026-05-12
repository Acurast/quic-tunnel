use log::info;
use sha2::{Digest, Sha256};
use tls_parser::{
    TlsExtension, TlsMessage, TlsMessageHandshake, parse_tls_extensions, parse_tls_plaintext,
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

/// Derive a client_id from a SEC1-compressed P-256 public key (33 bytes,
/// `0x02` or `0x03` followed by the X coordinate). Matches the Acurast
/// on-chain `ecdsa::Public` encoding so a deployment's assignment pubkey
/// hashes to the same client_id the tunnel announces.
pub(crate) fn id_from_pubkey(pubkey_sec1_compressed: &[u8]) -> String {
    hex::encode(&Sha256::digest(pubkey_sec1_compressed)[0..8])
}

/// Recover the identity public key from a P-256 recoverable ECDSA signature
/// over the announced domain. Returns `Some(pubkey_sec1_compressed)` (33
/// bytes) when the recovered key's id hashes to the first label of `domain`.
///
/// Wire format: 65 bytes — `r (32) || s (32) || v (1)` where `v` is the
/// recovery id (0 or 1). The signed message is the full domain UTF-8 bytes,
/// hashed implicitly with SHA-256 (ECDSA-NISTP256-SHA256).
pub(crate) fn recover_identity_pubkey(domain: &str, sig_recoverable: &[u8]) -> Option<Vec<u8>> {
    use p256::ecdsa::recoverable;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let rec_sig = recoverable::Signature::try_from(sig_recoverable).ok()?;
    let vk = rec_sig.recover_verifying_key(domain.as_bytes()).ok()?;
    // Compress to match the client-side client_id derivation (33-byte SEC1).
    let ep = vk.to_encoded_point(true);
    let pubkey = ep.as_bytes();
    let id_target = domain.split('.').next()?;
    if id_from_pubkey(pubkey) == id_target {
        Some(pubkey.to_vec())
    } else {
        None
    }
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
    use base64::{Engine, engine::general_purpose};
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_txt_expected() {
        let hex_source = "9a1a0c52c2d7f23820caa7757acf049e07fcb68015919638feece41a4b0ee538";
        let source = hex::decode(hex_source).expect("Can decode hex");
        let value = compute_txt_expected(source.as_slice(), "run.acurast-dev.papers.tech");
        println!("TXT Value: {value}")
    }
}
