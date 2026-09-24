pub mod acme;

use sha2::Digest;
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// QUIC close code for a rejection: the peer retries only at its maximum backoff.
pub const REJECT_UNAUTHORIZED: u32 = 1;
/// QUIC close code for a timed-out exchange: the peer may retry.
pub const CLOSE_TIMEOUT: u32 = 2;
/// H2 control path carrying a rejection reason as the request body.
pub const CTRL_REJECT_PATH: &str = "/_ctrl/reject";

/// OID for the custom data certificate extension.
/// Private enterprise arc: 1.3.6.1.4.1.65535.1
pub const CUSTOM_DATA_EXT_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65535, 1];
pub const CUSTOM_DATA_EXT_OID_STR: &str = "1.3.6.1.4.1.65535.1";

/// Upper bound on a single control frame, bounding the allocation an
/// unauthenticated peer can request with its own length prefix.
pub const MAX_CTRL_FRAME: usize = 4096;

// --- Combined async read/write stream ---

pub struct IO {
    r: Pin<Box<dyn AsyncRead + Send + Unpin>>,
    w: Pin<Box<dyn AsyncWrite + Send + Unpin>>,
}

impl IO {
    pub fn new<R, W>(r: R, w: W) -> Self
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        Self {
            r: Box::pin(r),
            w: Box::pin(w),
        }
    }
}

impl AsyncRead for IO {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<std::io::Result<()>> {
        self.r.as_mut().poll_read(cx, buf)
    }
}

impl AsyncWrite for IO {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.w.as_mut().poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::io::Result<()>> {
        self.w.as_mut().poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::io::Result<()>> {
        self.w.as_mut().poll_shutdown(cx)
    }
}

// --- H2 stream adapters ---

pub struct H2Send(pub h2::SendStream<bytes::Bytes>);

impl AsyncWrite for H2Send {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            // `poll_capacity` may report ready with zero capacity.
            let n = self.0.capacity().min(buf.len());
            if n > 0 {
                self.0
                    .send_data(bytes::Bytes::copy_from_slice(&buf[..n]), false)
                    .map_err(io_err)?;
                return Poll::Ready(Ok(n));
            }
            self.0.reserve_capacity(buf.len());
            match self.0.poll_capacity(cx) {
                Poll::Ready(Some(Ok(_))) => continue,
                Poll::Pending => return Poll::Pending,
                Poll::Ready(other) => {
                    let msg = other
                        .and_then(|r| r.err())
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "closed".into());
                    return Poll::Ready(Err(io_err(msg)));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context) -> Poll<std::io::Result<()>> {
        self.0
            .send_data(bytes::Bytes::new(), true)
            .map_err(io_err)?;
        Poll::Ready(Ok(()))
    }
}

pub struct H2Recv {
    pub r: h2::RecvStream,
    pub buf: bytes::Bytes,
}

impl H2Recv {
    /// Wraps an [`h2::RecvStream`] as an [`AsyncRead`].
    pub fn new(r: h2::RecvStream) -> Self {
        Self {
            r,
            buf: bytes::Bytes::new(),
        }
    }
}

impl AsyncRead for H2Recv {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<std::io::Result<()>> {
        // Drain buffered data first
        if !self.buf.is_empty() {
            let n = buf.remaining().min(self.buf.len());
            buf.put_slice(&self.buf.slice(0..n));
            self.buf = self.buf.slice(n..);
            return Poll::Ready(Ok(()));
        }
        // Read from stream
        match self.r.poll_data(cx) {
            Poll::Ready(Some(Ok(data))) => {
                let _ = self.r.flow_control().release_capacity(data.len());
                let n = buf.remaining().min(data.len());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.buf = data.slice(n..);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io_err(e))),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

// --- Certificate generation ---

pub fn cert(
    name: &str,
) -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let generated = rcgen::generate_simple_self_signed(vec![name.into()]).unwrap();
    let cert = generated.cert.der().to_vec().into();
    let key =
        rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der()).into();
    (cert, key)
}

/// Builds a TLS acceptor for the TLS-ALPN-01 challenge (RFC 8737).
/// The cert carries a critical id-pe-acmeIdentifier extension (OID 1.3.6.1.5.5.7.1.31)
/// whose value is an ASN.1 OCTET STRING holding SHA-256(key_authorization).
pub fn build_alpn_acceptor(
    domain: &str,
    key_authorization: &str,
) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    let thumbprint = sha2::Sha256::digest(key_authorization.as_bytes());
    // RFC 8737 §3: extension value = DER OCTET STRING (tag 0x04, len 0x20, 32 bytes)
    let mut ext_val = vec![0x04u8, 0x20];
    ext_val.extend_from_slice(&thumbprint);
    let mut ext = rcgen::CustomExtension::from_oid_content(&[1, 3, 6, 1, 5, 5, 7, 1, 31], ext_val);
    ext.set_criticality(true);

    let keypair = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])?;
    params.custom_extensions = vec![ext];
    let cert = params.self_signed(&keypair)?;

    let cert_der: rustls::pki_types::CertificateDer<'static> = cert.der().to_vec().into();
    let key_der: rustls::pki_types::PrivateKeyDer<'static> =
        rustls::pki_types::PrivatePkcs8KeyDer::from(keypair.serialize_der()).into();

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
        .map_err(|e| anyhow::anyhow!("unsupported key type: {:?}", e))?;
    let certified_key = Arc::new(rustls::sign::CertifiedKey::new(vec![cert_der], signing_key));

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(AlpnCertResolver(certified_key)));
    config.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

#[derive(Debug)]
struct AlpnCertResolver(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for AlpnCertResolver {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

pub fn io_err<E: Into<Box<dyn std::error::Error + Send + Sync>>>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)
}

// --- Control channel protocol ---
// Pre-registration control exchange on both transports.
// Wire format: [u32 big-endian length][payload bytes], capped at MAX_CTRL_FRAME.

pub async fn ctrl_read<R: AsyncRead + Unpin>(r: &mut R) -> anyhow::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_CTRL_FRAME {
        anyhow::bail!("control frame of {len} bytes exceeds the {MAX_CTRL_FRAME}-byte limit");
    }
    let mut buf = Vec::new();
    buf.try_reserve_exact(len)
        .map_err(|e| anyhow::anyhow!("cannot allocate {len} bytes for control frame: {e}"))?;
    buf.resize(len, 0);
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

pub async fn ctrl_write<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(
        data.len() <= MAX_CTRL_FRAME,
        "control frame of {} bytes exceeds the {MAX_CTRL_FRAME}-byte limit",
        data.len()
    );
    w.write_all(&(data.len() as u32).to_be_bytes()).await?;
    w.write_all(data).await?;
    Ok(())
}

/// Collects an H2 request/response body, refusing to buffer more than `max` bytes.
/// Control bodies should pass [`MAX_CTRL_FRAME`].
pub async fn collect_h2_body(mut body: h2::RecvStream, max: usize) -> anyhow::Result<bytes::Bytes> {
    let mut buf = bytes::BytesMut::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(io_err)?;
        if buf.len() + chunk.len() > max {
            anyhow::bail!("h2 control body exceeds the {max}-byte limit");
        }
        let _ = body.flow_control().release_capacity(chunk.len());
        buf.extend_from_slice(&chunk);
    }
    Ok(buf.freeze())
}

// --- H2 liveness ---

/// Default PING interval on an established H2 tunnel connection.
pub const H2_PING_INTERVAL: Duration = Duration::from_secs(10);
/// Default budget for the peer's PONG, mirroring QUIC's keep-alive/idle ratio.
pub const H2_PING_TIMEOUT: Duration = Duration::from_secs(20);

/// Per-stream flow-control window for an H2 tunnel data connection.
pub const H2_DATA_STREAM_WINDOW: u32 = 10_000_000;
/// Connection-level flow-control window for an H2 tunnel data connection.
pub const H2_DATA_CONN_WINDOW: u32 = 10_000_000;

// --- QUIC liveness ---

/// Interval between QUIC keep-alive packets on an established tunnel connection.
pub const QUIC_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// Idle budget for a QUIC tunnel connection, equal to the H2 dead-peer window
/// ([`H2_PING_INTERVAL`] + [`H2_PING_TIMEOUT`]) so both transports fail over alike.
pub const QUIC_MAX_IDLE_TIMEOUT: Duration =
    Duration::from_secs(H2_PING_INTERVAL.as_secs() + H2_PING_TIMEOUT.as_secs());

/// PING-based liveness for an H2 tunnel connection. [`Default`] is what
/// production runs with; tests shrink it.
#[derive(Debug, Clone, Copy)]
pub struct H2KeepAlive {
    /// Interval between PINGs.
    pub interval: Duration,
    /// How long the peer may take to answer before the connection is dead.
    pub timeout: Duration,
}

impl Default for H2KeepAlive {
    fn default() -> Self {
        Self {
            interval: H2_PING_INTERVAL,
            timeout: H2_PING_TIMEOUT,
        }
    }
}

impl H2KeepAlive {
    /// Rejects values the ping loop cannot honour.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.interval.is_zero(),
            "h2_keepalive.interval must be greater than zero"
        );
        anyhow::ensure!(
            !self.timeout.is_zero(),
            "h2_keepalive.timeout must be greater than zero"
        );
        Ok(())
    }
}

/// Pings the peer for as long as it answers, resolving with a description of the
/// failure once it stops. The caller drives the connection concurrently and drops
/// this future when the connection ends.
pub async fn h2_ping_loop(mut ping_pong: h2::PingPong, keepalive: H2KeepAlive) -> String {
    loop {
        tokio::time::sleep(keepalive.interval).await;
        match tokio::time::timeout(keepalive.timeout, ping_pong.ping(h2::Ping::opaque())).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return format!("H2 PING failed: {e}"),
            Err(_) => return format!("no H2 PONG within {:?}", keepalive.timeout),
        }
    }
}

// --- TLS certificate verifier (accepts all certs, extracts identity) ---

#[derive(Debug)]
pub struct NoVerify;

const SCHEMES: &[rustls::SignatureScheme] = &[
    rustls::SignatureScheme::RSA_PSS_SHA256,
    rustls::SignatureScheme::ED25519,
    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
    rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
];

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer,
        _: &[rustls::pki_types::CertificateDer],
        _: &rustls::pki_types::ServerName,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        SCHEMES.to_vec()
    }
}

impl rustls::server::danger::ClientCertVerifier for NoVerify {
    fn verify_client_cert(
        &self,
        _: &rustls::pki_types::CertificateDer,
        _: &[rustls::pki_types::CertificateDer],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        SCHEMES.to_vec()
    }
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
}

/// Client certificate verifier that accepts any self-signed certificate but
/// cryptographically verifies the TLS CertificateVerify handshake message,
/// proving the client holds the private key corresponding to the certificate.
#[derive(Debug)]
pub struct SelfSignedVerifier {
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl SelfSignedVerifier {
    pub fn new() -> Self {
        Self {
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }
}

impl Default for SelfSignedVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl rustls::server::danger::ClientCertVerifier for SelfSignedVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer,
        _intermediates: &[rustls::pki_types::CertificateDer],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // Key ownership is enforced by verify_tls1{2,3}_signature below.
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read_frame(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut r = bytes;
        ctrl_read(&mut r).await
    }

    #[test]
    fn quic_idle_budget_matches_the_h2_dead_peer_window() {
        assert_eq!(QUIC_MAX_IDLE_TIMEOUT, H2_PING_INTERVAL + H2_PING_TIMEOUT);
    }

    #[tokio::test]
    async fn ctrl_read_round_trips_a_domain_frame() {
        let domain = vec![b'a'; 253];
        let mut wire = Vec::new();
        ctrl_write(&mut wire, &domain).await.unwrap();
        assert_eq!(wire.len(), 4 + 253);
        assert_eq!(read_frame(&wire).await.unwrap(), domain);
    }

    #[tokio::test]
    async fn ctrl_read_round_trips_short_frames() {
        for payload in [&b""[..], &b"ack"[..], &b"done"[..]] {
            let mut wire = Vec::new();
            ctrl_write(&mut wire, payload).await.unwrap();
            assert_eq!(read_frame(&wire).await.unwrap(), payload);
        }
    }

    #[tokio::test]
    async fn ctrl_read_rejects_u32_max_length_without_allocating() {
        // Only the 4-byte length prefix is supplied: the length check must reject
        // before any allocation (a 4 GiB `vec!` would abort the process here).
        let err = read_frame(&[0xff, 0xff, 0xff, 0xff]).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("exceeds"), "unexpected error: {msg}");
        assert!(msg.contains("4294967295"), "unexpected error: {msg}");
    }

    #[tokio::test]
    async fn ctrl_read_accepts_exactly_max_ctrl_frame() {
        let payload = vec![0x5au8; MAX_CTRL_FRAME];
        let mut wire = Vec::new();
        ctrl_write(&mut wire, &payload).await.unwrap();
        assert_eq!(read_frame(&wire).await.unwrap(), payload);
    }

    #[tokio::test]
    async fn ctrl_read_rejects_one_byte_over_max_ctrl_frame() {
        // Framed by hand: `ctrl_write` refuses to emit an oversized frame, so the
        // decoder side has to be fed a hostile peer's bytes directly.
        let payload = vec![0u8; MAX_CTRL_FRAME + 1];
        let mut wire = ((payload.len() as u32).to_be_bytes()).to_vec();
        wire.extend_from_slice(&payload);
        let err = read_frame(&wire).await.unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[tokio::test]
    async fn ctrl_write_rejects_frames_over_max_ctrl_frame() {
        let mut wire = Vec::new();
        let err = ctrl_write(&mut wire, &vec![0u8; MAX_CTRL_FRAME + 1])
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("exceeds"), "unexpected error: {msg}");
        assert!(msg.contains("4097"), "unexpected error: {msg}");
        // Nothing may be emitted: a partial frame would desync the stream.
        assert!(wire.is_empty(), "{} bytes written", wire.len());
    }

    #[tokio::test]
    async fn ctrl_write_accepts_exactly_max_ctrl_frame() {
        let mut wire = Vec::new();
        ctrl_write(&mut wire, &vec![0u8; MAX_CTRL_FRAME])
            .await
            .unwrap();
        assert_eq!(wire.len(), 4 + MAX_CTRL_FRAME);
    }

    #[tokio::test]
    async fn ctrl_read_round_trips_over_a_duplex_pipe() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let sig = vec![7u8; 65];
        let expected = sig.clone();
        tokio::spawn(async move { ctrl_write(&mut a, &sig).await.unwrap() });
        assert_eq!(ctrl_read(&mut b).await.unwrap(), expected);
    }
}
