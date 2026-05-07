use sha2::Digest;
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// OID for the custom data certificate extension.
/// Private enterprise arc: 1.3.6.1.4.1.65535.1
pub const CUSTOM_DATA_EXT_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 65535, 1];
pub const CUSTOM_DATA_EXT_OID_STR: &str = "1.3.6.1.4.1.65535.1";

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
        if self.0.capacity() == 0 {
            self.0.reserve_capacity(buf.len());
            match self.0.poll_capacity(cx) {
                Poll::Ready(Some(Ok(_))) => {}
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
        let n = self.0.capacity().min(buf.len());
        if n == 0 {
            return Poll::Pending;
        }
        self.0
            .send_data(bytes::Bytes::copy_from_slice(&buf[..n]), false)
            .map_err(io_err)?;
        Poll::Ready(Ok(n))
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
/// The cert contains a critical id-pe-acmeIdentifier extension (OID 1.3.6.1.5.5.7.1.31)
/// whose value is an ASN.1 OCTET STRING holding SHA-256(key_authorization).
///
/// Uses `with_cert_resolver` instead of `with_single_cert` to bypass rustls's upfront
/// cert validation, which would reject our custom critical extension OID.
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
// Used for the CSR/cert exchange on both QUIC and H2 transports.
// Wire format: [u32 big-endian length][payload bytes]

pub async fn ctrl_read<R: AsyncRead + Unpin>(r: &mut R) -> anyhow::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

pub async fn ctrl_write<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> anyhow::Result<()> {
    w.write_all(&(data.len() as u32).to_be_bytes()).await?;
    w.write_all(data).await?;
    Ok(())
}

pub async fn collect_h2_body(mut body: h2::RecvStream) -> anyhow::Result<bytes::Bytes> {
    let mut buf = bytes::BytesMut::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(io_err)?;
        let _ = body.flow_control().release_capacity(chunk.len());
        buf.extend_from_slice(&chunk);
    }
    Ok(buf.freeze())
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
        // Accept the certificate itself unconditionally — there is no CA to
        // validate against for self-signed certs. Private-key ownership is
        // enforced by verify_tls1{2,3}_signature below.
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
