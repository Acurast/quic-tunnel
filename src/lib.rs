use std::{pin::Pin, task::{Context, Poll}};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
        Self { r: Box::pin(r), w: Box::pin(w) }
    }
}

impl AsyncRead for IO {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context, buf: &mut ReadBuf) -> Poll<std::io::Result<()>> {
        self.r.as_mut().poll_read(cx, buf)
    }
}

impl AsyncWrite for IO {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<std::io::Result<usize>> {
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
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.0.capacity() == 0 {
            self.0.reserve_capacity(buf.len());
            match self.0.poll_capacity(cx) {
                Poll::Ready(Some(Ok(_))) => {}
                Poll::Pending => return Poll::Pending,
                Poll::Ready(other) => {
                    let msg = other.and_then(|r| r.err()).map(|e| e.to_string()).unwrap_or_else(|| "closed".into());
                    return Poll::Ready(Err(io_err(msg)));
                }
            }
        }
        let n = self.0.capacity().min(buf.len());
        if n == 0 {
            return Poll::Pending;
        }
        self.0.send_data(bytes::Bytes::copy_from_slice(&buf[..n]), false).map_err(io_err)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context) -> Poll<std::io::Result<()>> {
        self.0.send_data(bytes::Bytes::new(), true).map_err(io_err)?;
        Poll::Ready(Ok(()))
    }
}

pub struct H2Recv {
    pub r: h2::RecvStream,
    pub buf: bytes::Bytes,
}

impl AsyncRead for H2Recv {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context, buf: &mut ReadBuf) -> Poll<std::io::Result<()>> {
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

pub fn cert(name: &str) -> (rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>) {
    let generated = rcgen::generate_simple_self_signed(vec![name.into()]).unwrap();
    let cert = generated.cert.der().to_vec().into();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der()).into();
    (cert, key)
}

pub fn io_err<E: Into<Box<dyn std::error::Error + Send + Sync>>>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)
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
    fn verify_server_cert(&self, _: &rustls::pki_types::CertificateDer, _: &[rustls::pki_types::CertificateDer], _: &rustls::pki_types::ServerName, _: &[u8], _: rustls::pki_types::UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        SCHEMES.to_vec()
    }
}

impl rustls::server::danger::ClientCertVerifier for NoVerify {
    fn verify_client_cert(&self, _: &rustls::pki_types::CertificateDer, _: &[rustls::pki_types::CertificateDer], _: rustls::pki_types::UnixTime) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        SCHEMES.to_vec()
    }
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
}
