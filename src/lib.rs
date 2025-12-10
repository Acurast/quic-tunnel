use std::{pin::Pin, task::{Context, Poll}};
use tokio::io::{AsyncRead, AsyncWrite};

// --- IO & Adapters ---

pub struct IO { 
    pub r: Pin<Box<dyn AsyncRead + Send + Unpin>>, 
    pub w: Pin<Box<dyn AsyncWrite + Send + Unpin>> 
}

impl IO { 
    pub fn new<R: AsyncRead+Send+Unpin+'static, W: AsyncWrite+Send+Unpin+'static>(r: R, w: W) -> Self { 
        Self { r: Box::pin(r), w: Box::pin(w) } 
    }
}

impl AsyncRead for IO { 
    fn poll_read(mut self: Pin<&mut Self>, c: &mut Context, b: &mut tokio::io::ReadBuf) -> Poll<std::io::Result<()>> { 
        self.r.as_mut().poll_read(c, b) 
    } 
}

impl AsyncWrite for IO { 
    fn poll_write(mut self: Pin<&mut Self>, c: &mut Context, b: &[u8]) -> Poll<std::io::Result<usize>> { 
        self.w.as_mut().poll_write(c, b) 
    } 
    fn poll_flush(mut self: Pin<&mut Self>, c: &mut Context) -> Poll<std::io::Result<()>> { 
        self.w.as_mut().poll_flush(c) 
    } 
    fn poll_shutdown(mut self: Pin<&mut Self>, c: &mut Context) -> Poll<std::io::Result<()>> { 
        self.w.as_mut().poll_shutdown(c) 
    } 
}

pub struct H2Send(pub h2::SendStream<bytes::Bytes>);

impl AsyncWrite for H2Send { 
    fn poll_write(mut self: Pin<&mut Self>, c: &mut Context, b: &[u8]) -> Poll<std::io::Result<usize>> { 
        if b.is_empty() { return Poll::Ready(Ok(0)); }
        let cap = self.0.capacity();
        if cap == 0 {
            self.0.reserve_capacity(b.len());
            match self.0.poll_capacity(c) {
                Poll::Ready(Some(Ok(_))) => {},
                Poll::Pending => return Poll::Pending,
                Poll::Ready(e) => return Poll::Ready(Err(eio(e.and_then(|r| r.err()).map(|e| e.to_string()).unwrap_or_else(|| "closed".into())))),
            }
        }
        let n = std::cmp::min(self.0.capacity(), b.len());
        if n == 0 { return Poll::Pending; }
        self.0.send_data(bytes::Bytes::copy_from_slice(&b[..n]), false).map_err(eio)?;
        Poll::Ready(Ok(n))
    } 
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context) -> Poll<std::io::Result<()>> { Poll::Ready(Ok(())) } 
    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context) -> Poll<std::io::Result<()>> { self.0.send_data(bytes::Bytes::new(), true).map_err(eio)?; Poll::Ready(Ok(())) } 
}

pub struct H2Recv { 
    pub r: h2::RecvStream, 
    pub b: bytes::Bytes 
}

impl AsyncRead for H2Recv { 
    fn poll_read(mut self: Pin<&mut Self>, c: &mut Context, buf: &mut tokio::io::ReadBuf) -> Poll<std::io::Result<()>> { 
        if !self.b.is_empty() { 
            let l = std::cmp::min(buf.remaining(), self.b.len()); 
            buf.put_slice(&self.b.slice(0..l)); 
            self.b = self.b.slice(l..); 
            return Poll::Ready(Ok(())); 
        } 
        match self.r.poll_data(c) { 
            Poll::Ready(Some(Ok(d))) => { 
                let l = std::cmp::min(buf.remaining(), d.len()); 
                buf.put_slice(&d[..l]); 
                let _ = self.r.flow_control().release_capacity(d.len()); 
                if l < d.len() { self.b = d.slice(l..); } 
                Poll::Ready(Ok(())) 
            }, 
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(eio(e))), 
            Poll::Ready(None) => Poll::Ready(Ok(())), 
            Poll::Pending => Poll::Pending 
        } 
    } 
}

pub fn cert(n: &str) -> (rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>) { 
    let c = rcgen::generate_simple_self_signed(vec![n.into()]).unwrap(); 
    (c.cert.der().to_vec().into(), rustls::pki_types::PrivatePkcs8KeyDer::from(c.key_pair.serialize_der()).into()) 
}

pub fn eio<E: Into<Box<dyn std::error::Error + Send + Sync>>>(e: E) -> std::io::Error { 
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, e) 
}

#[derive(Debug)] 
pub struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify { 
    fn verify_server_cert(&self, _: &rustls::pki_types::CertificateDer, _: &[rustls::pki_types::CertificateDer], _: &rustls::pki_types::ServerName, _: &[u8], _: rustls::pki_types::UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> { Ok(rustls::client::danger::ServerCertVerified::assertion()) } 
    fn verify_tls12_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> { Ok(rustls::client::danger::HandshakeSignatureValid::assertion()) } 
    fn verify_tls13_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> { Ok(rustls::client::danger::HandshakeSignatureValid::assertion()) } 
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> { vec![rustls::SignatureScheme::RSA_PSS_SHA256, rustls::SignatureScheme::ED25519, rustls::SignatureScheme::ECDSA_NISTP256_SHA256, rustls::SignatureScheme::ECDSA_NISTP384_SHA384] } 
}

impl rustls::server::danger::ClientCertVerifier for NoVerify { 
    fn verify_client_cert(&self, _: &rustls::pki_types::CertificateDer, _: &[rustls::pki_types::CertificateDer], _: rustls::pki_types::UnixTime) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> { Ok(rustls::server::danger::ClientCertVerified::assertion()) } 
    fn verify_tls12_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> { Ok(rustls::client::danger::HandshakeSignatureValid::assertion()) } 
    fn verify_tls13_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> { Ok(rustls::client::danger::HandshakeSignatureValid::assertion()) } 
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> { vec![rustls::SignatureScheme::RSA_PSS_SHA256, rustls::SignatureScheme::ED25519, rustls::SignatureScheme::ECDSA_NISTP256_SHA256, rustls::SignatureScheme::ECDSA_NISTP384_SHA384] } 
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] { &[] } 
}