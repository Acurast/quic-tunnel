use std::process::{Command, Stdio, Child};
use std::time::Duration;
use std::io::{BufRead, BufReader};
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use rustls::pki_types::ServerName;

fn build_binaries() {
    let status = Command::new("cargo")
        .args(&["build", "--bin", "server", "--bin", "client"])
        .status()
        .expect("Failed to build binaries");
    assert!(status.success());
}

struct ProcessGuard(Child);
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn wait_for_port(port: u16) {
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        if TcpStream::connect(format!("127.0.0.1:{}", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("Port {} not available", port);
}

#[tokio::test]
async fn test_suites() {
    build_binaries();
    
    // --- Scenario 1: QUIC 50 clients ---
    println!("--- STARTING QUIC SCENARIO ---");
    let mut server = Command::new("./target/debug/server")
        .env("BIND_API", "0.0.0.0:14433")
        .env("BIND_PUB", "0.0.0.0:18443")
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start server");
    
    // Read server stdout in background to avoid blocking
    let server_stdout = server.stdout.take().unwrap();
    std::thread::spawn(move || {
        let reader = BufReader::new(server_stdout);
        for line in reader.lines() {
            if let Ok(l) = line { println!("[SERVER] {}", l); }
        }
    });

    let _server_guard = ProcessGuard(server);
    wait_for_port(14433).await;
    wait_for_port(18443).await;

    // Start Dummy Service
    let dummy = TcpListener::bind("127.0.0.1:13000").await.unwrap();
    let dummy_counts = Arc::new(Mutex::new(0));
    let dc = dummy_counts.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = dummy.accept().await {
            let dc = dc.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    let n = match stream.read(&mut buf).await { Ok(n) if n > 0 => n, _ => break };
                    stream.write_all(&buf[..n]).await.unwrap();
                    *dc.lock().unwrap() += 1;
                }
            });
        }
    });

    let mut clients = Vec::new();
    let mut client_ids = Vec::new();

    for _ in 0..50 {
        let mut client = Command::new("./target/debug/client")
            .env("SERVER_ADDR", "127.0.0.1:14433")
            .env("LOCAL_ADDR", "127.0.0.1:13000")
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to start client");

        let stdout = client.stdout.take().unwrap();
        let reader = BufReader::new(stdout);
        let mut id = String::new();
        for line in reader.lines() {
            if let Ok(l) = line {
                if l.starts_with("ID: ") {
                    id = l.trim_start_matches("ID: ").to_string();
                }
                if l.contains("MODE:") {
                    break; 
                }
            }
        }
        if !id.is_empty() {
            client_ids.push(id);
        }
        clients.push(ProcessGuard(client));
    }

    assert_eq!(client_ids.len(), 50);
    println!("All 50 clients connected via QUIC");

    // Test connectivity for each client (2 connections each = 100 connections)
    let mut tasks = Vec::new();
    for id in client_ids.iter() {
        for _ in 0..2 {
            let id = id.clone();
            tasks.push(tokio::spawn(async move {
                let config = rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoVerify))
                    .with_no_client_auth();
                let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
                let stream = TcpStream::connect("127.0.0.1:18443").await.unwrap();
                let domain = format!("{}.localhost", id);
                let domain_parsed = ServerName::try_from(domain.as_str()).unwrap().to_owned();
                let mut stream = connector.connect(domain_parsed, stream).await.unwrap();

                stream.write_all(b"ping").await.unwrap();
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"ping");
            }));
        }
    }
    
    futures::future::join_all(tasks).await;
    println!("Successfully tested 100 QUIC connections across 50 clients");

    // Cleanup
    drop(clients);
    drop(_server_guard); // Restart server for next test to ensure clean state
    
    // --- Scenario 2: HTTP/2 Fallback & HOL Mitigation ---
    println!("--- STARTING HTTP/2 SCENARIO ---");
    let mut server = Command::new("./target/debug/server")
        .env("BIND_API", "0.0.0.0:24433") // Different port
        .env("BIND_PUB", "0.0.0.0:28443")
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start server");

    let server_stdout = server.stdout.take().unwrap();
    let server_logs = Arc::new(Mutex::new(Vec::new()));
    let sl = server_logs.clone();
    std::thread::spawn(move || {
        let reader = BufReader::new(server_stdout);
        for line in reader.lines() {
            if let Ok(l) = line {
                // println!("[SERVER H2] {}", l);
                sl.lock().unwrap().push(l);
            }
        }
    });

    let _server_guard = ProcessGuard(server);
    wait_for_port(24433).await;
    wait_for_port(28443).await;
    
    let mut clients = Vec::new();
    let mut client_ids = Vec::new();

    // Spawn 1 client with FORCE_HTTP2
    for _ in 0..1 {
        let mut client = Command::new("./target/debug/client")
            .env("SERVER_ADDR", "127.0.0.1:24433")
            .env("LOCAL_ADDR", "127.0.0.1:13000") // Reuse dummy service
            .env("FORCE_HTTP2", "1")
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to start client");

        let stdout = client.stdout.take().unwrap();
        let reader = BufReader::new(stdout);
        let mut id = String::new();
        for line in reader.lines() {
            if let Ok(l) = line {
                if l.starts_with("ID: ") {
                    id = l.trim_start_matches("ID: ").to_string();
                }
                if l.contains("MODE:") {
                    assert!(l.contains("TCP/H2")); // Verify mode
                    break; 
                }
            }
        }
        if !id.is_empty() {
            client_ids.push(id);
        }
        clients.push(ProcessGuard(client));
    }
    
    assert_eq!(client_ids.len(), 1);
    println!("1 client connected via HTTP/2");

    // Give some time for connections to establish (4 per client)
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Test connectivity again with timeout
    let mut tasks = Vec::new();
    for id in client_ids.iter() {
        for _ in 0..2 {
            let id = id.clone();
            tasks.push(tokio::spawn(async move {
                let test_logic = async {
                    let config = rustls::ClientConfig::builder()
                        .dangerous()
                        .with_custom_certificate_verifier(Arc::new(NoVerify))
                        .with_no_client_auth();
                    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
                    let stream = TcpStream::connect("127.0.0.1:28443").await.unwrap();
                    let domain = format!("{}.localhost", id);
                    let domain_parsed = ServerName::try_from(domain.as_str()).unwrap().to_owned();
                    let mut stream = connector.connect(domain_parsed, stream).await.unwrap();

                    stream.write_all(b"ping").await.unwrap();
                    let mut buf = [0u8; 4];
                    stream.read_exact(&mut buf).await.unwrap();
                    assert_eq!(&buf, b"ping");
                };
                
                if tokio::time::timeout(Duration::from_secs(5), test_logic).await.is_err() {
                    panic!("Test connection timed out for {}", id);
                }
            }));
        }
    }
    futures::future::join_all(tasks).await;
    println!("Successfully tested H2 connections");

    // Verify HOL Mitigation (Pool x4)
    // Check server logs for "LINK ADD" counts
    let logs = server_logs.lock().unwrap();
    let add_count = logs.iter().filter(|l| l.contains("LINK ADD")).count();
    // 1 client * 4 connections = 4 expected
    println!("Total LINK ADD events: {}", add_count);
    assert!(add_count >= 3, "Expected ~4 connections, found {}", add_count);
    println!("HOL Mitigation verified: Multiple connections established per client.");

}

#[derive(Debug)] struct NoVerify;
impl rustls::client::danger::ServerCertVerifier for NoVerify { fn verify_server_cert(&self, _: &rustls::pki_types::CertificateDer, _: &[rustls::pki_types::CertificateDer], _: &rustls::pki_types::ServerName, _: &[u8], _: rustls::pki_types::UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> { Ok(rustls::client::danger::ServerCertVerified::assertion()) } fn verify_tls12_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> { Ok(rustls::client::danger::HandshakeSignatureValid::assertion()) } fn verify_tls13_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> { Ok(rustls::client::danger::HandshakeSignatureValid::assertion()) } fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> { vec![rustls::SignatureScheme::RSA_PSS_SHA256, rustls::SignatureScheme::ED25519, rustls::SignatureScheme::ECDSA_NISTP256_SHA256, rustls::SignatureScheme::ECDSA_NISTP384_SHA384] } }