use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::AsyncWriteExt;
use tunnel_common::H2Send;

const WINDOW: u32 = 1024;
const PAYLOAD: usize = 64 * 1024;

/// Writing far more than the peer's flow-control window must complete rather
/// than stall: `poll_capacity` can report readiness with zero capacity.
#[tokio::test]
async fn write_all_exceeds_flow_control_window() {
    let (client_io, server_io) = tokio::io::duplex(4096);
    let received = Arc::new(AtomicUsize::new(0));

    let server = {
        let received = received.clone();
        tokio::spawn(async move {
            let mut conn: h2::server::Connection<_, bytes::Bytes> = h2::server::Builder::new()
                .initial_window_size(WINDOW)
                .initial_connection_window_size(WINDOW)
                .handshake(server_io)
                .await
                .expect("server handshake");
            while let Some(accepted) = conn.accept().await {
                let (req, mut respond) = accepted.expect("accept");
                let received = received.clone();
                tokio::spawn(async move {
                    let mut body = req.into_body();
                    while let Some(chunk) = body.data().await {
                        let chunk = chunk.expect("recv chunk");
                        received.fetch_add(chunk.len(), Ordering::SeqCst);
                        body.flow_control()
                            .release_capacity(chunk.len())
                            .expect("release capacity");
                    }
                    respond
                        .send_response(http::Response::new(()), true)
                        .expect("send response");
                });
            }
        })
    };

    let (mut client, connection) = h2::client::Builder::new()
        .max_send_buffer_size(2048)
        .handshake::<_, bytes::Bytes>(client_io)
        .await
        .expect("client handshake");
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = http::Request::builder()
        .method("POST")
        .uri("http://example.invalid/")
        .body(())
        .expect("build request");
    let (response, send) = client.send_request(request, false).expect("send request");
    drop(client);
    let mut w = H2Send(send);

    let payload = vec![0xa5u8; PAYLOAD];
    tokio::time::timeout(Duration::from_secs(10), async move {
        w.write_all(&payload).await.expect("write_all");
        w.shutdown().await.expect("shutdown");
        response.await.expect("response");
    })
    .await
    .expect("H2Send stalled on a flow-control-limited stream");

    assert_eq!(received.load(Ordering::SeqCst), PAYLOAD);

    server.abort();
    driver.abort();
}
