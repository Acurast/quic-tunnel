# QUIC Tunnel

A fast, modern reverse tunnel that exposes your local services to the internet. Think ngrok or Cloudflare Tunnel, but built from scratch in Rust with a focus on performance and reliability.

## Why Use This?

- **Expose local development servers** to the internet for testing webhooks, sharing demos, or mobile testing
- **Access services behind NAT/firewalls** without port forwarding
- **Self-hosted** — run your own tunnel infrastructure with full control
- **Optimized for multiplexed traffic** — handles many concurrent connections efficiently

## Key Features

- **QUIC-first with HTTP/2 fallback** — Uses QUIC (UDP) by default for best performance, automatically falls back to HTTP/2 (TCP) when UDP is blocked
- **Head-of-line blocking mitigation** — Independent QUIC streams mean packet loss on one connection doesn't stall others
- **Connection pooling** — Multiple parallel connections in HTTP/2 mode for better throughput
- **TLS everywhere** — End-to-end encryption with automatic certificate generation
- **Client identity via certificates** — Each client gets a unique subdomain based on its certificate fingerprint

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              INTERNET                                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TUNNEL SERVER                                       │
│  ┌────────────────┐    ┌────────────────┐    ┌────────────────────────────┐ │
│  │   API Port     │    │   Public Port  │    │      Agent Registry        │ │
│  │  (QUIC + TCP)  │    │   (TCP/TLS)    │    │  client_id → [connections] │ │
│  │    :4433       │    │     :8443      │    └────────────────────────────┘ │
│  └───────┬────────┘    └───────┬────────┘                                   │
│          │                     │                                            │
│          │  Agents connect     │  Users connect via                         │
│          │  and register       │  {client_id}.localhost:8443                │
└──────────┼─────────────────────┼────────────────────────────────────────────┘
           │                     │
     QUIC streams          SNI routing
     or H2 streams         to correct agent
           │                     │
           ▼                     │
┌─────────────────────┐          │
│    TUNNEL CLIENT    │◄─────────┘
│  ┌───────────────┐  │    Tunnel stream opened
│  │ TLS Acceptor  │  │    for each user request
│  └───────┬───────┘  │
│          │          │
│          ▼          │
│  ┌───────────────┐  │
│  │ Local Service │  │
│  │    :3000      │  │
│  └───────────────┘  │
└─────────────────────┘
```

## Connection Flow

### 1. Client Registration

```
Client                           Server
   │                                │
   │──── QUIC/H2 + Client Cert ────▶│
   │                                │
   │                     Extract cert fingerprint
   │                     Register as agent
   │                                │
   │◀─── Connection Established ────│
   │                                │
   ▼                                ▼
 Ready to accept tunnels      client_id registered
```

### 2. User Request Routing

```
User                    Server                    Client                Local
 │                         │                         │                    │
 │── TLS ClientHello ─────▶│                         │                    │
 │   (SNI: abc123.localhost)                         │                    │
 │                         │                         │                    │
 │              Extract SNI, lookup agent            │                    │
 │                         │                         │                    │
 │                         │── Open QUIC/H2 stream ─▶│                    │
 │                         │                         │                    │
 │◀─────────────── Bidirectional tunnel ────────────▶│──── TCP ──────────▶│
 │                         │                         │                    │
```

## Head-of-Line Blocking Mitigation

Traditional TCP-based tunnels suffer from **head-of-line (HOL) blocking**: if a packet is lost, all subsequent packets must wait for retransmission, even if they belong to different logical connections.

### The Problem with TCP/HTTP/2

```
User A ─────┐                   ┌───── Tunnel to A
User B ─────┼── Single TCP ─────┼───── Tunnel to B  (blocked by A's lost packet!)
User C ─────┘    connection     └───── Tunnel to C  (blocked by A's lost packet!)
```

### How QUIC Solves This

QUIC multiplexes streams over UDP with **independent loss recovery per stream**:

```
User A ─────── QUIC Stream 1 ─────── Tunnel to A  (packet loss only affects A)
User B ─────── QUIC Stream 2 ─────── Tunnel to B  (unaffected)
User C ─────── QUIC Stream 3 ─────── Tunnel to C  (unaffected)
```

Each user's connection is an independent QUIC stream. Packet loss or congestion on one stream doesn't block others — they continue flowing independently.

### How Our HTTP/2 Fallback Mitigates HOL

Standard HTTP/2 over a single TCP connection still suffers from TCP-level HOL blocking. Our implementation mitigates this with a **connection pool**:

```
                    ┌─── TCP Conn 1 ───── H2 Streams ─────▶ Users A, E, I...
                    │
Client ─────────────┼─── TCP Conn 2 ───── H2 Streams ─────▶ Users B, F, J...
  (POOL_SIZE=4)     │
                    ├─── TCP Conn 3 ───── H2 Streams ─────▶ Users C, G, K...
                    │
                    └─── TCP Conn 4 ───── H2 Streams ─────▶ Users D, H, L...
```

**How it helps:**

- **Distributed impact**: Packet loss on TCP Conn 1 only blocks users routed through that connection — users on Conn 2, 3, 4 are unaffected
- **Parallel recovery**: Multiple TCP connections can retransmit independently
- **Load spreading**: Incoming requests are distributed across the pool via random agent selection

While not as granular as QUIC (where each stream is independent), connection pooling significantly reduces the blast radius of TCP HOL blocking. With `POOL_SIZE=4`, a single packet loss event affects at most ~25% of concurrent connections instead of 100%.

## Transport Modes

### QUIC Mode (Default)

- **Protocol**: QUIC over UDP
- **Port**: Single port for control + data
- **Streams**: Native multiplexed streams with independent flow control
- **Best for**: Most scenarios, especially high-latency or lossy networks

### HTTP/2 Mode (Fallback)

Automatically activates when QUIC connection fails (e.g., UDP blocked by firewall).

- **Protocol**: HTTP/2 over TLS/TCP
- **Streams**: HTTP/2 multiplexed streams
- **Connection Pool**: Multiple parallel connections (configurable via `POOL_SIZE`)
- **Best for**: Networks that block UDP (corporate firewalls, some mobile networks)

The client automatically detects UDP availability and falls back seamlessly:

```
Attempt QUIC ──▶ Success? ──▶ Use QUIC
                    │
                    ▼ Failed
              Use HTTP/2 pool
```

## Usage

### Build

```bash
cargo build --release
```

### Run the Server

```bash
# Default: API on :4433, Public on :8443
./target/release/server

# Custom ports
BIND_API="0.0.0.0:4433" BIND_PUB="0.0.0.0:8443" ./target/release/server
```

### Run the Client

```bash
# Connect to server, forward to local port 3000
SERVER_ADDR="your-server.com:4433" LOCAL_ADDR="127.0.0.1:3000" ./target/release/client
```

The client will output:
```
ID: a1b2c3d4
URL: https://a1b2c3d4.localhost:8443
MODE: QUIC
```

### Access Your Service

Users can now access your local service at:
```
https://{client_id}.your-server.com:8443
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_ADDR` | `127.0.0.1:4433` | Server address for client to connect to |
| `LOCAL_ADDR` | `127.0.0.1:3000` | Local service address to forward traffic to |
| `BIND_API` | `0.0.0.0:4433` | Server API port (QUIC + TCP) |
| `BIND_PUB` | `0.0.0.0:8443` | Server public port for user connections |
| `FORCE_HTTP2` | (unset) | Force HTTP/2 mode (skip QUIC attempt) |
| `POOL_SIZE` | `4` | Number of HTTP/2 connections in pool |

## Security Notes

- **Self-signed certificates**: The tunnel uses self-signed certificates for simplicity. For production, consider using proper PKI or certificate pinning.
- **No certificate verification**: The default configuration skips certificate verification. This is intentional for ease of use but should be hardened for production deployments.
- **Client identity**: Clients are identified by the SHA256 hash of their certificate, providing cryptographic identity binding.

## Performance

The architecture is optimized for high concurrency:

- **QUIC mode**: Up to 1000 concurrent bidirectional streams per connection
- **HTTP/2 mode**: Connection pooling with configurable pool size
- **Zero-copy where possible**: Uses `tokio::io::copy_bidirectional` for efficient data transfer
- **Non-blocking I/O**: Fully async with Tokio runtime

## License

MIT
