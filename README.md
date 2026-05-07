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
- **TLS everywhere** — End-to-end encryption with publicly trusted Let's Encrypt certificates (ACME) on both server and per-client endpoints
- **Client identity via certificates** — Each client gets a unique subdomain based on its keypair fingerprint
- **Dual endpoints per client** — Optional second connection using a separate keypair and a self-signed certificate, alongside the primary ACME-backed endpoint
- **Multi-server clients** — A single client can connect to several relay servers in parallel

## Workspace Layout

| Crate | Kind | Purpose |
|-------|------|---------|
| `tunnel-common` | lib | Shared protocol/cert/utility code |
| `tunnel-server` | lib | Relay server runtime (QUIC + H2 listeners, public router, ACME) |
| `tunnel-client` | lib | Reusable client runtime (multi-server, ACME, dual-endpoint) |
| `tunnel-client-ffi` | cdylib + uniffi | Android/iOS FFI surface; produces `libtunnel_client_ffi.so` |
| `relay` | bin (`server`) | Standalone relay server binary |
| `client` | bin (`client`) | Standalone CLI client binary |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              INTERNET                                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TUNNEL SERVER (relay)                               │
│  ┌────────────────┐    ┌────────────────┐    ┌────────────────────────────┐ │
│  │   API Port     │    │   Public Port  │    │      Agent Registry        │ │
│  │  (QUIC + TCP)  │    │   (TCP/TLS)    │    │  client_id → [connections] │ │
│  │    :4433       │    │     :8443      │    └────────────────────────────┘ │
│  └───────┬────────┘    └───────┬────────┘                                   │
│          │                     │      ┌────────────────────────────┐        │
│          │                     │      │     ALPN Port (TLS-ALPN-01)│        │
│          │                     │      │            :443            │        │
│          │                     │      │  Server's own LE cert      │        │
│          │                     │      │  (auto-renewed)            │        │
│          │                     │      └────────────────────────────┘        │
│          │  Agents connect     │  Users connect via                         │
│          │  and register       │  {client_id}.<suffix>:8443                 │
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
│  │ (ACME LE cert)│  │
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
 │   (SNI: abc123.<suffix>)                          │                    │
 │                         │                         │                    │
 │              Extract SNI, lookup agent            │                    │
 │                         │                         │                    │
 │                         │── Open QUIC/H2 stream ─▶│                    │
 │                         │                         │                    │
 │◀────── Bidirectional tunnel (terminated by client's LE cert) ─────────▶│
 │                         │                         │                    │
```

## TLS / Certificate Model

Two independent ACME flows:

- **Server cert** — covers the relay's public port (`:8443`) and ALPN/API listeners. Provisioned via TLS-ALPN-01 (`:443` must be reachable from the public internet) when `--acme-domain` is set; otherwise loaded from a `--tls-cert` PEM, or self-signed if neither is provided.
- **Per-client cert** — each tunnel client provisions its own publicly trusted LE cert for `{client_id}.<domain-suffix>` via HTTP-01-style challenge proxied through the server. The client terminates user TLS itself using this cert.

Optional **secondary endpoint** per client (`--secondary-key`) opens a second connection that terminates user TLS with a self-signed cert (no ACME).

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
  (--pool-size 4)   │
                    ├─── TCP Conn 3 ───── H2 Streams ─────▶ Users C, G, K...
                    │
                    └─── TCP Conn 4 ───── H2 Streams ─────▶ Users D, H, L...
```

**How it helps:**

- **Distributed impact**: Packet loss on TCP Conn 1 only blocks users routed through that connection — users on Conn 2, 3, 4 are unaffected
- **Parallel recovery**: Multiple TCP connections can retransmit independently
- **Load spreading**: Incoming requests are distributed across the pool via random agent selection

While not as granular as QUIC (where each stream is independent), connection pooling significantly reduces the blast radius of TCP HOL blocking. With `--pool-size 4`, a single packet loss event affects at most ~25% of concurrent connections instead of 100%.

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
- **Connection Pool**: Multiple parallel connections (configurable via `--pool-size`)
- **Best for**: Networks that block UDP (corporate firewalls, some mobile networks)

The client automatically detects UDP availability and falls back seamlessly:

```
Attempt QUIC ──▶ Success? ──▶ Use QUIC
                    │
                    ▼ Failed
              Use HTTP/2 pool
```

## Building

### Native (server + client binaries)

```bash
cargo build --release
# Binaries land at target/release/server and target/release/client
```

### Docker images

```bash
# Build both targets
docker compose build
# Or individually
docker build --target server -t quic-tunnel-server .
docker build --target client -t quic-tunnel-client .
```

### Android library (`libtunnel_client_ffi.so` + Kotlin bindings)

The provided helper script builds the FFI cdylib for the standard Android ABIs:

```bash
./build-android.sh                       # arm64-v8a + armeabi-v7a
COPY_TO=/path/to/android-app ./build-android.sh
```

To build the full AAR via Gradle (regenerates Kotlin bindings via uniffi):

```bash
cd android
./gradlew assembleRelease
# AAR at android/app/build/outputs/aar/app-release.aar
```

## Running

### Server (`relay`)

```bash
# Self-signed dev mode (no public domain)
./target/release/server

# With externally managed cert (e.g. certbot on host, mounted via volume)
./target/release/server \
  --tls-cert /etc/letsencrypt/live/yourserver.com/fullchain.pem \
  --tls-key  /etc/letsencrypt/live/yourserver.com/privkey.pem \
  --domain-suffix yourserver.com

# With server-provisioned ACME cert (TLS-ALPN-01; :443 must be reachable)
./target/release/server \
  --acme-domain yourserver.com \
  --acme-email you@example.com \
  --domain-suffix yourserver.com
```

Server CLI flags (`./target/release/server --help`):

| Flag | Default | Purpose |
|------|---------|---------|
| `--bind-addr` | `0.0.0.0` | Bind address for all listeners |
| `--api-port` | `4433` | QUIC + H2 agent port |
| `--pub-port` | `8443` | Public user-facing TLS port |
| `--alpn-port` | `443` | TLS-ALPN-01 challenge port (must be reachable as 443) |
| `--domain-suffix` | _(any)_ | Allowlisted client suffix; repeatable |
| `--tls-cert`, `--tls-key` | _(none)_ | PEM cert + key paths |
| `--acme-domain` | _(none)_ | Enables server ACME provisioning |
| `--acme-email` | _(none)_ | ACME account contact |
| `--acme-creds-path` | `server_acme_creds.json` | ACME account persistence |
| `--acme-staging` | off | Use Let's Encrypt staging |
| `--acme-renew-days` | `30` | Days-before-expiry renewal trigger |

### Client

```bash
# Single relay
./target/release/client \
  --server yourserver.com:4433 \
  --local 127.0.0.1:3000 \
  --domain-suffix yourserver.com \
  --acme-email you@example.com

# Multiple relays in parallel
./target/release/client \
  --server eu.yourserver.com:4433 --server us.yourserver.com:4433 \
  --local 127.0.0.1:3000 --domain-suffix yourserver.com \
  --acme-email you@example.com
```

The client logs:

```
ID: a1b2c3d4...
URL: https://a1b2c3d4....yourserver.com:8443
```

Client CLI flags (`./target/release/client --help`):

| Flag | Default | Purpose |
|------|---------|---------|
| `--server` | _(required, repeatable)_ | Relay address(es) |
| `--local` | `127.0.0.1:3000` | Local service address |
| `--domain-suffix` | `localhost` | Suffix used to form `{client_id}.<suffix>` |
| `--primary-key` | `client.key` | Primary keypair (auto-generated if missing) |
| `--force-h2` | off | Skip QUIC, use H2 pool only |
| `--pool-size` | `4` | H2 connections per relay |
| `--acme-email` | _(none)_ | LE account contact |
| `--acme-creds-path` | `acme_credentials.json` | LE account persistence |
| `--acme-staging` | off | Use LE staging |
| `--cert-pem` | `acme_cert.pem` | Cached LE cert path |
| `--primary-cert-extension-hex` | _(none)_ | Custom bytes embedded in primary cert |
| `--secondary-key` | _(none)_ | Enables a second self-signed endpoint |
| `--secondary-cert-extension-hex` | _(none)_ | Custom bytes for secondary cert |

### Secondary self-signed endpoint (optional)

```bash
./target/release/client \
  --server yourserver.com:4433 --local 127.0.0.1:3000 \
  --domain-suffix yourserver.com --acme-email you@example.com \
  --primary-key client.key --secondary-key client2.key
```

Exposes two endpoints for the same local service:

- `https://{primary_id}.yourserver.com:8443` — publicly trusted (Let's Encrypt)
- `https://{secondary_id}.yourserver.com:8443` — self-signed (use `curl -k` or pin the cert)

### Docker Compose

`docker-compose.yml` ships server + client targets. Set env in your shell or `.env`:

```bash
DOMAIN_SUFFIX=yourserver.com \
ACME_DOMAIN=yourserver.com \
ACME_EMAIL=you@example.com \
SERVER_ADDR=server:4433 \
LOCAL_ADDR=host.docker.internal:3000 \
docker compose up
```

The entrypoint scripts (`docker/server-entrypoint.sh`, `docker/client-entrypoint.sh`) translate env vars into CLI flags. See `docker-compose.yml` for the full env-var surface.

## Security Notes

- **Server cert** can be externally managed or auto-provisioned via TLS-ALPN-01. Pure self-signed mode exists for local dev only.
- **Per-client certs** are publicly trusted LE certs; the client owns its private key, the server only proxies HTTP-01 challenges.
- **Client identity** is the SHA-256 fingerprint of the client's keypair, providing cryptographic identity binding independent of the cert lifecycle.

## Performance

The architecture is optimized for high concurrency:

- **QUIC mode**: Up to 1000 concurrent bidirectional streams per connection
- **HTTP/2 mode**: Connection pooling with configurable pool size
- **Zero-copy where possible**: Uses `tokio::io::copy_bidirectional` for efficient data transfer
- **Non-blocking I/O**: Fully async with Tokio runtime

## License

MIT
