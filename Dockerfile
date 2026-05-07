# syntax=docker/dockerfile:1

# ── Build ─────────────────────────────────────────────────────────────────────
FROM rust:1.86.0-slim-bookworm AS build

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config && \
    rm -rf /var/lib/apt/lists/*

# Fetch dependencies before copying source so this layer is cached
# as long as any Cargo.toml / Cargo.lock is unchanged.
COPY Cargo.toml Cargo.lock ./
COPY tunnel-common/Cargo.toml tunnel-common/
COPY tunnel-client/Cargo.toml tunnel-client/
COPY tunnel-client-ffi/Cargo.toml tunnel-client-ffi/
COPY tunnel-server/Cargo.toml tunnel-server/
COPY client/Cargo.toml client/
COPY relay/Cargo.toml relay/
RUN mkdir -p tunnel-common/src tunnel-client/src tunnel-client-ffi/src \
             tunnel-server/src client/src relay/src && \
    touch tunnel-common/src/lib.rs tunnel-client/src/lib.rs \
          tunnel-client-ffi/src/lib.rs tunnel-server/src/lib.rs \
          client/src/main.rs relay/src/main.rs
RUN cargo fetch --locked

COPY . .
RUN cargo build --release --bin server --bin client

# ── Server ────────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS server

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /app/target/release/server /usr/local/bin/server
COPY docker/server-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# /data holds the ACME account credentials JSON (persisted via volume)
VOLUME /data
WORKDIR /data

# 443/tcp  — TLS-ALPN-01 challenge port (Let's Encrypt validation)
# 4433/udp — QUIC (agent connections)
# 4433/tcp — HTTP/2 (agent connections)
# 8443/tcp — public port (user connections)
EXPOSE 443/tcp 4433/udp 4433/tcp 8443/tcp

ENTRYPOINT ["/entrypoint.sh"]

# ── Client ────────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS client

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /app/target/release/client /usr/local/bin/client
COPY docker/client-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# /data holds client.key (the persistent keypair — determines client_id)
# and optionally cert.pem (pre-issued LE cert, set CERT_PEM_PATH=/data/cert.pem)
VOLUME /data
WORKDIR /data

ENTRYPOINT ["/entrypoint.sh"]
