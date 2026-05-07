#!/bin/sh
set -e

: "${SERVER_ADDR:?SERVER_ADDR is required}"
: "${DOMAIN_SUFFIX:?DOMAIN_SUFFIX is required}"

# SERVER_ADDR may be comma-separated for multiple relay servers
SERVER_ARGS=""
for addr in $(echo "$SERVER_ADDR" | tr ',' ' '); do
    SERVER_ARGS="$SERVER_ARGS --server $addr"
done

exec client \
    $SERVER_ARGS \
    --domain-suffix "$DOMAIN_SUFFIX" \
    --local "${LOCAL_ADDR:-127.0.0.1:3000}" \
    --pool-size "${POOL_SIZE:-4}" \
    --primary-key "${PRIMARY_KEY:-/data/client.key}" \
    --cert-pem "${CERT_PEM_PATH:-/data/acme_cert.pem}" \
    ${ACME_EMAIL:+--acme-email "$ACME_EMAIL"} \
    ${ACME_CREDS_PATH:+--acme-creds-path "$ACME_CREDS_PATH"} \
    ${ACME_STAGING:+--acme-staging} \
    ${FORCE_HTTP2:+--force-h2} \
    ${PRIMARY_CERT_EXTENSION_HEX:+--primary-cert-extension-hex "$PRIMARY_CERT_EXTENSION_HEX"} \
    ${SECONDARY_KEY:+--secondary-key "$SECONDARY_KEY"} \
    ${SECONDARY_CERT_EXTENSION_HEX:+--secondary-cert-extension-hex "$SECONDARY_CERT_EXTENSION_HEX"}
