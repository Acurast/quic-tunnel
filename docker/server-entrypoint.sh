#!/bin/sh
set -e

# DOMAIN_SUFFIX is optional. May be comma-separated for multiple allowed
# suffixes. If unset/empty, the server accepts all client domains.
SUFFIX_ARGS=""
if [ -n "$DOMAIN_SUFFIX" ]; then
    for suffix in $(echo "$DOMAIN_SUFFIX" | tr ',' ' '); do
        SUFFIX_ARGS="$SUFFIX_ARGS --domain-suffix $suffix"
    done
fi

exec server \
    $SUFFIX_ARGS \
    ${BIND_ADDR:+--bind-addr "$BIND_ADDR"} \
    ${API_PORT:+--api-port "$API_PORT"} \
    ${PUB_PORT:+--pub-port "$PUB_PORT"} \
    ${TLS_CERT_PATH:+--tls-cert "$TLS_CERT_PATH"} \
    ${TLS_KEY_PATH:+--tls-key "$TLS_KEY_PATH"} \
    ${ACME_DOMAIN:+--acme-domain "$ACME_DOMAIN"} \
    ${ACME_EMAIL:+--acme-email "$ACME_EMAIL"} \
    ${ACME_CREDS_PATH:+--acme-creds-path "$ACME_CREDS_PATH"} \
    ${ACME_STAGING:+--acme-staging} \
    ${ACME_RENEW_DAYS:+--acme-renew-days "$ACME_RENEW_DAYS"}
