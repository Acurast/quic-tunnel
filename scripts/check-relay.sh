#!/usr/bin/env bash
# Checks that a relay is reachable and correctly set up for tunnel clients.
# Run it from any machine on the public internet, not from the relay host.
#
# Usage: check-relay.sh [options] <relay-host> [domain-suffix]
#   --api-port N   agent port (QUIC + H2), default 4433
#   --pub-port N   public port, default 443
#   domain-suffix  tunnel URL suffix; omit it to skip the wildcard DNS check
#
# Requires: dig, openssl (3.2+ for the QUIC check), curl, perl.
#
# The relay only admits clients of an acknowledged on-chain deployment, so this
# checks the setup around it. For a full end-to-end test, run the tunnel example
# deployment (acurast-example-apps/apps/app-tunnel) against the relay.

set -uo pipefail

API_PORT=4433
PUB_PORT=443

usage() {
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --api-port) API_PORT="$2"; shift 2 ;;
        --pub-port) PUB_PORT="$2"; shift 2 ;;
        -h|--help) usage ;;
        -*) echo "unknown option: $1" >&2; usage ;;
        *) break ;;
    esac
done
[ $# -ge 1 ] && [ $# -le 2 ] || usage
RELAY="$1"
SUFFIX="${2:-}"

FAILS=0
WARNS=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
warn() { printf '  \033[33mWARN\033[0m %s\n' "$*"; WARNS=$((WARNS + 1)); }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILS=$((FAILS + 1)); }
info() { printf '       %s\n' "$*"; }
section() { printf '\n== %s\n' "$*"; }

# Portable timeout: macOS has no `timeout`.
with_timeout() {
    local secs="$1"
    shift
    perl -e 'alarm shift; exec @ARGV' "$secs" "$@"
}

for tool in dig openssl curl perl; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 2; }
done

sorted_ips() {
    dig +short "$2" "$1" | grep -E '^[0-9a-fA-F.:]+$' | sort -u | tr '\n' ' ' | sed 's/ $//'
}

check_dns() {
    section "DNS"
    local probe="relay-check-$RANDOM$RANDOM.$SUFFIX"
    local family
    RELAY_V4=$(sorted_ips "$RELAY" A)
    RELAY_V6=$(sorted_ips "$RELAY" AAAA)
    if [ -z "$RELAY_V4$RELAY_V6" ]; then
        fail "$RELAY does not resolve"
        return
    fi
    pass "$RELAY resolves: $(echo "$RELAY_V4 $RELAY_V6" | xargs)"
    if [ -z "$SUFFIX" ]; then
        info "wildcard check skipped: no domain suffix given"
        return
    fi

    for family in A AAAA; do
        local relay_ips wildcard_ips
        [ "$family" = A ] && relay_ips="$RELAY_V4" || relay_ips="$RELAY_V6"
        wildcard_ips=$(sorted_ips "$probe" "$family")
        if [ -z "$wildcard_ips" ] && [ -z "$relay_ips" ]; then
            continue
        fi
        if [ -z "$wildcard_ips" ]; then
            if [ "$family" = A ]; then
                fail "*.$SUFFIX has no A record (tunnel URLs and Let's Encrypt cannot reach the relay)"
            else
                warn "*.$SUFFIX has no AAAA record while $RELAY does (IPv6-only visitors cannot connect)"
            fi
        elif [ "$wildcard_ips" = "$relay_ips" ]; then
            pass "*.$SUFFIX $family -> $wildcard_ips (same as relay)"
        else
            fail "*.$SUFFIX $family -> $wildcard_ips, but $RELAY -> ${relay_ips:-none}"
            info "Let's Encrypt validation and visitor traffic for tunnel URLs go to $wildcard_ips."
            [ "$family" = AAAA ] && info "Let's Encrypt prefers IPv6, so a wrong AAAA record breaks cert issuance."
        fi
    done
}

check_api_cert() {
    section "Relay certificate (TCP $API_PORT)"
    local err rc
    err=$(curl -sS -o /dev/null --max-time 10 "https://$RELAY:$API_PORT/" 2>&1)
    rc=$?
    case $rc in
        7|28) fail "TCP $API_PORT unreachable (curl exit $rc)"; return ;;
        51|60) fail "certificate rejected: $(echo "${err#curl: }" | head -1)"; return ;;
    esac
    # Any other outcome means the certificate verified; the relay then
    # demands a client certificate, which curl does not have.
    pass "certificate is trusted and matches $RELAY"

    local pem
    pem=$(with_timeout 10 openssl s_client -connect "$RELAY:$API_PORT" -servername "$RELAY" </dev/null 2>/dev/null |
        openssl x509 2>/dev/null)
    if [ -z "$pem" ]; then
        warn "could not read the certificate to check its expiry"
        return
    fi
    info "$(echo "$pem" | openssl x509 -noout -issuer) / $(echo "$pem" | openssl x509 -noout -enddate)"
    if ! echo "$pem" | openssl x509 -noout -checkend $((14 * 86400)) >/dev/null; then
        fail "expires within 14 days; renewal is overdue"
    elif ! echo "$pem" | openssl x509 -noout -checkend $((28 * 86400)) >/dev/null; then
        warn "expires within 28 days; renewal (30 days before expiry by default) should already have happened"
    else
        pass "more than 28 days of validity left"
    fi
}

check_quic() {
    section "QUIC (UDP $API_PORT)"
    if ! openssl s_client -help 2>&1 | grep -q -- '-quic'; then
        warn "skipped: this openssl ($(openssl version)) has no QUIC support; install OpenSSL 3.2+ to test UDP"
        return
    fi
    local out
    out=$(with_timeout 10 openssl s_client -quic -alpn relay-check -connect "$RELAY:$API_PORT" \
        -servername "$RELAY" </dev/null 2>&1)
    # Any reply, even a rejection, proves the UDP path works; silence means it is blocked.
    if echo "$out" | grep -q "Protocol: QUIC"; then
        pass "relay answers QUIC on UDP $API_PORT"
    else
        fail "no QUIC reply on UDP $API_PORT (firewall or security group blocking UDP?)"
        info "Clients fall back to HTTP/2, which works but is slower under packet loss."
    fi
}

public_probe() {
    local sni="$1"
    shift
    with_timeout 10 openssl s_client -connect "$RELAY:$PUB_PORT" -servername "$sni" "$@" </dev/null 2>&1
}

check_public_port() {
    section "Public port (TCP $PUB_PORT)"
    local sni="relay-check-$RANDOM$RANDOM.${SUFFIX:-invalid}"
    local out
    out=$(public_probe "$sni")
    if echo "$out" | grep -qiE "connection refused|connect:errno|Network is unreachable|No route"; then
        fail "TCP $PUB_PORT unreachable"
        return
    fi
    if ! echo "$out" | grep -q "CONNECTED"; then
        fail "TCP $PUB_PORT unreachable (no connection within 10s)"
        return
    fi
    pass "TCP $PUB_PORT reachable"

    # The relay routes raw TLS by SNI and never terminates it itself: for an
    # unknown name it closes the connection without a TLS alert or certificate.
    local verdict=ok
    if echo "$out" | grep -q "BEGIN CERTIFICATE\|^subject="; then
        verdict=cert
    elif echo "$out" | grep -qiE "alert|SSL alert number"; then
        verdict=alert
    fi
    case $verdict in
        ok) pass "unknown hostname is dropped without TLS, as the relay does" ;;
        cert)
            fail "port $PUB_PORT presents its own certificate: another TLS server (reverse proxy?) is in front of the relay"
            info "$(echo "$out" | grep -m1 '^subject=')"
            ;;
        alert)
            fail "port $PUB_PORT answers with a TLS alert: another TLS server (reverse proxy?) is in front of the relay"
            info "$(echo "$out" | grep -m1 -iE 'alert')"
            ;;
    esac
    if [ "$verdict" != ok ]; then
        info "Typical culprits: nginx (alert 112 unrecognized_name), Caddy (alert 80 internal_error)."
        info "Port $PUB_PORT must reach the relay's public listener as raw TCP (or SNI passthrough, e.g. nginx stream + ssl_preread)."
        info "Otherwise tunnel traffic and Let's Encrypt TLS-ALPN-01 validation never reach the relay."
        return
    fi

    out=$(public_probe "$sni" -alpn acme-tls/1)
    if echo "$out" | grep -qiE "alert|^subject="; then
        fail "TLS-ALPN-01 (acme-tls/1) is intercepted on port $PUB_PORT; Let's Encrypt validation will fail"
    else
        pass "TLS-ALPN-01 (acme-tls/1) reaches the relay listener"
    fi
}

echo "Checking relay $RELAY (agent port $API_PORT, public port $PUB_PORT, suffix ${SUFFIX:-none})"
check_dns
check_api_cert
check_quic
check_public_port

printf '\n== Result: %d failed, %d warnings\n' "$FAILS" "$WARNS"
[ "$FAILS" -eq 0 ]
