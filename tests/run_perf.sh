#!/bin/bash
set -e

# Cleanup function
cleanup() {
    echo "Stopping processes..."
    kill $(jobs -p) 2>/dev/null || true
}
trap cleanup EXIT

echo "========================================="
echo "        PERFORMANCE BENCHMARK"
echo "========================================="

# 1. Start Dummy Echo Server
echo "[Setup] Starting Echo Server on 13001..."
python3 tests/dummy_echo.py 13001 &
DUMMY_PID=$!
sleep 1

# --- QUIC BENCHMARK ---
echo ""
echo "--- BENCHMARK: QUIC ---"

export BIND_API="0.0.0.0:14433"
export BIND_PUB="0.0.0.0:18443"
echo "[Setup] Starting Tunnel Server (QUIC Port: 14433, Pub: 18443)..."
./target/debug/server > /dev/null 2>&1 &
SERVER_PID=$!
sleep 1

export SERVER_ADDR="127.0.0.1:14433"
export LOCAL_ADDR="127.0.0.1:13001"
unset FORCE_HTTP2
echo "[Setup] Starting Tunnel Client (QUIC)..."
./target/debug/client > client_perf_quic.log 2>&1 &
CLIENT_PID=$!

sleep 2
CLIENT_ID=$(grep "ID: " client_perf_quic.log | head -n 1 | awk '{print $2}')
if [ -z "$CLIENT_ID" ]; then echo "Failed to get Client ID"; exit 1; fi
echo "[Info] Client ID: $CLIENT_ID"

echo "[Run] Running Perf Client (10 seconds)..."
python3 tests/perf_client.py 18443 "${CLIENT_ID}.localhost" 10

kill $SERVER_PID $CLIENT_PID
sleep 1

# --- HTTP/2 BENCHMARK ---
echo ""
echo "--- BENCHMARK: HTTP/2 ---"

export BIND_API="0.0.0.0:24433"
export BIND_PUB="0.0.0.0:28443"
echo "[Setup] Starting Tunnel Server (H2 Port: 24433, Pub: 28443)..."
./target/debug/server > /dev/null 2>&1 &
SERVER_PID=$!
sleep 1

export SERVER_ADDR="127.0.0.1:24433"
export LOCAL_ADDR="127.0.0.1:13001"
export FORCE_HTTP2="1"
echo "[Setup] Starting Tunnel Client (H2)..."
./target/debug/client > client_perf_h2.log 2>&1 &
CLIENT_PID=$!

sleep 2
CLIENT_ID=$(grep "ID: " client_perf_h2.log | head -n 1 | awk '{print $2}')
if [ -z "$CLIENT_ID" ]; then echo "Failed to get Client ID"; exit 1; fi
echo "[Info] Client ID: $CLIENT_ID"

echo "[Run] Running Perf Client (10 seconds)..."
python3 tests/perf_client.py 28443 "${CLIENT_ID}.localhost" 10

echo ""
echo "========================================="
echo "        BENCHMARK COMPLETE"
echo "========================================="
