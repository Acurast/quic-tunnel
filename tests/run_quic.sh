#!/bin/bash
set -e

# Cleanup function
cleanup() {
    echo "Stopping processes..."
    kill $(jobs -p) 2>/dev/null || true
}
trap cleanup EXIT

echo "--- STARTING QUIC SCENARIO ---"

# 1. Start Dummy Echo Server
python3 tests/dummy_echo.py 13001 &
DUMMY_PID=$!
sleep 1

# 2. Start Tunnel Server
export BIND_API="0.0.0.0:14433"
export BIND_PUB="0.0.0.0:18443"
./target/debug/server > server_quic.log 2>&1 &
SERVER_PID=$!
sleep 1

# 3. Start Tunnel Client
export SERVER_ADDR="127.0.0.1:14433"
export LOCAL_ADDR="127.0.0.1:13001"
./target/debug/client > client_quic.log 2>&1 &
CLIENT_PID=$!

# Wait for client to initialize and grab ID
echo "Waiting for client ID..."
sleep 2
CLIENT_ID=$(grep "ID: " client_quic.log | head -n 1 | awk '{print $2}')

if [ -z "$CLIENT_ID" ]; then
    echo "Failed to get Client ID"
    cat client_quic.log
    exit 1
fi

echo "Client ID: $CLIENT_ID"

# 4. Test Connectivity
echo "Sending Ping..."
python3 tests/verify_client.py 18443 "${CLIENT_ID}.localhost"

if [ $? -eq 0 ]; then
    echo "SUCCESS: Ping echoed back via QUIC"
else
    echo "FAILURE: Did not receive ping back"
    exit 1
fi

echo "QUIC Test Passed"
