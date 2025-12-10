#!/bin/bash
set -e

cleanup() {
    echo "Stopping processes..."
    kill $(jobs -p) 2>/dev/null || true
}
trap cleanup EXIT

echo "--- STARTING HTTP/2 SCENARIO (Pooling) ---"

# 1. Start Dummy Echo Server
python3 tests/dummy_echo.py 13001 &
sleep 1

# 2. Start Tunnel Server
export BIND_API="0.0.0.0:24433"
export BIND_PUB="0.0.0.0:28443"
./target/debug/server > server_h2.log 2>&1 &
sleep 1

# 3. Start 5 Tunnel Clients
export SERVER_ADDR="127.0.0.1:24433"
export LOCAL_ADDR="127.0.0.1:13001"
export FORCE_HTTP2="1"

CLIENT_IDS=()

for i in {1..5}; do
    ./target/debug/client > "client_h2_$i.log" 2>&1 &
    sleep 0.5
done

echo "Waiting for clients to connect..."
sleep 5

# Collect IDs
for i in {1..5}; do
    ID=$(grep "ID: " "client_h2_$i.log" | head -n 1 | awk '{print $2}')
    if [ ! -z "$ID" ]; then
        CLIENT_IDS+=("$ID")
        echo "Client $i ID: $ID"
    fi
done

if [ ${#CLIENT_IDS[@]} -eq 0 ]; then
    echo "No clients connected?"
    exit 1
fi

# 4. Verify Pooling (Check logs)
echo "Verifying Pooling (LINK ADD events)..."
LINK_ADDS=$(grep "LINK ADD" server_h2.log | wc -l)
echo "Total Link Adds: $LINK_ADDS"

# 5 clients * 4 connections = 20 expected. Allow some slack.
if [ "$LINK_ADDS" -ge 15 ]; then
    echo "Pooling Verified (>= 15 connections for 5 clients)"
else
    echo "FAILURE: Pooling count too low: $LINK_ADDS"
    exit 1
fi

# 5. Test Connectivity for the first client
TEST_ID=${CLIENT_IDS[0]}
echo "Testing connectivity for $TEST_ID..."

if python3 tests/verify_client.py 28443 "${TEST_ID}.localhost"; then
    echo "SUCCESS: Ping echoed back via HTTP/2"
else
    echo "FAILURE: Did not receive ping back"
    echo "--- Server Log ---"
    cat server_h2.log
    echo "--- Client Logs ---"
    # Show last 50 lines of all client logs combined, to catch any relevant output
    tail -n 50 client_h2_*.log
    exit 1
fi

echo "HTTP/2 Test Passed"
