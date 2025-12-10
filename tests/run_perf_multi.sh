#!/bin/bash
set -e

cleanup() {
    echo "Stopping processes..."
    kill $(jobs -p) 2>/dev/null || true
    rm -f client_multi_*.log perf_*.log
}
trap cleanup EXIT

NUM_CLIENTS=5
DURATION=10

echo "========================================="
echo "    MULTI-CLIENT PERFORMANCE BENCHMARK"
echo "    Clients: $NUM_CLIENTS | Duration: ${DURATION}s"
echo "========================================="

run_benchmark() {
    MODE=$1
    API_PORT=$2
    PUB_PORT=$3
    FORCE_H2_ENV=$4

    echo ""
    echo "--- BENCHMARK: $MODE ($NUM_CLIENTS clients) ---"

    # Start Echo Server for this benchmark
    python3 tests/dummy_echo.py 13001 > /dev/null 2>&1 &
    ECHO_PID=$!
    sleep 0.5

    # Start Tunnel Server
    export BIND_API="0.0.0.0:$API_PORT"
    export BIND_PUB="0.0.0.0:$PUB_PORT"
    echo "[Setup] Starting Tunnel Server..."
    ./target/debug/server > server.log 2>&1 &
    SERVER_PID=$!
    sleep 1

    # Start Tunnel Clients
    export SERVER_ADDR="127.0.0.1:$API_PORT"
    export LOCAL_ADDR="127.0.0.1:13001"
    if [ "$FORCE_H2_ENV" == "1" ]; then
        export FORCE_HTTP2="1"
    else
        unset FORCE_HTTP2
    fi

    CLIENT_IDS=()
    for i in $(seq 1 $NUM_CLIENTS); do
        ./target/debug/client > "client_multi_$i.log" 2>&1 &
        # Small stagger to allow connection setup
        sleep 0.2
    done

    echo "[Setup] Waiting for $NUM_CLIENTS clients to initialize..."
    sleep 10

    # Harvest IDs
    for i in $(seq 1 $NUM_CLIENTS); do
        ID=$(grep "ID: " "client_multi_$i.log" | head -n 1 | awk '{print $2}')
        if [ -z "$ID" ]; then
            echo "Error: Could not find ID for client $i"
            cat "client_multi_$i.log"
            exit 1
        fi
        CLIENT_IDS+=("$ID")
    done

    echo "[Run] Starting $NUM_CLIENTS concurrent perf clients..."
    
    PIDS=()
    for i in $(seq 1 $NUM_CLIENTS); do
        ID=${CLIENT_IDS[$((i-1))]}
        python3 tests/perf_client.py $PUB_PORT "${ID}.localhost" $DURATION > "perf_${i}.log" 2>&1 &
        PIDS+=($!)
    done

    # Wait for all perf clients
    for pid in "${PIDS[@]}"; do
        wait $pid
    done

    echo "--- Results ($MODE) ---"
    TOTAL_MB_SENT=0
    TOTAL_MB_RECV=0
    
    for i in $(seq 1 $NUM_CLIENTS); do
        LOG="perf_${i}.log"
        SENT=$(grep "Sent:" $LOG | awk '{print $2}')
        RECV=$(grep "Recv:" $LOG | awk '{print $2}')
        THROUGHPUT_RECV=$(grep "Recv:" $LOG | awk -F'throughput: ' '{print $2}' | awk '{print $1}')
        
        echo "Client $i (${CLIENT_IDS[$((i-1))]}): $RECV MB ($THROUGHPUT_RECV MB/s)"
        
        # Simple floating point addition in bash using python/bc or just integer approximation
        # Using python for summing floats to be safe
        TOTAL_MB_SENT=$(python3 -c "print($TOTAL_MB_SENT + $SENT)")
        TOTAL_MB_RECV=$(python3 -c "print($TOTAL_MB_RECV + $RECV)")
    done

    TOTAL_THROUGHPUT=$(python3 -c "print(f'{($TOTAL_MB_RECV / $DURATION):.2f}')")
    echo "----------------------------------------"
    echo "Total Data Received: ${TOTAL_MB_RECV} MB"
    echo "Aggregate Throughput: ${TOTAL_THROUGHPUT} MB/s"
    echo "----------------------------------------"

    if [ "$TOTAL_MB_RECV" == "0.0" ]; then
        echo "FAILURE: No data received."
        echo "--- Server Log ---"
        cat server.log
    fi

    # Kill server and clients for this round
    kill $(jobs -p) 2>/dev/null || true
    sleep 2
}

# Run QUIC
run_benchmark "QUIC" 14433 18443 "0"

# Run HTTP/2
export POOL_SIZE=1
run_benchmark "HTTP/2" 24433 28443 "1"

echo ""
echo "========================================="
echo "    MULTI-CLIENT BENCHMARK COMPLETE"
echo "========================================="
