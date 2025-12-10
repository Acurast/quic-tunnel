#!/bin/bash

# 1. Check Arguments
if [ -z "$1" ]; then
    echo "Usage: $0 <TARGET_URL>"
    echo "Example: $0 https://feb81ec3f09b6f02.localhost:8443/test.bin"
    exit 1
fi

URL="$1"

# 2. Setup Backend (The Tunnel needs something to fetch!)
# We create a 5MB dummy file and serve it on port 3000
echo "[Setup] Generating 5MB dummy file..."
dd if=/dev/urandom of=test.bin bs=1m count=5 status=none

echo "[Setup] Starting background Python server on port 3000..."
python3 -m http.server 3000 > /dev/null 2>&1 &
SERVER_PID=$!
sleep 1 # Give it a moment to bind

# 3. The Race
echo "[Race] Firing 10 concurrent requests to: $URL"
echo "---------------------------------------------------"

for i in {1..10}; do
    (
        # High-precision timer
        start=$(date +%s.%N)
        
        # Curl the Tunnel URL (insecure for self-signed, silent output)
        if curl -k -s -o /dev/null "$URL"; then
            end=$(date +%s.%N)
            diff=$(echo "$end - $start" | bc)
            
            # Formatting: Mark slow requests (Packet Loss hits)
            if (( $(echo "$diff > 1.0" | bc -l) )); then
                echo "⚠️  Req #$i STALLED: ${diff}s (Hit Packet Loss)"
            else
                echo "✅ Req #$i FAST:    ${diff}s"
            fi
        else
            echo "❌ Req #$i FAILED"
        fi
    ) &
done

# Wait for all background curls to finish
wait

# 4. Cleanup
echo "---------------------------------------------------"
echo "[Cleanup] Stopping backend and removing file."
kill $SERVER_PID
rm test.bin
