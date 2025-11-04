#!/bin/bash

# Simulate 1k events to test bridge
BASE_URL="http://localhost:8080"
EVENT_COUNT=1000
SUCCESS_RATE=0.8

echo "Starting simulation of $EVENT_COUNT events..."

for i in $(seq 1 $EVENT_COUNT); do
  CHAIN=$([ $((i % 2)) -eq 0 ] && echo "eth" || echo "sol")
  STATUS=$([ $(od -An -N1 -tu1 /dev/urandom | tr -d ' \n') -le $((256 * $SUCCESS_RATE)) ] && echo "success" || echo "failed")
  
  # Generate random data
  TX_HASH="0x$(openssl rand -hex 20)"
  AMOUNT=$(printf "%.6f" $(echo "scale=6; $RANDOM / 32767 * 1000" | bc -l))
  
  # POST to relay endpoint
  curl -s -X POST "$BASE_URL/relay/$CHAIN" \
    -H "Content-Type: application/json" \
    -d "{\"tx_hash\":\"$TX_HASH\",\"amount\":\"$AMOUNT\",\"status\":\"$STATUS\"}" \
    -w "\nStatus: %{http_code}\n" \
    --connect-timeout 5 \
    --max-time 10 || echo "Failed to send request $i"

  if [ $((i % 100)) -eq 0 ]; then
    echo "Processed $i events..."
  fi
done

echo "Simulation complete. Check logs for details."