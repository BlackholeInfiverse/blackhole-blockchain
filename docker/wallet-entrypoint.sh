#!/bin/sh

# Ensure required tools are available
if ! command -v go >/dev/null 2>&1; then
  apk add --no-cache go >/dev/null
fi
if ! command -v curl >/dev/null 2>&1; then
  apk add --no-cache curl >/dev/null
fi
if ! command -v jq >/dev/null 2>&1; then
  apk add --no-cache jq >/dev/null
fi

# Default ports (can be overridden by env BLOCKCHAIN_API_URL / BRIDGE_API_URL)
: "${BLOCKCHAIN_API_URL:=http://blackhole-node-1:8080}"
: "${BRIDGE_API_URL:=http://blackhole-bridge:8084}"

# Wait up to 60s for blockchain health; if not available, fall back to offline mode
echo "[wallet-entrypoint] Probing blockchain health at ${BLOCKCHAIN_API_URL}/health ..."
ATTEMPTS=0
MAX_ATTEMPTS=30
SLEEP_SECS=2
ONLINE=0
while [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
  if curl -sf "${BLOCKCHAIN_API_URL}/health" >/dev/null; then
    ONLINE=1
    break
  fi
  ATTEMPTS=$((ATTEMPTS+1))
  sleep $SLEEP_SECS
done

if [ "$ONLINE" = "1" ]; then
  echo "[wallet-entrypoint] Blockchain is up. Fetching peerId ..."
  PEER_ID=$(curl -s "${BLOCKCHAIN_API_URL}/api/p2p/info" | jq -r '.peerId // empty')
  if [ -n "$PEER_ID" ] && [ "$PEER_ID" != "null" ]; then
    PEER_ADDR="/dns4/blackhole-node-1/tcp/3000/p2p/${PEER_ID}"
    echo "[wallet-entrypoint] Discovered peer: $PEER_ID"
    exec go run services/wallet/main.go -web -port 9000 -peerAddr "$PEER_ADDR"
  else
    echo "[wallet-entrypoint] PeerId not discovered. Starting in offline mode."
    exec go run services/wallet/main.go -web -port 9000
  fi
else
  echo "[wallet-entrypoint] Blockchain not reachable. Starting wallet in offline mode."
  exec go run services/wallet/main.go -web -port 9000
fi
