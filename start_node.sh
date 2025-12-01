#!/bin/bash

# BlackHole Blockchain Node Startup Script
# Simple wrapper to run the node with environment variables

set -e

# Load environment variables from .env file if it exists
if [ -f ".env" ]; then
    echo "Loading environment variables from .env"
    export $(grep -v '^#' .env | xargs)
fi

# Set default values if not provided
: "${NODE_ENV:=production}"
: "${DOCKER_MODE:=false}"
: "${LOG_LEVEL:=info}"
: "${BLOCKCHAIN_PORT:=8080}"
: "${RPC_PORT:=8545}"
: "${P2P_PORT:=30303}"
: "${DATABASE_PATH:=./data/blockchain.db}"
: "${LOG_FILE:=./logs/blockchain.log}"
: "${PEER_DISCOVERY:=true}"
: "${MAX_PEERS:=50}"
: "${NODE_ID:=blackhole-node-1}"

# Create necessary directories
mkdir -p ./data ./logs

# Export environment variables for the node
export NODE_ENV DOCKER_MODE LOG_LEVEL BLOCKCHAIN_PORT RPC_PORT P2P_PORT
export DATABASE_PATH LOG_FILE PEER_DISCOVERY MAX_PEERS NODE_ID

echo "Starting BlackHole Blockchain Node..."
echo "  Dashboard: http://localhost:$BLOCKCHAIN_PORT"
echo "  RPC: http://localhost:$RPC_PORT"
echo "  P2P: localhost:$P2P_PORT"
echo "  Database: $DATABASE_PATH"
echo "  Logs: $LOG_FILE"

# Run the blockchain node
exec ./core/relay-chain/cmd/relay/blackhole-node