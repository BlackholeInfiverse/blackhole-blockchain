#!/bin/bash

echo "🌍 Real-World Blockchain Faucet"
echo "================================"
echo ""
echo "This is a production-grade blockchain faucet with enterprise features."
echo ""
echo "You can either:"
echo "1. Start without peer address (configure later via admin panel)"
echo "2. Provide peer address now for immediate connection"
echo ""
echo "Example peer address: /ip4/192.168.0.86/tcp/3000/p2p/12D3KooWG5v7Kff6pcNjAyd9upk53d47vLADeD1DkKJ55mfsiwEL"
echo ""
read -p "Enter peer address (or press Enter to skip): " PEER_ADDRESS
echo ""

if [ -z "$PEER_ADDRESS" ]; then
    echo "Starting faucet without initial connection..."
    echo "Configure peer address through admin panel: http://localhost:8095/admin"
    go run real_world_faucet.go
else
    echo "Starting faucet with peer: $PEER_ADDRESS"
    go run real_world_faucet.go "$PEER_ADDRESS"
fi

echo ""
echo "Access Points:"
echo "- Web Interface: http://localhost:8095"
echo "- Admin Panel: http://localhost:8095/admin"
echo "- API Base: http://localhost:8095/api/v1"
echo ""
