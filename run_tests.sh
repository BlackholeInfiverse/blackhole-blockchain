#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "Running tests for all components..."
echo

# Run OTC tests
echo "=== Running OTC Tests ==="
cd core/relay-chain/otc
go test -v ./...
OTC_RESULT=$?
echo

# Run Bridge SDK tests
echo "=== Running Bridge SDK Tests ==="
cd ../../../bridge-sdk
go test -v ./...
BRIDGE_RESULT=$?
echo

# Run Governance tests
echo "=== Running Governance Tests ==="
cd ../core/relay-chain/governance
go test -v ./...
GOV_RESULT=$?
echo

# Check results
if [ $OTC_RESULT -eq 0 ] && [ $BRIDGE_RESULT -eq 0 ] && [ $GOV_RESULT -eq 0 ]; then
    echo -e "${GREEN}All tests passed successfully!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Please check the output above for details.${NC}"
    exit 1
fi 