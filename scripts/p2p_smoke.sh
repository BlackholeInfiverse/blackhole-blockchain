#!/bin/bash

# BlackHole P2P Smoke Test Script
# Basic block propagation test using existing RPC endpoints

set -e

# Configuration
RPC_HOSTS=("localhost:8545" "localhost:8546" "localhost:8547" "localhost:8548" "localhost:8549")
DASHBOARD_HOSTS=("localhost:8080" "localhost:8081" "localhost:8082" "localhost:8083" "localhost:8085")
TEST_DURATION=${TEST_DURATION:-60}  # seconds
CHECK_INTERVAL=${CHECK_INTERVAL:-5}  # seconds

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

log_success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] SUCCESS: $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

log_error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

# Check if a node is responding
check_node_health() {
    local host="$1"
    local port="$2"

    if curl -s -f "http://${host}/health" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Get block height from RPC
get_block_height() {
    local rpc_host="$1"

    local response
    response=$(curl -s -X POST "http://${rpc_host}" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null)

    if echo "$response" | jq -e '.result' >/dev/null 2>&1; then
        # Convert hex to decimal
        echo "$response" | jq -r '.result' | sed 's/0x//' | xargs printf "%d\n"
    else
        echo "error"
    fi
}

# Get peer count
get_peer_count() {
    local rpc_host="$1"

    local response
    response=$(curl -s -X POST "http://${rpc_host}" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}' 2>/dev/null)

    if echo "$response" | jq -e '.result' >/dev/null 2>&1; then
        # Convert hex to decimal
        echo "$response" | jq -r '.result' | sed 's/0x//' | xargs printf "%d\n"
    else
        echo "error"
    fi
}

# Send a test transaction to trigger block mining
send_test_transaction() {
    local rpc_host="$1"

    # This is a simplified transaction send - in reality you'd need proper keys and gas
    log_info "Attempting to send test transaction on ${rpc_host}"

    # For smoke test, we'll just check if the RPC accepts the method
    local response
    response=$(curl -s -X POST "http://${rpc_host}" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_accounts","params":[],"id":1}' 2>/dev/null)

    if echo "$response" | jq -e '.result' >/dev/null 2>&1; then
        log_success "RPC call successful on ${rpc_host}"
        return 0
    else
        log_warning "RPC call failed on ${rpc_host}"
        return 1
    fi
}

# Check block propagation between nodes
check_block_propagation() {
    local -A block_heights
    local max_height=0
    local min_height=999999
    local active_nodes=0

    log_info "Checking block heights across nodes..."

    for rpc_host in "${RPC_HOSTS[@]}"; do
        if check_node_health "${rpc_host%:*}" "${rpc_host#*:}"; then
            local height
            height=$(get_block_height "$rpc_host")

            if [ "$height" != "error" ]; then
                block_heights["$rpc_host"]=$height
                ((active_nodes++))

                if [ "$height" -gt "$max_height" ]; then
                    max_height=$height
                fi
                if [ "$height" -lt "$min_height" ]; then
                    min_height=$height
                fi

                log_info "Node ${rpc_host}: Block height ${height}"
            else
                log_warning "Failed to get block height from ${rpc_host}"
            fi
        else
            log_warning "Node ${rpc_host} is not responding"
        fi
    done

    if [ $active_nodes -eq 0 ]; then
        log_error "No active nodes found"
        return 1
    fi

    local height_diff=$((max_height - min_height))

    log_info "Active nodes: ${active_nodes}"
    log_info "Block height range: ${min_height} - ${max_height} (diff: ${height_diff})"

    # Check if blocks are reasonably synchronized (within 5 blocks)
    if [ $height_diff -le 5 ]; then
        log_success "Block propagation appears healthy (height difference: ${height_diff})"
        return 0
    else
        log_warning "Block propagation may be delayed (height difference: ${height_diff})"
        return 1
    fi
}

# Check P2P connectivity
check_p2p_connectivity() {
    log_info "Checking P2P connectivity..."

    local total_peers=0
    local active_nodes=0

    for rpc_host in "${RPC_HOSTS[@]}"; do
        if check_node_health "${rpc_host%:*}" "${rpc_host#*:}"; then
            local peer_count
            peer_count=$(get_peer_count "$rpc_host")

            if [ "$peer_count" != "error" ]; then
                total_peers=$((total_peers + peer_count))
                ((active_nodes++))
                log_info "Node ${rpc_host}: ${peer_count} peers"
            else
                log_warning "Failed to get peer count from ${rpc_host}"
            fi
        fi
    done

    if [ $active_nodes -gt 0 ]; then
        local avg_peers=$((total_peers / active_nodes))
        log_info "Average peers per node: ${avg_peers}"

        if [ $avg_peers -gt 0 ]; then
            log_success "P2P network appears connected"
            return 0
        else
            log_warning "P2P network may have connectivity issues"
            return 1
        fi
    else
        log_error "No active nodes for P2P check"
        return 1
    fi
}

# Run the smoke test
run_smoke_test() {
    local start_time=$(date +%s)
    local end_time=$((start_time + TEST_DURATION))
    local iteration=1
    local propagation_healthy=0
    local p2p_healthy=0

    log_info "Starting P2P smoke test for ${TEST_DURATION} seconds..."
    log_info "Check interval: ${CHECK_INTERVAL} seconds"

    while [ $(date +%s) -lt $end_time ]; do
        log_info "=== Test Iteration $iteration ==="

        # Check block propagation
        if check_block_propagation; then
            ((propagation_healthy++))
        fi

        # Check P2P connectivity
        if check_p2p_connectivity; then
            ((p2p_healthy++))
        fi

        # Send test transaction on first available node
        for rpc_host in "${RPC_HOSTS[@]}"; do
            if check_node_health "${rpc_host%:*}" "${rpc_host#*:}"; then
                send_test_transaction "$rpc_host"
                break
            fi
        done

        iteration=$((iteration + 1))
        sleep "$CHECK_INTERVAL"
    done

    # Summary
    log_info "=== Test Summary ==="
    log_info "Total iterations: $((iteration - 1))"
    log_info "Block propagation healthy: ${propagation_healthy}/${iteration} iterations"
    log_info "P2P connectivity healthy: ${p2p_healthy}/${iteration} iterations"

    local success_rate=$(( (propagation_healthy + p2p_healthy) * 100 / (iteration * 2) ))

    if [ $success_rate -ge 80 ]; then
        log_success "P2P smoke test PASSED (success rate: ${success_rate}%)"
        return 0
    else
        log_error "P2P smoke test FAILED (success rate: ${success_rate}%)"
        return 1
    fi
}

# Main function
main() {
    log_info "BlackHole P2P Smoke Test"
    log_info "========================"

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --duration)
                TEST_DURATION="$2"
                shift 2
                ;;
            --interval)
                CHECK_INTERVAL="$2"
                shift 2
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --duration SECONDS    Test duration in seconds (default: 60)"
                echo "  --interval SECONDS    Check interval in seconds (default: 5)"
                echo "  --help               Show this help message"
                echo ""
                echo "Environment variables:"
                echo "  TEST_DURATION        Test duration in seconds"
                echo "  CHECK_INTERVAL       Check interval in seconds"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    # Check if jq is available
    if ! command -v jq >/dev/null 2>&1; then
        log_error "jq is required but not installed. Please install jq."
        exit 1
    fi

    # Run the test
    if run_smoke_test; then
        log_success "P2P smoke test completed successfully"
        exit 0
    else
        log_error "P2P smoke test failed"
        exit 1
    fi
}

# Run main function
main "$@"