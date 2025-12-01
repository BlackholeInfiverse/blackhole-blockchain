#!/bin/bash

# BlackHole Swap Test Script
# Simple guarded swap test using wallet CLI + RPC

set -e

# Configuration
RPC_HOST="localhost:8545"
WALLET_HOST="localhost:9000"
BRIDGE_HOST="localhost:8084"
TEST_DURATION=${TEST_DURATION:-30}  # seconds
CHECK_INTERVAL=${CHECK_INTERVAL:-5}  # seconds

# Test parameters
TOKEN_A="BHX"
TOKEN_B="USDT"
SWAP_AMOUNT=1000
MIN_AMOUNT_OUT=50

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

# Check if services are running
check_services() {
    log_info "Checking if required services are running..."

    # Check RPC
    if curl -s -f "http://${RPC_HOST}/health" >/dev/null 2>&1; then
        log_success "RPC service is running at ${RPC_HOST}"
    else
        log_error "RPC service is not accessible at ${RPC_HOST}"
        return 1
    fi

    # Check Wallet
    if curl -s -f "http://${WALLET_HOST}/health" >/dev/null 2>&1; then
        log_success "Wallet service is running at ${WALLET_HOST}"
    else
        log_warning "Wallet service health check failed, but continuing..."
    fi

    # Check Bridge SDK
    if curl -s -f "http://${BRIDGE_HOST}/health" >/dev/null 2>&1; then
        log_success "Bridge SDK is running at ${BRIDGE_HOST}"
    else
        log_error "Bridge SDK is not accessible at ${BRIDGE_HOST}"
        return 1
    fi

    return 0
}

# Get wallet balance
get_wallet_balance() {
    local address="$1"

    if [ -z "$address" ]; then
        log_warning "No wallet address provided, skipping balance check"
        return 0
    fi

    local response
    response=$(curl -s -X POST "http://${RPC_HOST}" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBalance\",\"params\":[\"${address}\",\"latest\"],\"id\":1}" 2>/dev/null)

    if echo "$response" | jq -e '.result' >/dev/null 2>&1; then
        local balance_hex
        balance_hex=$(echo "$response" | jq -r '.result')
        # Convert hex to decimal (assuming wei, convert to ether)
        local balance_wei
        balance_wei=$(printf "%d" "$balance_hex")
        local balance_eth=$((balance_wei / 1000000000000000000))
        log_info "Wallet balance: ${balance_eth} ETH"
        return 0
    else
        log_warning "Failed to get wallet balance"
        return 1
    fi
}

# Create test DEX pool via bridge API
create_test_pool() {
    log_info "Creating test DEX pool: ${TOKEN_A}/${TOKEN_B}"

    local response
    response=$(curl -s -X POST "http://${BRIDGE_HOST}/api/dex/pools" \
        -H "Content-Type: application/json" \
        -d "{\"token_a\":\"${TOKEN_A}\",\"token_b\":\"${TOKEN_B}\",\"reserve_a\":100,\"reserve_b\":1}" 2>/dev/null)

    if echo "$response" | jq -e '.success' >/dev/null 2>&1; then
        log_success "Test pool created successfully"
        return 0
    else
        log_warning "Failed to create test pool (may already exist): $response"
        return 0  # Continue anyway
    fi
}

# Perform swap using wallet CLI
perform_swap_via_wallet() {
    log_info "Attempting swap via wallet CLI: ${SWAP_AMOUNT} ${TOKEN_A} -> ${TOKEN_B}"

    # Note: This assumes the wallet has CLI commands for DEX operations
    # In a real implementation, you'd use wallet API endpoints or CLI commands

    # For this test, we'll simulate by calling the bridge DEX API directly
    # as the wallet would internally call these endpoints

    local response
    response=$(curl -s -X POST "http://${BRIDGE_HOST}/api/dex/swap" \
        -H "Content-Type: application/json" \
        -d "{\"token_a\":\"${TOKEN_A}\",\"token_b\":\"${TOKEN_B}\",\"amount_in\":${SWAP_AMOUNT},\"min_amount_out\":${MIN_AMOUNT_OUT}}" 2>/dev/null)

    if echo "$response" | jq -e '.success' >/dev/null 2>&1; then
        local tx_hash
        tx_hash=$(echo "$response" | jq -r '.data.tx_hash // empty')
        if [ -n "$tx_hash" ]; then
            log_success "Swap transaction submitted: ${tx_hash}"
            echo "$tx_hash"
            return 0
        else
            log_success "Swap request accepted (no tx hash returned)"
            return 0
        fi
    else
        log_error "Swap failed: $response"
        return 1
    fi
}

# Check transaction status
check_transaction_status() {
    local tx_hash="$1"

    if [ -z "$tx_hash" ]; then
        return 0
    fi

    local response
    response=$(curl -s -X POST "http://${RPC_HOST}" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"${tx_hash}\"],\"id\":1}" 2>/dev/null)

    if echo "$response" | jq -e '.result' >/dev/null 2>&1; then
        local status
        status=$(echo "$response" | jq -r '.result.status')
        if [ "$status" = "0x1" ]; then
            log_success "Transaction confirmed successfully"
            return 0
        elif [ "$status" = "0x0" ]; then
            log_error "Transaction failed"
            return 1
        else
            log_info "Transaction pending..."
            return 2  # Pending
        fi
    else
        log_warning "Could not get transaction receipt"
        return 2  # Pending/Unknown
    fi
}

# Test slippage protection
test_slippage_protection() {
    log_info "Testing slippage protection with high slippage scenario"

    # Try a swap that should trigger slippage protection
    local high_amount=50000  # Very high amount that should cause high slippage

    local response
    response=$(curl -s -X POST "http://${BRIDGE_HOST}/api/dex/test-slippage" \
        -H "Content-Type: application/json" \
        -d "{\"token_a\":\"${TOKEN_A}\",\"token_b\":\"${TOKEN_B}\",\"amount_in\":${high_amount},\"min_amount_out\":${MIN_AMOUNT_OUT}}" 2>/dev/null)

    if echo "$response" | jq -e '.protected' >/dev/null 2>&1; then
        local protected
        protected=$(echo "$response" | jq -r '.protected')
        local slippage
        slippage=$(echo "$response" | jq -r '.slippage_percent')

        if [ "$protected" = "true" ]; then
            log_success "Slippage protection working: prevented swap with ${slippage}% slippage"
            return 0
        else
            log_warning "Slippage protection failed: allowed swap with ${slippage}% slippage"
            return 1
        fi
    else
        log_warning "Could not test slippage protection"
        return 1
    fi
}

# Run the swap test
run_swap_test() {
    local start_time=$(date +%s)
    local end_time=$((start_time + TEST_DURATION))
    local swap_successful=0
    local protection_successful=0
    local tx_hash=""

    log_info "Starting swap test for ${TEST_DURATION} seconds..."

    # Initial setup
    if ! create_test_pool; then
        log_error "Failed to set up test environment"
        return 1
    fi

    # Perform swap
    tx_hash=$(perform_swap_via_wallet)
    if [ $? -eq 0 ]; then
        ((swap_successful++))
    fi

    # Test slippage protection
    if test_slippage_protection; then
        ((protection_successful++))
    fi

    # Monitor transaction if we have a hash
    if [ -n "$tx_hash" ]; then
        log_info "Monitoring transaction: ${tx_hash}"
        local attempts=0
        local max_attempts=10

        while [ $attempts -lt $max_attempts ] && [ $(date +%s) -lt $end_time ]; do
            local status
            status=$(check_transaction_status "$tx_hash")
            case $status in
                0)  # Success
                    log_success "Transaction confirmed"
                    break
                    ;;
                1)  # Failed
                    log_error "Transaction failed"
                    break
                    ;;
                2)  # Pending
                    log_info "Transaction still pending..."
                    ;;
            esac

            ((attempts++))
            sleep "$CHECK_INTERVAL"
        done
    fi

    # Summary
    log_info "=== Swap Test Summary ==="
    log_info "Swap attempts: ${swap_successful}/1"
    log_info "Slippage protection: ${protection_successful}/1"

    local success_rate=$(( (swap_successful + protection_successful) * 100 / 2 ))

    if [ $success_rate -ge 75 ]; then
        log_success "Swap test PASSED (success rate: ${success_rate}%)"
        return 0
    else
        log_error "Swap test FAILED (success rate: ${success_rate}%)"
        return 1
    fi
}

# Main function
main() {
    log_info "BlackHole Swap Test"
    log_info "==================="

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
            --amount)
                SWAP_AMOUNT="$2"
                shift 2
                ;;
            --min-out)
                MIN_AMOUNT_OUT="$2"
                shift 2
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --duration SECONDS    Test duration in seconds (default: 30)"
                echo "  --interval SECONDS    Check interval in seconds (default: 5)"
                echo "  --amount AMOUNT       Swap amount (default: 1000)"
                echo "  --min-out AMOUNT      Minimum amount out (default: 50)"
                echo "  --help               Show this help message"
                echo ""
                echo "Environment variables:"
                echo "  RPC_HOST             RPC endpoint (default: localhost:8545)"
                echo "  WALLET_HOST          Wallet service (default: localhost:9000)"
                echo "  BRIDGE_HOST          Bridge SDK (default: localhost:8084)"
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

    # Check services
    if ! check_services; then
        log_error "Required services are not running"
        exit 1
    fi

    # Run the test
    if run_swap_test; then
        log_success "Swap test completed successfully"
        exit 0
    else
        log_error "Swap test failed"
        exit 1
    fi
}

# Run main function
main "$@"