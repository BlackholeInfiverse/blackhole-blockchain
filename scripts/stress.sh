#!/bin/bash

# BlackHole Stress Test Script
# Send many TXs using existing wallet CLI

set -e

# Configuration
RPC_HOST="localhost:8545"
WALLET_HOST="localhost:9000"
TX_COUNT=${TX_COUNT:-100}  # Number of transactions to send
CONCURRENT_TXS=${CONCURRENT_TXS:-10}  # Concurrent transactions
TX_DELAY=${TX_DELAY:-0.1}  # Delay between transactions in seconds

# Test wallet addresses (these would need to be created/funded)
SENDER_ADDRESS="0x742d35Cc6634C0532925a3b8D4C9db96590c6C87"  # Example
RECIPIENT_ADDRESSES=(
    "0x742d35Cc6634C0532925a3b8D4C9db96590c6C88"
    "0x742d35Cc6634C0532925a3b8D4C9db96590c6C89"
    "0x742d35Cc6634C0532925a3b8D4C9db96590c6C8a"
)

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

    return 0
}

# Get current gas price
get_gas_price() {
    local response
    response=$(curl -s -X POST "http://${RPC_HOST}" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_gasPrice","params":[],"id":1}' 2>/dev/null)

    if echo "$response" | jq -e '.result' >/dev/null 2>&1; then
        echo "$response" | jq -r '.result'
    else
        echo "0x4a817c800"  # Default 20 gwei
    fi
}

# Send a single transaction
send_transaction() {
    local tx_id="$1"
    local recipient_index=$((tx_id % ${#RECIPIENT_ADDRESSES[@]}))
    local recipient="${RECIPIENT_ADDRESSES[$recipient_index]}"
    local amount=$((1000000000000000 + RANDOM % 10000000000000000))  # 0.001 to 0.01 ETH in wei

    log_info "Sending TX ${tx_id}: ${amount} wei to ${recipient}"

    # Get gas price
    local gas_price
    gas_price=$(get_gas_price)

    # Create transaction data
    local tx_data="{
        \"jsonrpc\": \"2.0\",
        \"method\": \"eth_sendTransaction\",
        \"params\": [{
            \"from\": \"${SENDER_ADDRESS}\",
            \"to\": \"${recipient}\",
            \"value\": \"0x$(printf '%x' $amount)\",
            \"gas\": \"0x5208\",
            \"gasPrice\": \"${gas_price}\"
        }],
        \"id\": ${tx_id}
    }"

    local response
    response=$(curl -s -X POST "http://${RPC_HOST}" \
        -H "Content-Type: application/json" \
        -d "$tx_data" 2>/dev/null)

    if echo "$response" | jq -e '.result' >/dev/null 2>&1; then
        local tx_hash
        tx_hash=$(echo "$response" | jq -r '.result')
        log_success "TX ${tx_id} submitted: ${tx_hash}"
        echo "$tx_hash"
    else
        local error_msg
        error_msg=$(echo "$response" | jq -r '.error.message // "Unknown error"')
        log_error "TX ${tx_id} failed: ${error_msg}"
        echo "error"
    fi
}

# Check transaction status
check_tx_status() {
    local tx_hash="$1"
    local tx_id="$2"

    if [ "$tx_hash" = "error" ]; then
        return 1
    fi

    local response
    response=$(curl -s -X POST "http://${RPC_HOST}" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\",\"params\":[\"${tx_hash}\"],\"id\":1}" 2>/dev/null)

    if echo "$response" | jq -e '.result' >/dev/null 2>&1; then
        local status
        status=$(echo "$response" | jq -r '.result.status')
        if [ "$status" = "0x1" ]; then
            log_success "TX ${tx_id} confirmed"
            return 0
        elif [ "$status" = "0x0" ]; then
            log_error "TX ${tx_id} failed"
            return 1
        else
            return 2  # Still pending
        fi
    else
        return 2  # Still pending or not found
    fi
}

# Monitor network stats
monitor_network() {
    local start_time="$1"
    local tx_submitted="$2"
    local tx_confirmed="$3"

    # Get current block number
    local response
    response=$(curl -s -X POST "http://${RPC_HOST}" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null)

    local current_block="unknown"
    if echo "$response" | jq -e '.result' >/dev/null 2>&1; then
        current_block=$(printf "%d" "$(echo "$response" | jq -r '.result')")
    fi

    # Get pending transactions
    response=$(curl -s -X POST "http://${RPC_HOST}" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_getBlockTransactionCountByNumber","params":["pending"],"id":1}' 2>/dev/null)

    local pending_txs="unknown"
    if echo "$response" | jq -e '.result' >/dev/null 2>&1; then
        pending_txs=$(printf "%d" "$(echo "$response" | jq -r '.result')")
    fi

    local elapsed=$(( $(date +%s) - start_time ))
    local tps=0
    if [ $elapsed -gt 0 ]; then
        tps=$((tx_confirmed * 100 / elapsed))
        tps=$((tps / 100))
    fi

    log_info "Network Status - Block: ${current_block}, Pending TXs: ${pending_txs}, TPS: ${tps}"
    log_info "Transactions - Submitted: ${tx_submitted}, Confirmed: ${tx_confirmed}"
}

# Run stress test
run_stress_test() {
    local start_time=$(date +%s)
    local tx_submitted=0
    local tx_confirmed=0
    local tx_failed=0
    local -a tx_hashes
    local -a tx_statuses

    log_info "Starting stress test: ${TX_COUNT} transactions, ${CONCURRENT_TXS} concurrent"

    # Initialize arrays
    for ((i=0; i<TX_COUNT; i++)); do
        tx_hashes[$i]=""
        tx_statuses[$i]=0  # 0=not sent, 1=submitted, 2=confirmed, 3=failed
    done

    # Phase 1: Submit transactions
    log_info "Phase 1: Submitting transactions..."

    for ((batch_start=0; batch_start<TX_COUNT; batch_start+=CONCURRENT_TXS)); do
        local batch_end=$((batch_start + CONCURRENT_TXS))
        if [ $batch_end -gt $TX_COUNT ]; then
            batch_end=$TX_COUNT
        fi

        log_info "Submitting batch ${batch_start}-${batch_end}..."

        # Submit batch concurrently
        for ((i=batch_start; i<batch_end; i++)); do
            (
                local tx_hash
                tx_hash=$(send_transaction "$i")
                if [ "$tx_hash" != "error" ]; then
                    tx_hashes[$i]="$tx_hash"
                    tx_statuses[$i]=1
                else
                    tx_statuses[$i]=3
                fi
            ) &

            # Small delay between submissions
            sleep "$TX_DELAY"
        done

        # Wait for batch to complete
        wait

        # Update counters
        for ((i=batch_start; i<batch_end; i++)); do
            if [ "${tx_statuses[$i]}" -eq 1 ]; then
                ((tx_submitted++))
            elif [ "${tx_statuses[$i]}" -eq 3 ]; then
                ((tx_failed++))
            fi
        done

        # Monitor network occasionally
        if (( batch_start % 50 == 0 )); then
            monitor_network "$start_time" "$tx_submitted" "$tx_confirmed"
        fi
    done

    log_info "Phase 1 complete - Submitted: ${tx_submitted}, Failed: ${tx_failed}"

    # Phase 2: Monitor confirmations
    log_info "Phase 2: Monitoring transaction confirmations..."

    local pending_txs=$tx_submitted
    local check_count=0

    while [ $pending_txs -gt 0 ] && [ $check_count -lt 60 ]; do  # Max 5 minutes
        ((check_count++))
        local newly_confirmed=0

        for ((i=0; i<TX_COUNT; i++)); do
            if [ "${tx_statuses[$i]}" -eq 1 ]; then
                local status
                status=$(check_tx_status "${tx_hashes[$i]}" "$i")
                case $status in
                    0)  # Confirmed
                        tx_statuses[$i]=2
                        ((newly_confirmed++))
                        ((tx_confirmed++))
                        ((pending_txs--))
                        ;;
                    1)  # Failed
                        tx_statuses[$i]=3
                        ((tx_failed++))
                        ((pending_txs--))
                        ;;
                esac
            fi
        done

        log_info "Check ${check_count}: ${newly_confirmed} newly confirmed, ${pending_txs} still pending"

        if [ $newly_confirmed -gt 0 ] || (( check_count % 10 == 0 )); then
            monitor_network "$start_time" "$tx_submitted" "$tx_confirmed"
        fi

        sleep 5
    done

    # Final summary
    local end_time=$(date +%s)
    local total_time=$((end_time - start_time))
    local success_rate=0

    if [ $tx_submitted -gt 0 ]; then
        success_rate=$((tx_confirmed * 100 / tx_submitted))
    fi

    local avg_tps=0
    if [ $total_time -gt 0 ]; then
        avg_tps=$((tx_confirmed * 100 / total_time))
        avg_tps=$((avg_tps / 100))
    fi

    log_info "=== Stress Test Results ==="
    log_info "Total transactions: ${TX_COUNT}"
    log_info "Submitted: ${tx_submitted}"
    log_info "Confirmed: ${tx_confirmed}"
    log_info "Failed: ${tx_failed}"
    log_info "Success rate: ${success_rate}%"
    log_info "Total time: ${total_time} seconds"
    log_info "Average TPS: ${avg_tps}"

    if [ $success_rate -ge 80 ]; then
        log_success "Stress test PASSED (success rate: ${success_rate}%)"
        return 0
    else
        log_error "Stress test FAILED (success rate: ${success_rate}%)"
        return 1
    fi
}

# Main function
main() {
    log_info "BlackHole Stress Test"
    log_info "===================="

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --count)
                TX_COUNT="$2"
                shift 2
                ;;
            --concurrent)
                CONCURRENT_TXS="$2"
                shift 2
                ;;
            --delay)
                TX_DELAY="$2"
                shift 2
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --count NUM         Number of transactions to send (default: 100)"
                echo "  --concurrent NUM    Number of concurrent transactions (default: 10)"
                echo "  --delay SECONDS     Delay between transactions (default: 0.1)"
                echo "  --help             Show this help message"
                echo ""
                echo "Environment variables:"
                echo "  RPC_HOST           RPC endpoint (default: localhost:8545)"
                echo "  WALLET_HOST        Wallet service (default: localhost:9000)"
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
    if run_stress_test; then
        log_success "Stress test completed successfully"
        exit 0
    else
        log_error "Stress test failed"
        exit 1
    fi
}

# Run main function
main "$@"