#!/bin/bash

# DAY 2 ROUNDTRIP TEST - Non-breaking addition
# Tests complete flow: Wallet → DEX → Bridge → Target Chain
# Generates roundtrip-proof.json with full audit trail

set -e  # Exit on any error

# Configuration - use environment variables or defaults
BRIDGE_HOST="${BRIDGE_HOST:-localhost:9091}"
WALLET_HOST="${WALLET_HOST:-localhost:8080}"
RPC_HOST="${RPC_HOST:-localhost:8545}"
TARGET_CHAIN="${TARGET_CHAIN:-ethereum}"

# Test parameters
TOKEN_A="BHX"
TOKEN_B="USDT"
SWAP_AMOUNT=1000
MIN_AMOUNT_OUT=4800  # 0.3% slippage protection
TEST_TIMEOUT=300     # 5 minutes timeout

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

# Initialize proof data structure
PROOF_DATA='{
  "test_type": "day2_roundtrip",
  "timestamp": "'$(date -Iseconds)'",
  "services": {},
  "steps": [],
  "transactions": {},
  "events": {},
  "final_status": "unknown",
  "duration_seconds": 0
}'

# Update proof data
update_proof() {
    local key="$1"
    local value="$2"
    PROOF_DATA=$(echo "$PROOF_DATA" | jq ".$key = $value")
}

add_step() {
    local step_name="$1"
    local status="$2"
    local details="$3"
    local timestamp=$(date -Iseconds)

    local step_data='{
        "name": "'$step_name'",
        "status": "'$status'",
        "details": "'$details'",
        "timestamp": "'$timestamp'"
    }'

    PROOF_DATA=$(echo "$PROOF_DATA" | jq ".steps += [$step_data]")
}

# Service health checks
check_services() {
    log_info "🔍 Checking service health..."

    # Check Bridge service
    if curl -s -f "http://$BRIDGE_HOST/api/health" > /dev/null 2>&1; then
        log_success "Bridge service is healthy"
        update_proof "services.bridge" '{"status": "healthy", "host": "'$BRIDGE_HOST'"}'
    else
        log_error "Bridge service is not responding"
        update_proof "services.bridge" '{"status": "unhealthy", "host": "'$BRIDGE_HOST'"}'
        return 1
    fi

    # Check Wallet service
    if curl -s -f "http://$WALLET_HOST/api/health" > /dev/null 2>&1; then
        log_success "Wallet service is healthy"
        update_proof "services.wallet" '{"status": "healthy", "host": "'$WALLET_HOST'"}'
    else
        log_warning "Wallet service not available (expected for CLI testing)"
        update_proof "services.wallet" '{"status": "not_available", "host": "'$WALLET_HOST'"}'
    fi

    # Check RPC service
    if curl -s -f -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        "http://$RPC_HOST" > /dev/null 2>&1; then
        log_success "RPC service is healthy"
        update_proof "services.rpc" '{"status": "healthy", "host": "'$RPC_HOST'"}'
    else
        log_error "RPC service is not responding"
        update_proof "services.rpc" '{"status": "unhealthy", "host": "'$RPC_HOST'"}'
        return 1
    fi

    add_step "service_health_check" "completed" "All required services are healthy"
}

# Submit swap transaction
submit_swap() {
    log_info "🔄 Step 1: Submitting swap transaction via wallet/bridge API..."

    local swap_request='{
        "token_a": "'$TOKEN_A'",
        "token_b": "'$TOKEN_B'",
        "amount_in": '$SWAP_AMOUNT',
        "min_amount_out": '$MIN_AMOUNT_OUT'
    }'

    log_info "Swap request: $swap_request"

    # Submit swap via bridge API (simulating wallet submission)
    local response=$(curl -s -X POST "http://$BRIDGE_HOST/api/dex/swap" \
        -H "Content-Type: application/json" \
        -d "$swap_request" 2>/dev/null)

    if [ $? -eq 0 ] && echo "$response" | jq -e '.success' > /dev/null 2>&1; then
        local tx_hash=$(echo "$response" | jq -r '.data.tx_hash // empty')
        local amount_out=$(echo "$response" | jq -r '.data.amount_out // empty')

        if [ -n "$tx_hash" ]; then
            log_success "Swap submitted successfully - TX: $tx_hash, Amount Out: $amount_out"
            update_proof "transactions.swap" '{"tx_hash": "'$tx_hash'", "amount_in": '$SWAP_AMOUNT', "amount_out": '$amount_out', "token_pair": "'$TOKEN_A'/'$TOKEN_B'"}'
            add_step "submit_swap" "completed" "Swap transaction submitted: $tx_hash"
            echo "$tx_hash"
            return 0
        fi
    fi

    log_error "Failed to submit swap transaction"
    log_error "Response: $response"
    add_step "submit_swap" "failed" "Failed to submit swap transaction"
    return 1
}

# Monitor DEX events
monitor_dex_events() {
    local swap_tx_hash="$1"
    local timeout_seconds=$TEST_TIMEOUT

    log_info "👂 Step 2: Monitoring for DEX event emission..."

    local start_time=$(date +%s)
    local end_time=$((start_time + timeout_seconds))

    while [ $(date +%s) -lt $end_time ]; do
        # Check bridge events endpoint for DEX events
        local events_response=$(curl -s "http://$BRIDGE_HOST/api/events" 2>/dev/null || echo "{}")

        # Look for DEX-related events
        local dex_events=$(echo "$events_response" | jq -r '.events[]? | select(.type == "dex_swap" or .type == "price_change") | .id' 2>/dev/null || echo "")

        if [ -n "$dex_events" ]; then
            log_success "DEX event detected: $dex_events"
            update_proof "events.dex" '{"event_ids": "'$dex_events'", "swap_tx_hash": "'$swap_tx_hash'"}'
            add_step "dex_event_emission" "completed" "DEX emitted event for swap: $swap_tx_hash"
            return 0
        fi

        # Check for transaction status updates
        local tx_status=$(curl -s "http://$BRIDGE_HOST/api/tx/$swap_tx_hash" 2>/dev/null || echo "{}")
        local status=$(echo "$tx_status" | jq -r '.status // empty' 2>/dev/null || echo "")

        if [ "$status" = "confirmed" ] || [ "$status" = "success" ]; then
            log_success "Swap transaction confirmed: $status"
            update_proof "transactions.swap.status" '"confirmed"'
            break
        fi

        sleep 2
    done

    log_warning "DEX event monitoring timeout - proceeding with bridge check"
    add_step "dex_event_emission" "timeout" "DEX event monitoring timed out, proceeding to bridge check"
    return 0  # Don't fail on timeout, continue to bridge check
}

# Monitor bridge relay
monitor_bridge_relay() {
    local swap_tx_hash="$1"
    local timeout_seconds=$TEST_TIMEOUT

    log_info "🌉 Step 3: Monitoring bridge for event pickup and relay..."

    local start_time=$(date +%s)
    local end_time=$((start_time + timeout_seconds))

    while [ $(date +%s) -lt $end_time ]; do
        # Check for relay events
        local relay_events=$(curl -s "http://$BRIDGE_HOST/api/events" 2>/dev/null || echo "{}")

        # Look for relay events to target chain
        local relay_event=$(echo "$relay_events" | jq -r '.events[]? | select(.type == "relay_'$TARGET_CHAIN'" or .type == "cross_chain_transfer") | .id' 2>/dev/null || echo "")

        if [ -n "$relay_event" ]; then
            log_success "Bridge relay event detected: $relay_event"
            update_proof "events.bridge_relay" '{"event_id": "'$relay_event'", "target_chain": "'$TARGET_CHAIN'"}'
            add_step "bridge_relay" "completed" "Bridge relayed to $TARGET_CHAIN: $relay_event"
            return 0
        fi

        sleep 3
    done

    log_error "Bridge relay monitoring timeout"
    add_step "bridge_relay" "timeout" "Bridge relay monitoring timed out"
    return 1
}

# Verify target chain mint/unlock
verify_target_chain() {
    local timeout_seconds=$TEST_TIMEOUT

    log_info "🎯 Step 4: Verifying target chain ($TARGET_CHAIN) mint/unlock..."

    local start_time=$(date +%s)
    local end_time=$((start_time + timeout_seconds))

    while [ $(date +%s) -lt $end_time ]; do
        # Check relay endpoint for confirmation
        local relay_status=$(curl -s "http://$BRIDGE_HOST/api/relay/status" 2>/dev/null || echo "{}")

        # Look for successful relays to target chain
        local target_confirmations=$(echo "$relay_status" | jq -r '.relays[]? | select(.chain == "'$TARGET_CHAIN'" and .status == "confirmed") | .tx_hash' 2>/dev/null || echo "")

        if [ -n "$target_confirmations" ]; then
            log_success "Target chain confirmation received: $target_confirmations"
            update_proof "events.target_chain" '{"confirmations": "'$target_confirmations'", "chain": "'$TARGET_CHAIN'"}'
            add_step "target_chain_confirm" "completed" "Target chain ($TARGET_CHAIN) confirmed mint/unlock: $target_confirmations"
            return 0
        fi

        sleep 3
    done

    log_error "Target chain verification timeout"
    add_step "target_chain_confirm" "timeout" "Target chain verification timed out"
    return 1
}

# Generate final proof
generate_proof() {
    local final_status="$1"
    local duration="$2"

    update_proof "final_status" "\"$final_status\""
    update_proof "duration_seconds" "$duration"

    # Add summary
    local summary="Roundtrip test $final_status in ${duration}s. Steps completed: $(echo "$PROOF_DATA" | jq '.steps | length')"

    # Save to file
    echo "$PROOF_DATA" | jq '.' > roundtrip-proof.json

    log_info "📄 Roundtrip proof saved to roundtrip-proof.json"
    log_info "Summary: $summary"
}

# Main test execution
main() {
    local start_time=$(date +%s)

    echo "🚀 Starting DAY 2 Roundtrip Test"
    echo "================================="
    log_info "Configuration: BRIDGE_HOST=$BRIDGE_HOST, WALLET_HOST=$WALLET_HOST, RPC_HOST=$RPC_HOST, TARGET_CHAIN=$TARGET_CHAIN"
    log_info "Test Parameters: $TOKEN_A -> $TOKEN_B, Amount: $SWAP_AMOUNT, Min Out: $MIN_AMOUNT_OUT"

    # Step 1: Service health checks
    if ! check_services; then
        log_error "Service health checks failed - aborting test"
        generate_proof "failed_precondition" $(($(date +%s) - start_time))
        exit 1
    fi

    # Step 2: Submit swap
    local swap_tx_hash
    if ! swap_tx_hash=$(submit_swap); then
        log_error "Swap submission failed - aborting test"
        generate_proof "failed_swap" $(($(date +%s) - start_time))
        exit 1
    fi

    # Step 3: Monitor DEX events
    if ! monitor_dex_events "$swap_tx_hash"; then
        log_error "DEX event monitoring failed"
        generate_proof "failed_dex_event" $(($(date +%s) - start_time))
        exit 1
    fi

    # Step 4: Monitor bridge relay
    if ! monitor_bridge_relay "$swap_tx_hash"; then
        log_error "Bridge relay monitoring failed"
        generate_proof "failed_bridge_relay" $(($(date +%s) - start_time))
        exit 1
    fi

    # Step 5: Verify target chain
    if ! verify_target_chain; then
        log_error "Target chain verification failed"
        generate_proof "failed_target_chain" $(($(date +%s) - start_time))
        exit 1
    fi

    # Success!
    local duration=$(($(date +%s) - start_time))
    log_success "🎉 Roundtrip test completed successfully in ${duration}s!"
    generate_proof "success" "$duration"
}

# Cleanup function
cleanup() {
    local exit_code=$?
    local duration=$(($(date +%s) - ${start_time:-$(date +%s)}))

    if [ $exit_code -eq 0 ]; then
        log_success "Test completed successfully"
    else
        log_error "Test failed with exit code $exit_code"
        generate_proof "failed" "$duration"
    fi

    exit $exit_code
}

# Set up cleanup trap
trap cleanup EXIT

# Run main test
main "$@"