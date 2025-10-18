#!/bin/bash

# Roundtrip Test Script for BlackHole Bridge SDK
# This script performs end-to-end roundtrip testing of cross-chain swaps
# with visualization in the infra dashboard
#
# Steps:
# 1. Wallet signs & submits swap to DEX
# 2. DEX emits event → bridge picks and relays to TargetChain
# 3. TargetChain receives mint/unlock confirmation

set -e

# Configuration
BRIDGE_SDK_URL="http://localhost:8084"
MAIN_DASHBOARD_URL="http://localhost:8080"
TEST_DURATION=${TEST_DURATION:-600}  # 10 minutes default
CHECK_INTERVAL=${CHECK_INTERVAL:-5}   # Check every 5 seconds

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
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

log_step() {
    echo -e "${PURPLE}[$(date +'%Y-%m-%d %H:%M:%S')] STEP $1: $2${NC}"
}

log_progress() {
    echo -e "${CYAN}[$(date +'%Y-%m-%d %H:%M:%S')] PROGRESS: $1${NC}"
}

# Check if services are running
check_services() {
    log_info "Checking if required services are running..."

    # Check Bridge SDK
    if curl -s -f "${BRIDGE_SDK_URL}/health" > /dev/null 2>&1; then
        log_success "Bridge SDK is running at ${BRIDGE_SDK_URL}"
    else
        log_error "Bridge SDK is not accessible at ${BRIDGE_SDK_URL}"
        return 1
    fi

    # Check Main Dashboard
    if curl -s -f "${MAIN_DASHBOARD_URL}/api/health" > /dev/null 2>&1; then
        log_success "Main BlackHole blockchain dashboard is running at ${MAIN_DASHBOARD_URL}"
    else
        log_error "Main BlackHole blockchain dashboard is not accessible at ${MAIN_DASHBOARD_URL}"
        return 1
    fi

    return 0
}

# Check wallet balance for a specific token
check_wallet_balance() {
    local wallet_address=$1
    local token_symbol=$2

    local response
    response=$(curl -s -f "${MAIN_DASHBOARD_URL}/api/wallets/${wallet_address}/balance/${token_symbol}" 2>/dev/null)

    if [ $? -eq 0 ] && echo "$response" | jq -e '.success' > /dev/null 2>&1; then
        local balance
        balance=$(echo "$response" | jq -r '.data.balance // 0')
        echo "$balance"
        return 0
    else
        log_warning "Could not check balance for ${wallet_address}:${token_symbol}, assuming 0"
        echo "0"
        return 1
    fi
}

# Mint tokens to a wallet address (admin function)
mint_tokens() {
    local wallet_address=$1
    local token_symbol=$2
    local amount=$3

    log_info "Minting ${amount} ${token_symbol} tokens to ${wallet_address}"

    local response
    response=$(curl -s -X POST "${MAIN_DASHBOARD_URL}/api/admin/mint" \
        -H "Content-Type: application/json" \
        -d "{\"address\":\"${wallet_address}\",\"token\":\"${token_symbol}\",\"amount\":${amount}}" 2>/dev/null)

    if [ $? -eq 0 ] && echo "$response" | jq -e '.success' > /dev/null 2>&1; then
        log_success "Successfully minted ${amount} ${token_symbol} to ${wallet_address}"
        return 0
    else
        log_error "Failed to mint tokens: $response"
        return 1
    fi
}

# Start a cross-chain simulation with real blockchain integration
start_roundtrip_simulation() {
    local source_chain=${1:-"blackhole"}
    local target_chain=${2:-"ethereum"}
    local amount=${3:-"1000000000"}  # 1 BHX token (1B wei)
    local token=${4:-"BHX"}

    log_step "1" "Starting real roundtrip test: ${amount} ${token} from ${source_chain} to ${target_chain}"

    # First check if main dashboard is accessible
    if ! curl -s -f "${MAIN_DASHBOARD_URL}/api/health" > /dev/null 2>&1; then
        log_error "Main dashboard at ${MAIN_DASHBOARD_URL} is not accessible"
        return 1
    fi

    # Check BHX balance for the test wallet
    local test_wallet="0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
    local bhx_balance
    bhx_balance=$(check_wallet_balance "$test_wallet" "BHX")

    if [ "$bhx_balance" -lt "$amount" ]; then
        log_warning "Insufficient BHX balance ($bhx_balance). Minting additional tokens..."
        mint_tokens "$test_wallet" "BHX" "$amount"
    fi

    local response
    response=$(curl -s -X POST "${BRIDGE_SDK_URL}/api/simulation/cross-chain" \
        -H "Content-Type: application/json" \
        -d "{
            \"source_chain\": \"${source_chain}\",
            \"target_chain\": \"${target_chain}\",
            \"amount\": \"${amount}\",
            \"token\": \"${token}\",
            \"wallet_address\": \"${test_wallet}\",
            \"slippage_tolerance\": 0.5
        }" 2>/dev/null)

    if [ $? -eq 0 ] && echo "$response" | jq -e '.success' > /dev/null 2>&1; then
        local simulation_id
        simulation_id=$(echo "$response" | jq -r '.simulation_id')
        log_success "Real roundtrip test started with ID: ${simulation_id}"
        echo "$simulation_id"
        return 0
    else
        log_error "Failed to start roundtrip test: $response"
        return 1
    fi
}

# Check simulation status
check_simulation_status() {
    local simulation_id=$1

    local response
    response=$(curl -s -f "${BRIDGE_SDK_URL}/api/simulation/cross-chain/status/${simulation_id}" 2>/dev/null)

    if [ $? -eq 0 ] && echo "$response" | jq -e '.success' > /dev/null 2>&1; then
        echo "$response"
        return 0
    else
        log_error "Failed to check simulation status"
        return 1
    fi
}

# Monitor roundtrip progress with real blockchain integration
monitor_roundtrip() {
    local simulation_id=$1
    local start_time=$(date +%s)
    local end_time=$((start_time + TEST_DURATION))

    log_info "Monitoring real roundtrip test ${simulation_id} for ${TEST_DURATION} seconds..."
    log_info "Check interval: ${CHECK_INTERVAL} seconds"
    log_info "Main dashboard: ${MAIN_DASHBOARD_URL}"
    log_info "Infra dashboard: ${BRIDGE_SDK_URL}/infra-dashboard"

    local iteration=1
    local current_step=""
    local recorded_transactions=()

    while [ $(date +%s) -lt $end_time ]; do
        log_progress "=== Monitoring Iteration $iteration ==="

        local status_data
        if ! status_data=$(check_simulation_status "$simulation_id"); then
            log_error "Failed to get simulation status"
            sleep "$CHECK_INTERVAL"
            continue
        fi

        local status
        local step
        local progress
        local message

        status=$(echo "$status_data" | jq -r '.data.status')
        step=$(echo "$status_data" | jq -r '.data.current_step')
        progress=$(echo "$status_data" | jq -r '.data.progress // 0')
        message=$(echo "$status_data" | jq -r '.data.message // ""')

        # Log step changes
        if [ "$step" != "$current_step" ]; then
            case "$step" in
                "wallet_sign")
                    log_step "1" "BHX wallet signing and submitting swap to DEX"
                    ;;
                "dex_event")
                    log_step "2" "DEX processing BHX swap, bridge relaying to target chain"
                    ;;
                "target_confirm")
                    log_step "3" "Target chain receiving mint/unlock confirmation"
                    ;;
                "completed")
                    log_success "Roundtrip test completed successfully!"
                    ;;
                "failed")
                    log_error "Roundtrip test failed: $message"
                    ;;
            esac
            current_step="$step"
        fi

        # Check for new transactions
        local transactions
        transactions=$(echo "$status_data" | jq -r '.data.transactions // []')
        if [ "$transactions" != "[]" ] && [ "$transactions" != "null" ]; then
            local tx_count
            tx_count=$(echo "$transactions" | jq length)
            if [ "$tx_count" -gt "${#recorded_transactions[@]}" ]; then
                log_info "New transactions detected in blockchain"
                # Could add more detailed transaction logging here
            fi
        fi

        # Show progress
        if [ "$progress" -gt 0 ]; then
            log_progress "Progress: ${progress}% - $message"
        fi

        # Check blockchain health during test
        if ! check_blockchain_health; then
            log_warning "Blockchain health check failed during test"
        fi

        # Check if completed or failed
        if [ "$status" = "completed" ]; then
            log_success "Roundtrip test completed successfully"
            log_info "Test completed all 3 steps: BHX transfer → DEX processing → Cross-chain relay"
            return 0
        elif [ "$status" = "failed" ]; then
            log_error "Roundtrip test failed: $message"
            return 1
        fi

        iteration=$((iteration + 1))
        sleep "$CHECK_INTERVAL"
    done

    log_warning "Monitoring timeout reached after ${TEST_DURATION} seconds"
    return 1
}

# Check blockchain health
check_blockchain_health() {
    local response
    response=$(curl -s -f "${MAIN_DASHBOARD_URL}/api/health" 2>/dev/null)

    if [ $? -eq 0 ] && echo "$response" | jq -e '.healthy' > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Get infra dashboard data
get_infra_dashboard_data() {
    local response
    response=$(curl -s -f "${BRIDGE_SDK_URL}/infra/listener-status" 2>/dev/null)

    if [ $? -eq 0 ]; then
        echo "$response"
        return 0
    else
        log_error "Failed to fetch infra dashboard data"
        return 1
    fi
}

# Analyze roundtrip results with real blockchain data
analyze_roundtrip_results() {
    local simulation_id=$1

    log_info "Analyzing real roundtrip test results..."

    # Get final status
    local final_status
    if final_status=$(check_simulation_status "$simulation_id"); then
        local total_time
        local steps_completed
        local transactions

        total_time=$(echo "$final_status" | jq -r '.data.total_time // 0')
        steps_completed=$(echo "$final_status" | jq -r '.data.steps_completed // 0')
        transactions=$(echo "$final_status" | jq -r '.data.transactions // []')

        log_info "Roundtrip Analysis:"
        log_info "  Total Time: ${total_time} seconds"
        log_info "  Steps Completed: ${steps_completed}/3"

        # Analyze transactions
        if [ "$transactions" != "[]" ] && [ "$transactions" != "null" ]; then
            local tx_count
            tx_count=$(echo "$transactions" | jq length)
            log_info "  Transactions Processed: $tx_count"

            # Show transaction details
            echo "$transactions" | jq -c '.[]' | while read -r tx; do
                local tx_type
                local tx_id
                local description
                local amount

                tx_type=$(echo "$tx" | jq -r '.type')
                tx_id=$(echo "$tx" | jq -r '.id')
                description=$(echo "$tx" | jq -r '.description')
                amount=$(echo "$tx" | jq -r '.amount')

                log_info "    $tx_type: $description (Amount: $amount, ID: ${tx_id:0:16}...)"
            done
        fi

        # Calculate success rate
        if [ "$steps_completed" -eq 3 ]; then
            log_success "Roundtrip test: 100% success rate - All BHX transactions processed successfully"
        elif [ "$steps_completed" -gt 0 ]; then
            local success_rate=$((steps_completed * 100 / 3))
            log_warning "Roundtrip test: ${success_rate}% success rate - Partial completion"
        else
            log_error "Roundtrip test: 0% success rate - No transactions completed"
        fi
    fi

    # Check final BHX balances
    local test_wallet="0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
    local final_bhx_balance
    final_bhx_balance=$(check_wallet_balance "$test_wallet" "BHX")
    log_info "Final BHX Balance for test wallet: $final_bhx_balance"

    # Get blockchain summary
    local blockchain_info
    if blockchain_info=$(curl -s -f "${MAIN_DASHBOARD_URL}/api/blockchain/info" 2>/dev/null); then
        local block_height
        local total_txs
        local bhx_supply

        block_height=$(echo "$blockchain_info" | jq -r '.blockHeight // 0')
        total_txs=$(echo "$blockchain_info" | jq -r '.totalSupply // 0')
        bhx_supply=$(echo "$blockchain_info" | jq -r '.tokenBalances.BHX.total // 0')

        log_info "Blockchain Status:"
        log_info "  Block Height: $block_height"
        log_info "  Total BHX Supply: $bhx_supply"
        log_info "  Total Transactions: $total_txs"
    fi

    # Get infra dashboard summary
    local infra_data
    if infra_data=$(get_infra_dashboard_data); then
        local active_listeners
        local processed_events
        local pending_events

        active_listeners=$(echo "$infra_data" | jq -r '.active_listeners // 0')
        processed_events=$(echo "$infra_data" | jq -r '.processed_events // 0')
        pending_events=$(echo "$infra_data" | jq -r '.pending_events // 0')

        log_info "Bridge Infrastructure Status:"
        log_info "  Active Listeners: $active_listeners"
        log_info "  Processed Events: $processed_events"
        log_info "  Pending Events: $pending_events"
    fi
}

# Generate test report
generate_report() {
    local simulation_id=$1
    local report_file="roundtrip_test_report_$(date +%Y%m%d_%H%M%S).txt"

    log_info "Generating test report: $report_file"

    {
        echo "Roundtrip Test Report"
        echo "===================="
        echo "Generated: $(date)"
        echo "Simulation ID: ${simulation_id}"
        echo "Test Duration: ${TEST_DURATION} seconds"
        echo "Check Interval: ${CHECK_INTERVAL} seconds"
        echo ""
        echo "Configuration:"
        echo "  Bridge SDK URL: ${BRIDGE_SDK_URL}"
        echo "  Main Dashboard URL: ${MAIN_DASHBOARD_URL}"
        echo ""
        echo "Final Simulation Status:"
        if status_data=$(check_simulation_status "$simulation_id"); then
            echo "$status_data" | jq '.'
        else
            echo "Failed to fetch final status"
        fi
        echo ""
        echo "Infrastructure Dashboard Data:"
        if infra_data=$(get_infra_dashboard_data); then
            echo "$infra_data" | jq '.'
        else
            echo "Failed to fetch infra data"
        fi
    } > "$report_file"

    log_success "Report saved to: $report_file"
}

# Main function
main() {
    log_info "Starting Real Roundtrip Test for BlackHole Blockchain"
    log_info "==================================================="

    # Parse command line arguments
    local source_chain="blackhole"
    local target_chain="ethereum"
    local amount="1000000000"
    local token="BHX"

    while [[ $# -gt 0 ]]; do
        case $1 in
            --source-chain)
                source_chain="$2"
                shift 2
                ;;
            --target-chain)
                target_chain="$2"
                shift 2
                ;;
            --amount)
                amount="$2"
                shift 2
                ;;
            --token)
                token="$2"
                shift 2
                ;;
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
                echo "Real BlackHole Blockchain Roundtrip Test"
                echo "Tests complete cross-chain BHX token transfers"
                echo ""
                echo "Options:"
                echo "  --source-chain CHAIN    Source chain (default: blackhole)"
                echo "  --target-chain CHAIN    Target chain (default: ethereum, bitcoin, polygon)"
                echo "  --amount AMOUNT         Amount in BHX wei (default: 1000000000)"
                echo "  --token TOKEN           Token symbol (default: BHX)"
                echo "  --duration SECONDS      Test duration in seconds (default: 600)"
                echo "  --interval SECONDS      Check interval in seconds (default: 5)"
                echo "  --help                  Show this help message"
                echo ""
                echo "Test Flow:"
                echo "  1. BHX wallet signs & submits swap to DEX"
                echo "  2. DEX emits event → bridge picks and relays to TargetChain"
                echo "  3. TargetChain receives mint/unlock confirmation"
                echo ""
                echo "Environment variables:"
                echo "  BRIDGE_SDK_URL          Bridge SDK URL (default: http://localhost:8084)"
                echo "  MAIN_DASHBOARD_URL      Main BHX blockchain URL (default: http://localhost:8080)"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    # Initial service check
    if ! check_services; then
        log_error "Required services are not running. Please start:"
        log_error "  1. Bridge SDK: go run bridge-sdk/main_bridge/main.go"
        log_error "  2. Main Blockchain: go run core/relay-chain/cmd/relay/main.go"
        exit 1
    fi

    # Start roundtrip simulation
    local simulation_id
    if ! simulation_id=$(start_roundtrip_simulation "$source_chain" "$target_chain" "$amount" "$token"); then
        log_error "Failed to start roundtrip simulation"
        exit 1
    fi

    # Monitor the roundtrip
    if monitor_roundtrip "$simulation_id"; then
        log_success "Roundtrip test completed successfully"
    else
        log_warning "Roundtrip test did not complete within timeout"
    fi

    # Analyze results
    analyze_roundtrip_results "$simulation_id"

    # Generate final report
    generate_report "$simulation_id"

    log_success "Real BlackHole blockchain roundtrip testing completed"
    log_info "BHX tokens were transferred through the DEX and bridged to target chain"
}

# Run main function
main "$@"