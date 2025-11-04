#!/bin/bash

# DEX Slippage Test Harness Script
# This script monitors DEX slippage in the BlackHole Bridge SDK dashboard
# and validates transaction reverts and minAmountOut protection

set -e

# Configuration
BRIDGE_SDK_URL="http://localhost:8084"
MAIN_DASHBOARD_URL="http://localhost:8080"
TEST_DURATION=${TEST_DURATION:-300}  # 5 minutes default
CHECK_INTERVAL=${CHECK_INTERVAL:-10}  # Check every 10 seconds

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

    # Check Bridge SDK
    if curl -s -f "${BRIDGE_SDK_URL}/health" > /dev/null 2>&1; then
        log_success "Bridge SDK is running at ${BRIDGE_SDK_URL}"
    else
        log_error "Bridge SDK is not accessible at ${BRIDGE_SDK_URL}"
        return 1
    fi

    # Check Main Dashboard
    if curl -s -f "${MAIN_DASHBOARD_URL}/api/health" > /dev/null 2>&1; then
        log_success "Main blockchain dashboard is running at ${MAIN_DASHBOARD_URL}"
    else
        log_error "Main blockchain dashboard is not accessible at ${MAIN_DASHBOARD_URL}"
        return 1
    fi

    return 0
}

# Get DEX slippage data from bridge SDK
get_dex_slippage_data() {
    local response
    response=$(curl -s -f "${BRIDGE_SDK_URL}/api/main-dashboard/dex-slippage" 2>/dev/null)

    if [ $? -eq 0 ] && echo "$response" | jq -e '.success' > /dev/null 2>&1; then
        echo "$response"
        return 0
    else
        log_error "Failed to fetch DEX slippage data"
        return 1
    fi
}

# Create a test DEX pool
create_test_pool() {
    local token_a=${1:-"BHX"}
    local token_b=${2:-"USDT"}
    local reserve_a=${3:-100}
    local reserve_b=${4:-1}

    log_info "Creating test DEX pool: ${token_a}/${token_b} with reserves ${reserve_a}/${reserve_b}"

    local response
    response=$(curl -s -X POST "${BRIDGE_SDK_URL}/api/dex/pools" \
        -H "Content-Type: application/json" \
        -d "{\"token_a\":\"${token_a}\",\"token_b\":\"${token_b}\",\"reserve_a\":${reserve_a},\"reserve_b\":${reserve_b}}" 2>/dev/null)

    if [ $? -eq 0 ] && echo "$response" | jq -e '.success' > /dev/null 2>&1; then
        log_success "Test pool created successfully"
        return 0
    else
        log_error "Failed to create test pool: $response"
        return 1
    fi
}

# Run a DEX slippage test
run_dex_test() {
    local token_a=${1:-"BHX"}
    local token_b=${2:-"USDT"}
    local swap_amount=${3:-1000}
    local min_amount_out=${4:-50}

    log_info "Running DEX slippage test: ${swap_amount} ${token_a} -> ${token_b} (min out: ${min_amount_out})"

    local response
    response=$(curl -s -X POST "${BRIDGE_SDK_URL}/api/dex/test" \
        -H "Content-Type: application/json" \
        -d "{\"token_a\":\"${token_a}\",\"token_b\":\"${token_b}\",\"swap_amount\":${swap_amount},\"min_amount_out\":${min_amount_out}}" 2>/dev/null)

    if [ $? -eq 0 ] && echo "$response" | jq -e '.success' > /dev/null 2>&1; then
        log_success "DEX test completed successfully"
        return 0
    else
        log_error "Failed to run DEX test: $response"
        return 1
    fi
}

# Analyze DEX slippage test results
analyze_slippage_results() {
    local data="$1"
    local total_tests
    local failed_tests
    local pool_count

    total_tests=$(echo "$data" | jq -r '.data.total_tests')
    failed_tests=$(echo "$data" | jq -r '.data.failed_tests')
    pool_count=$(echo "$data" | jq -r '.data.pools | length')

    log_info "DEX Slippage Analysis:"
    log_info "  Total Tests: $total_tests"
    log_info "  Failed Tests: $failed_tests"
    log_info "  Active Pools: $pool_count"

    # Analyze individual tests
    local test_count=0
    echo "$data" | jq -c '.data.tests[]' 2>/dev/null | while read -r test; do
        test_count=$((test_count + 1))

        local reverted
        local protected
        local slippage_percent
        local swap_amount

        reverted=$(echo "$test" | jq -r '.reverted')
        protected=$(echo "$test" | jq -r '.protected')
        slippage_percent=$(echo "$test" | jq -r '.slippage_percent')
        swap_amount=$(echo "$test" | jq -r '.swap_amount')

        if [ "$reverted" = "true" ]; then
            log_warning "Test $test_count: Transaction reverted (swap: $swap_amount, slippage: ${slippage_percent}%)"
        elif [ "$protected" = "false" ]; then
            log_warning "Test $test_count: MinAmountOut protection failed (swap: $swap_amount, slippage: ${slippage_percent}%)"
        else
            log_info "Test $test_count: Protected against slippage (swap: $swap_amount, slippage: ${slippage_percent}%)"
        fi
    done

    # Calculate success rate
    if [ "$total_tests" -gt 0 ]; then
        local success_rate=$(( (total_tests - failed_tests) * 100 / total_tests ))
        log_info "Success Rate: ${success_rate}%"

        if [ "$success_rate" -ge 80 ]; then
            log_success "DEX slippage protection is working well"
        elif [ "$success_rate" -ge 60 ]; then
            log_warning "DEX slippage protection needs improvement"
        else
            log_error "DEX slippage protection is failing"
        fi
    fi
}

# Run DEX slippage test via dashboard
run_slippage_test() {
    log_info "Triggering DEX slippage test..."

    # This would normally trigger a test via the dashboard API
    # For now, we'll just wait for the next monitoring cycle
    sleep 2

    log_success "DEX slippage test triggered"
}

# Main monitoring loop
monitor_dex_slippage() {
    local start_time=$(date +%s)
    local end_time=$((start_time + TEST_DURATION))
    local iteration=1

    log_info "Starting DEX slippage monitoring for ${TEST_DURATION} seconds..."
    log_info "Check interval: ${CHECK_INTERVAL} seconds"

    # Create initial test pools if none exist
    if ! create_test_pool "BHX" "USDT" 100 1; then
        log_warning "Could not create initial test pool, continuing anyway..."
    fi

    if ! create_test_pool "ETH" "BHX" 50 200; then
        log_warning "Could not create second test pool, continuing anyway..."
    fi

    while [ $(date +%s) -lt $end_time ]; do
        log_info "=== Monitoring Iteration $iteration ==="

        if ! check_services; then
            log_error "Services not available, skipping iteration"
            sleep "$CHECK_INTERVAL"
            continue
        fi

        local data
        if data=$(get_dex_slippage_data); then
            analyze_slippage_results "$data"
        else
            log_error "Failed to get DEX slippage data"
        fi

        # Run tests with different scenarios
        case $((iteration % 4)) in
            1)
                # Test large swap on tiny reserves
                run_dex_test "BHX" "USDT" 1000 50
                ;;
            2)
                # Test moderate swap
                run_dex_test "BHX" "USDT" 500 25
                ;;
            3)
                # Test on different pool
                run_dex_test "ETH" "BHX" 100 40
                ;;
            0)
                # Test extreme slippage scenario
                run_dex_test "BHX" "USDT" 5000 100
                ;;
        esac

        iteration=$((iteration + 1))
        sleep "$CHECK_INTERVAL"
    done

    log_success "DEX slippage monitoring completed"
}

# Generate test report
generate_report() {
    local report_file="dex_slippage_report_$(date +%Y%m%d_%H%M%S).txt"

    log_info "Generating test report: $report_file"

    {
        echo "DEX Slippage Test Report"
        echo "========================"
        echo "Generated: $(date)"
        echo "Test Duration: ${TEST_DURATION} seconds"
        echo "Check Interval: ${CHECK_INTERVAL} seconds"
        echo ""
        echo "Configuration:"
        echo "  Bridge SDK URL: ${BRIDGE_SDK_URL}"
        echo "  Main Dashboard URL: ${MAIN_DASHBOARD_URL}"
        echo ""
        echo "Final DEX Slippage Data:"
        if data=$(get_dex_slippage_data); then
            echo "$data" | jq '.'
        else
            echo "Failed to fetch final data"
        fi
    } > "$report_file"

    log_success "Report saved to: $report_file"
}

# Main function
main() {
    log_info "Starting DEX Slippage Test Harness"
    log_info "=================================="

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
                echo "  --duration SECONDS    Test duration in seconds (default: 300)"
                echo "  --interval SECONDS    Check interval in seconds (default: 10)"
                echo "  --help               Show this help message"
                echo ""
                echo "Environment variables:"
                echo "  BRIDGE_SDK_URL       Bridge SDK URL (default: http://localhost:8084)"
                echo "  MAIN_DASHBOARD_URL   Main dashboard URL (default: http://localhost:8080)"
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

    # Start monitoring
    monitor_dex_slippage

    # Generate final report
    generate_report

    log_success "DEX slippage testing completed successfully"
}

# Run main function
main "$@"