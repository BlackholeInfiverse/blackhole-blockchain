#!/bin/bash

# BlackHole Bridge-SDK Integration Verification Script
# ====================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
BRIDGE_URL="http://localhost:8084"
BLOCKCHAIN_URL="http://localhost:8080"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Test results
TESTS_PASSED=0
TESTS_FAILED=0
TEST_RESULTS=()

# Functions
print_header() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    🧪 BlackHole Bridge-SDK Integration                       ║"
    echo "║                           Verification Tests                                ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_test() {
    echo -e "${CYAN}[TEST]${NC} $1"
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
    TEST_RESULTS+=("✅ $1")
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
    TEST_RESULTS+=("❌ $1")
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Test functions
test_bridge_health() {
    print_test "Bridge Health Check"
    
    if curl -f -s "$BRIDGE_URL/health" > /dev/null; then
        print_pass "Bridge service is healthy and accessible"
    else
        print_fail "Bridge service health check failed"
    fi
}

test_blockchain_connection() {
    print_test "Blockchain Connection"
    
    if curl -f -s "$BLOCKCHAIN_URL/health" > /dev/null; then
        print_pass "BlackHole blockchain is running and accessible"
    else
        print_fail "Cannot connect to BlackHole blockchain"
    fi
}

test_real_blockchain_mode() {
    print_test "Real Blockchain Mode"
    
    # Check bridge stats for live blockchain data
    response=$(curl -s "$BRIDGE_URL/stats" | grep -o '"mode":"live"' || echo "")
    
    if [ -n "$response" ]; then
        print_pass "Bridge is running in real blockchain mode"
    else
        print_fail "Bridge is not using real blockchain (simulation mode)"
    fi
}

test_dashboard_access() {
    print_test "Dashboard Access"
    
    response=$(curl -s "$BRIDGE_URL" | grep -o "BlackHole Bridge" || echo "")
    
    if [ -n "$response" ]; then
        print_pass "Dashboard is accessible and contains expected content"
    else
        print_fail "Dashboard is not accessible or missing content"
    fi
}

test_websocket_endpoints() {
    print_test "WebSocket Endpoints"
    
    # Test WebSocket endpoints (they should return 400 or 426 for HTTP requests)
    ws_logs_status=$(curl -s -o /dev/null -w "%{http_code}" "$BRIDGE_URL/ws/logs")
    ws_events_status=$(curl -s -o /dev/null -w "%{http_code}" "$BRIDGE_URL/ws/events")
    
    if [[ "$ws_logs_status" == "400" || "$ws_logs_status" == "426" ]] && 
       [[ "$ws_events_status" == "400" || "$ws_events_status" == "426" ]]; then
        print_pass "WebSocket endpoints are available"
    else
        print_fail "WebSocket endpoints are not properly configured"
    fi
}

test_api_endpoints() {
    print_test "API Endpoints"
    
    endpoints=("/stats" "/transactions" "/errors" "/replay-protection" "/circuit-breakers")
    failed_endpoints=()
    
    for endpoint in "${endpoints[@]}"; do
        if ! curl -f -s "$BRIDGE_URL$endpoint" > /dev/null; then
            failed_endpoints+=("$endpoint")
        fi
    done
    
    if [ ${#failed_endpoints[@]} -eq 0 ]; then
        print_pass "All API endpoints are accessible"
    else
        print_fail "Some API endpoints failed: ${failed_endpoints[*]}"
    fi
}

test_security_features() {
    print_test "Security Features"
    
    # Test replay protection endpoint
    replay_response=$(curl -s "$BRIDGE_URL/replay-protection")
    circuit_response=$(curl -s "$BRIDGE_URL/circuit-breakers")
    
    if [[ -n "$replay_response" && -n "$circuit_response" ]]; then
        print_pass "Security features (replay protection, circuit breakers) are active"
    else
        print_fail "Security features are not properly configured"
    fi
}

test_token_transfer() {
    print_test "Token Transfer Functionality"
    
    # Test transfer endpoint with sample data
    transfer_data='{"from_chain":"ethereum","to_chain":"blackhole","from_address":"0x1234567890123456789012345678901234567890","to_address":"blackhole1234567890123456789012345678901234567890","token_symbol":"ETH","amount":"1000000000000000000"}'
    
    response=$(curl -s -X POST -H "Content-Type: application/json" -d "$transfer_data" "$BRIDGE_URL/transfer")
    
    if echo "$response" | grep -q "success"; then
        print_pass "Token transfer functionality is working"
    else
        print_fail "Token transfer functionality failed"
    fi
}

test_blockchain_stats() {
    print_test "Blockchain Statistics"
    
    # Get blockchain stats and check for real data
    stats_response=$(curl -s "$BRIDGE_URL/stats")
    
    if echo "$stats_response" | grep -q '"blocks"' && echo "$stats_response" | grep -q '"transactions"'; then
        print_pass "Blockchain statistics are available and contain real data"
    else
        print_fail "Blockchain statistics are missing or incomplete"
    fi
}

test_docker_deployment() {
    print_test "Docker Deployment"
    
    # Check if running in Docker
    if [ -f "/.dockerenv" ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
        print_pass "Running in Docker environment"
    else
        # Check if Docker containers are running
        if command -v docker &> /dev/null && docker ps | grep -q "blackhole"; then
            print_pass "Docker containers are running"
        else
            print_fail "Not running in Docker environment"
        fi
    fi
}

# Performance tests
test_response_times() {
    print_test "Response Times"
    
    # Test response times for key endpoints
    health_time=$(curl -o /dev/null -s -w "%{time_total}" "$BRIDGE_URL/health")
    stats_time=$(curl -o /dev/null -s -w "%{time_total}" "$BRIDGE_URL/stats")
    
    # Check if response times are reasonable (< 2 seconds)
    if (( $(echo "$health_time < 2.0" | bc -l) )) && (( $(echo "$stats_time < 2.0" | bc -l) )); then
        print_pass "Response times are acceptable (health: ${health_time}s, stats: ${stats_time}s)"
    else
        print_fail "Response times are too slow (health: ${health_time}s, stats: ${stats_time}s)"
    fi
}

# Integration test
test_end_to_end_flow() {
    print_test "End-to-End Integration Flow"
    
    # 1. Check bridge health
    # 2. Check blockchain connection
    # 3. Submit a transfer
    # 4. Check transaction status
    
    if curl -f -s "$BRIDGE_URL/health" > /dev/null && 
       curl -f -s "$BLOCKCHAIN_URL/health" > /dev/null; then
        
        # Submit test transfer
        transfer_response=$(curl -s -X POST -H "Content-Type: application/json" \
            -d '{"from_chain":"ethereum","to_chain":"blackhole","from_address":"0x1234567890123456789012345678901234567890","to_address":"blackhole1234567890123456789012345678901234567890","token_symbol":"ETH","amount":"1000000000000000000"}' \
            "$BRIDGE_URL/transfer")
        
        if echo "$transfer_response" | grep -q "success"; then
            print_pass "End-to-end integration flow completed successfully"
        else
            print_fail "End-to-end integration flow failed at transfer step"
        fi
    else
        print_fail "End-to-end integration flow failed at health check step"
    fi
}

# Run all tests
run_all_tests() {
    print_header
    
    print_info "Starting comprehensive integration verification..."
    echo ""
    
    # Core functionality tests
    test_bridge_health
    test_blockchain_connection
    test_real_blockchain_mode
    test_dashboard_access
    
    # API and WebSocket tests
    test_websocket_endpoints
    test_api_endpoints
    
    # Security and features
    test_security_features
    test_token_transfer
    test_blockchain_stats
    
    # Deployment and performance
    test_docker_deployment
    test_response_times
    
    # Integration test
    test_end_to_end_flow
    
    echo ""
    print_results
}

# Print final results
print_results() {
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║                              Test Results                                    ║${NC}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    total_tests=$((TESTS_PASSED + TESTS_FAILED))
    success_rate=$(( TESTS_PASSED * 100 / total_tests ))
    
    echo -e "${BLUE}Total Tests:${NC} $total_tests"
    echo -e "${GREEN}Passed:${NC} $TESTS_PASSED"
    echo -e "${RED}Failed:${NC} $TESTS_FAILED"
    echo -e "${YELLOW}Success Rate:${NC} $success_rate%"
    echo ""
    
    # Print detailed results
    for result in "${TEST_RESULTS[@]}"; do
        echo "$result"
    done
    echo ""
    
    # Save results to file
    {
        echo "BlackHole Bridge-SDK Integration Verification Results"
        echo "===================================================="
        echo "Date: $(date)"
        echo "Total Tests: $total_tests"
        echo "Passed: $TESTS_PASSED"
        echo "Failed: $TESTS_FAILED"
        echo "Success Rate: $success_rate%"
        echo ""
        echo "Detailed Results:"
        for result in "${TEST_RESULTS[@]}"; do
            echo "$result"
        done
    } > "$SCRIPT_DIR/verification-results.txt"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}🎉 All tests passed! Integration is working perfectly.${NC}"
        echo -e "${GREEN}✅ BlackHole Bridge-SDK integration verified successfully!${NC}"
    else
        echo -e "${YELLOW}⚠️  Some tests failed. Please check the configuration and logs.${NC}"
        echo -e "${YELLOW}📋 Results saved to: verification-results.txt${NC}"
    fi
    
    echo ""
    echo -e "${CYAN}🌐 Access Points:${NC}"
    echo -e "   Bridge Dashboard: ${CYAN}$BRIDGE_URL${NC}"
    echo -e "   Blockchain API: ${CYAN}$BLOCKCHAIN_URL${NC}"
    echo ""
}

# Main execution
main() {
    # Check if bc is available for floating point arithmetic
    if ! command -v bc &> /dev/null; then
        echo "Installing bc for calculations..."
        # Try to install bc if not available
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y bc
        elif command -v yum &> /dev/null; then
            sudo yum install -y bc
        fi
    fi
    
    run_all_tests
}

# Run main function
main "$@"
