# 🧪 End-to-End Testing Suite

Comprehensive E2E testing for the complete Blackhole Blockchain workflow.

## 🎯 **Testing Objectives**

### Primary Goals
- **Complete Workflow Validation**: Test entire user journeys from start to finish
- **Integration Testing**: Verify all components work together seamlessly
- **Real-world Scenarios**: Simulate actual user behavior and edge cases
- **Performance Validation**: Ensure system performs under realistic loads
- **Security Verification**: Test security measures in complete workflows

### Coverage Areas
- ✅ **Wallet Operations**: Creation, import, export, transfers
- ✅ **Staking Workflows**: Deposit, rewards, withdrawal, slashing
- ✅ **DEX Operations**: Swaps, liquidity, cross-chain trades
- ✅ **OTC Trading**: Order creation, matching, execution
- ✅ **Blockchain Operations**: Block production, validation, consensus
- ✅ **API Integration**: All endpoints working together

## 🏗️ **Test Environment Setup**

### Prerequisites
```bash
# Install dependencies
go mod tidy
npm install -g newman  # For Postman collection testing

# Install testing tools
go install github.com/onsi/ginkgo/v2/ginkgo@latest
go install github.com/onsi/gomega/...@latest
```

### Environment Configuration
```bash
# Set environment variables
export BLACKHOLE_ENV=testing
export BLACKHOLE_DB_PATH=./test_data
export BLACKHOLE_LOG_LEVEL=debug
export BLACKHOLE_PORT=8080
export WALLET_PORT=9000
```

### Test Data Setup
```bash
# Create test directories
mkdir -p test_data/blockchain
mkdir -p test_data/wallets
mkdir -p test_data/logs

# Initialize test blockchain
cd core/relay-chain/cmd/relay
go run main.go -testnet -port 3001 &

# Start test wallet service
cd services/wallet
go run main.go -web -port 9001 -testnet &
```

## 🔄 **Complete Workflow Tests**

### Test Suite 1: User Onboarding Journey
```bash
# Test: New User Complete Journey
# Duration: ~5 minutes
# Coverage: Registration → Wallet Creation → First Transaction

1. User Registration
   - Open wallet UI: http://localhost:9001
   - Register new account
   - Verify session creation
   - Confirm dashboard access

2. Wallet Creation
   - Create new wallet with mnemonic
   - Verify wallet appears in list
   - Check initial balance (should be 0)
   - Export private key (test security warnings)

3. Initial Funding
   - Use faucet to fund wallet
   - Verify balance update
   - Check transaction history
   - Confirm blockchain integration

4. First Transfer
   - Create second wallet
   - Transfer tokens between wallets
   - Verify transaction completion
   - Check both wallet balances
```

### Test Suite 2: Staking Complete Workflow
```bash
# Test: Complete Staking Lifecycle
# Duration: ~10 minutes
# Coverage: Stake → Validate → Rewards → Withdrawal

1. Stake Deposit
   - Fund wallet with sufficient tokens
   - Execute stake deposit transaction
   - Verify validator registration
   - Check staking dashboard

2. Validation Process
   - Monitor block production
   - Verify validator participation
   - Check consensus participation
   - Monitor uptime metrics

3. Reward Accumulation
   - Wait for reward cycles
   - Verify reward calculations
   - Check reward distribution
   - Validate APY calculations

4. Stake Withdrawal
   - Initiate withdrawal process
   - Wait for unbonding period
   - Complete withdrawal
   - Verify final balances
```

### Test Suite 3: Cross-Chain DEX Workflow
```bash
# Test: Complete Cross-Chain Trading
# Duration: ~8 minutes
# Coverage: Quote → Bridge → Swap → Completion

1. Cross-Chain Quote
   - Select source/destination chains
   - Input trade parameters
   - Get real-time quote
   - Verify fee calculations

2. Trade Execution
   - Execute cross-chain swap
   - Monitor order status
   - Track bridging phase
   - Verify swap execution

3. Order Tracking
   - Check order history
   - Verify status updates
   - Confirm transaction IDs
   - Validate completion

4. Balance Verification
   - Check source chain balance
   - Verify destination balance
   - Confirm fee deductions
   - Validate total amounts
```

### Test Suite 4: OTC Trading Workflow
```bash
# Test: Complete OTC Trading Process
# Duration: ~6 minutes
# Coverage: Order Creation → Matching → Execution

1. Order Creation
   - Create OTC sell order
   - Set terms and conditions
   - Enable multi-sig if needed
   - Verify order publication

2. Order Matching
   - Create matching buy order
   - Verify order discovery
   - Check compatibility
   - Initiate matching process

3. Trade Execution
   - Execute matched trade
   - Handle escrow process
   - Complete multi-sig if enabled
   - Verify trade completion

4. Settlement
   - Check final balances
   - Verify token transfers
   - Confirm trade history
   - Validate all participants
```

## 🤖 **Automated Test Scripts**

### Master Test Runner
```bash
#!/bin/bash
# run_e2e_tests.sh

echo "🚀 Starting Blackhole Blockchain E2E Tests"

# Start services
echo "📡 Starting blockchain node..."
cd core/relay-chain/cmd/relay
go run main.go -testnet -port 3001 &
BLOCKCHAIN_PID=$!

echo "💼 Starting wallet service..."
cd ../../services/wallet
go run main.go -web -port 9001 -testnet &
WALLET_PID=$!

# Wait for services to start
sleep 10

# Run test suites
echo "🧪 Running test suites..."

# API Tests
echo "📡 Testing APIs..."
newman run docs/api/postman/Blackhole_Blockchain_Core.postman_collection.json \
  --environment docs/api/postman/test_environment.json \
  --reporters cli,json \
  --reporter-json-export test_results/api_tests.json

# Workflow Tests
echo "🔄 Testing workflows..."
go test ./tests/e2e/... -v -timeout 30m

# Performance Tests
echo "⚡ Running performance tests..."
go test ./tests/performance/... -v -timeout 15m

# Security Tests
echo "🔒 Running security tests..."
go test ./tests/security/... -v -timeout 10m

# Cleanup
echo "🧹 Cleaning up..."
kill $BLOCKCHAIN_PID $WALLET_PID

echo "✅ E2E Tests Complete!"
```

### Individual Test Scripts

#### Wallet Workflow Test
```go
// tests/e2e/wallet_test.go
package e2e

import (
    "testing"
    "time"
    "net/http"
    "encoding/json"
    . "github.com/onsi/ginkgo/v2"
    . "github.com/onsi/gomega"
)

var _ = Describe("Wallet E2E Workflow", func() {
    var (
        baseURL = "http://localhost:9001"
        apiURL  = "http://localhost:8080/api"
        sessionCookie string
    )

    BeforeEach(func() {
        // Setup test user session
        sessionCookie = createTestSession()
    })

    Context("Complete User Journey", func() {
        It("should complete full wallet workflow", func() {
            By("registering new user")
            registerResponse := registerUser("testuser", "testpass")
            Expect(registerResponse.Success).To(BeTrue())

            By("creating new wallet")
            wallet := createWallet("Test Wallet")
            Expect(wallet.Address).ToNot(BeEmpty())

            By("funding wallet from faucet")
            fundResponse := fundWallet(wallet.Address, 1000000)
            Expect(fundResponse.Success).To(BeTrue())

            By("checking wallet balance")
            balance := getWalletBalance(wallet.Address)
            Expect(balance.BHX).To(Equal(uint64(1000000)))

            By("creating second wallet for transfer")
            wallet2 := createWallet("Test Wallet 2")
            Expect(wallet2.Address).ToNot(BeEmpty())

            By("transferring tokens between wallets")
            transferResponse := transferTokens(wallet.Address, wallet2.Address, 100000)
            Expect(transferResponse.Success).To(BeTrue())

            By("verifying final balances")
            balance1 := getWalletBalance(wallet.Address)
            balance2 := getWalletBalance(wallet2.Address)
            Expect(balance1.BHX).To(Equal(uint64(899000))) // 1000000 - 100000 - 1000 (fee)
            Expect(balance2.BHX).To(Equal(uint64(100000)))
        })
    })
})
```

#### Cross-Chain DEX Test
```go
// tests/e2e/cross_chain_test.go
package e2e

var _ = Describe("Cross-Chain DEX E2E", func() {
    Context("Complete Cross-Chain Swap", func() {
        It("should execute full cross-chain swap workflow", func() {
            By("getting cross-chain quote")
            quote := getCrossChainQuote("ethereum", "blackhole", "USDT", "BHX", 1000000)
            Expect(quote.EstimatedOut).To(BeNumerically(">", 0))

            By("executing cross-chain swap")
            swapResponse := executeCrossChainSwap(quote)
            Expect(swapResponse.Success).To(BeTrue())
            orderID := swapResponse.Data.ID

            By("monitoring swap progress")
            Eventually(func() string {
                order := getCrossChainOrder(orderID)
                return order.Status
            }, 30*time.Second, 2*time.Second).Should(Equal("bridging"))

            Eventually(func() string {
                order := getCrossChainOrder(orderID)
                return order.Status
            }, 60*time.Second, 2*time.Second).Should(Equal("swapping"))

            Eventually(func() string {
                order := getCrossChainOrder(orderID)
                return order.Status
            }, 90*time.Second, 2*time.Second).Should(Equal("completed"))

            By("verifying final order details")
            finalOrder := getCrossChainOrder(orderID)
            Expect(finalOrder.CompletedAt).To(BeNumerically(">", 0))
            Expect(finalOrder.BridgeTxID).ToNot(BeEmpty())
            Expect(finalOrder.SwapTxID).ToNot(BeEmpty())
        })
    })
})
```

## 📊 **Test Metrics & Reporting**

### Performance Benchmarks
```go
// tests/performance/benchmarks_test.go
func BenchmarkCompleteWorkflow(b *testing.B) {
    for i := 0; i < b.N; i++ {
        // Measure complete user workflow time
        start := time.Now()
        
        // Execute full workflow
        runCompleteWorkflow()
        
        duration := time.Since(start)
        b.ReportMetric(float64(duration.Milliseconds()), "ms/workflow")
    }
}

func BenchmarkCrossChainSwap(b *testing.B) {
    for i := 0; i < b.N; i++ {
        start := time.Now()
        
        executeCrossChainSwapWorkflow()
        
        duration := time.Since(start)
        b.ReportMetric(float64(duration.Milliseconds()), "ms/swap")
    }
}
```

### Test Coverage Report
```bash
# Generate coverage report
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html

# Expected coverage targets:
# - Core blockchain: >90%
# - Wallet operations: >85%
# - API endpoints: >95%
# - Cross-chain: >80%
# - Overall: >85%
```

## 🎯 **Success Criteria**

### Functional Requirements
- ✅ **All workflows complete successfully** (100% pass rate)
- ✅ **No data corruption** during any operation
- ✅ **Consistent state** across all components
- ✅ **Proper error handling** for edge cases
- ✅ **Security measures** working correctly

### Performance Requirements
- ✅ **Wallet operations** complete within 2 seconds
- ✅ **Cross-chain swaps** complete within 2 minutes
- ✅ **API responses** under 500ms (95th percentile)
- ✅ **Block production** maintains 5-second intervals
- ✅ **System handles** 100+ concurrent users

### Security Requirements
- ✅ **Authentication** prevents unauthorized access
- ✅ **Private keys** never exposed in logs
- ✅ **Transactions** properly signed and validated
- ✅ **Slashing** activates for malicious behavior
- ✅ **Cross-chain** transfers are secure

## 🚀 **Running the Tests**

### Quick Test Run
```bash
# Run all E2E tests
./scripts/run_e2e_tests.sh

# Run specific test suite
go test ./tests/e2e/wallet_test.go -v

# Run with coverage
go test ./tests/e2e/... -v -cover
```

### Continuous Integration
```yaml
# .github/workflows/e2e.yml
name: E2E Tests
on: [push, pull_request]
jobs:
  e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-go@v2
        with:
          go-version: 1.21
      - name: Run E2E Tests
        run: ./scripts/run_e2e_tests.sh
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: test-results
          path: test_results/
```

---

**Test Suite Version**: 1.0.0  
**Last Updated**: December 2024  
**Status**: Production Ready
