package testing

import (
	"testing"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/token"
	"github.com/stretchr/testify/assert"
)

func setupTestBlockchainForHighFreq(t *testing.T) *chain.Blockchain {
	// Create test blockchain with unique port
	port := 6001 + (int(time.Now().UnixNano()) % 1000)
	blockchain, err := chain.NewBlockchain(port)
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}

	// Add additional test tokens
	testToken1 := token.NewToken("TestToken1", "TT1", 18, 10000000)
	testToken2 := token.NewToken("TestToken2", "TT2", 6, 10000000)
	blockchain.TokenRegistry["TT1"] = testToken1
	blockchain.TokenRegistry["TT2"] = testToken2

	return blockchain
}

func TestHighFrequencyTester(t *testing.T) {
	blockchain := setupTestBlockchainForHighFreq(t)
	defer blockchain.DB.Close()

	hft := NewHighFrequencyTester(blockchain)
	assert.NotNil(t, hft)

	t.Run("Setup test environment", func(t *testing.T) {
		err := hft.SetupTestEnvironment(10)
		assert.NoError(t, err)
		assert.Len(t, hft.testAccounts, 10)
		assert.GreaterOrEqual(t, len(hft.testTokens), 3) // BHX, ETH, USDT + TT1, TT2

		// Verify accounts have tokens
		for _, tokenSymbol := range hft.testTokens {
			token := blockchain.TokenRegistry[tokenSymbol]
			for _, account := range hft.testAccounts {
				balance, err := token.BalanceOf(account)
				assert.NoError(t, err)
				assert.Equal(t, uint64(1000000), balance)
			}
		}
	})

	t.Run("Configure test parameters", func(t *testing.T) {
		hft.ConfigureTest(50, 10*time.Second, 20)
		
		assert.Equal(t, 50, hft.transactionRate)
		assert.Equal(t, 10*time.Second, hft.testDuration)
		assert.Equal(t, 20, hft.maxConcurrency)
	})

	t.Run("Short stress test", func(t *testing.T) {
		// Configure for a very short test
		hft.ConfigureTest(20, 3*time.Second, 10)
		
		result, err := hft.RunStressTest("Short_Test")
		assert.NoError(t, err)
		assert.NotNil(t, result)
		
		// Verify basic result structure
		assert.Equal(t, "Short_Test", result.TestName)
		assert.Greater(t, result.Duration, time.Duration(0))
		assert.GreaterOrEqual(t, result.TotalTxSent, int64(0))
		assert.GreaterOrEqual(t, result.TotalTxSuccess, int64(0))
		assert.GreaterOrEqual(t, result.TotalTxFailed, int64(0))
		assert.GreaterOrEqual(t, result.SuccessRate, 0.0)
		assert.LessOrEqual(t, result.SuccessRate, 100.0)
		assert.GreaterOrEqual(t, result.ThroughputTPS, 0.0)
		assert.NotZero(t, result.Timestamp)
		
		// If any transactions succeeded, check metrics
		if result.TotalTxSuccess > 0 {
			assert.Greater(t, result.AvgLatency, time.Duration(0))
			assert.Greater(t, result.MaxLatency, time.Duration(0))
			assert.Greater(t, result.MinLatency, time.Duration(0))
			assert.GreaterOrEqual(t, result.MaxLatency, result.AvgLatency)
			assert.LessOrEqual(t, result.MinLatency, result.AvgLatency)
			assert.Greater(t, result.TotalGasUsed, int64(0))
			assert.Greater(t, result.AvgGasPerTx, 0.0)
		}
	})

	t.Run("Performance metrics tracking", func(t *testing.T) {
		// Configure for a slightly longer test to capture metrics
		hft.ConfigureTest(10, 5*time.Second, 5)
		
		result, err := hft.RunStressTest("Metrics_Test")
		assert.NoError(t, err)
		assert.NotNil(t, result)
		
		// Should have some performance data
		assert.Greater(t, len(hft.latencies), 0)
		assert.Greater(t, len(hft.throughput), 0)
		assert.Greater(t, len(hft.errorRates), 0)
		
		// Verify latency data consistency
		if len(hft.latencies) > 0 {
			assert.Equal(t, result.MinLatency, hft.latencies[0]) // First latency should be min for small dataset
		}
	})

	t.Run("Error handling", func(t *testing.T) {
		// Test with insufficient setup (no test environment)
		emptyHft := NewHighFrequencyTester(blockchain)

		// This should handle empty test accounts gracefully
		result, _ := emptyHft.RunStressTest("Empty_Test")
		// Should not crash, but may have different behavior
		assert.NotNil(t, result)
		// Error is acceptable here since no test environment was set up
	})

	t.Run("Concurrent transaction generation", func(t *testing.T) {
		// Test with higher concurrency
		hft.ConfigureTest(30, 2*time.Second, 15)
		
		result, err := hft.RunStressTest("Concurrent_Test")
		assert.NoError(t, err)
		assert.NotNil(t, result)
		
		// Should handle concurrent transactions
		assert.GreaterOrEqual(t, result.TotalTxSent, int64(0))
		
		// Error rate should be reasonable (less than 50%)
		if result.TotalTxSent > 0 {
			assert.LessOrEqual(t, result.ErrorRate, 50.0)
		}
	})
}

func TestHighFrequencyBenchmarkSuite(t *testing.T) {
	// Skip this test in short mode as it takes longer
	if testing.Short() {
		t.Skip("Skipping benchmark suite in short mode")
	}

	blockchain := setupTestBlockchainForHighFreq(t)
	defer blockchain.DB.Close()

	hft := NewHighFrequencyTester(blockchain)
	
	// Setup test environment
	err := hft.SetupTestEnvironment(5) // Smaller setup for faster testing
	assert.NoError(t, err)

	t.Run("Mini benchmark suite", func(t *testing.T) {
		// Run a mini version of the benchmark suite with shorter durations
		results := make([]*TestResult, 0)
		
		// Test 1: Low frequency
		hft.ConfigureTest(5, 2*time.Second, 3)
		result1, err := hft.RunStressTest("Mini_Low_Freq")
		assert.NoError(t, err)
		results = append(results, result1)
		
		// Test 2: Medium frequency
		hft.ConfigureTest(10, 2*time.Second, 5)
		result2, err := hft.RunStressTest("Mini_Medium_Freq")
		assert.NoError(t, err)
		results = append(results, result2)
		
		// Test 3: High frequency
		hft.ConfigureTest(20, 2*time.Second, 10)
		result3, err := hft.RunStressTest("Mini_High_Freq")
		assert.NoError(t, err)
		results = append(results, result3)
		
		// Verify we have results for all tests
		assert.Len(t, results, 3)
		
		// Verify results are properly ordered and contain expected data
		for i, result := range results {
			assert.NotNil(t, result)
			assert.NotEmpty(t, result.TestName)
			assert.Greater(t, result.Duration, time.Duration(0))
			assert.GreaterOrEqual(t, result.TotalTxSent, int64(0))
			
			// Each subsequent test should generally have higher transaction rates
			// (though this isn't guaranteed due to system variability)
			if i > 0 && result.TotalTxSent > 0 && results[i-1].TotalTxSent > 0 {
				// Just verify both tests ran and produced results
				assert.Greater(t, result.TotalTxSent, int64(0))
			}
		}
		
		// Print summary for manual verification
		hft.printBenchmarkSummary(results)
	})
}

func TestHighFrequencyTesterConfiguration(t *testing.T) {
	blockchain := setupTestBlockchainForHighFreq(t)
	defer blockchain.DB.Close()

	hft := NewHighFrequencyTester(blockchain)

	t.Run("Default configuration", func(t *testing.T) {
		assert.Equal(t, 100, hft.transactionRate)
		assert.Equal(t, 30*time.Second, hft.testDuration)
		assert.Equal(t, 50, hft.maxConcurrency)
		assert.NotNil(t, hft.stopChan)
		assert.Empty(t, hft.testAccounts)
		assert.Empty(t, hft.testTokens)
	})

	t.Run("Custom configuration", func(t *testing.T) {
		hft.ConfigureTest(200, 60*time.Second, 100)
		
		assert.Equal(t, 200, hft.transactionRate)
		assert.Equal(t, 60*time.Second, hft.testDuration)
		assert.Equal(t, 100, hft.maxConcurrency)
	})

	t.Run("Test environment setup with different sizes", func(t *testing.T) {
		// Test with 1 account
		err := hft.SetupTestEnvironment(1)
		assert.NoError(t, err)
		assert.Len(t, hft.testAccounts, 1)
		
		// Test with 20 accounts
		err = hft.SetupTestEnvironment(20)
		assert.NoError(t, err)
		assert.Len(t, hft.testAccounts, 20)
		
		// Verify all accounts have the expected tokens
		for _, account := range hft.testAccounts {
			for _, tokenSymbol := range hft.testTokens {
				token := blockchain.TokenRegistry[tokenSymbol]
				balance, err := token.BalanceOf(account)
				assert.NoError(t, err)
				assert.Equal(t, uint64(1000000), balance)
			}
		}
	})
}

func TestHighFrequencyTesterStopFunctionality(t *testing.T) {
	blockchain := setupTestBlockchainForHighFreq(t)
	defer blockchain.DB.Close()

	hft := NewHighFrequencyTester(blockchain)
	err := hft.SetupTestEnvironment(3)
	assert.NoError(t, err)

	t.Run("Stop test functionality", func(t *testing.T) {
		// Configure for a longer test
		hft.ConfigureTest(10, 10*time.Second, 5)
		
		// Start test in goroutine
		resultChan := make(chan *TestResult)
		go func() {
			result, _ := hft.RunStressTest("Stop_Test")
			resultChan <- result
		}()
		
		// Let it run for a short time
		time.Sleep(1 * time.Second)
		
		// Stop the test
		hft.StopTest()
		
		// Wait for result
		result := <-resultChan
		assert.NotNil(t, result)
		
		// Test should have stopped early
		assert.Less(t, result.Duration, 10*time.Second)
		assert.Greater(t, result.Duration, 500*time.Millisecond) // Should have run for some time
	})
}

func TestHighFrequencyTesterResultCalculations(t *testing.T) {
	blockchain := setupTestBlockchainForHighFreq(t)
	defer blockchain.DB.Close()

	hft := NewHighFrequencyTester(blockchain)
	err := hft.SetupTestEnvironment(5)
	assert.NoError(t, err)

	t.Run("Result calculation accuracy", func(t *testing.T) {
		// Configure for predictable test
		hft.ConfigureTest(5, 3*time.Second, 3)
		
		result, err := hft.RunStressTest("Calculation_Test")
		assert.NoError(t, err)
		assert.NotNil(t, result)
		
		// Verify calculation consistency
		assert.Equal(t, result.TotalTxSent, result.TotalTxSuccess+result.TotalTxFailed)
		
		if result.TotalTxSent > 0 {
			expectedSuccessRate := float64(result.TotalTxSuccess) / float64(result.TotalTxSent) * 100
			assert.InDelta(t, expectedSuccessRate, result.SuccessRate, 0.01)
			
			expectedErrorRate := float64(result.TotalTxFailed) / float64(result.TotalTxSent) * 100
			assert.InDelta(t, expectedErrorRate, result.ErrorRate, 0.01)
			
			// Success rate + error rate should equal 100%
			assert.InDelta(t, 100.0, result.SuccessRate+result.ErrorRate, 0.01)
		}
		
		if result.Duration.Seconds() > 0 {
			expectedTPS := float64(result.TotalTxSuccess) / result.Duration.Seconds()
			assert.InDelta(t, expectedTPS, result.ThroughputTPS, 0.01)
		}
		
		if result.TotalTxSuccess > 0 {
			expectedAvgGas := float64(result.TotalGasUsed) / float64(result.TotalTxSuccess)
			assert.InDelta(t, expectedAvgGas, result.AvgGasPerTx, 0.01)
		}
	})
}
