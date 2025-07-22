package testing

import (
	"fmt"
	"log"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

// HighFrequencyTester performs stress testing with high transaction volumes
type HighFrequencyTester struct {
	blockchain      *chain.Blockchain
	testAccounts    []string
	testTokens      []string
	
	// Test configuration
	transactionRate int           // transactions per second
	testDuration    time.Duration // how long to run the test
	maxConcurrency  int           // maximum concurrent goroutines
	
	// Test statistics
	totalTxSent     int64
	totalTxSuccess  int64
	totalTxFailed   int64
	totalGasUsed    int64
	startTime       time.Time
	endTime         time.Time
	
	// Performance metrics
	latencies       []time.Duration
	throughput      []int64
	errorRates      []float64
	
	mu              sync.RWMutex
	stopChan        chan bool
	wg              sync.WaitGroup
}

// TestResult represents the results of a high-frequency test
type TestResult struct {
	TestName        string        `json:"test_name"`
	Duration        time.Duration `json:"duration"`
	TotalTxSent     int64         `json:"total_tx_sent"`
	TotalTxSuccess  int64         `json:"total_tx_success"`
	TotalTxFailed   int64         `json:"total_tx_failed"`
	SuccessRate     float64       `json:"success_rate"`
	AvgLatency      time.Duration `json:"avg_latency"`
	MaxLatency      time.Duration `json:"max_latency"`
	MinLatency      time.Duration `json:"min_latency"`
	ThroughputTPS   float64       `json:"throughput_tps"`
	TotalGasUsed    int64         `json:"total_gas_used"`
	AvgGasPerTx     float64       `json:"avg_gas_per_tx"`
	ErrorRate       float64       `json:"error_rate"`
	BlocksCreated   int           `json:"blocks_created"`
	Timestamp       time.Time     `json:"timestamp"`
}

// NewHighFrequencyTester creates a new high-frequency tester
func NewHighFrequencyTester(blockchain *chain.Blockchain) *HighFrequencyTester {
	return &HighFrequencyTester{
		blockchain:      blockchain,
		testAccounts:    make([]string, 0),
		testTokens:      make([]string, 0),
		transactionRate: 100, // 100 TPS default
		testDuration:    30 * time.Second,
		maxConcurrency:  50,
		latencies:       make([]time.Duration, 0),
		throughput:      make([]int64, 0),
		errorRates:      make([]float64, 0),
		stopChan:        make(chan bool),
	}
}

// SetupTestEnvironment prepares the test environment with accounts and tokens
func (hft *HighFrequencyTester) SetupTestEnvironment(numAccounts int) error {
	log.Printf("🔧 Setting up test environment with %d accounts", numAccounts)

	// Create test accounts
	for i := 0; i < numAccounts; i++ {
		account := fmt.Sprintf("test_account_%d", i)
		hft.testAccounts = append(hft.testAccounts, account)
	}

	// Get available tokens
	for tokenSymbol := range hft.blockchain.TokenRegistry {
		hft.testTokens = append(hft.testTokens, tokenSymbol)
	}

	// Mint tokens to test accounts
	for _, tokenSymbol := range hft.testTokens {
		token := hft.blockchain.TokenRegistry[tokenSymbol]
		for _, account := range hft.testAccounts {
			err := token.Mint(account, 1000000) // 1M tokens per account
			if err != nil {
				return fmt.Errorf("failed to mint tokens to %s: %v", account, err)
			}
		}
	}

	log.Printf("✅ Test environment setup complete: %d accounts, %d tokens", 
		len(hft.testAccounts), len(hft.testTokens))
	return nil
}

// ConfigureTest sets test parameters
func (hft *HighFrequencyTester) ConfigureTest(tps int, duration time.Duration, concurrency int) {
	hft.mu.Lock()
	defer hft.mu.Unlock()
	
	hft.transactionRate = tps
	hft.testDuration = duration
	hft.maxConcurrency = concurrency
	
	log.Printf("📊 Test configured: %d TPS, %v duration, %d max concurrency", 
		tps, duration, concurrency)
}

// RunStressTest executes the high-frequency stress test
func (hft *HighFrequencyTester) RunStressTest(testName string) (*TestResult, error) {
	log.Printf("🚀 Starting high-frequency stress test: %s", testName)
	
	// Reset counters
	atomic.StoreInt64(&hft.totalTxSent, 0)
	atomic.StoreInt64(&hft.totalTxSuccess, 0)
	atomic.StoreInt64(&hft.totalTxFailed, 0)
	atomic.StoreInt64(&hft.totalGasUsed, 0)
	
	hft.mu.Lock()
	hft.latencies = hft.latencies[:0]
	hft.throughput = hft.throughput[:0]
	hft.errorRates = hft.errorRates[:0]
	hft.mu.Unlock()
	
	hft.startTime = time.Now()
	initialBlocks := len(hft.blockchain.Blocks)
	
	// Start transaction generators
	semaphore := make(chan struct{}, hft.maxConcurrency)
	ticker := time.NewTicker(time.Second / time.Duration(hft.transactionRate))
	defer ticker.Stop()
	
	// Start monitoring goroutine
	go hft.monitorPerformance()
	
	// Generate transactions
	testTimer := time.NewTimer(hft.testDuration)
	defer testTimer.Stop()
	
	for {
		select {
		case <-testTimer.C:
			log.Printf("⏰ Test duration reached, stopping...")
			goto cleanup
		case <-hft.stopChan:
			log.Printf("🛑 Test stopped by signal")
			goto cleanup
		case <-ticker.C:
			select {
			case semaphore <- struct{}{}:
				hft.wg.Add(1)
				go func() {
					defer hft.wg.Done()
					defer func() { <-semaphore }()
					hft.generateRandomTransaction()
				}()
			default:
				// Skip if at max concurrency
				atomic.AddInt64(&hft.totalTxFailed, 1)
			}
		}
	}
	
cleanup:
	// Wait for all transactions to complete
	log.Printf("⏳ Waiting for pending transactions to complete...")
	hft.wg.Wait()
	hft.endTime = time.Now()
	
	// Calculate results
	result := hft.calculateResults(testName, initialBlocks)
	
	log.Printf("✅ Stress test completed: %s", testName)
	hft.printResults(result)
	
	return result, nil
}

// generateRandomTransaction creates and submits a random transaction
func (hft *HighFrequencyTester) generateRandomTransaction() {
	startTime := time.Now()
	
	// Select random accounts and token
	fromAccount := hft.testAccounts[rand.Intn(len(hft.testAccounts))]
	toAccount := hft.testAccounts[rand.Intn(len(hft.testAccounts))]
	tokenSymbol := hft.testTokens[rand.Intn(len(hft.testTokens))]
	
	// Ensure different accounts
	for fromAccount == toAccount {
		toAccount = hft.testAccounts[rand.Intn(len(hft.testAccounts))]
	}
	
	// Random amount (1-1000)
	amount := uint64(rand.Intn(1000) + 1)
	
	atomic.AddInt64(&hft.totalTxSent, 1)
	
	// Execute transaction
	token := hft.blockchain.TokenRegistry[tokenSymbol]
	err := token.Transfer(fromAccount, toAccount, amount)
	
	latency := time.Since(startTime)
	
	hft.mu.Lock()
	hft.latencies = append(hft.latencies, latency)
	hft.mu.Unlock()
	
	if err != nil {
		atomic.AddInt64(&hft.totalTxFailed, 1)
	} else {
		atomic.AddInt64(&hft.totalTxSuccess, 1)
		// Estimate gas used (simplified)
		atomic.AddInt64(&hft.totalGasUsed, 21000) // Base gas for transfer
	}
}

// monitorPerformance monitors performance metrics during the test
func (hft *HighFrequencyTester) monitorPerformance() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	lastTxCount := int64(0)
	
	for {
		select {
		case <-ticker.C:
			currentTxCount := atomic.LoadInt64(&hft.totalTxSuccess)
			currentThroughput := currentTxCount - lastTxCount
			lastTxCount = currentTxCount
			
			totalSent := atomic.LoadInt64(&hft.totalTxSent)
			totalFailed := atomic.LoadInt64(&hft.totalTxFailed)
			
			var errorRate float64
			if totalSent > 0 {
				errorRate = float64(totalFailed) / float64(totalSent) * 100
			}
			
			hft.mu.Lock()
			hft.throughput = append(hft.throughput, currentThroughput)
			hft.errorRates = append(hft.errorRates, errorRate)
			hft.mu.Unlock()
			
			log.Printf("📊 TPS: %d, Success: %d, Failed: %d, Error Rate: %.2f%%", 
				currentThroughput, currentTxCount, totalFailed, errorRate)
				
		case <-hft.stopChan:
			return
		}
	}
}

// calculateResults computes the final test results
func (hft *HighFrequencyTester) calculateResults(testName string, initialBlocks int) *TestResult {
	hft.mu.RLock()
	defer hft.mu.RUnlock()
	
	duration := hft.endTime.Sub(hft.startTime)
	totalSent := atomic.LoadInt64(&hft.totalTxSent)
	totalSuccess := atomic.LoadInt64(&hft.totalTxSuccess)
	totalFailed := atomic.LoadInt64(&hft.totalTxFailed)
	totalGas := atomic.LoadInt64(&hft.totalGasUsed)
	
	result := &TestResult{
		TestName:       testName,
		Duration:       duration,
		TotalTxSent:    totalSent,
		TotalTxSuccess: totalSuccess,
		TotalTxFailed:  totalFailed,
		TotalGasUsed:   totalGas,
		BlocksCreated:  len(hft.blockchain.Blocks) - initialBlocks,
		Timestamp:      time.Now(),
	}
	
	// Calculate success rate
	if totalSent > 0 {
		result.SuccessRate = float64(totalSuccess) / float64(totalSent) * 100
		result.ErrorRate = float64(totalFailed) / float64(totalSent) * 100
	}
	
	// Calculate throughput
	if duration.Seconds() > 0 {
		result.ThroughputTPS = float64(totalSuccess) / duration.Seconds()
	}
	
	// Calculate gas metrics
	if totalSuccess > 0 {
		result.AvgGasPerTx = float64(totalGas) / float64(totalSuccess)
	}
	
	// Calculate latency metrics
	if len(hft.latencies) > 0 {
		var totalLatency time.Duration
		result.MinLatency = hft.latencies[0]
		result.MaxLatency = hft.latencies[0]
		
		for _, latency := range hft.latencies {
			totalLatency += latency
			if latency < result.MinLatency {
				result.MinLatency = latency
			}
			if latency > result.MaxLatency {
				result.MaxLatency = latency
			}
		}
		
		result.AvgLatency = totalLatency / time.Duration(len(hft.latencies))
	}
	
	return result
}

// printResults prints detailed test results
func (hft *HighFrequencyTester) printResults(result *TestResult) {
	log.Printf("📈 HIGH-FREQUENCY TEST RESULTS: %s", result.TestName)
	log.Printf("⏱️  Duration: %v", result.Duration)
	log.Printf("📤 Transactions Sent: %d", result.TotalTxSent)
	log.Printf("✅ Transactions Success: %d", result.TotalTxSuccess)
	log.Printf("❌ Transactions Failed: %d", result.TotalTxFailed)
	log.Printf("📊 Success Rate: %.2f%%", result.SuccessRate)
	log.Printf("🚀 Throughput: %.2f TPS", result.ThroughputTPS)
	log.Printf("⚡ Avg Latency: %v", result.AvgLatency)
	log.Printf("⚡ Max Latency: %v", result.MaxLatency)
	log.Printf("⚡ Min Latency: %v", result.MinLatency)
	log.Printf("⛽ Total Gas Used: %d", result.TotalGasUsed)
	log.Printf("⛽ Avg Gas Per Tx: %.2f", result.AvgGasPerTx)
	log.Printf("🧱 Blocks Created: %d", result.BlocksCreated)
	log.Printf("❌ Error Rate: %.2f%%", result.ErrorRate)
}

// StopTest stops the running test
func (hft *HighFrequencyTester) StopTest() {
	close(hft.stopChan)
}

// RunBenchmarkSuite runs a series of benchmark tests
func (hft *HighFrequencyTester) RunBenchmarkSuite() ([]*TestResult, error) {
	log.Printf("🏁 Starting benchmark suite")
	
	results := make([]*TestResult, 0)
	
	// Test 1: Low frequency baseline
	hft.ConfigureTest(10, 30*time.Second, 10)
	result1, err := hft.RunStressTest("Low_Frequency_Baseline")
	if err != nil {
		return nil, err
	}
	results = append(results, result1)
	
	time.Sleep(5 * time.Second) // Cool down
	
	// Test 2: Medium frequency
	hft.ConfigureTest(50, 30*time.Second, 25)
	result2, err := hft.RunStressTest("Medium_Frequency")
	if err != nil {
		return nil, err
	}
	results = append(results, result2)
	
	time.Sleep(5 * time.Second) // Cool down
	
	// Test 3: High frequency
	hft.ConfigureTest(100, 30*time.Second, 50)
	result3, err := hft.RunStressTest("High_Frequency")
	if err != nil {
		return nil, err
	}
	results = append(results, result3)
	
	time.Sleep(5 * time.Second) // Cool down
	
	// Test 4: Extreme frequency
	hft.ConfigureTest(200, 30*time.Second, 100)
	result4, err := hft.RunStressTest("Extreme_Frequency")
	if err != nil {
		return nil, err
	}
	results = append(results, result4)
	
	log.Printf("🏆 Benchmark suite completed with %d tests", len(results))

	// Print summary comparison
	hft.printBenchmarkSummary(results)

	return results, nil
}

// printBenchmarkSummary prints a comparison of all benchmark results
func (hft *HighFrequencyTester) printBenchmarkSummary(results []*TestResult) {
	log.Printf("📋 BENCHMARK SUITE SUMMARY")
	log.Printf("%s", strings.Repeat("=", 80))
	log.Printf("%-20s %-10s %-10s %-10s %-10s %-10s",
		"Test Name", "TPS", "Success%", "Latency", "Gas/Tx", "Blocks")
	log.Printf("%s", strings.Repeat("-", 80))

	for _, result := range results {
		log.Printf("%-20s %-10.1f %-10.1f %-10v %-10.0f %-10d",
			result.TestName,
			result.ThroughputTPS,
			result.SuccessRate,
			result.AvgLatency,
			result.AvgGasPerTx,
			result.BlocksCreated)
	}
	log.Printf("%s", strings.Repeat("=", 80))
}
