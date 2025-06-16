package testing

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// LoadTestConfig represents load testing configuration
type LoadTestConfig struct {
	TotalTransactions    int           `json:"total_transactions"`
	ConcurrentUsers      int           `json:"concurrent_users"`
	TestDuration         time.Duration `json:"test_duration"`
	TransactionTypes     []string      `json:"transaction_types"`
	TargetTPS            float64       `json:"target_tps"`
	RampUpDuration       time.Duration `json:"ramp_up_duration"`
	SteadyStateDuration  time.Duration `json:"steady_state_duration"`
	RampDownDuration     time.Duration `json:"ramp_down_duration"`
}

// LoadTestResult represents the results of a load test
type LoadTestResult struct {
	Config                *LoadTestConfig   `json:"config"`
	StartTime             time.Time         `json:"start_time"`
	EndTime               time.Time         `json:"end_time"`
	TotalDuration         time.Duration     `json:"total_duration"`
	TransactionsSent      int64             `json:"transactions_sent"`
	TransactionsSucceeded int64             `json:"transactions_succeeded"`
	TransactionsFailed    int64             `json:"transactions_failed"`
	AverageTPS            float64           `json:"average_tps"`
	PeakTPS               float64           `json:"peak_tps"`
	MinResponseTime       time.Duration     `json:"min_response_time"`
	MaxResponseTime       time.Duration     `json:"max_response_time"`
	AvgResponseTime       time.Duration     `json:"avg_response_time"`
	P95ResponseTime       time.Duration     `json:"p95_response_time"`
	P99ResponseTime       time.Duration     `json:"p99_response_time"`
	ErrorRate             float64           `json:"error_rate"`
	ThroughputMBps        float64           `json:"throughput_mbps"`
	MemoryUsageMB         float64           `json:"memory_usage_mb"`
	CPUUsagePercent       float64           `json:"cpu_usage_percent"`
	Errors                map[string]int64  `json:"errors"`
	ResponseTimes         []time.Duration   `json:"response_times"`
	TPSOverTime           []TPSDataPoint    `json:"tps_over_time"`
}

// TPSDataPoint represents TPS at a specific time
type TPSDataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	TPS       float64   `json:"tps"`
}

// TransactionResult represents the result of a single transaction
type TransactionResult struct {
	Success      bool          `json:"success"`
	ResponseTime time.Duration `json:"response_time"`
	Error        string        `json:"error,omitempty"`
	TxHash       string        `json:"tx_hash,omitempty"`
	Timestamp    time.Time     `json:"timestamp"`
}

// LoadTester provides comprehensive load testing capabilities
type LoadTester struct {
	config           *LoadTestConfig
	results          *LoadTestResult
	mu               sync.RWMutex
	ctx              context.Context
	cancel           context.CancelFunc
	transactionsSent int64
	transactionsOK   int64
	transactionsFail int64
	responseTimes    []time.Duration
	errors           map[string]int64
	tpsData          []TPSDataPoint
	startTime        time.Time
}

// NewLoadTester creates a new load tester
func NewLoadTester(config *LoadTestConfig) *LoadTester {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &LoadTester{
		config:        config,
		ctx:           ctx,
		cancel:        cancel,
		responseTimes: make([]time.Duration, 0),
		errors:        make(map[string]int64),
		tpsData:       make([]TPSDataPoint, 0),
	}
}

// RunLoadTest executes a comprehensive load test
func (lt *LoadTester) RunLoadTest() (*LoadTestResult, error) {
	fmt.Println("🚀 Starting comprehensive load test...")
	fmt.Printf("📊 Configuration:\n")
	fmt.Printf("   Total Transactions: %d\n", lt.config.TotalTransactions)
	fmt.Printf("   Concurrent Users: %d\n", lt.config.ConcurrentUsers)
	fmt.Printf("   Target TPS: %.1f\n", lt.config.TargetTPS)
	fmt.Printf("   Test Duration: %v\n", lt.config.TestDuration)
	
	lt.startTime = time.Now()
	
	// Initialize results
	lt.results = &LoadTestResult{
		Config:            lt.config,
		StartTime:         lt.startTime,
		Errors:            make(map[string]int64),
		ResponseTimes:     make([]time.Duration, 0),
		TPSOverTime:       make([]TPSDataPoint, 0),
		MinResponseTime:   time.Hour, // Initialize to high value
	}
	
	// Start monitoring goroutine
	go lt.monitorPerformance()
	
	// Start TPS tracking goroutine
	go lt.trackTPS()
	
	// Execute load test phases
	if err := lt.executeLoadTestPhases(); err != nil {
		return nil, fmt.Errorf("load test failed: %v", err)
	}
	
	// Finalize results
	lt.finalizeResults()
	
	fmt.Println("✅ Load test completed successfully!")
	lt.printResults()
	
	return lt.results, nil
}

// executeLoadTestPhases executes the different phases of the load test
func (lt *LoadTester) executeLoadTestPhases() error {
	// Phase 1: Ramp-up
	if lt.config.RampUpDuration > 0 {
		fmt.Printf("📈 Phase 1: Ramp-up (%v)\n", lt.config.RampUpDuration)
		if err := lt.rampUpPhase(); err != nil {
			return fmt.Errorf("ramp-up phase failed: %v", err)
		}
	}
	
	// Phase 2: Steady state
	if lt.config.SteadyStateDuration > 0 {
		fmt.Printf("⚡ Phase 2: Steady state (%v)\n", lt.config.SteadyStateDuration)
		if err := lt.steadyStatePhase(); err != nil {
			return fmt.Errorf("steady state phase failed: %v", err)
		}
	}
	
	// Phase 3: Ramp-down
	if lt.config.RampDownDuration > 0 {
		fmt.Printf("📉 Phase 3: Ramp-down (%v)\n", lt.config.RampDownDuration)
		if err := lt.rampDownPhase(); err != nil {
			return fmt.Errorf("ramp-down phase failed: %v", err)
		}
	}
	
	return nil
}

// rampUpPhase gradually increases load
func (lt *LoadTester) rampUpPhase() error {
	duration := lt.config.RampUpDuration
	maxUsers := lt.config.ConcurrentUsers
	
	ticker := time.NewTicker(duration / time.Duration(maxUsers))
	defer ticker.Stop()
	
	activeUsers := 0
	userChannels := make([]chan bool, maxUsers)
	
	for i := 0; i < maxUsers; i++ {
		userChannels[i] = make(chan bool, 1)
	}
	
	for activeUsers < maxUsers {
		select {
		case <-lt.ctx.Done():
			return lt.ctx.Err()
		case <-ticker.C:
			if activeUsers < maxUsers {
				go lt.simulateUser(activeUsers, userChannels[activeUsers])
				activeUsers++
				fmt.Printf("👤 Active users: %d/%d\n", activeUsers, maxUsers)
			}
		}
	}
	
	// Wait for ramp-up to complete
	time.Sleep(duration)
	
	// Stop all users
	for i := 0; i < activeUsers; i++ {
		userChannels[i] <- true
	}
	
	return nil
}

// steadyStatePhase maintains constant load
func (lt *LoadTester) steadyStatePhase() error {
	duration := lt.config.SteadyStateDuration
	users := lt.config.ConcurrentUsers
	
	userChannels := make([]chan bool, users)
	var wg sync.WaitGroup
	
	// Start all users
	for i := 0; i < users; i++ {
		userChannels[i] = make(chan bool, 1)
		wg.Add(1)
		go func(userID int) {
			defer wg.Done()
			lt.simulateUser(userID, userChannels[userID])
		}(i)
	}
	
	// Run for specified duration
	time.Sleep(duration)
	
	// Stop all users
	for i := 0; i < users; i++ {
		userChannels[i] <- true
	}
	
	wg.Wait()
	return nil
}

// rampDownPhase gradually decreases load
func (lt *LoadTester) rampDownPhase() error {
	duration := lt.config.RampDownDuration
	maxUsers := lt.config.ConcurrentUsers
	
	ticker := time.NewTicker(duration / time.Duration(maxUsers))
	defer ticker.Stop()
	
	activeUsers := maxUsers
	userChannels := make([]chan bool, maxUsers)
	
	for i := 0; i < maxUsers; i++ {
		userChannels[i] = make(chan bool, 1)
		go lt.simulateUser(i, userChannels[i])
	}
	
	for activeUsers > 0 {
		select {
		case <-lt.ctx.Done():
			return lt.ctx.Err()
		case <-ticker.C:
			if activeUsers > 0 {
				activeUsers--
				userChannels[activeUsers] <- true
				fmt.Printf("👤 Active users: %d/%d\n", activeUsers, maxUsers)
			}
		}
	}
	
	return nil
}

// simulateUser simulates a single user's behavior
func (lt *LoadTester) simulateUser(userID int, stopCh chan bool) {
	ticker := time.NewTicker(time.Duration(float64(time.Second) / lt.config.TargetTPS * float64(lt.config.ConcurrentUsers)))
	defer ticker.Stop()
	
	for {
		select {
		case <-stopCh:
			return
		case <-lt.ctx.Done():
			return
		case <-ticker.C:
			lt.sendTransaction(userID)
		}
	}
}

// sendTransaction simulates sending a transaction
func (lt *LoadTester) sendTransaction(userID int) {
	start := time.Now()
	
	// Simulate transaction processing
	result := lt.simulateTransactionProcessing()
	
	responseTime := time.Since(start)
	
	// Record metrics
	atomic.AddInt64(&lt.transactionsSent, 1)
	
	if result.Success {
		atomic.AddInt64(&lt.transactionsOK, 1)
	} else {
		atomic.AddInt64(&lt.transactionsFail, 1)
		lt.mu.Lock()
		lt.errors[result.Error]++
		lt.mu.Unlock()
	}
	
	// Record response time
	lt.mu.Lock()
	lt.responseTimes = append(lt.responseTimes, responseTime)
	lt.mu.Unlock()
}

// simulateTransactionProcessing simulates blockchain transaction processing
func (lt *LoadTester) simulateTransactionProcessing() *TransactionResult {
	// Simulate processing time (50-200ms)
	processingTime := time.Duration(50+rand.Intn(150)) * time.Millisecond
	time.Sleep(processingTime)
	
	// Simulate success/failure (95% success rate)
	success := rand.Float64() < 0.95
	
	result := &TransactionResult{
		Success:   success,
		Timestamp: time.Now(),
	}
	
	if success {
		// Generate mock transaction hash
		hash := make([]byte, 32)
		rand.Read(hash)
		result.TxHash = hex.EncodeToString(hash)
	} else {
		// Simulate different error types
		errors := []string{
			"insufficient_balance",
			"invalid_signature",
			"nonce_too_low",
			"gas_limit_exceeded",
			"network_timeout",
		}
		result.Error = errors[rand.Intn(len(errors))]
	}
	
	return result
}

// monitorPerformance monitors system performance during the test
func (lt *LoadTester) monitorPerformance() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-lt.ctx.Done():
			return
		case <-ticker.C:
			// Mock performance metrics
			lt.results.MemoryUsageMB = 256 + float64(atomic.LoadInt64(&lt.transactionsSent))/1000*10
			lt.results.CPUUsagePercent = 20 + float64(atomic.LoadInt64(&lt.transactionsSent))/10000*50
		}
	}
}

// trackTPS tracks transactions per second over time
func (lt *LoadTester) trackTPS() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	lastCount := int64(0)
	
	for {
		select {
		case <-lt.ctx.Done():
			return
		case <-ticker.C:
			currentCount := atomic.LoadInt64(&lt.transactionsSent)
			tps := float64(currentCount - lastCount)
			
			lt.mu.Lock()
			lt.tpsData = append(lt.tpsData, TPSDataPoint{
				Timestamp: time.Now(),
				TPS:       tps,
			})
			lt.mu.Unlock()
			
			if tps > lt.results.PeakTPS {
				lt.results.PeakTPS = tps
			}
			
			lastCount = currentCount
		}
	}
}

// finalizeResults calculates final test results
func (lt *LoadTester) finalizeResults() {
	lt.results.EndTime = time.Now()
	lt.results.TotalDuration = lt.results.EndTime.Sub(lt.results.StartTime)
	lt.results.TransactionsSent = atomic.LoadInt64(&lt.transactionsSent)
	lt.results.TransactionsSucceeded = atomic.LoadInt64(&lt.transactionsOK)
	lt.results.TransactionsFailed = atomic.LoadInt64(&lt.transactionsFail)
	
	if lt.results.TotalDuration > 0 {
		lt.results.AverageTPS = float64(lt.results.TransactionsSent) / lt.results.TotalDuration.Seconds()
	}
	
	if lt.results.TransactionsSent > 0 {
		lt.results.ErrorRate = float64(lt.results.TransactionsFailed) / float64(lt.results.TransactionsSent) * 100
	}
	
	// Calculate response time statistics
	if len(lt.responseTimes) > 0 {
		lt.calculateResponseTimeStats()
	}
	
	// Copy collected data
	lt.results.ResponseTimes = lt.responseTimes
	lt.results.TPSOverTime = lt.tpsData
	lt.results.Errors = lt.errors
	
	// Calculate throughput (mock calculation)
	avgTxSize := 250.0 // bytes
	lt.results.ThroughputMBps = lt.results.AverageTPS * avgTxSize / (1024 * 1024)
}

// calculateResponseTimeStats calculates response time statistics
func (lt *LoadTester) calculateResponseTimeStats() {
	times := lt.responseTimes
	n := len(times)
	
	// Sort response times for percentile calculations
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			if times[j] > times[j+1] {
				times[j], times[j+1] = times[j+1], times[j]
			}
		}
	}
	
	// Min and Max
	lt.results.MinResponseTime = times[0]
	lt.results.MaxResponseTime = times[n-1]
	
	// Average
	var total time.Duration
	for _, t := range times {
		total += t
	}
	lt.results.AvgResponseTime = total / time.Duration(n)
	
	// Percentiles
	p95Index := int(float64(n) * 0.95)
	p99Index := int(float64(n) * 0.99)
	
	if p95Index < n {
		lt.results.P95ResponseTime = times[p95Index]
	}
	if p99Index < n {
		lt.results.P99ResponseTime = times[p99Index]
	}
}

// printResults prints a summary of the load test results
func (lt *LoadTester) printResults() {
	fmt.Println("\n📊 Load Test Results Summary:")
	fmt.Println("=" + string(make([]byte, 50)))
	fmt.Printf("⏱️  Total Duration: %v\n", lt.results.TotalDuration)
	fmt.Printf("📤 Transactions Sent: %d\n", lt.results.TransactionsSent)
	fmt.Printf("✅ Transactions Succeeded: %d\n", lt.results.TransactionsSucceeded)
	fmt.Printf("❌ Transactions Failed: %d\n", lt.results.TransactionsFailed)
	fmt.Printf("📈 Average TPS: %.2f\n", lt.results.AverageTPS)
	fmt.Printf("🚀 Peak TPS: %.2f\n", lt.results.PeakTPS)
	fmt.Printf("⚡ Error Rate: %.2f%%\n", lt.results.ErrorRate)
	fmt.Printf("🕐 Avg Response Time: %v\n", lt.results.AvgResponseTime)
	fmt.Printf("📊 P95 Response Time: %v\n", lt.results.P95ResponseTime)
	fmt.Printf("📊 P99 Response Time: %v\n", lt.results.P99ResponseTime)
	fmt.Printf("💾 Memory Usage: %.1f MB\n", lt.results.MemoryUsageMB)
	fmt.Printf("🖥️  CPU Usage: %.1f%%\n", lt.results.CPUUsagePercent)
	fmt.Printf("🌐 Throughput: %.2f MB/s\n", lt.results.ThroughputMBps)
	
	if len(lt.results.Errors) > 0 {
		fmt.Println("\n❌ Error Breakdown:")
		for errorType, count := range lt.results.Errors {
			fmt.Printf("   %s: %d\n", errorType, count)
		}
	}
	
	fmt.Println("\n🎯 Performance Assessment:")
	if lt.results.AverageTPS >= lt.config.TargetTPS*0.9 {
		fmt.Println("✅ Target TPS achieved!")
	} else {
		fmt.Printf("⚠️  Target TPS not met (%.1f%% of target)\n", 
			lt.results.AverageTPS/lt.config.TargetTPS*100)
	}
	
	if lt.results.ErrorRate < 1.0 {
		fmt.Println("✅ Error rate within acceptable limits!")
	} else {
		fmt.Println("⚠️  High error rate detected!")
	}
	
	if lt.results.P95ResponseTime < 1*time.Second {
		fmt.Println("✅ Response times within acceptable limits!")
	} else {
		fmt.Println("⚠️  High response times detected!")
	}
}

// Stop stops the load test
func (lt *LoadTester) Stop() {
	lt.cancel()
}

// Global load tester instance
var GlobalLoadTester *LoadTester

// InitializeGlobalLoadTester initializes the global load tester
func InitializeGlobalLoadTester(config *LoadTestConfig) {
	GlobalLoadTester = NewLoadTester(config)
}
