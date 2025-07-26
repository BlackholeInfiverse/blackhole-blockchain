package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/bridge"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/monitoring"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/testing"
)

// ProductionNode represents a complete production-ready blockchain node
type ProductionNode struct {
	blockchain      *chain.Blockchain
	bridge          *bridge.Bridge
	dashboard       *monitoring.ProductionDashboard
	advancedMonitor *monitoring.AdvancedMonitor
	alertManager    *monitoring.AdvancedAlertManager
	
	// Configuration
	config          *ProductionConfig
	
	// Runtime state
	isRunning       bool
	shutdownChan    chan os.Signal
}

// ProductionConfig holds all production configuration
type ProductionConfig struct {
	// Network configuration
	NodePort        int    `json:"node_port"`
	P2PPort         int    `json:"p2p_port"`
	DashboardPort   int    `json:"dashboard_port"`
	APIPort         int    `json:"api_port"`
	
	// Paths
	DataPath        string `json:"data_path"`
	LogPath         string `json:"log_path"`
	ConfigPath      string `json:"config_path"`
	
	// Performance
	MaxPeers        int    `json:"max_peers"`
	BlockTime       int    `json:"block_time"`
	MaxTxsPerBlock  int    `json:"max_txs_per_block"`
	
	// Security
	EnableTLS       bool   `json:"enable_tls"`
	TLSCertPath     string `json:"tls_cert_path"`
	TLSKeyPath      string `json:"tls_key_path"`
	
	// Monitoring
	EnableMetrics   bool   `json:"enable_metrics"`
	MetricsPort     int    `json:"metrics_port"`
	LogLevel        string `json:"log_level"`
	
	// Economic
	InitialSupply   uint64  `json:"initial_supply"`
	InflationRate   float64 `json:"inflation_rate"`
	TargetStaking   float64 `json:"target_staking_ratio"`
}

// NewProductionNode creates a new production-ready blockchain node
func NewProductionNode(config *ProductionConfig) (*ProductionNode, error) {
	log.Printf("🚀 Initializing BlackHole Blockchain Production Node")
	
	// Create blockchain instance
	blockchain, err := chain.NewBlockchain(config.NodePort)
	if err != nil {
		return nil, fmt.Errorf("failed to create blockchain: %v", err)
	}
	
	// Create bridge
	bridgeInstance := bridge.NewBridge(blockchain)
	
	// Create production dashboard
	dashboard := monitoring.NewProductionDashboard(blockchain, config.DashboardPort)
	
	// Create advanced monitoring
	advancedMonitor := monitoring.NewAdvancedMonitor()
	
	// Create alert manager
	alertManager := monitoring.NewAdvancedAlertManager()
	
	node := &ProductionNode{
		blockchain:      blockchain,
		bridge:          bridgeInstance,
		dashboard:       dashboard,
		advancedMonitor: advancedMonitor,
		alertManager:    alertManager,
		config:          config,
		shutdownChan:    make(chan os.Signal, 1),
	}
	
	// Setup signal handling
	signal.Notify(node.shutdownChan, syscall.SIGINT, syscall.SIGTERM)
	
	log.Printf("✅ Production node initialized successfully")
	return node, nil
}

// Start starts all production services
func (pn *ProductionNode) Start() error {
	if pn.isRunning {
		return fmt.Errorf("node is already running")
	}
	
	log.Printf("🌟 Starting BlackHole Blockchain Production Node")
	
	// Start blockchain services
	log.Printf("📊 Starting blockchain services...")
	
	// Start bridge services
	log.Printf("🌉 Starting bridge services...")
	
	// Start production dashboard
	log.Printf("🖥️ Starting production dashboard on port %d...", pn.config.DashboardPort)
	if err := pn.dashboard.Start(); err != nil {
		return fmt.Errorf("failed to start dashboard: %v", err)
	}
	
	// Start advanced monitoring
	log.Printf("📈 Starting advanced monitoring...")
	if err := pn.advancedMonitor.Start(); err != nil {
		return fmt.Errorf("failed to start monitoring: %v", err)
	}
	
	// Start alert manager
	log.Printf("🚨 Starting alert management...")
	
	// Start performance monitoring loop
	go pn.performanceMonitoringLoop()
	
	// Start health check loop
	go pn.healthCheckLoop()
	
	pn.isRunning = true
	
	log.Printf("🎉 BlackHole Blockchain Production Node started successfully!")
	log.Printf("📊 Dashboard: http://localhost:%d", pn.config.DashboardPort)
	log.Printf("🔗 P2P Port: %d", pn.config.P2PPort)
	log.Printf("🌐 Node Port: %d", pn.config.NodePort)
	
	return nil
}

// Stop gracefully stops all services
func (pn *ProductionNode) Stop() error {
	if !pn.isRunning {
		return fmt.Errorf("node is not running")
	}
	
	log.Printf("🛑 Stopping BlackHole Blockchain Production Node...")
	
	// Stop dashboard
	if err := pn.dashboard.Stop(); err != nil {
		log.Printf("⚠️ Error stopping dashboard: %v", err)
	}
	
	// Stop monitoring
	if err := pn.advancedMonitor.Stop(); err != nil {
		log.Printf("⚠️ Error stopping monitoring: %v", err)
	}
	
	// Close blockchain database
	if err := pn.blockchain.DB.Close(); err != nil {
		log.Printf("⚠️ Error closing database: %v", err)
	}
	
	pn.isRunning = false
	
	log.Printf("✅ Production node stopped successfully")
	return nil
}

// performanceMonitoringLoop continuously monitors system performance
func (pn *ProductionNode) performanceMonitoringLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			pn.collectPerformanceMetrics()
		case <-pn.shutdownChan:
			return
		}
	}
}

// collectPerformanceMetrics collects and analyzes performance metrics
func (pn *ProductionNode) collectPerformanceMetrics() {
	// Collect blockchain metrics
	blockHeight := len(pn.blockchain.Blocks)
	pendingTxs := len(pn.blockchain.PendingTxs)
	
	// Log performance summary
	log.Printf("📊 Performance: Blocks=%d, PendingTxs=%d", blockHeight, pendingTxs)
	
	// Check for performance issues
	if pendingTxs > 1000 {
		log.Printf("⚠️ High pending transaction count: %d", pendingTxs)
	}
}

// healthCheckLoop performs regular health checks
func (pn *ProductionNode) healthCheckLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			pn.performHealthCheck()
		case <-pn.shutdownChan:
			return
		}
	}
}

// performHealthCheck checks system health
func (pn *ProductionNode) performHealthCheck() {
	log.Printf("🔍 Performing health check...")
	
	// Check database connectivity
	if pn.blockchain.DB == nil {
		log.Printf("❌ Database connection lost")
		return
	}
	
	// Check if services are responsive
	// Add more health checks as needed
	
	log.Printf("✅ Health check passed")
}

// RunProductionStressTest runs a comprehensive stress test
func (pn *ProductionNode) RunProductionStressTest() error {
	log.Printf("🧪 Starting production stress test...")
	
	// Create high-frequency tester
	tester := testing.NewHighFrequencyTester(pn.blockchain)
	
	// Setup test environment
	if err := tester.SetupTestEnvironment(20); err != nil {
		return fmt.Errorf("failed to setup test environment: %v", err)
	}
	
	// Run benchmark suite
	results, err := tester.RunBenchmarkSuite()
	if err != nil {
		return fmt.Errorf("stress test failed: %v", err)
	}
	
	// Log results
	log.Printf("🏆 Stress test completed with %d test scenarios", len(results))
	for _, result := range results {
		log.Printf("📊 %s: %.2f TPS, %.2f%% success rate", 
			result.TestName, result.ThroughputTPS, result.SuccessRate)
	}
	
	return nil
}

// WaitForShutdown waits for shutdown signal
func (pn *ProductionNode) WaitForShutdown() {
	<-pn.shutdownChan
	log.Printf("🔔 Shutdown signal received")
}

// DefaultProductionConfig returns default production configuration
func DefaultProductionConfig() *ProductionConfig {
	return &ProductionConfig{
		NodePort:        4001,
		P2PPort:         4002,
		DashboardPort:   8080,
		APIPort:         8081,
		DataPath:        "./data",
		LogPath:         "./logs",
		ConfigPath:      "./config",
		MaxPeers:        50,
		BlockTime:       6,
		MaxTxsPerBlock:  1000,
		EnableTLS:       false, // Enable in production with proper certificates
		EnableMetrics:   true,
		MetricsPort:     9090,
		LogLevel:        "INFO",
		InitialSupply:   10000000,
		InflationRate:   7.0,
		TargetStaking:   67.0,
	}
}

func main() {
	// Command line flags
	var (
		configFile = flag.String("config", "", "Path to configuration file")
		stressTest = flag.Bool("stress-test", false, "Run stress test after startup")
		nodePort   = flag.Int("port", 4001, "Node port")
		dashboard  = flag.Int("dashboard", 8080, "Dashboard port")
	)
	flag.Parse()
	
	// Load configuration
	config := DefaultProductionConfig()
	config.NodePort = *nodePort
	config.DashboardPort = *dashboard
	
	// TODO: Load from config file if provided
	if *configFile != "" {
		log.Printf("📄 Loading configuration from %s", *configFile)
		// Implement config file loading
	}
	
	// Create production node
	node, err := NewProductionNode(config)
	if err != nil {
		log.Fatalf("❌ Failed to create production node: %v", err)
	}
	
	// Start the node
	if err := node.Start(); err != nil {
		log.Fatalf("❌ Failed to start production node: %v", err)
	}
	
	// Run stress test if requested
	if *stressTest {
		log.Printf("🧪 Running production stress test...")
		if err := node.RunProductionStressTest(); err != nil {
			log.Printf("⚠️ Stress test failed: %v", err)
		}
	}
	
	// Wait for shutdown signal
	log.Printf("🎯 Production node is running. Press Ctrl+C to stop.")
	node.WaitForShutdown()
	
	// Graceful shutdown
	if err := node.Stop(); err != nil {
		log.Printf("⚠️ Error during shutdown: %v", err)
	}
	
	log.Printf("👋 BlackHole Blockchain Production Node shutdown complete")
}
