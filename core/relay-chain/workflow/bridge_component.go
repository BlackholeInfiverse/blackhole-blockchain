package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

// BridgeComponentImpl implements the BridgeComponent interface
type BridgeComponentImpl struct {
	name         string
	version      string
	blockchain   *chain.Blockchain
	status       ComponentStatus
	mutex        sync.RWMutex
	bridgeSDK    *BridgeSDKProcess
	config       map[string]interface{}
	metrics      map[string]interface{}
	startedAt    *time.Time
	errorCount   int
	lastError    string
}

// BridgeSDKProcess manages the external bridge SDK process
type BridgeSDKProcess struct {
	cmd       *exec.Cmd
	running   bool
	port      int
	mutex     sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewBridgeComponent creates a new bridge component
func NewBridgeComponent(blockchain *chain.Blockchain) *BridgeComponentImpl {
	return &BridgeComponentImpl{
		name:       "bridge",
		version:    "1.0.0",
		blockchain: blockchain,
		status: ComponentStatus{
			Name:         "bridge",
			Version:      "1.0.0",
			Status:       "stopped",
			Healthy:      false,
			LastUpdate:   time.Now(),
			Metrics:      make(map[string]interface{}),
			ErrorCount:   0,
			Dependencies: []string{"blockchain"},
		},
		metrics: make(map[string]interface{}),
	}
}

// GetName returns the component name
func (b *BridgeComponentImpl) GetName() string {
	return b.name
}

// GetVersion returns the component version
func (b *BridgeComponentImpl) GetVersion() string {
	return b.version
}

// Initialize sets up the bridge component
func (b *BridgeComponentImpl) Initialize(ctx context.Context, config map[string]interface{}) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	b.config = config
	b.status.Status = "initializing"
	b.status.LastUpdate = time.Now()

	// Set default configuration
	if b.config == nil {
		b.config = make(map[string]interface{})
	}

	// Set default bridge SDK port
	if _, exists := b.config["bridge_port"]; !exists {
		b.config["bridge_port"] = 8084
	}

	// Set default auto-start
	if _, exists := b.config["auto_start"]; !exists {
		b.config["auto_start"] = true
	}

	b.status.Status = "initialized"
	b.status.LastUpdate = time.Now()

	return nil
}

// Start begins the bridge component operations
func (b *BridgeComponentImpl) Start(ctx context.Context) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if b.status.Status == "running" {
		return fmt.Errorf("bridge component is already running")
	}

	b.status.Status = "starting"
	b.status.LastUpdate = time.Now()

	// Check if auto-start is enabled
	autoStart, ok := b.config["auto_start"].(bool)
	if !ok {
		autoStart = true
	}

	if autoStart {
		// Start the bridge SDK process
		if err := b.startBridgeSDK(ctx); err != nil {
			b.status.Status = "error"
			b.status.LastUpdate = time.Now()
			b.errorCount++
			b.lastError = err.Error()
			return fmt.Errorf("failed to start bridge SDK: %v", err)
		}
	}

	now := time.Now()
	b.startedAt = &now
	b.status.Status = "running"
	b.status.Healthy = true
	b.status.StartedAt = &now
	b.status.LastUpdate = time.Now()

	// Start metrics collection
	go b.collectMetrics(ctx)

	return nil
}

// Stop gracefully shuts down the bridge component
func (b *BridgeComponentImpl) Stop(ctx context.Context) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if b.status.Status == "stopped" {
		return nil
	}

	b.status.Status = "stopping"
	b.status.LastUpdate = time.Now()

	// Stop the bridge SDK process
	if b.bridgeSDK != nil {
		if err := b.stopBridgeSDK(); err != nil {
			b.errorCount++
			b.lastError = err.Error()
			// Continue with shutdown even if there's an error
		}
	}

	b.status.Status = "stopped"
	b.status.Healthy = false
	b.status.LastUpdate = time.Now()
	b.startedAt = nil

	return nil
}

// IsHealthy returns the health status
func (b *BridgeComponentImpl) IsHealthy() bool {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	if b.status.Status != "running" {
		return false
	}

	// Check if bridge SDK process is running and healthy
	if b.bridgeSDK != nil && !b.isBridgeSDKHealthy() {
		return false
	}

	return b.status.Healthy
}

// GetMetrics returns current metrics
func (b *BridgeComponentImpl) GetMetrics() map[string]interface{} {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	// Create a copy of metrics
	metrics := make(map[string]interface{})
	for k, v := range b.metrics {
		metrics[k] = v
	}

	return metrics
}

// GetStatus returns the current status
func (b *BridgeComponentImpl) GetStatus() ComponentStatus {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	status := b.status
	status.Metrics = b.GetMetrics()
	status.ErrorCount = b.errorCount
	status.LastError = b.lastError

	return status
}

// startBridgeSDK starts the bridge SDK as an external process
func (b *BridgeComponentImpl) startBridgeSDK(ctx context.Context) error {
	port, ok := b.config["bridge_port"].(int)
	if !ok {
		port = 8084
	}

	// Create context for the bridge SDK process
	bridgeCtx, cancel := context.WithCancel(ctx)

	// Determine the bridge SDK executable path
	bridgeSDKPath := "./bridge-sdk/example/main.go"
	if _, err := os.Stat(bridgeSDKPath); os.IsNotExist(err) {
		// Try alternative paths
		bridgeSDKPath = "../bridge-sdk/example/main.go"
		if _, err := os.Stat(bridgeSDKPath); os.IsNotExist(err) {
			bridgeSDKPath = "../../bridge-sdk/example/main.go"
			if _, err := os.Stat(bridgeSDKPath); os.IsNotExist(err) {
				bridgeSDKPath = "../../../bridge-sdk/example/main.go"
				if _, err := os.Stat(bridgeSDKPath); os.IsNotExist(err) {
					bridgeSDKPath = "../../../../bridge-sdk/example/main.go"
				}
			}
		}
	}

	// Log the bridge SDK path being used
	fmt.Printf("🔗 Starting bridge SDK from path: %s\n", bridgeSDKPath)

	// Kill any existing processes on the port first
	fmt.Printf("🧹 Checking for existing processes on port %d\n", port)
	killCmd := exec.Command("powershell", "-Command", fmt.Sprintf("Get-Process | Where-Object {$_.ProcessName -eq 'go'} | Stop-Process -Force"))
	killCmd.Run() // Ignore errors

	// Wait a moment for cleanup
	time.Sleep(2 * time.Second)

	// Create the command to run the bridge SDK
	cmd := exec.CommandContext(bridgeCtx, "go", "run", bridgeSDKPath)

	// Set environment variables for the bridge SDK
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("SERVER_PORT=%d", port),
		"BRIDGE_EMBEDDED=true",
		"BRIDGE_PARENT_PID="+fmt.Sprintf("%d", os.Getpid()),
		"LOG_LEVEL=info",
		"BLACKHOLE_ENDPOINT=http://localhost:8080",
		"DOCKER_MODE=false",
	)

	// Set working directory to the bridge SDK directory
	bridgeDir := filepath.Dir(bridgeSDKPath)
	cmd.Dir = bridgeDir

	fmt.Printf("🔗 Bridge SDK command: go run %s (port: %d)\n", bridgeSDKPath, port)
	fmt.Printf("🔗 Bridge SDK working directory: %s\n", bridgeDir)

	// Start the process
	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("failed to start bridge SDK process: %v", err)
	}

	fmt.Printf("🚀 Bridge SDK process started with PID: %d\n", cmd.Process.Pid)

	b.bridgeSDK = &BridgeSDKProcess{
		cmd:     cmd,
		running: true,
		port:    port,
		ctx:     bridgeCtx,
		cancel:  cancel,
	}

	// Monitor the process
	go b.monitorBridgeSDK()

	// Wait for the bridge SDK to be ready
	if err := b.waitForBridgeSDK(port, 30*time.Second); err != nil {
		b.stopBridgeSDK()
		return fmt.Errorf("bridge SDK failed to start: %v", err)
	}

	return nil
}

// stopBridgeSDK stops the bridge SDK process
func (b *BridgeComponentImpl) stopBridgeSDK() error {
	if b.bridgeSDK == nil {
		return nil
	}

	b.bridgeSDK.mutex.Lock()
	defer b.bridgeSDK.mutex.Unlock()

	if !b.bridgeSDK.running {
		return nil
	}

	// Cancel the context to signal shutdown
	b.bridgeSDK.cancel()

	// Give the process time to shutdown gracefully
	done := make(chan error, 1)
	go func() {
		done <- b.bridgeSDK.cmd.Wait()
	}()

	select {
	case <-time.After(10 * time.Second):
		// Force kill if graceful shutdown takes too long
		if err := b.bridgeSDK.cmd.Process.Kill(); err != nil {
			return fmt.Errorf("failed to kill bridge SDK process: %v", err)
		}
	case err := <-done:
		if err != nil && err.Error() != "signal: killed" {
			return fmt.Errorf("bridge SDK process exited with error: %v", err)
		}
	}

	b.bridgeSDK.running = false
	return nil
}

// monitorBridgeSDK monitors the bridge SDK process
func (b *BridgeComponentImpl) monitorBridgeSDK() {
	if b.bridgeSDK == nil {
		return
	}

	// Wait for the process to exit
	err := b.bridgeSDK.cmd.Wait()

	b.bridgeSDK.mutex.Lock()
	b.bridgeSDK.running = false
	b.bridgeSDK.mutex.Unlock()

	b.mutex.Lock()
	if err != nil && b.status.Status == "running" {
		b.status.Healthy = false
		b.errorCount++
		b.lastError = fmt.Sprintf("bridge SDK process exited: %v", err)
	}
	b.mutex.Unlock()
}

// waitForBridgeSDK waits for the bridge SDK to be ready
func (b *BridgeComponentImpl) waitForBridgeSDK(port int, timeout time.Duration) error {
	fmt.Printf("⏳ Waiting for bridge SDK to be ready on port %d (timeout: %v)\n", port, timeout)

	start := time.Now()
	attempts := 0
	for time.Since(start) < timeout {
		attempts++
		// Try to connect to the bridge SDK health endpoint
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get(fmt.Sprintf("http://localhost:%d/health", port))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				fmt.Printf("✅ Bridge SDK is ready on port %d after %d attempts\n", port, attempts)
				return nil // Bridge SDK is responding
			}
		}

		// Also try the root endpoint as fallback
		resp2, err2 := client.Get(fmt.Sprintf("http://localhost:%d/", port))
		if err2 == nil {
			resp2.Body.Close()
			if resp2.StatusCode == http.StatusOK {
				fmt.Printf("✅ Bridge SDK is ready on port %d (root endpoint) after %d attempts\n", port, attempts)
				return nil // Bridge SDK is responding
			}
		}

		if attempts%3 == 0 {
			fmt.Printf("🔄 Still waiting for bridge SDK (attempt %d, elapsed: %v)\n", attempts, time.Since(start))
		}

		// Wait before retrying
		time.Sleep(2 * time.Second)
	}

	fmt.Printf("❌ Bridge SDK did not become ready within %v after %d attempts\n", timeout, attempts)
	return fmt.Errorf("bridge SDK did not become ready within %v", timeout)
}

// isBridgeSDKHealthy checks if the bridge SDK is healthy by testing its health endpoint
func (b *BridgeComponentImpl) isBridgeSDKHealthy() bool {
	if b.bridgeSDK == nil {
		return false
	}

	// Test the bridge SDK health endpoint
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://localhost:%d/health", b.bridgeSDK.port))
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	// Parse the response to check if it's actually healthy
	var healthResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&healthResponse); err != nil {
		return false
	}

	// Check if the response indicates the bridge is healthy
	if data, ok := healthResponse["data"].(map[string]interface{}); ok {
		if healthy, ok := data["healthy"].(bool); ok {
			return healthy
		}
	}

	// Fallback: if we got a 200 response, consider it healthy
	return true
}

// collectMetrics collects metrics from the bridge SDK
func (b *BridgeComponentImpl) collectMetrics(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.updateMetrics()
		}
	}
}

// updateMetrics updates the component metrics
func (b *BridgeComponentImpl) updateMetrics() {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	now := time.Now()
	uptime := time.Duration(0)
	if b.startedAt != nil {
		uptime = now.Sub(*b.startedAt)
	}

	// Check if bridge SDK is actually running by testing health endpoint
	bridgeRunning := b.isBridgeSDKHealthy()

	b.metrics = map[string]interface{}{
		"uptime_seconds":    uptime.Seconds(),
		"error_count":       b.errorCount,
		"last_update":       now.Format(time.RFC3339),
		"bridge_sdk_running": bridgeRunning,
		"bridge_port":       b.config["bridge_port"],
	}

	b.status.Metrics = b.metrics
	b.status.LastUpdate = now
}

// Bridge-specific methods implementing BridgeComponent interface

// BridgeTokens initiates a cross-chain token transfer
func (b *BridgeComponentImpl) BridgeTokens(ctx context.Context, fromChain, toChain, tokenSymbol string, amount uint64, toAddress string) error {
	// This would make an API call to the bridge SDK
	// For now, return a placeholder implementation
	return fmt.Errorf("bridge tokens functionality will be implemented via API calls to bridge SDK")
}

// GetBridgeStatus returns the status of a bridge transaction
func (b *BridgeComponentImpl) GetBridgeStatus(transactionID string) (BridgeStatus, error) {
	// This would make an API call to the bridge SDK
	return BridgeStatus{}, fmt.Errorf("get bridge status functionality will be implemented via API calls to bridge SDK")
}

// GetSupportedChains returns supported blockchain networks
func (b *BridgeComponentImpl) GetSupportedChains() []ChainInfo {
	// Return default supported chains
	return []ChainInfo{
		{ID: "ethereum", Name: "Ethereum", Symbol: "ETH", Supported: true, MinConfirms: 12},
		{ID: "solana", Name: "Solana", Symbol: "SOL", Supported: true, MinConfirms: 32},
		{ID: "blackhole", Name: "BlackHole", Symbol: "BHX", Supported: true, MinConfirms: 6},
	}
}

// GetBridgeHistory returns bridge transaction history
func (b *BridgeComponentImpl) GetBridgeHistory(address string, limit int) ([]BridgeRecord, error) {
	// This would make an API call to the bridge SDK
	return []BridgeRecord{}, fmt.Errorf("get bridge history functionality will be implemented via API calls to bridge SDK")
}

// GetBridgeSDKPort returns the port the bridge SDK is running on
func (b *BridgeComponentImpl) GetBridgeSDKPort() int {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	if port, ok := b.config["bridge_port"].(int); ok {
		return port
	}
	return 8084
}

// IsBridgeSDKRunning returns true if the bridge SDK process is running and healthy
func (b *BridgeComponentImpl) IsBridgeSDKRunning() bool {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	// Use the health check method instead of just checking the running flag
	return b.isBridgeSDKHealthy()
}
