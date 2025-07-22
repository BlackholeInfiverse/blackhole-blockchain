package monitoring

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	"github.com/stretchr/testify/assert"
)

func setupTestBlockchainForDashboard(t *testing.T) *chain.Blockchain {
	// Create test blockchain with unique port
	port := 7001 + (int(time.Now().UnixNano()) % 1000)
	blockchain, err := chain.NewBlockchain(port)
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}
	return blockchain
}

func TestProductionDashboard(t *testing.T) {
	blockchain := setupTestBlockchainForDashboard(t)
	defer blockchain.DB.Close()

	dashboard := NewProductionDashboard(blockchain, 8080)
	assert.NotNil(t, dashboard)

	t.Run("Dashboard initialization", func(t *testing.T) {
		assert.NotNil(t, dashboard.blockchain)
		assert.NotNil(t, dashboard.metrics)
		assert.NotNil(t, dashboard.alerts)
		assert.NotNil(t, dashboard.server)
		assert.Equal(t, 5*time.Second, dashboard.updateInterval)
		assert.False(t, dashboard.isRunning)
	})

	t.Run("Metrics collection", func(t *testing.T) {
		startTime := time.Now()
		dashboard.collectMetrics(startTime)

		metrics := dashboard.metrics
		assert.NotZero(t, metrics.LastUpdated)
		assert.Greater(t, metrics.Uptime, time.Duration(0))
		assert.GreaterOrEqual(t, metrics.BlockHeight, 0)
		assert.GreaterOrEqual(t, metrics.PendingTxs, 0)
		assert.GreaterOrEqual(t, metrics.TotalSupply, uint64(0))
		assert.GreaterOrEqual(t, metrics.CPUUsage, 0.0)
		assert.GreaterOrEqual(t, metrics.MemoryUsage, 0.0)
		assert.Contains(t, []string{"healthy", "warning", "critical", "degraded"}, metrics.SystemStatus)
	})

	t.Run("TPS calculation", func(t *testing.T) {
		tps := dashboard.calculateTPS()
		assert.GreaterOrEqual(t, tps, 0.0)
		// TPS should be reasonable (not negative or extremely high)
		assert.LessOrEqual(t, tps, 10000.0)
	})

	t.Run("Recent blocks retrieval", func(t *testing.T) {
		blocks := dashboard.getRecentBlocks(5)
		assert.LessOrEqual(t, len(blocks), 5)
		
		// If we have blocks, verify structure
		for _, block := range blocks {
			assert.GreaterOrEqual(t, block.Height, uint64(0))
			assert.NotEmpty(t, block.Hash)
			assert.GreaterOrEqual(t, block.TxCount, 0)
			assert.NotZero(t, block.Timestamp)
		}
	})

	t.Run("Recent transactions retrieval", func(t *testing.T) {
		txs := dashboard.getRecentTransactions(10)
		assert.LessOrEqual(t, len(txs), 10)
		
		// If we have transactions, verify structure
		for _, tx := range txs {
			assert.NotEmpty(t, tx.Hash)
			assert.NotEmpty(t, tx.Type)
			assert.NotEmpty(t, tx.Status)
			assert.NotZero(t, tx.Timestamp)
		}
	})

	t.Run("System status determination", func(t *testing.T) {
		// Test healthy status
		dashboard.metrics.ErrorRate = 1.0
		dashboard.metrics.CPUUsage = 50.0
		dashboard.metrics.ConnectedPeers = 5
		status := dashboard.determineSystemStatus()
		assert.Equal(t, "healthy", status)

		// Test warning status
		dashboard.metrics.ErrorRate = 7.0
		status = dashboard.determineSystemStatus()
		assert.Equal(t, "warning", status)

		// Test critical status
		dashboard.metrics.ErrorRate = 15.0
		status = dashboard.determineSystemStatus()
		assert.Equal(t, "critical", status)

		// Test degraded status
		dashboard.metrics.ErrorRate = 1.0
		dashboard.metrics.ConnectedPeers = 2
		status = dashboard.determineSystemStatus()
		assert.Equal(t, "degraded", status)
	})
}

func TestProductionDashboardHTTPHandlers(t *testing.T) {
	blockchain := setupTestBlockchainForDashboard(t)
	defer blockchain.DB.Close()

	dashboard := NewProductionDashboard(blockchain, 8080)
	
	// Collect some metrics first
	dashboard.collectMetrics(time.Now())

	t.Run("Health check endpoint", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/health", nil)
		w := httptest.NewRecorder()

		dashboard.handleHealthCheck(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var health map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &health)
		assert.NoError(t, err)
		assert.Contains(t, health, "status")
		assert.Contains(t, health, "timestamp")
		assert.Contains(t, health, "healthy")
	})

	t.Run("Metrics API endpoint", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/metrics", nil)
		w := httptest.NewRecorder()

		dashboard.handleMetricsAPI(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var metrics ProductionMetrics
		err := json.Unmarshal(w.Body.Bytes(), &metrics)
		assert.NoError(t, err)
		assert.NotEmpty(t, metrics.SystemStatus)
		assert.GreaterOrEqual(t, metrics.BlockHeight, 0)
		assert.GreaterOrEqual(t, metrics.TotalSupply, uint64(0))
	})

	t.Run("Alerts API endpoint", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/alerts", nil)
		w := httptest.NewRecorder()

		dashboard.handleAlertsAPI(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var alerts []Alert
		err := json.Unmarshal(w.Body.Bytes(), &alerts)
		assert.NoError(t, err)
		// Should be empty initially
		assert.GreaterOrEqual(t, len(alerts), 0)
	})

	t.Run("Dashboard HTML endpoint", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		dashboard.handleDashboard(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "text/html", w.Header().Get("Content-Type"))
		assert.Contains(t, w.Body.String(), "BlackHole Blockchain")
		assert.Contains(t, w.Body.String(), "Production Dashboard")
		assert.Contains(t, w.Body.String(), "Blockchain Metrics")
	})

	t.Run("Static files endpoint", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/static/test.css", nil)
		w := httptest.NewRecorder()

		dashboard.handleStatic(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestAlertManager(t *testing.T) {
	blockchain := setupTestBlockchainForDashboard(t)
	defer blockchain.DB.Close()

	dashboard := NewProductionDashboard(blockchain, 8080)

	t.Run("Alert thresholds", func(t *testing.T) {
		thresholds := dashboard.alerts.thresholds
		assert.Equal(t, 80.0, thresholds.HighCPUUsage)
		assert.Equal(t, 85.0, thresholds.HighMemoryUsage)
		assert.Equal(t, 5.0, thresholds.HighErrorRate)
		assert.Equal(t, 3, thresholds.LowPeerCount)
		assert.Equal(t, 30.0, thresholds.HighBlockTime)
		assert.Equal(t, 50.0, thresholds.LowStakingRatio)
		assert.Equal(t, 15.0, thresholds.HighInflationRate)
	})

	t.Run("Alert triggering", func(t *testing.T) {
		initialAlertCount := len(dashboard.alerts.alerts)

		// Trigger a high CPU alert
		dashboard.triggerAlert("high_cpu", AlertCritical, "Test high CPU alert")

		dashboard.alerts.mu.RLock()
		alerts := dashboard.alerts.alerts
		dashboard.alerts.mu.RUnlock()

		assert.Len(t, alerts, initialAlertCount+1)
		
		newAlert := alerts[len(alerts)-1]
		assert.Equal(t, AlertCritical, newAlert.Level)
		assert.Contains(t, newAlert.Title, "high_cpu")
		assert.Equal(t, "Test high CPU alert", newAlert.Description)
		assert.NotZero(t, newAlert.Timestamp)
	})

	t.Run("Alert condition checking", func(t *testing.T) {
		// Set metrics that should trigger alerts
		dashboard.metrics.CPUUsage = 95.0  // Above 80% threshold
		dashboard.metrics.ErrorRate = 10.0 // Above 5% threshold
		dashboard.metrics.ConnectedPeers = 2 // Below 3 threshold

		initialAlertCount := len(dashboard.alerts.alerts)
		
		dashboard.checkAlertConditions()

		dashboard.alerts.mu.RLock()
		finalAlertCount := len(dashboard.alerts.alerts)
		dashboard.alerts.mu.RUnlock()

		// Should have triggered multiple alerts
		assert.Greater(t, finalAlertCount, initialAlertCount)
	})
}

func TestProductionDashboardLifecycle(t *testing.T) {
	blockchain := setupTestBlockchainForDashboard(t)
	defer blockchain.DB.Close()

	dashboard := NewProductionDashboard(blockchain, 8081) // Different port

	t.Run("Start and stop dashboard", func(t *testing.T) {
		// Initially not running
		assert.False(t, dashboard.isRunning)

		// Start dashboard
		err := dashboard.Start()
		assert.NoError(t, err)
		assert.True(t, dashboard.isRunning)

		// Give it a moment to start
		time.Sleep(100 * time.Millisecond)

		// Try to start again (should fail)
		err = dashboard.Start()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already running")

		// Stop dashboard
		err = dashboard.Stop()
		assert.NoError(t, err)
		assert.False(t, dashboard.isRunning)

		// Try to stop again (should fail)
		err = dashboard.Stop()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not running")
	})
}

func TestProductionMetricsStructure(t *testing.T) {
	t.Run("ProductionMetrics JSON serialization", func(t *testing.T) {
		metrics := ProductionMetrics{
			SystemStatus:      "healthy",
			Uptime:           time.Hour,
			LastUpdated:      time.Now(),
			BlockHeight:      100,
			TotalTransactions: 1000,
			PendingTxs:       5,
			TPS:              50.5,
			TotalSupply:      1000000,
			ConnectedPeers:   10,
			CPUUsage:         45.5,
			MemoryUsage:      512.0,
			InflationRate:    7.5,
			StakingRatio:     65.0,
			ErrorRate:        1.2,
		}

		data, err := json.Marshal(metrics)
		assert.NoError(t, err)
		assert.NotEmpty(t, data)

		var unmarshaled ProductionMetrics
		err = json.Unmarshal(data, &unmarshaled)
		assert.NoError(t, err)
		assert.Equal(t, metrics.SystemStatus, unmarshaled.SystemStatus)
		assert.Equal(t, metrics.BlockHeight, unmarshaled.BlockHeight)
		assert.Equal(t, metrics.TotalTransactions, unmarshaled.TotalTransactions)
	})

	t.Run("BlockSummary and TxSummary structures", func(t *testing.T) {
		block := BlockSummary{
			Height:    100,
			Hash:      "0xabc123...",
			Validator: "validator1",
			TxCount:   5,
			Timestamp: time.Now(),
			Size:      1024,
		}

		tx := TxSummary{
			Hash:      "0xdef456...",
			Type:      "transfer",
			From:      "user1",
			To:        "user2",
			Amount:    1000,
			Status:    "confirmed",
			Timestamp: time.Now(),
		}

		// Test JSON serialization
		blockData, err := json.Marshal(block)
		assert.NoError(t, err)
		assert.NotEmpty(t, blockData)

		txData, err := json.Marshal(tx)
		assert.NoError(t, err)
		assert.NotEmpty(t, txData)
	})
}
