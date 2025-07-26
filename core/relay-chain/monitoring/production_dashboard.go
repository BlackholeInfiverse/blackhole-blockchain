package monitoring

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

// ProductionDashboard provides real-time monitoring for production deployment
type ProductionDashboard struct {
	blockchain      *chain.Blockchain
	server          *http.Server
	metrics         *ProductionMetrics
	alerts          *AlertManager
	mu              sync.RWMutex
	isRunning       bool
	updateInterval  time.Duration
}

// ProductionMetrics holds comprehensive system metrics
type ProductionMetrics struct {
	// System Health
	SystemStatus        string    `json:"system_status"`
	Uptime             time.Duration `json:"uptime"`
	LastUpdated        time.Time `json:"last_updated"`
	
	// Blockchain Metrics
	BlockHeight        int       `json:"block_height"`
	TotalTransactions  int64     `json:"total_transactions"`
	PendingTxs         int       `json:"pending_txs"`
	BlockTime          float64   `json:"avg_block_time_seconds"`
	TPS                float64   `json:"transactions_per_second"`
	
	// Token Metrics
	TotalSupply        uint64    `json:"total_supply"`
	CirculatingSupply  uint64    `json:"circulating_supply"`
	TokenHolders       int       `json:"token_holders"`
	
	// Network Metrics
	ConnectedPeers     int       `json:"connected_peers"`
	NetworkLatency     float64   `json:"network_latency_ms"`
	SyncStatus         string    `json:"sync_status"`
	
	// Performance Metrics
	CPUUsage           float64   `json:"cpu_usage_percent"`
	MemoryUsage        float64   `json:"memory_usage_mb"`
	DiskUsage          float64   `json:"disk_usage_mb"`
	
	// Economic Metrics
	InflationRate      float64   `json:"inflation_rate"`
	StakingRatio       float64   `json:"staking_ratio"`
	TotalStaked        uint64    `json:"total_staked"`
	
	// Error Metrics
	ErrorRate          float64   `json:"error_rate_percent"`
	FailedTxs          int64     `json:"failed_transactions"`
	SystemErrors       int       `json:"system_errors"`
	
	// Recent Activity
	RecentBlocks       []BlockSummary `json:"recent_blocks"`
	RecentTransactions []TxSummary    `json:"recent_transactions"`
	ActiveAlerts       []Alert        `json:"active_alerts"`
}

// BlockSummary provides summary information for recent blocks
type BlockSummary struct {
	Height      uint64    `json:"height"`
	Hash        string    `json:"hash"`
	Validator   string    `json:"validator"`
	TxCount     int       `json:"tx_count"`
	Timestamp   time.Time `json:"timestamp"`
	Size        int       `json:"size_bytes"`
}

// TxSummary provides summary information for recent transactions
type TxSummary struct {
	Hash      string    `json:"hash"`
	Type      string    `json:"type"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	Amount    uint64    `json:"amount"`
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

// AlertManager handles system alerts and notifications
type AlertManager struct {
	alerts          []Alert
	thresholds      AlertThresholds
	mu              sync.RWMutex
	notificationCh  chan Alert
}

// AlertThresholds defines when to trigger alerts
type AlertThresholds struct {
	HighCPUUsage        float64 `json:"high_cpu_usage"`        // 80%
	HighMemoryUsage     float64 `json:"high_memory_usage"`     // 85%
	HighErrorRate       float64 `json:"high_error_rate"`       // 5%
	LowPeerCount        int     `json:"low_peer_count"`        // 3
	HighBlockTime       float64 `json:"high_block_time"`       // 30 seconds
	LowStakingRatio     float64 `json:"low_staking_ratio"`     // 50%
	HighInflationRate   float64 `json:"high_inflation_rate"`   // 15%
}

// NewProductionDashboard creates a new production monitoring dashboard
func NewProductionDashboard(blockchain *chain.Blockchain, port int) *ProductionDashboard {
	alertMgr := &AlertManager{
		alerts: make([]Alert, 0),
		thresholds: AlertThresholds{
			HighCPUUsage:      80.0,
			HighMemoryUsage:   85.0,
			HighErrorRate:     5.0,
			LowPeerCount:      3,
			HighBlockTime:     30.0,
			LowStakingRatio:   50.0,
			HighInflationRate: 15.0,
		},
		notificationCh: make(chan Alert, 100),
	}

	dashboard := &ProductionDashboard{
		blockchain:     blockchain,
		metrics:        &ProductionMetrics{},
		alerts:         alertMgr,
		updateInterval: 5 * time.Second,
	}

	// Setup HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/", dashboard.handleDashboard)
	mux.HandleFunc("/api/metrics", dashboard.handleMetricsAPI)
	mux.HandleFunc("/api/health", dashboard.handleHealthCheck)
	mux.HandleFunc("/api/alerts", dashboard.handleAlertsAPI)
	mux.HandleFunc("/static/", dashboard.handleStatic)

	dashboard.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	return dashboard
}

// Start begins the production dashboard
func (pd *ProductionDashboard) Start() error {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	if pd.isRunning {
		return fmt.Errorf("dashboard is already running")
	}

	// Start metrics collection
	go pd.metricsCollectionLoop()
	
	// Start alert monitoring
	go pd.alertMonitoringLoop()

	// Start HTTP server
	go func() {
		log.Printf("🖥️ Production dashboard starting on %s", pd.server.Addr)
		if err := pd.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("❌ Dashboard server error: %v", err)
		}
	}()

	pd.isRunning = true
	log.Printf("✅ Production dashboard started successfully")
	return nil
}

// Stop stops the production dashboard
func (pd *ProductionDashboard) Stop() error {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	if !pd.isRunning {
		return fmt.Errorf("dashboard is not running")
	}

	// Stop HTTP server
	if err := pd.server.Close(); err != nil {
		return fmt.Errorf("failed to stop dashboard server: %v", err)
	}

	pd.isRunning = false
	log.Printf("🛑 Production dashboard stopped")
	return nil
}

// metricsCollectionLoop continuously collects system metrics
func (pd *ProductionDashboard) metricsCollectionLoop() {
	ticker := time.NewTicker(pd.updateInterval)
	defer ticker.Stop()

	startTime := time.Now()

	for range ticker.C {
		pd.mu.Lock()
		pd.collectMetrics(startTime)
		pd.mu.Unlock()
	}
}

// collectMetrics gathers current system metrics
func (pd *ProductionDashboard) collectMetrics(startTime time.Time) {
	pd.metrics.LastUpdated = time.Now()
	pd.metrics.Uptime = time.Since(startTime)

	// Blockchain metrics
	pd.metrics.BlockHeight = len(pd.blockchain.Blocks)
	pd.metrics.PendingTxs = len(pd.blockchain.PendingTxs)
	pd.metrics.SyncStatus = "synced" // Simplified

	// Calculate TPS (transactions in last 60 seconds)
	pd.metrics.TPS = pd.calculateTPS()

	// Token metrics
	if bhxToken, exists := pd.blockchain.TokenRegistry["BHX"]; exists {
		pd.metrics.TotalSupply = bhxToken.TotalSupply()
		pd.metrics.CirculatingSupply = bhxToken.TotalSupply() // Simplified
	}

	// Network metrics (simplified)
	pd.metrics.ConnectedPeers = 5 // Mock value
	pd.metrics.NetworkLatency = 50.0 // Mock value

	// Economic metrics
	if pd.blockchain.RewardInflationMgr != nil {
		stats := pd.blockchain.RewardInflationMgr.GetInflationStats()
		pd.metrics.InflationRate = stats["current_inflation_rate"].(float64)
		pd.metrics.StakingRatio = stats["current_staking_ratio"].(float64)
		pd.metrics.TotalStaked = stats["total_staked"].(uint64)
	}

	// System metrics (mock values for demonstration)
	pd.metrics.CPUUsage = 45.0 + (float64(time.Now().Unix()%20) - 10) // Simulate 35-55%
	pd.metrics.MemoryUsage = 512.0 + float64(time.Now().Unix()%100)   // Simulate 512-612MB
	pd.metrics.DiskUsage = 1024.0 + float64(time.Now().Unix()%500)    // Simulate growth

	// Error metrics
	pd.metrics.ErrorRate = 0.5 // Mock low error rate
	pd.metrics.SystemErrors = 0

	// Recent activity
	pd.metrics.RecentBlocks = pd.getRecentBlocks(5)
	pd.metrics.RecentTransactions = pd.getRecentTransactions(10)

	// System status
	pd.metrics.SystemStatus = pd.determineSystemStatus()
}

// calculateTPS calculates transactions per second
func (pd *ProductionDashboard) calculateTPS() float64 {
	// Simplified TPS calculation
	if len(pd.blockchain.Blocks) < 2 {
		return 0.0
	}

	// Get last few blocks and calculate average
	recentBlocks := pd.blockchain.Blocks
	if len(recentBlocks) > 10 {
		recentBlocks = recentBlocks[len(recentBlocks)-10:]
	}

	totalTxs := 0
	for _, block := range recentBlocks {
		totalTxs += len(block.Transactions)
	}

	if len(recentBlocks) > 1 {
		timeSpan := recentBlocks[len(recentBlocks)-1].Header.Timestamp.Sub(recentBlocks[0].Header.Timestamp)
		if timeSpan.Seconds() > 0 {
			return float64(totalTxs) / timeSpan.Seconds()
		}
	}

	return 0.0
}

// getRecentBlocks returns summary of recent blocks
func (pd *ProductionDashboard) getRecentBlocks(count int) []BlockSummary {
	blocks := make([]BlockSummary, 0, count)
	
	start := len(pd.blockchain.Blocks) - count
	if start < 0 {
		start = 0
	}

	for i := start; i < len(pd.blockchain.Blocks); i++ {
		block := pd.blockchain.Blocks[i]
		summary := BlockSummary{
			Height:    block.Header.Index,
			Hash:      block.Hash[:16] + "...", // Truncate for display
			Validator: block.Header.Validator,
			TxCount:   len(block.Transactions),
			Timestamp: block.Header.Timestamp,
			Size:      len(block.Hash) * 64, // Rough estimate
		}
		blocks = append(blocks, summary)
	}

	return blocks
}

// getRecentTransactions returns summary of recent transactions
func (pd *ProductionDashboard) getRecentTransactions(count int) []TxSummary {
	transactions := make([]TxSummary, 0, count)
	
	// Get transactions from recent blocks
	blockCount := 0
	for i := len(pd.blockchain.Blocks) - 1; i >= 0 && blockCount < 3; i-- {
		block := pd.blockchain.Blocks[i]
		for j := len(block.Transactions) - 1; j >= 0 && len(transactions) < count; j-- {
			tx := block.Transactions[j]
			summary := TxSummary{
				Hash:      tx.ID[:16] + "...",
				Type:      pd.transactionTypeToString(tx.Type),
				From:      tx.From,
				To:        tx.To,
				Amount:    tx.Amount,
				Status:    "confirmed",
				Timestamp: time.Unix(tx.Timestamp, 0),
			}
			transactions = append(transactions, summary)
		}
		blockCount++
	}

	return transactions
}

// determineSystemStatus determines overall system health
func (pd *ProductionDashboard) determineSystemStatus() string {
	if pd.metrics.ErrorRate > 10.0 {
		return "critical"
	}
	if pd.metrics.CPUUsage > 90.0 || pd.metrics.ErrorRate > 5.0 {
		return "warning"
	}
	if pd.metrics.ConnectedPeers < 3 {
		return "degraded"
	}
	return "healthy"
}

// alertMonitoringLoop monitors for alert conditions
func (pd *ProductionDashboard) alertMonitoringLoop() {
	ticker := time.NewTicker(30 * time.Second) // Check every 30 seconds
	defer ticker.Stop()

	for range ticker.C {
		pd.checkAlertConditions()
	}
}

// checkAlertConditions checks if any alert thresholds are exceeded
func (pd *ProductionDashboard) checkAlertConditions() {
	pd.mu.RLock()
	metrics := *pd.metrics
	thresholds := pd.alerts.thresholds
	pd.mu.RUnlock()

	// Check CPU usage
	if metrics.CPUUsage > thresholds.HighCPUUsage {
		pd.triggerAlert("high_cpu", AlertCritical, 
			fmt.Sprintf("High CPU usage: %.1f%%", metrics.CPUUsage))
	}

	// Check memory usage
	if metrics.MemoryUsage > thresholds.HighMemoryUsage {
		pd.triggerAlert("high_memory", AlertWarning,
			fmt.Sprintf("High memory usage: %.1f MB", metrics.MemoryUsage))
	}

	// Check error rate
	if metrics.ErrorRate > thresholds.HighErrorRate {
		pd.triggerAlert("high_error_rate", AlertCritical,
			fmt.Sprintf("High error rate: %.1f%%", metrics.ErrorRate))
	}

	// Check peer count
	if metrics.ConnectedPeers < thresholds.LowPeerCount {
		pd.triggerAlert("low_peers", AlertWarning,
			fmt.Sprintf("Low peer count: %d", metrics.ConnectedPeers))
	}

	// Check staking ratio
	if metrics.StakingRatio < thresholds.LowStakingRatio {
		pd.triggerAlert("low_staking", AlertInfo,
			fmt.Sprintf("Low staking ratio: %.1f%%", metrics.StakingRatio))
	}
}

// triggerAlert creates and processes a new alert
func (pd *ProductionDashboard) triggerAlert(alertType string, level AlertLevel, message string) {
	alert := Alert{
		ID:          fmt.Sprintf("%s_%d", alertType, time.Now().Unix()),
		Level:       level,
		Title:       fmt.Sprintf("System Alert: %s", alertType),
		Description: message,
		Source:      "production_dashboard",
		Timestamp:   time.Now(),
	}

	pd.alerts.mu.Lock()
	pd.alerts.alerts = append(pd.alerts.alerts, alert)
	pd.alerts.mu.Unlock()

	// Send to notification channel
	select {
	case pd.alerts.notificationCh <- alert:
	default:
		// Channel full, skip
	}

	log.Printf("🚨 Alert triggered: %s - %s", alert.Title, alert.Description)
}

// HTTP Handlers

// handleDashboard serves the main dashboard HTML page
func (pd *ProductionDashboard) handleDashboard(w http.ResponseWriter, r *http.Request) {
	pd.mu.RLock()
	metrics := *pd.metrics
	pd.mu.RUnlock()

	dashboardHTML := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BlackHole Blockchain - Production Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0a0a; color: #fff; }
        .header { background: linear-gradient(135deg, #1a1a2e, #16213e); padding: 20px; text-align: center; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .status-badge { display: inline-block; padding: 5px 15px; border-radius: 20px; font-weight: bold; }
        .status-healthy { background: #28a745; }
        .status-warning { background: #ffc107; color: #000; }
        .status-critical { background: #dc3545; }
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; padding: 20px; }
        .card { background: #1a1a2e; border-radius: 10px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        .card h3 { color: #4fc3f7; margin-bottom: 15px; border-bottom: 2px solid #4fc3f7; padding-bottom: 5px; }
        .metric { display: flex; justify-content: space-between; margin: 10px 0; }
        .metric-label { color: #ccc; }
        .metric-value { font-weight: bold; color: #fff; }
        .metric-good { color: #28a745; }
        .metric-warning { color: #ffc107; }
        .metric-critical { color: #dc3545; }
        .progress-bar { width: 100%; height: 20px; background: #333; border-radius: 10px; overflow: hidden; margin: 5px 0; }
        .progress-fill { height: 100%; transition: width 0.3s ease; }
        .progress-good { background: linear-gradient(90deg, #28a745, #20c997); }
        .progress-warning { background: linear-gradient(90deg, #ffc107, #fd7e14); }
        .progress-critical { background: linear-gradient(90deg, #dc3545, #e74c3c); }
        .recent-list { max-height: 200px; overflow-y: auto; }
        .recent-item { background: #2a2a3e; margin: 5px 0; padding: 10px; border-radius: 5px; font-size: 0.9em; }
        .auto-refresh { position: fixed; top: 20px; right: 20px; background: #4fc3f7; color: #000; padding: 10px; border-radius: 5px; }
    </style>
    <script>
        function refreshDashboard() {
            fetch('/api/metrics')
                .then(response => response.json())
                .then(data => updateDashboard(data))
                .catch(error => console.error('Error:', error));
        }

        function updateDashboard(metrics) {
            // Update system status
            const statusBadge = document.getElementById('system-status');
            statusBadge.textContent = metrics.system_status.toUpperCase();
            statusBadge.className = 'status-badge status-' + metrics.system_status;

            // Update metrics
            document.getElementById('block-height').textContent = metrics.block_height;
            document.getElementById('total-txs').textContent = metrics.total_transactions.toLocaleString();
            document.getElementById('pending-txs').textContent = metrics.pending_txs;
            document.getElementById('tps').textContent = metrics.transactions_per_second.toFixed(2);
            document.getElementById('total-supply').textContent = (metrics.total_supply / 1000000).toFixed(2) + 'M';
            document.getElementById('inflation-rate').textContent = metrics.inflation_rate.toFixed(2) + '%';
            document.getElementById('staking-ratio').textContent = metrics.staking_ratio.toFixed(1) + '%';
            document.getElementById('connected-peers').textContent = metrics.connected_peers;

            // Update progress bars
            updateProgressBar('cpu-progress', metrics.cpu_usage_percent, 80, 90);
            updateProgressBar('memory-progress', (metrics.memory_usage_mb / 1024) * 100, 70, 85);
            updateProgressBar('staking-progress', metrics.staking_ratio, 50, 30);

            // Update last updated time
            document.getElementById('last-updated').textContent = new Date(metrics.last_updated).toLocaleTimeString();
        }

        function updateProgressBar(id, value, warningThreshold, criticalThreshold) {
            const bar = document.getElementById(id);
            const percentage = Math.min(value, 100);
            bar.style.width = percentage + '%';

            if (value >= criticalThreshold) {
                bar.className = 'progress-fill progress-critical';
            } else if (value >= warningThreshold) {
                bar.className = 'progress-fill progress-warning';
            } else {
                bar.className = 'progress-fill progress-good';
            }
        }

        // Auto-refresh every 5 seconds
        setInterval(refreshDashboard, 5000);

        // Initial load
        window.onload = refreshDashboard;
    </script>
</head>
<body>
    <div class="header">
        <h1>🌌 BlackHole Blockchain</h1>
        <h2>Production Dashboard</h2>
        <span id="system-status" class="status-badge status-{{.SystemStatus}}">{{.SystemStatus | ToUpper}}</span>
    </div>

    <div class="auto-refresh">
        🔄 Auto-refresh: ON<br>
        Last updated: <span id="last-updated">{{.LastUpdated.Format "15:04:05"}}</span>
    </div>

    <div class="dashboard">
        <!-- Blockchain Metrics -->
        <div class="card">
            <h3>📊 Blockchain Metrics</h3>
            <div class="metric">
                <span class="metric-label">Block Height:</span>
                <span class="metric-value" id="block-height">{{.BlockHeight}}</span>
            </div>
            <div class="metric">
                <span class="metric-label">Total Transactions:</span>
                <span class="metric-value" id="total-txs">{{.TotalTransactions}}</span>
            </div>
            <div class="metric">
                <span class="metric-label">Pending Transactions:</span>
                <span class="metric-value" id="pending-txs">{{.PendingTxs}}</span>
            </div>
            <div class="metric">
                <span class="metric-label">TPS (Current):</span>
                <span class="metric-value" id="tps">{{printf "%.2f" .TPS}}</span>
            </div>
        </div>

        <!-- Token Economics -->
        <div class="card">
            <h3>💰 Token Economics</h3>
            <div class="metric">
                <span class="metric-label">Total Supply:</span>
                <span class="metric-value" id="total-supply">{{printf "%.2fM" (div .TotalSupply 1000000)}}</span>
            </div>
            <div class="metric">
                <span class="metric-label">Inflation Rate:</span>
                <span class="metric-value" id="inflation-rate">{{printf "%.2f%%" .InflationRate}}</span>
            </div>
            <div class="metric">
                <span class="metric-label">Staking Ratio:</span>
                <span class="metric-value" id="staking-ratio">{{printf "%.1f%%" .StakingRatio}}</span>
            </div>
            <div class="progress-bar">
                <div id="staking-progress" class="progress-fill progress-good" style="width: {{.StakingRatio}}%"></div>
            </div>
        </div>

        <!-- System Performance -->
        <div class="card">
            <h3>⚡ System Performance</h3>
            <div class="metric">
                <span class="metric-label">CPU Usage:</span>
                <span class="metric-value">{{printf "%.1f%%" .CPUUsage}}</span>
            </div>
            <div class="progress-bar">
                <div id="cpu-progress" class="progress-fill progress-good" style="width: {{.CPUUsage}}%"></div>
            </div>
            <div class="metric">
                <span class="metric-label">Memory Usage:</span>
                <span class="metric-value">{{printf "%.0f MB" .MemoryUsage}}</span>
            </div>
            <div class="progress-bar">
                <div id="memory-progress" class="progress-fill progress-good" style="width: {{div .MemoryUsage 10.24}}%"></div>
            </div>
            <div class="metric">
                <span class="metric-label">Connected Peers:</span>
                <span class="metric-value" id="connected-peers">{{.ConnectedPeers}}</span>
            </div>
        </div>

        <!-- Recent Blocks -->
        <div class="card">
            <h3>🧱 Recent Blocks</h3>
            <div class="recent-list">
                {{range .RecentBlocks}}
                <div class="recent-item">
                    <strong>Block {{.Height}}</strong><br>
                    Hash: {{.Hash}}<br>
                    Validator: {{.Validator}}<br>
                    Transactions: {{.TxCount}}
                </div>
                {{end}}
            </div>
        </div>

        <!-- Recent Transactions -->
        <div class="card">
            <h3>💸 Recent Transactions</h3>
            <div class="recent-list">
                {{range .RecentTransactions}}
                <div class="recent-item">
                    <strong>{{.Type}}</strong><br>
                    {{.From}} → {{.To}}<br>
                    Amount: {{.Amount}} | {{.Status}}
                </div>
                {{end}}
            </div>
        </div>

        <!-- System Status -->
        <div class="card">
            <h3>🔍 System Status</h3>
            <div class="metric">
                <span class="metric-label">Uptime:</span>
                <span class="metric-value">{{.Uptime.Round (time.Second)}}</span>
            </div>
            <div class="metric">
                <span class="metric-label">Sync Status:</span>
                <span class="metric-value metric-good">{{.SyncStatus}}</span>
            </div>
            <div class="metric">
                <span class="metric-label">Error Rate:</span>
                <span class="metric-value {{if gt .ErrorRate 5.0}}metric-critical{{else if gt .ErrorRate 1.0}}metric-warning{{else}}metric-good{{end}}">{{printf "%.2f%%" .ErrorRate}}</span>
            </div>
        </div>
    </div>
</body>
</html>`

	tmpl, err := template.New("dashboard").Funcs(template.FuncMap{
		"ToUpper": func(s string) string { return fmt.Sprintf("%s", s) },
		"div":     func(a, b float64) float64 { return a / b },
	}).Parse(dashboardHTML)

	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	tmpl.Execute(w, metrics)
}

// handleMetricsAPI serves metrics data as JSON
func (pd *ProductionDashboard) handleMetricsAPI(w http.ResponseWriter, r *http.Request) {
	pd.mu.RLock()
	metrics := *pd.metrics
	pd.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// handleHealthCheck provides a simple health check endpoint
func (pd *ProductionDashboard) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	pd.mu.RLock()
	status := pd.metrics.SystemStatus
	pd.mu.RUnlock()

	health := map[string]interface{}{
		"status":    status,
		"timestamp": time.Now(),
		"healthy":   status == "healthy",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// handleAlertsAPI serves active alerts as JSON
func (pd *ProductionDashboard) handleAlertsAPI(w http.ResponseWriter, r *http.Request) {
	pd.alerts.mu.RLock()
	alerts := make([]Alert, len(pd.alerts.alerts))
	copy(alerts, pd.alerts.alerts)
	pd.alerts.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

// handleStatic serves static files (placeholder)
func (pd *ProductionDashboard) handleStatic(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

// transactionTypeToString converts TransactionType to string
func (pd *ProductionDashboard) transactionTypeToString(txType chain.TransactionType) string {
	switch txType {
	case chain.RegularTransfer:
		return "transfer"
	case chain.TokenTransfer:
		return "token_transfer"
	case chain.TokenMint:
		return "mint"
	case chain.TokenBurn:
		return "burn"
	case chain.StakeDeposit:
		return "stake_deposit"
	case chain.StakeWithdraw:
		return "stake_withdraw"
	case chain.SmartContractCall:
		return "contract_call"
	default:
		return "unknown"
	}
}
