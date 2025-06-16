package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// MetricType represents different types of metrics
type MetricType string

const (
	MetricCounter   MetricType = "counter"
	MetricGauge     MetricType = "gauge"
	MetricHistogram MetricType = "histogram"
	MetricTimer     MetricType = "timer"
)

// AlertLevel represents alert severity levels
type AlertLevel string

const (
	AlertInfo     AlertLevel = "info"
	AlertWarning  AlertLevel = "warning"
	AlertCritical AlertLevel = "critical"
	AlertError    AlertLevel = "error"
)

// Metric represents a single metric measurement
type Metric struct {
	Name      string                 `json:"name"`
	Type      MetricType             `json:"type"`
	Value     float64                `json:"value"`
	Labels    map[string]string      `json:"labels"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// Alert represents a system alert
type Alert struct {
	ID          string                 `json:"id"`
	Level       AlertLevel             `json:"level"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	Timestamp   time.Time              `json:"timestamp"`
	Resolved    bool                   `json:"resolved"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// PerformanceStats represents system performance statistics
type PerformanceStats struct {
	CPUUsage           float64           `json:"cpu_usage"`
	MemoryUsage        float64           `json:"memory_usage"`
	DiskUsage          float64           `json:"disk_usage"`
	NetworkIn          uint64            `json:"network_in"`
	NetworkOut         uint64            `json:"network_out"`
	ActiveConnections  int               `json:"active_connections"`
	TransactionTPS     float64           `json:"transaction_tps"`
	BlockTime          time.Duration     `json:"block_time"`
	PendingTransactions int              `json:"pending_transactions"`
	ValidatorCount     int               `json:"validator_count"`
	CustomMetrics      map[string]float64 `json:"custom_metrics"`
	Timestamp          time.Time         `json:"timestamp"`
}

// AdvancedMonitor provides comprehensive monitoring capabilities
type AdvancedMonitor struct {
	metrics         map[string]*Metric
	alerts          map[string]*Alert
	performanceLog  []*PerformanceStats
	alertHandlers   []AlertHandler
	metricHandlers  []MetricHandler
	logFile         *os.File
	mu              sync.RWMutex
	ctx             context.Context
	cancel          context.CancelFunc
	alertThresholds map[string]float64
	enabled         bool
}

// AlertHandler defines the interface for alert handling
type AlertHandler interface {
	HandleAlert(alert *Alert) error
}

// MetricHandler defines the interface for metric handling
type MetricHandler interface {
	HandleMetric(metric *Metric) error
}

// ConsoleAlertHandler logs alerts to console
type ConsoleAlertHandler struct{}

func (h *ConsoleAlertHandler) HandleAlert(alert *Alert) error {
	levelEmoji := map[AlertLevel]string{
		AlertInfo:     "ℹ️",
		AlertWarning:  "⚠️",
		AlertCritical: "🚨",
		AlertError:    "❌",
	}
	
	fmt.Printf("%s [%s] %s: %s\n", 
		levelEmoji[alert.Level], 
		alert.Level, 
		alert.Title, 
		alert.Description)
	return nil
}

func (h *ConsoleAlertHandler) HandleMetric(metric *Metric) error {
	fmt.Printf("📊 [%s] %s: %.2f\n", metric.Type, metric.Name, metric.Value)
	return nil
}

// FileLogHandler logs metrics and alerts to file
type FileLogHandler struct {
	logFile *os.File
}

func NewFileLogHandler(filename string) (*FileLogHandler, error) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return &FileLogHandler{logFile: file}, nil
}

func (h *FileLogHandler) HandleAlert(alert *Alert) error {
	data, _ := json.Marshal(alert)
	_, err := h.logFile.WriteString(fmt.Sprintf("ALERT: %s\n", string(data)))
	return err
}

func (h *FileLogHandler) HandleMetric(metric *Metric) error {
	data, _ := json.Marshal(metric)
	_, err := h.logFile.WriteString(fmt.Sprintf("METRIC: %s\n", string(data)))
	return err
}

// NewAdvancedMonitor creates a new advanced monitoring system
func NewAdvancedMonitor() *AdvancedMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	
	monitor := &AdvancedMonitor{
		metrics:         make(map[string]*Metric),
		alerts:          make(map[string]*Alert),
		performanceLog:  make([]*PerformanceStats, 0),
		alertHandlers:   make([]AlertHandler, 0),
		metricHandlers:  make([]MetricHandler, 0),
		ctx:             ctx,
		cancel:          cancel,
		alertThresholds: make(map[string]float64),
		enabled:         true,
	}
	
	// Add default handlers
	monitor.AddAlertHandler(&ConsoleAlertHandler{})
	
	// Set default alert thresholds
	monitor.SetAlertThreshold("cpu_usage", 80.0)
	monitor.SetAlertThreshold("memory_usage", 85.0)
	monitor.SetAlertThreshold("disk_usage", 90.0)
	monitor.SetAlertThreshold("transaction_tps", 1000.0)
	monitor.SetAlertThreshold("block_time_ms", 10000.0)
	
	return monitor
}

// Start begins the monitoring process
func (am *AdvancedMonitor) Start() error {
	if !am.enabled {
		return fmt.Errorf("monitoring is disabled")
	}
	
	// Initialize log file
	logFile, err := os.OpenFile("monitoring.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}
	am.logFile = logFile
	
	// Start background monitoring
	go am.backgroundMonitoring()
	
	fmt.Println("✅ Advanced monitoring system started")
	return nil
}

// Stop stops the monitoring system
func (am *AdvancedMonitor) Stop() error {
	am.cancel()
	if am.logFile != nil {
		am.logFile.Close()
	}
	fmt.Println("🛑 Advanced monitoring system stopped")
	return nil
}

// RecordMetric records a new metric
func (am *AdvancedMonitor) RecordMetric(name string, metricType MetricType, value float64, labels map[string]string) {
	if !am.enabled {
		return
	}
	
	am.mu.Lock()
	defer am.mu.Unlock()
	
	metric := &Metric{
		Name:      name,
		Type:      metricType,
		Value:     value,
		Labels:    labels,
		Timestamp: time.Now(),
	}
	
	am.metrics[name] = metric
	
	// Handle metric with all handlers
	for _, handler := range am.metricHandlers {
		if err := handler.HandleMetric(metric); err != nil {
			log.Printf("Error handling metric: %v", err)
		}
	}
	
	// Check for alert conditions
	am.checkAlertConditions(name, value)
}

// TriggerAlert triggers a new alert
func (am *AdvancedMonitor) TriggerAlert(level AlertLevel, title, description, source string, metadata map[string]interface{}) {
	if !am.enabled {
		return
	}
	
	am.mu.Lock()
	defer am.mu.Unlock()
	
	alertID := fmt.Sprintf("%s_%d", source, time.Now().Unix())
	alert := &Alert{
		ID:          alertID,
		Level:       level,
		Title:       title,
		Description: description,
		Source:      source,
		Timestamp:   time.Now(),
		Resolved:    false,
		Metadata:    metadata,
	}
	
	am.alerts[alertID] = alert
	
	// Handle alert with all handlers
	for _, handler := range am.alertHandlers {
		if err := handler.HandleAlert(alert); err != nil {
			log.Printf("Error handling alert: %v", err)
		}
	}
}

// AddAlertHandler adds a new alert handler
func (am *AdvancedMonitor) AddAlertHandler(handler AlertHandler) {
	am.alertHandlers = append(am.alertHandlers, handler)
}

// AddMetricHandler adds a new metric handler
func (am *AdvancedMonitor) AddMetricHandler(handler MetricHandler) {
	am.metricHandlers = append(am.metricHandlers, handler)
}

// SetAlertThreshold sets an alert threshold for a metric
func (am *AdvancedMonitor) SetAlertThreshold(metricName string, threshold float64) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.alertThresholds[metricName] = threshold
}

// checkAlertConditions checks if any alert conditions are met
func (am *AdvancedMonitor) checkAlertConditions(metricName string, value float64) {
	if threshold, exists := am.alertThresholds[metricName]; exists {
		if value > threshold {
			am.TriggerAlert(
				AlertWarning,
				fmt.Sprintf("High %s", metricName),
				fmt.Sprintf("%s is %.2f, exceeding threshold of %.2f", metricName, value, threshold),
				"monitoring_system",
				map[string]interface{}{
					"metric_name": metricName,
					"value":       value,
					"threshold":   threshold,
				},
			)
		}
	}
}

// backgroundMonitoring runs continuous monitoring tasks
func (am *AdvancedMonitor) backgroundMonitoring() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-am.ctx.Done():
			return
		case <-ticker.C:
			am.collectSystemMetrics()
			am.cleanupOldData()
		}
	}
}

// collectSystemMetrics collects system performance metrics
func (am *AdvancedMonitor) collectSystemMetrics() {
	// Mock system metrics collection - replace with actual system monitoring
	stats := &PerformanceStats{
		CPUUsage:            float64(time.Now().Unix()%100) / 100.0 * 50, // Mock CPU usage
		MemoryUsage:         float64(time.Now().Unix()%100) / 100.0 * 60, // Mock memory usage
		DiskUsage:           float64(time.Now().Unix()%100) / 100.0 * 30, // Mock disk usage
		NetworkIn:           uint64(time.Now().Unix() % 1000000),
		NetworkOut:          uint64(time.Now().Unix() % 1000000),
		ActiveConnections:   int(time.Now().Unix() % 100),
		TransactionTPS:      float64(time.Now().Unix()%1000) / 10.0,
		BlockTime:           time.Duration(6) * time.Second,
		PendingTransactions: int(time.Now().Unix() % 50),
		ValidatorCount:      3,
		CustomMetrics:       make(map[string]float64),
		Timestamp:           time.Now(),
	}
	
	am.mu.Lock()
	am.performanceLog = append(am.performanceLog, stats)
	am.mu.Unlock()
	
	// Record individual metrics
	am.RecordMetric("cpu_usage", MetricGauge, stats.CPUUsage, nil)
	am.RecordMetric("memory_usage", MetricGauge, stats.MemoryUsage, nil)
	am.RecordMetric("disk_usage", MetricGauge, stats.DiskUsage, nil)
	am.RecordMetric("transaction_tps", MetricGauge, stats.TransactionTPS, nil)
	am.RecordMetric("block_time_ms", MetricGauge, float64(stats.BlockTime.Milliseconds()), nil)
}

// cleanupOldData removes old metrics and alerts
func (am *AdvancedMonitor) cleanupOldData() {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	// Keep only last 1000 performance stats
	if len(am.performanceLog) > 1000 {
		am.performanceLog = am.performanceLog[len(am.performanceLog)-1000:]
	}
	
	// Remove resolved alerts older than 24 hours
	cutoff := time.Now().Add(-24 * time.Hour)
	for id, alert := range am.alerts {
		if alert.Resolved && alert.Timestamp.Before(cutoff) {
			delete(am.alerts, id)
		}
	}
}

// GetMetrics returns current metrics
func (am *AdvancedMonitor) GetMetrics() map[string]*Metric {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	result := make(map[string]*Metric)
	for k, v := range am.metrics {
		result[k] = v
	}
	return result
}

// GetAlerts returns current alerts
func (am *AdvancedMonitor) GetAlerts() map[string]*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	result := make(map[string]*Alert)
	for k, v := range am.alerts {
		result[k] = v
	}
	return result
}

// GetPerformanceStats returns recent performance statistics
func (am *AdvancedMonitor) GetPerformanceStats(limit int) []*PerformanceStats {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	if limit <= 0 || limit > len(am.performanceLog) {
		limit = len(am.performanceLog)
	}
	
	start := len(am.performanceLog) - limit
	result := make([]*PerformanceStats, limit)
	copy(result, am.performanceLog[start:])
	return result
}

// Global monitoring instance
var GlobalMonitor *AdvancedMonitor

// InitializeGlobalMonitor initializes the global monitoring system
func InitializeGlobalMonitor() error {
	GlobalMonitor = NewAdvancedMonitor()
	return GlobalMonitor.Start()
}
