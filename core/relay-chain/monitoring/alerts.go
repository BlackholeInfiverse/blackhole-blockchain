package monitoring

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ExtendedAlert represents a system alert with additional fields
type ExtendedAlert struct {
	Alert                          // Embed the existing Alert type
	Type        string     `json:"type"`
	Resolved    bool       `json:"resolved"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
}

// AlertRule defines conditions for triggering alerts
type AlertRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Condition   AlertCondition         `json:"condition"`
	Level       AlertLevel             `json:"level"`
	Enabled     bool                   `json:"enabled"`
	Cooldown    time.Duration          `json:"cooldown"`
	LastFired   time.Time              `json:"last_fired"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AlertCondition defines the condition that triggers an alert
type AlertCondition struct {
	Metric    string      `json:"metric"`
	Operator  string      `json:"operator"` // >, <, >=, <=, ==, !=
	Threshold interface{} `json:"threshold"`
	Duration  time.Duration `json:"duration"` // How long condition must persist
}

// AlertNotifier handles alert notifications
type AlertNotifier struct {
	channels []NotificationChannel
	mu       sync.RWMutex
}

// NotificationChannel represents a way to send notifications
type NotificationChannel interface {
	SendNotification(alert Alert) error
	GetChannelType() string
}

// ConsoleNotificationChannel sends notifications to console/logs
type ConsoleNotificationChannel struct{}

// EmailNotificationChannel sends notifications via email (placeholder)
type EmailNotificationChannel struct {
	SMTPServer string
	Recipients []string
}

// WebhookNotificationChannel sends notifications to webhooks
type WebhookNotificationChannel struct {
	URL     string
	Headers map[string]string
}

// AdvancedAlertManager provides comprehensive alert management
type AdvancedAlertManager struct {
	rules           []AlertRule
	activeAlerts    map[string]ExtendedAlert
	alertHistory    []ExtendedAlert
	notifier        *AlertNotifier
	mu              sync.RWMutex
	maxHistorySize  int
	evaluationTicker *time.Ticker
}

// NewAdvancedAlertManager creates a new advanced alert manager
func NewAdvancedAlertManager() *AdvancedAlertManager {
	notifier := &AlertNotifier{
		channels: []NotificationChannel{
			&ConsoleNotificationChannel{},
		},
	}

	manager := &AdvancedAlertManager{
		rules:          make([]AlertRule, 0),
		activeAlerts:   make(map[string]ExtendedAlert),
		alertHistory:   make([]ExtendedAlert, 0),
		notifier:       notifier,
		maxHistorySize: 1000,
	}

	// Add default alert rules
	manager.addDefaultRules()

	return manager
}

// addDefaultRules adds standard alert rules for blockchain monitoring
func (aam *AdvancedAlertManager) addDefaultRules() {
	defaultRules := []AlertRule{
		{
			ID:          "high_cpu_usage",
			Name:        "High CPU Usage",
			Description: "CPU usage is above threshold",
			Condition: AlertCondition{
				Metric:    "cpu_usage_percent",
				Operator:  ">",
				Threshold: 80.0,
				Duration:  2 * time.Minute,
			},
			Level:    AlertCritical,
			Enabled:  true,
			Cooldown: 5 * time.Minute,
		},
		{
			ID:          "high_memory_usage",
			Name:        "High Memory Usage",
			Description: "Memory usage is above threshold",
			Condition: AlertCondition{
				Metric:    "memory_usage_mb",
				Operator:  ">",
				Threshold: 1024.0, // 1GB
				Duration:  3 * time.Minute,
			},
			Level:    AlertWarning,
			Enabled:  true,
			Cooldown: 5 * time.Minute,
		},
		{
			ID:          "low_peer_count",
			Name:        "Low Peer Count",
			Description: "Connected peer count is below minimum",
			Condition: AlertCondition{
				Metric:    "connected_peers",
				Operator:  "<",
				Threshold: 3,
				Duration:  1 * time.Minute,
			},
			Level:    AlertWarning,
			Enabled:  true,
			Cooldown: 10 * time.Minute,
		},
		{
			ID:          "high_error_rate",
			Name:        "High Error Rate",
			Description: "Transaction error rate is above threshold",
			Condition: AlertCondition{
				Metric:    "error_rate_percent",
				Operator:  ">",
				Threshold: 5.0,
				Duration:  1 * time.Minute,
			},
			Level:    AlertCritical,
			Enabled:  true,
			Cooldown: 3 * time.Minute,
		},
		{
			ID:          "low_staking_ratio",
			Name:        "Low Staking Ratio",
			Description: "Staking ratio is below optimal level",
			Condition: AlertCondition{
				Metric:    "staking_ratio",
				Operator:  "<",
				Threshold: 50.0,
				Duration:  10 * time.Minute,
			},
			Level:    AlertInfo,
			Enabled:  true,
			Cooldown: 30 * time.Minute,
		},
		{
			ID:          "high_inflation_rate",
			Name:        "High Inflation Rate",
			Description: "Inflation rate is above maximum threshold",
			Condition: AlertCondition{
				Metric:    "inflation_rate",
				Operator:  ">",
				Threshold: 15.0,
				Duration:  5 * time.Minute,
			},
			Level:    AlertWarning,
			Enabled:  true,
			Cooldown: 15 * time.Minute,
		},
		{
			ID:          "block_production_slow",
			Name:        "Slow Block Production",
			Description: "Block production time is above normal",
			Condition: AlertCondition{
				Metric:    "avg_block_time_seconds",
				Operator:  ">",
				Threshold: 30.0,
				Duration:  2 * time.Minute,
			},
			Level:    AlertWarning,
			Enabled:  true,
			Cooldown: 5 * time.Minute,
		},
	}

	aam.rules = append(aam.rules, defaultRules...)
}

// EvaluateAlerts checks all alert rules against current metrics
func (aam *AdvancedAlertManager) EvaluateAlerts(metrics *ProductionMetrics) {
	aam.mu.Lock()
	defer aam.mu.Unlock()

	now := time.Now()

	for _, rule := range aam.rules {
		if !rule.Enabled {
			continue
		}

		// Check cooldown
		if now.Sub(rule.LastFired) < rule.Cooldown {
			continue
		}

		// Evaluate condition
		if aam.evaluateCondition(rule.Condition, metrics) {
			// Check if alert already exists
			if _, exists := aam.activeAlerts[rule.ID]; !exists {
				alert := ExtendedAlert{
					Alert: Alert{
						ID:          fmt.Sprintf("%s_%d", rule.ID, now.Unix()),
						Level:       rule.Level,
						Title:       rule.Name,
						Description: aam.formatAlertDescription(rule, metrics),
						Source:      "alert_manager",
						Timestamp:   now,
						Metadata: map[string]interface{}{
							"rule_id": rule.ID,
							"metric":  rule.Condition.Metric,
							"threshold": rule.Condition.Threshold,
						},
					},
					Type:        rule.ID,
					Resolved:    false,
				}

				aam.activeAlerts[rule.ID] = alert
				aam.alertHistory = append(aam.alertHistory, alert)

				// Update rule last fired time
				for i := range aam.rules {
					if aam.rules[i].ID == rule.ID {
						aam.rules[i].LastFired = now
						break
					}
				}

				// Send notification
				go aam.notifier.SendNotification(alert.Alert)

				log.Printf("🚨 Alert triggered: %s - %s", alert.Title, alert.Description)
			}
		} else {
			// Check if we should resolve an existing alert
			if alert, exists := aam.activeAlerts[rule.ID]; exists && !alert.Resolved {
				alert.Resolved = true
				resolvedAt := now
				alert.ResolvedAt = &resolvedAt
				aam.activeAlerts[rule.ID] = alert

				log.Printf("✅ Alert resolved: %s", alert.Alert.Title)
			}
		}
	}

	// Trim history if needed
	if len(aam.alertHistory) > aam.maxHistorySize {
		aam.alertHistory = aam.alertHistory[len(aam.alertHistory)-aam.maxHistorySize:]
	}
}

// evaluateCondition checks if an alert condition is met
func (aam *AdvancedAlertManager) evaluateCondition(condition AlertCondition, metrics *ProductionMetrics) bool {
	var currentValue interface{}

	// Get current metric value
	switch condition.Metric {
	case "cpu_usage_percent":
		currentValue = metrics.CPUUsage
	case "memory_usage_mb":
		currentValue = metrics.MemoryUsage
	case "connected_peers":
		currentValue = metrics.ConnectedPeers
	case "error_rate_percent":
		currentValue = metrics.ErrorRate
	case "staking_ratio":
		currentValue = metrics.StakingRatio
	case "inflation_rate":
		currentValue = metrics.InflationRate
	case "avg_block_time_seconds":
		currentValue = metrics.BlockTime
	default:
		return false
	}

	// Compare values based on operator
	return aam.compareValues(currentValue, condition.Operator, condition.Threshold)
}

// compareValues compares two values using the specified operator
func (aam *AdvancedAlertManager) compareValues(current interface{}, operator string, threshold interface{}) bool {
	switch operator {
	case ">":
		return aam.toFloat64(current) > aam.toFloat64(threshold)
	case "<":
		return aam.toFloat64(current) < aam.toFloat64(threshold)
	case ">=":
		return aam.toFloat64(current) >= aam.toFloat64(threshold)
	case "<=":
		return aam.toFloat64(current) <= aam.toFloat64(threshold)
	case "==":
		return aam.toFloat64(current) == aam.toFloat64(threshold)
	case "!=":
		return aam.toFloat64(current) != aam.toFloat64(threshold)
	default:
		return false
	}
}

// toFloat64 converts interface{} to float64 for comparison
func (aam *AdvancedAlertManager) toFloat64(value interface{}) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case uint64:
		return float64(v)
	default:
		return 0.0
	}
}

// formatAlertDescription creates a detailed alert description
func (aam *AdvancedAlertManager) formatAlertDescription(rule AlertRule, metrics *ProductionMetrics) string {
	var currentValue interface{}
	
	switch rule.Condition.Metric {
	case "cpu_usage_percent":
		currentValue = fmt.Sprintf("%.1f%%", metrics.CPUUsage)
	case "memory_usage_mb":
		currentValue = fmt.Sprintf("%.0f MB", metrics.MemoryUsage)
	case "connected_peers":
		currentValue = fmt.Sprintf("%d", metrics.ConnectedPeers)
	case "error_rate_percent":
		currentValue = fmt.Sprintf("%.2f%%", metrics.ErrorRate)
	case "staking_ratio":
		currentValue = fmt.Sprintf("%.1f%%", metrics.StakingRatio)
	case "inflation_rate":
		currentValue = fmt.Sprintf("%.2f%%", metrics.InflationRate)
	case "avg_block_time_seconds":
		currentValue = fmt.Sprintf("%.1fs", metrics.BlockTime)
	default:
		currentValue = "unknown"
	}

	return fmt.Sprintf("%s: Current value %v %s threshold %v", 
		rule.Description, currentValue, rule.Condition.Operator, rule.Condition.Threshold)
}

// GetActiveAlerts returns all currently active alerts
func (aam *AdvancedAlertManager) GetActiveAlerts() []Alert {
	aam.mu.RLock()
	defer aam.mu.RUnlock()

	alerts := make([]Alert, 0, len(aam.activeAlerts))
	for _, extAlert := range aam.activeAlerts {
		if !extAlert.Resolved {
			alerts = append(alerts, extAlert.Alert)
		}
	}

	return alerts
}

// GetAlertHistory returns recent alert history
func (aam *AdvancedAlertManager) GetAlertHistory(limit int) []Alert {
	aam.mu.RLock()
	defer aam.mu.RUnlock()

	if limit <= 0 || limit > len(aam.alertHistory) {
		limit = len(aam.alertHistory)
	}

	start := len(aam.alertHistory) - limit
	if start < 0 {
		start = 0
	}

	history := make([]Alert, limit)
	for i, extAlert := range aam.alertHistory[start:start+limit] {
		history[i] = extAlert.Alert
	}

	return history
}

// Notification Channel Implementations

// SendNotification sends alert to console
func (cnc *ConsoleNotificationChannel) SendNotification(alert Alert) error {
	emoji := map[AlertLevel]string{
		AlertInfo:     "ℹ️",
		AlertWarning:  "⚠️",
		AlertCritical: "🚨",
	}

	log.Printf("%s [%s] %s: %s", 
		emoji[alert.Level], 
		string(alert.Level), 
		alert.Title, 
		alert.Description)
	
	return nil
}

// GetChannelType returns the channel type
func (cnc *ConsoleNotificationChannel) GetChannelType() string {
	return "console"
}

// SendNotification sends alert via email (placeholder implementation)
func (enc *EmailNotificationChannel) SendNotification(alert Alert) error {
	// Placeholder for email notification
	log.Printf("📧 Email notification would be sent to %v: %s", enc.Recipients, alert.Title)
	return nil
}

// GetChannelType returns the channel type
func (enc *EmailNotificationChannel) GetChannelType() string {
	return "email"
}

// SendNotification sends alert to webhook (placeholder implementation)
func (wnc *WebhookNotificationChannel) SendNotification(alert Alert) error {
	// Placeholder for webhook notification
	log.Printf("🔗 Webhook notification would be sent to %s: %s", wnc.URL, alert.Title)
	return nil
}

// GetChannelType returns the channel type
func (wnc *WebhookNotificationChannel) GetChannelType() string {
	return "webhook"
}

// SendNotification sends alert through all configured channels
func (an *AlertNotifier) SendNotification(alert Alert) {
	an.mu.RLock()
	defer an.mu.RUnlock()

	for _, channel := range an.channels {
		go func(ch NotificationChannel) {
			if err := ch.SendNotification(alert); err != nil {
				log.Printf("❌ Failed to send notification via %s: %v", ch.GetChannelType(), err)
			}
		}(channel)
	}
}

// AddNotificationChannel adds a new notification channel
func (an *AlertNotifier) AddNotificationChannel(channel NotificationChannel) {
	an.mu.Lock()
	defer an.mu.Unlock()
	an.channels = append(an.channels, channel)
}
