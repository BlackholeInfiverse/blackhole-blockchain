package bridgesdk

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

type RetryItem struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Data        map[string]interface{} `json:"data"`
	Attempts    int                    `json:"attempts"`
	MaxAttempts int                    `json:"max_attempts"`
	NextRetry   time.Time              `json:"next_retry"`
	CreatedAt   time.Time              `json:"created_at"`
}

type FailedEvent struct {
	ID          string                 `json:"id"`
	Event       Event                  `json:"event"`
	Error       string                 `json:"error"`
	RetryCount  int                    `json:"retry_count"`
	LastRetry   time.Time              `json:"last_retry"`
	NextRetry   time.Time              `json:"next_retry"`
	Data        map[string]interface{} `json:"data"`
}

type ErrorInfo struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	Component string    `json:"component"`
	Severity  string    `json:"severity"`
}

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Component string    `json:"component"`
}

type ErrorMetrics struct {
	ErrorRate    float64              `json:"error_rate"`
	TotalErrors  int                  `json:"total_errors"`
	ErrorsByType map[string]int       `json:"errors_by_type"`
	RecentErrors []ErrorInfo          `json:"recent_errors"`
}

type RetryQueue struct {
	items []RetryItem
	mutex sync.RWMutex
}

func (rq *RetryQueue) ProcessRetries(ctx context.Context, processor func(RetryItem) error) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rq.processItems(processor)
		}
	}
}

func (rq *RetryQueue) processItems(processor func(RetryItem) error) {
	rq.mutex.Lock()
	defer rq.mutex.Unlock()
	
	now := time.Now()
	for i := len(rq.items) - 1; i >= 0; i-- {
		item := rq.items[i]
		if now.After(item.NextRetry) {
			if err := processor(item); err == nil {
				// Remove successful item
				rq.items = append(rq.items[:i], rq.items[i+1:]...)
			} else {
				// Update retry info
				item.Attempts++
				if item.Attempts >= item.MaxAttempts {
					// Remove failed item
					rq.items = append(rq.items[:i], rq.items[i+1:]...)
				} else {
					// Schedule next retry
					item.NextRetry = now.Add(time.Duration(item.Attempts*item.Attempts) * time.Second)
					rq.items[i] = item
				}
			}
		}
	}
}

type EventRecovery struct {
	failedEvents []FailedEvent
	mutex        sync.RWMutex
}

type ErrorHandler struct {
	errors []ErrorInfo
	mutex  sync.RWMutex
}

type PanicRecovery struct {
	recoveries []map[string]interface{}
	mutex      sync.RWMutex
}

func (pr *PanicRecovery) RecoverFromPanic(component string) {
	if r := recover(); r != nil {
		pr.mutex.Lock()
		defer pr.mutex.Unlock()
		
		recovery := map[string]interface{}{
			"component": component,
			"error":     fmt.Sprintf("%v", r),
			"timestamp": time.Now(),
		}
		
		pr.recoveries = append(pr.recoveries, recovery)
		
		// Keep only last 100 recoveries
		if len(pr.recoveries) > 100 {
			pr.recoveries = pr.recoveries[len(pr.recoveries)-100:]
		}
		
		log.Printf("🚨 Panic recovered in %s: %v", component, r)
	}
}

// GetFailedEvents returns failed events
func (sdk *BridgeSDK) GetFailedEvents() []FailedEvent {
	sdk.eventRecovery.mutex.RLock()
	defer sdk.eventRecovery.mutex.RUnlock()

	return sdk.eventRecovery.failedEvents
}

// GetProcessedEvents returns recently processed events
func (sdk *BridgeSDK) GetProcessedEvents() []Event {
	sdk.eventsMutex.RLock()
	defer sdk.eventsMutex.RUnlock()

	// Return last 100 events
	start := 0
	if len(sdk.events) > 100 {
		start = len(sdk.events) - 100
	}

	return sdk.events[start:]
}

// GetErrorMetrics returns error metrics
func (sdk *BridgeSDK) GetErrorMetrics() *ErrorMetrics {
	sdk.errorHandler.mutex.RLock()
	defer sdk.errorHandler.mutex.RUnlock()

	totalErrors := len(sdk.errorHandler.errors)
	errorsByType := make(map[string]int)
	
	for _, err := range sdk.errorHandler.errors {
		errorsByType[err.Type]++
	}

	// Get recent errors (last 10)
	recentErrors := sdk.errorHandler.errors
	if len(recentErrors) > 10 {
		recentErrors = recentErrors[len(recentErrors)-10:]
	}

	return &ErrorMetrics{
		ErrorRate:    0.5, // Placeholder
		TotalErrors:  totalErrors,
		ErrorsByType: errorsByType,
		RecentErrors: recentErrors,
	}
}
