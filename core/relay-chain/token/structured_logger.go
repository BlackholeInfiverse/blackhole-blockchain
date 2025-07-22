package token

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LogLevel represents different log levels
type LogLevel string

const (
	LogLevelDebug   LogLevel = "DEBUG"
	LogLevelInfo    LogLevel = "INFO"
	LogLevelWarning LogLevel = "WARNING"
	LogLevelError   LogLevel = "ERROR"
	LogLevelCritical LogLevel = "CRITICAL"
)

// TokenTransactionLog represents a structured log entry for token transactions
type TokenTransactionLog struct {
	// Basic transaction info
	TransactionID   string    `json:"transaction_id"`
	TxHash          string    `json:"tx_hash"`
	Timestamp       time.Time `json:"timestamp"`
	BlockHeight     uint64    `json:"block_height,omitempty"`
	
	// Token info
	TokenSymbol     string    `json:"token_symbol"`
	TokenName       string    `json:"token_name"`
	TokenDecimals   uint8     `json:"token_decimals"`
	
	// Transaction details
	Operation       string    `json:"operation"` // mint, burn, transfer, approve, transferFrom
	From            string    `json:"from,omitempty"`
	To              string    `json:"to,omitempty"`
	Amount          uint64    `json:"amount"`
	
	// State changes
	FromBalanceBefore uint64  `json:"from_balance_before,omitempty"`
	FromBalanceAfter  uint64  `json:"from_balance_after,omitempty"`
	ToBalanceBefore   uint64  `json:"to_balance_before,omitempty"`
	ToBalanceAfter    uint64  `json:"to_balance_after,omitempty"`
	TotalSupplyBefore uint64  `json:"total_supply_before,omitempty"`
	TotalSupplyAfter  uint64  `json:"total_supply_after,omitempty"`
	
	// Approval specific
	Spender           string  `json:"spender,omitempty"`
	AllowanceBefore   uint64  `json:"allowance_before,omitempty"`
	AllowanceAfter    uint64  `json:"allowance_after,omitempty"`
	
	// Gas and fees
	GasUsed           uint64  `json:"gas_used,omitempty"`
	GasPrice          uint64  `json:"gas_price,omitempty"`
	TransactionFee    uint64  `json:"transaction_fee,omitempty"`
	
	// Status and validation
	Status            string  `json:"status"` // success, failed, pending
	ErrorMessage      string  `json:"error_message,omitempty"`
	ValidationChecks  map[string]bool `json:"validation_checks,omitempty"`
	
	// Context and metadata
	LogLevel          LogLevel `json:"log_level"`
	NodeID            string   `json:"node_id,omitempty"`
	UserAgent         string   `json:"user_agent,omitempty"`
	IPAddress         string   `json:"ip_address,omitempty"`
	SessionID         string   `json:"session_id,omitempty"`
	
	// Additional metadata
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
	
	// Performance metrics
	ProcessingTimeMs  int64   `json:"processing_time_ms,omitempty"`
	QueueTimeMs       int64   `json:"queue_time_ms,omitempty"`
}

// TokenStructuredLogger handles structured logging for token operations
type TokenStructuredLogger struct {
	logFile     *os.File
	logDir      string
	mu          sync.RWMutex
	enabled     bool
	logLevel    LogLevel
	bufferSize  int
	logBuffer   []TokenTransactionLog
	flushTicker *time.Ticker
}

// NewTokenStructuredLogger creates a new structured logger for token operations
func NewTokenStructuredLogger(logDir string, logLevel LogLevel) (*TokenStructuredLogger, error) {
	// Create logs directory if it doesn't exist
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %v", err)
	}

	// Create log file with timestamp
	timestamp := time.Now().Format("2006-01-02")
	logFileName := fmt.Sprintf("token_transactions_%s.jsonl", timestamp)
	logFilePath := filepath.Join(logDir, logFileName)

	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to create log file: %v", err)
	}

	logger := &TokenStructuredLogger{
		logFile:     logFile,
		logDir:      logDir,
		enabled:     true,
		logLevel:    logLevel,
		bufferSize:  100,
		logBuffer:   make([]TokenTransactionLog, 0, 100),
		flushTicker: time.NewTicker(5 * time.Second),
	}

	// Start background flushing
	go logger.backgroundFlush()

	return logger, nil
}

// LogTokenTransaction logs a token transaction with structured data
func (tsl *TokenStructuredLogger) LogTokenTransaction(logEntry TokenTransactionLog) {
	if !tsl.enabled {
		return
	}

	tsl.mu.Lock()
	defer tsl.mu.Unlock()

	// Set timestamp if not provided
	if logEntry.Timestamp.IsZero() {
		logEntry.Timestamp = time.Now()
	}

	// Set default log level if not provided
	if logEntry.LogLevel == "" {
		logEntry.LogLevel = LogLevelInfo
	}

	// Add to buffer
	tsl.logBuffer = append(tsl.logBuffer, logEntry)

	// Flush if buffer is full
	if len(tsl.logBuffer) >= tsl.bufferSize {
		tsl.flushBuffer()
	}

	// Also log to console for immediate visibility
	tsl.logToConsole(logEntry)
}

// flushBuffer writes buffered logs to file
func (tsl *TokenStructuredLogger) flushBuffer() {
	if len(tsl.logBuffer) == 0 {
		return
	}

	for _, entry := range tsl.logBuffer {
		jsonData, err := json.Marshal(entry)
		if err != nil {
			log.Printf("Error marshaling log entry: %v", err)
			continue
		}

		// Write as JSON Lines format (one JSON object per line)
		if _, err := tsl.logFile.WriteString(string(jsonData) + "\n"); err != nil {
			log.Printf("Error writing to log file: %v", err)
		}
	}

	// Sync to disk
	tsl.logFile.Sync()

	// Clear buffer
	tsl.logBuffer = tsl.logBuffer[:0]
}

// backgroundFlush periodically flushes the buffer
func (tsl *TokenStructuredLogger) backgroundFlush() {
	for range tsl.flushTicker.C {
		tsl.mu.Lock()
		tsl.flushBuffer()
		tsl.mu.Unlock()
	}
}

// logToConsole logs to console with emoji and formatting
func (tsl *TokenStructuredLogger) logToConsole(entry TokenTransactionLog) {
	emoji := map[LogLevel]string{
		LogLevelDebug:    "🔍",
		LogLevelInfo:     "ℹ️",
		LogLevelWarning:  "⚠️",
		LogLevelError:    "❌",
		LogLevelCritical: "🚨",
	}

	operationEmoji := map[string]string{
		"mint":         "🪙",
		"burn":         "🔥",
		"transfer":     "💸",
		"approve":      "✅",
		"transferFrom": "🔄",
	}

	statusEmoji := map[string]string{
		"success": "✅",
		"failed":  "❌",
		"pending": "⏳",
	}

	opEmoji := operationEmoji[entry.Operation]
	if opEmoji == "" {
		opEmoji = "🔄"
	}

	statEmoji := statusEmoji[entry.Status]
	if statEmoji == "" {
		statEmoji = "❓"
	}

	// Format console output
	fmt.Printf("%s %s [%s] %s %s: %d %s %s→%s (%s) [%s]\n",
		emoji[entry.LogLevel],
		opEmoji,
		entry.LogLevel,
		entry.Operation,
		statEmoji,
		entry.Amount,
		entry.TokenSymbol,
		entry.From,
		entry.To,
		entry.TxHash[:8]+"...",
		entry.Status,
	)
}

// Close closes the logger and flushes remaining logs
func (tsl *TokenStructuredLogger) Close() error {
	tsl.mu.Lock()
	defer tsl.mu.Unlock()

	// Stop background flushing
	if tsl.flushTicker != nil {
		tsl.flushTicker.Stop()
	}

	// Flush remaining logs
	tsl.flushBuffer()

	// Close log file
	if tsl.logFile != nil {
		return tsl.logFile.Close()
	}

	return nil
}

// SetLogLevel sets the minimum log level
func (tsl *TokenStructuredLogger) SetLogLevel(level LogLevel) {
	tsl.mu.Lock()
	defer tsl.mu.Unlock()
	tsl.logLevel = level
}

// Enable enables or disables logging
func (tsl *TokenStructuredLogger) Enable(enabled bool) {
	tsl.mu.Lock()
	defer tsl.mu.Unlock()
	tsl.enabled = enabled
}

// GetLogStats returns statistics about logged transactions
func (tsl *TokenStructuredLogger) GetLogStats() map[string]interface{} {
	tsl.mu.RLock()
	defer tsl.mu.RUnlock()

	return map[string]interface{}{
		"enabled":           tsl.enabled,
		"log_level":         tsl.logLevel,
		"buffer_size":       tsl.bufferSize,
		"buffered_entries":  len(tsl.logBuffer),
		"log_directory":     tsl.logDir,
		"log_file_open":     tsl.logFile != nil,
	}
}

// CreateTokenTransactionLog creates a structured log entry from token operation
func CreateTokenTransactionLog(token *Token, operation string, from, to string, amount uint64, status string, metadata map[string]interface{}) TokenTransactionLog {
	txHash := ""
	if metadata != nil {
		if hash, exists := metadata["tx_hash"]; exists {
			txHash = hash.(string)
		}
	}

	logEntry := TokenTransactionLog{
		TransactionID:   fmt.Sprintf("%s_%d", operation, time.Now().UnixNano()),
		TxHash:          txHash,
		Timestamp:       time.Now(),
		TokenSymbol:     token.Symbol,
		TokenName:       token.Name,
		TokenDecimals:   token.Decimals,
		Operation:       operation,
		From:            from,
		To:              to,
		Amount:          amount,
		Status:          status,
		LogLevel:        LogLevelInfo,
		Metadata:        metadata,
		ValidationChecks: map[string]bool{
			"address_valid":    from != "" && to != "",
			"amount_positive":  amount > 0,
			"balance_sufficient": true, // Will be updated by caller
		},
	}

	// Add token state information
	if token != nil {
		logEntry.TotalSupplyAfter = token.TotalSupply()
		
		if from != "" {
			if balance, err := token.BalanceOf(from); err == nil {
				logEntry.FromBalanceAfter = balance
			}
		}
		
		if to != "" && to != from {
			if balance, err := token.BalanceOf(to); err == nil {
				logEntry.ToBalanceAfter = balance
			}
		}
	}

	return logEntry
}

// Global logger instance
var GlobalTokenLogger *TokenStructuredLogger

// InitializeGlobalTokenLogger initializes the global token logger
func InitializeGlobalTokenLogger(logDir string, logLevel LogLevel) error {
	var err error
	GlobalTokenLogger, err = NewTokenStructuredLogger(logDir, logLevel)
	if err != nil {
		return fmt.Errorf("failed to initialize global token logger: %v", err)
	}
	
	log.Printf("✅ Global token structured logger initialized in %s", logDir)
	return nil
}

// LogTokenOperation is a convenience function to log token operations
func LogTokenOperation(token *Token, operation string, from, to string, amount uint64, status string, metadata map[string]interface{}) {
	if GlobalTokenLogger == nil {
		// If no global logger, just log to console
		log.Printf("🪙 [%s] %s: %d %s %s→%s (%s)",
			operation, token.Symbol, amount, token.Symbol, from, to, status)
		return
	}

	logEntry := CreateTokenTransactionLog(token, operation, from, to, amount, status, metadata)
	GlobalTokenLogger.LogTokenTransaction(logEntry)
}
