package bridgesdk

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// LogLevel represents different log levels
type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
	LogLevelFatal LogLevel = "fatal"
)

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp   time.Time              `json:"timestamp"`
	Level       string                 `json:"level"`
	Component   string                 `json:"component"`
	Message     string                 `json:"message"`
	Fields      map[string]interface{} `json:"fields,omitempty"`
	Error       string                 `json:"error,omitempty"`
	StackTrace  string                 `json:"stack_trace,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
	Duration    string                 `json:"duration,omitempty"`
}

// BridgeLogger provides structured logging with colored CLI output
type BridgeLogger struct {
	zapLogger    *zap.Logger
	sugar        *zap.SugaredLogger
	config       *LoggerConfig
	colorEnabled bool
	mu           sync.RWMutex
	logBuffer    []LogEntry
	maxBuffer    int
	subscribers  []chan LogEntry
}

// LoggerConfig configures the logger behavior
type LoggerConfig struct {
	Level            LogLevel `json:"level"`
	EnableConsole    bool     `json:"enable_console"`
	EnableFile       bool     `json:"enable_file"`
	EnableColors     bool     `json:"enable_colors"`
	EnableJSON       bool     `json:"enable_json"`
	FilePath         string   `json:"file_path"`
	MaxFileSize      int      `json:"max_file_size_mb"`
	MaxBackups       int      `json:"max_backups"`
	MaxAge           int      `json:"max_age_days"`
	BufferSize       int      `json:"buffer_size"`
	EnableStackTrace bool     `json:"enable_stack_trace"`
}

// DefaultLoggerConfig returns a default logger configuration
func DefaultLoggerConfig() *LoggerConfig {
	return &LoggerConfig{
		Level:            LogLevelInfo,
		EnableConsole:    true,
		EnableFile:       true,
		EnableColors:     true,
		EnableJSON:       false,
		FilePath:         "logs/bridge.log",
		MaxFileSize:      100,
		MaxBackups:       5,
		MaxAge:           30,
		BufferSize:       1000,
		EnableStackTrace: true,
	}
}

// NewBridgeLogger creates a new structured logger
func NewBridgeLogger(config *LoggerConfig) (*BridgeLogger, error) {
	if config == nil {
		config = DefaultLoggerConfig()
	}

	// Create logs directory
	if config.EnableFile {
		logDir := filepath.Dir(config.FilePath)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}
	}

	// Configure zap logger
	zapConfig := zap.NewProductionConfig()
	zapConfig.Level = zap.NewAtomicLevelAt(getZapLevel(config.Level))
	zapConfig.DisableStacktrace = !config.EnableStackTrace

	// Configure output paths
	var outputPaths []string
	if config.EnableConsole {
		outputPaths = append(outputPaths, "stdout")
	}
	if config.EnableFile {
		outputPaths = append(outputPaths, config.FilePath)
	}
	zapConfig.OutputPaths = outputPaths
	zapConfig.ErrorOutputPaths = outputPaths

	// Configure encoding
	if config.EnableJSON {
		zapConfig.Encoding = "json"
	} else {
		zapConfig.Encoding = "console"
		consoleConfig := zapcore.EncoderConfig{
			TimeKey:        "time",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			MessageKey:     "msg",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.CapitalLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.StringDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		}
		zapConfig.EncoderConfig = consoleConfig
	}

	zapLogger, err := zapConfig.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build zap logger: %w", err)
	}

	logger := &BridgeLogger{
		zapLogger:    zapLogger,
		sugar:        zapLogger.Sugar(),
		config:       config,
		colorEnabled: config.EnableColors && isTerminal(),
		logBuffer:    make([]LogEntry, 0, config.BufferSize),
		maxBuffer:    config.BufferSize,
		subscribers:  make([]chan LogEntry, 0),
	}

	return logger, nil
}

// getZapLevel converts LogLevel to zapcore.Level
func getZapLevel(level LogLevel) zapcore.Level {
	switch level {
	case LogLevelDebug:
		return zapcore.DebugLevel
	case LogLevelInfo:
		return zapcore.InfoLevel
	case LogLevelWarn:
		return zapcore.WarnLevel
	case LogLevelError:
		return zapcore.ErrorLevel
	case LogLevelFatal:
		return zapcore.FatalLevel
	default:
		return zapcore.InfoLevel
	}
}

// isTerminal checks if output is a terminal for color support
func isTerminal() bool {
	return color.NoColor == false
}

// Subscribe adds a channel to receive log entries in real-time
func (bl *BridgeLogger) Subscribe() chan LogEntry {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	ch := make(chan LogEntry, 100)
	bl.subscribers = append(bl.subscribers, ch)
	return ch
}

// Unsubscribe removes a channel from receiving log entries
func (bl *BridgeLogger) Unsubscribe(ch chan LogEntry) {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	for i, subscriber := range bl.subscribers {
		if subscriber == ch {
			close(subscriber)
			bl.subscribers = append(bl.subscribers[:i], bl.subscribers[i+1:]...)
			break
		}
	}
}

// addToBuffer adds a log entry to the buffer and notifies subscribers
func (bl *BridgeLogger) addToBuffer(entry LogEntry) {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	// Add to buffer
	bl.logBuffer = append(bl.logBuffer, entry)
	if len(bl.logBuffer) > bl.maxBuffer {
		bl.logBuffer = bl.logBuffer[1:]
	}

	// Notify subscribers
	for _, subscriber := range bl.subscribers {
		select {
		case subscriber <- entry:
		default:
			// Channel is full, skip
		}
	}
}

// GetRecentLogs returns recent log entries from the buffer
func (bl *BridgeLogger) GetRecentLogs(limit int) []LogEntry {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	if limit <= 0 || limit > len(bl.logBuffer) {
		limit = len(bl.logBuffer)
	}

	start := len(bl.logBuffer) - limit
	if start < 0 {
		start = 0
	}

	result := make([]LogEntry, limit)
	copy(result, bl.logBuffer[start:])
	return result
}

// colorizeLevel adds color to log levels for CLI output
func (bl *BridgeLogger) colorizeLevel(level string) string {
	if !bl.colorEnabled {
		return level
	}

	switch strings.ToUpper(level) {
	case "DEBUG":
		return color.HiBlackString(level)
	case "INFO":
		return color.CyanString(level)
	case "WARN":
		return color.YellowString(level)
	case "ERROR":
		return color.RedString(level)
	case "FATAL":
		return color.HiRedString(level)
	default:
		return level
	}
}

// colorizeComponent adds color to component names
func (bl *BridgeLogger) colorizeComponent(component string) string {
	if !bl.colorEnabled {
		return component
	}

	switch component {
	case "ethereum", "eth":
		return color.HiBlueString(component)
	case "solana", "sol":
		return color.HiMagentaString(component)
	case "bridge", "relay":
		return color.HiGreenString(component)
	case "error", "panic":
		return color.HiRedString(component)
	case "security", "replay":
		return color.HiYellowString(component)
	default:
		return color.HiCyanString(component)
	}
}

// formatMessage formats a message with emojis and colors
func (bl *BridgeLogger) formatMessage(level, component, message string) string {
	if !bl.colorEnabled {
		return message
	}

	var emoji string
	switch strings.ToUpper(level) {
	case "DEBUG":
		emoji = "🔍"
	case "INFO":
		emoji = getComponentEmoji(component)
	case "WARN":
		emoji = "⚠️"
	case "ERROR":
		emoji = "❌"
	case "FATAL":
		emoji = "💀"
	default:
		emoji = "📝"
	}

	return fmt.Sprintf("%s %s", emoji, message)
}

// getComponentEmoji returns appropriate emoji for component
func getComponentEmoji(component string) string {
	switch component {
	case "ethereum", "eth":
		return "🔗"
	case "solana", "sol":
		return "🪙"
	case "bridge", "relay":
		return "🌉"
	case "security", "replay":
		return "🔒"
	case "health":
		return "🏥"
	case "metrics":
		return "📊"
	case "websocket":
		return "🔌"
	case "api":
		return "🌐"
	default:
		return "ℹ️"
	}
}

// Debug logs a debug message
func (bl *BridgeLogger) Debug(component, message string, fields ...zap.Field) {
	bl.logWithLevel(zapcore.DebugLevel, component, message, fields...)
}

// Info logs an info message
func (bl *BridgeLogger) Info(component, message string, fields ...zap.Field) {
	bl.logWithLevel(zapcore.InfoLevel, component, message, fields...)
}

// Warn logs a warning message
func (bl *BridgeLogger) Warn(component, message string, fields ...zap.Field) {
	bl.logWithLevel(zapcore.WarnLevel, component, message, fields...)
}

// Error logs an error message
func (bl *BridgeLogger) Error(component, message string, err error, fields ...zap.Field) {
	allFields := append(fields, zap.Error(err))
	bl.logWithLevel(zapcore.ErrorLevel, component, message, allFields...)
}

// Fatal logs a fatal message and exits
func (bl *BridgeLogger) Fatal(component, message string, fields ...zap.Field) {
	bl.logWithLevel(zapcore.FatalLevel, component, message, fields...)
	os.Exit(1)
}

// logWithLevel logs a message at the specified level
func (bl *BridgeLogger) logWithLevel(level zapcore.Level, component, message string, fields ...zap.Field) {
	// Add component field
	allFields := append(fields, zap.String("component", component))

	// Create log entry for buffer
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level.String(),
		Component: component,
		Message:   message,
		Fields:    make(map[string]interface{}),
	}

	// Extract fields for buffer entry
	for _, field := range fields {
		switch field.Type {
		case zapcore.StringType:
			entry.Fields[field.Key] = field.String
		case zapcore.Int64Type:
			entry.Fields[field.Key] = field.Integer
		case zapcore.Float64Type:
			entry.Fields[field.Key] = field.Interface
		case zapcore.ErrorType:
			if field.Interface != nil {
				entry.Error = field.Interface.(error).Error()
			}
		default:
			entry.Fields[field.Key] = field.Interface
		}
	}

	// Add to buffer and notify subscribers
	bl.addToBuffer(entry)

	// Log with colored console output if enabled
	if bl.config.EnableConsole && bl.colorEnabled {
		coloredLevel := bl.colorizeLevel(level.String())
		coloredComponent := bl.colorizeComponent(component)
		coloredMessage := bl.formatMessage(level.String(), component, message)

		fmt.Printf("[%s] %s [%s] %s\n",
			time.Now().Format("15:04:05"),
			coloredLevel,
			coloredComponent,
			coloredMessage,
		)

		// Print fields if any
		if len(entry.Fields) > 0 {
			for key, value := range entry.Fields {
				fmt.Printf("  %s: %v\n", color.HiBlackString(key), value)
			}
		}

		// Print error if any
		if entry.Error != "" {
			fmt.Printf("  %s: %s\n", color.RedString("error"), entry.Error)
		}
	}

	// Log with zap (for file output and structured logging)
	switch level {
	case zapcore.DebugLevel:
		bl.zapLogger.Debug(message, allFields...)
	case zapcore.InfoLevel:
		bl.zapLogger.Info(message, allFields...)
	case zapcore.WarnLevel:
		bl.zapLogger.Warn(message, allFields...)
	case zapcore.ErrorLevel:
		bl.zapLogger.Error(message, allFields...)
	case zapcore.FatalLevel:
		bl.zapLogger.Fatal(message, allFields...)
	}
}

// LogTransaction logs a transaction event with structured data
func (bl *BridgeLogger) LogTransaction(component string, txHash string, amount float64, sourceChain, destChain string, status string) {
	bl.Info(component, "Transaction processed",
		zap.String("tx_hash", txHash),
		zap.Float64("amount", amount),
		zap.String("source_chain", sourceChain),
		zap.String("dest_chain", destChain),
		zap.String("status", status),
	)
}

// LogRelay logs a relay operation with timing
func (bl *BridgeLogger) LogRelay(component string, relayID string, duration time.Duration, success bool, err error) {
	fields := []zap.Field{
		zap.String("relay_id", relayID),
		zap.Duration("duration", duration),
		zap.Bool("success", success),
	}

	if success {
		bl.Info(component, "Relay completed successfully", fields...)
	} else {
		bl.Error(component, "Relay failed", err, fields...)
	}
}

// LogSecurity logs security-related events
func (bl *BridgeLogger) LogSecurity(component string, eventType string, details map[string]interface{}) {
	fields := []zap.Field{
		zap.String("event_type", eventType),
	}

	for key, value := range details {
		fields = append(fields, zap.Any(key, value))
	}

	bl.Warn(component, "Security event detected", fields...)
}

// LogMetrics logs performance metrics
func (bl *BridgeLogger) LogMetrics(component string, metrics map[string]interface{}) {
	fields := make([]zap.Field, 0, len(metrics))
	for key, value := range metrics {
		fields = append(fields, zap.Any(key, value))
	}

	bl.Info(component, "Performance metrics", fields...)
}

// Close closes the logger and flushes any remaining logs
func (bl *BridgeLogger) Close() error {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	// Close all subscribers
	for _, subscriber := range bl.subscribers {
		close(subscriber)
	}
	bl.subscribers = nil

	// Sync and close zap logger
	if err := bl.zapLogger.Sync(); err != nil {
		return err
	}

	return nil
}
