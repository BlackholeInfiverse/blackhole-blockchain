package token

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStructuredLogging(t *testing.T) {
	// Create temporary directory for test logs
	tempDir, err := ioutil.TempDir("", "token_logs_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Initialize structured logger
	logger, err := NewTokenStructuredLogger(tempDir, LogLevelInfo)
	assert.NoError(t, err)
	defer logger.Close()

	// Set as global logger
	GlobalTokenLogger = logger

	t.Run("Basic token operations logging", func(t *testing.T) {
		token := NewToken("TestToken", "TT", 18, 1000000)
		user := "0xTestUser"

		// Clear any existing logs
		logger.mu.Lock()
		logger.logBuffer = logger.logBuffer[:0]
		logger.mu.Unlock()

		// Test mint operation
		err := token.Mint(user, 1000)
		assert.NoError(t, err)

		// Test transfer operation
		err = token.Transfer(user, "0xRecipient", 500)
		assert.NoError(t, err)

		// Test approval operation
		err = token.Approve(user, "0xSpender", 200)
		assert.NoError(t, err)

		// Force flush logs
		logger.mu.Lock()
		logger.flushBuffer()
		logger.mu.Unlock()

		// Verify log file was created
		files, err := ioutil.ReadDir(tempDir)
		assert.NoError(t, err)
		assert.Len(t, files, 1)

		// Read and verify log content
		logFile := filepath.Join(tempDir, files[0].Name())
		content, err := ioutil.ReadFile(logFile)
		assert.NoError(t, err)

		lines := strings.Split(strings.TrimSpace(string(content)), "\n")
		assert.Len(t, lines, 3) // mint, transfer, approve

		// Parse and verify each log entry
		for i, line := range lines {
			var logEntry TokenTransactionLog
			err := json.Unmarshal([]byte(line), &logEntry)
			assert.NoError(t, err)

			// Common assertions
			assert.Equal(t, "TT", logEntry.TokenSymbol)
			assert.Equal(t, "TestToken", logEntry.TokenName)
			assert.Equal(t, uint8(18), logEntry.TokenDecimals)
			assert.Equal(t, "success", logEntry.Status)
			assert.Equal(t, LogLevelInfo, logEntry.LogLevel)
			assert.NotEmpty(t, logEntry.TransactionID)
			assert.NotEmpty(t, logEntry.TxHash)
			assert.NotZero(t, logEntry.Timestamp)

			// Operation-specific assertions
			switch i {
			case 0: // mint
				assert.Equal(t, "mint", logEntry.Operation)
				assert.Equal(t, "", logEntry.From)
				assert.Equal(t, user, logEntry.To)
				assert.Equal(t, uint64(1000), logEntry.Amount)
				assert.Equal(t, uint64(1000), logEntry.ToBalanceAfter)
				assert.Equal(t, uint64(1000), logEntry.TotalSupplyAfter)
			case 1: // transfer
				assert.Equal(t, "transfer", logEntry.Operation)
				assert.Equal(t, user, logEntry.From)
				assert.Equal(t, "0xRecipient", logEntry.To)
				assert.Equal(t, uint64(500), logEntry.Amount)
				assert.Equal(t, uint64(500), logEntry.FromBalanceAfter)
				assert.Equal(t, uint64(500), logEntry.ToBalanceAfter)
			case 2: // approve
				assert.Equal(t, "approve", logEntry.Operation)
				assert.Equal(t, user, logEntry.From)
				assert.Equal(t, "0xSpender", logEntry.To)
				assert.Equal(t, uint64(200), logEntry.Amount)
				assert.Equal(t, uint64(200), logEntry.AllowanceAfter)
			}
		}
	})

	t.Run("Failed operations logging", func(t *testing.T) {
		token := NewToken("TestToken", "TT", 18, 1000000)

		// Clear previous logs
		logger.mu.Lock()
		logger.logBuffer = logger.logBuffer[:0]
		logger.mu.Unlock()

		// Test failed mint (invalid address)
		err := token.Mint("", 1000)
		assert.Error(t, err)

		// Test failed transfer (insufficient balance)
		err = token.Transfer("0xNoBalance", "0xRecipient", 1000)
		assert.Error(t, err)

		// Force flush logs
		logger.mu.Lock()
		logger.flushBuffer()
		logger.mu.Unlock()

		// Read log file again
		files, err := ioutil.ReadDir(tempDir)
		assert.NoError(t, err)
		logFile := filepath.Join(tempDir, files[0].Name())
		content, err := ioutil.ReadFile(logFile)
		assert.NoError(t, err)

		lines := strings.Split(strings.TrimSpace(string(content)), "\n")
		// Should have previous 3 + 2 new failed operations
		assert.GreaterOrEqual(t, len(lines), 5)

		// Check the last two entries (failed operations)
		for i := len(lines) - 2; i < len(lines); i++ {
			var logEntry TokenTransactionLog
			err := json.Unmarshal([]byte(lines[i]), &logEntry)
			assert.NoError(t, err)

			assert.Equal(t, "failed", logEntry.Status)
			assert.NotEmpty(t, logEntry.ErrorMessage)
			assert.Contains(t, logEntry.Metadata, "error")
		}
	})

	t.Run("Performance metrics logging", func(t *testing.T) {
		token := NewToken("TestToken", "TT", 18, 1000000)
		user := "0xPerfUser"

		// Clear previous logs
		logger.mu.Lock()
		logger.logBuffer = logger.logBuffer[:0]
		logger.mu.Unlock()

		// Mint tokens
		err := token.Mint(user, 1000)
		assert.NoError(t, err)

		// Force flush logs
		logger.mu.Lock()
		logger.flushBuffer()
		logger.mu.Unlock()

		// Read and verify performance metrics
		files, err := ioutil.ReadDir(tempDir)
		assert.NoError(t, err)
		logFile := filepath.Join(tempDir, files[0].Name())
		content, err := ioutil.ReadFile(logFile)
		assert.NoError(t, err)

		lines := strings.Split(strings.TrimSpace(string(content)), "\n")
		lastLine := lines[len(lines)-1]

		var logEntry TokenTransactionLog
		err = json.Unmarshal([]byte(lastLine), &logEntry)
		assert.NoError(t, err)

		// Verify performance metrics are present
		assert.Contains(t, logEntry.Metadata, "processing_time_ms")
		processingTime := logEntry.Metadata["processing_time_ms"].(float64)
		assert.GreaterOrEqual(t, processingTime, 0.0)
		assert.LessOrEqual(t, processingTime, 1000.0) // Should be less than 1 second
	})

	t.Run("Logger statistics", func(t *testing.T) {
		stats := logger.GetLogStats()
		
		assert.Equal(t, true, stats["enabled"])
		assert.Equal(t, LogLevelInfo, stats["log_level"])
		assert.Equal(t, 100, stats["buffer_size"])
		assert.Equal(t, tempDir, stats["log_directory"])
		assert.Equal(t, true, stats["log_file_open"])
	})

	t.Run("Log level filtering", func(t *testing.T) {
		// Set log level to ERROR (should filter out INFO logs)
		logger.SetLogLevel(LogLevelError)

		token := NewToken("TestToken", "TT", 18, 1000000)
		
		// Clear previous logs
		logger.mu.Lock()
		logger.logBuffer = logger.logBuffer[:0]
		logger.mu.Unlock()

		// This should not be logged (INFO level)
		LogTokenOperation(token, "mint", "", "0xUser", 1000, "success", map[string]interface{}{})

		// Verify no new logs were added
		logger.mu.Lock()
		bufferSize := len(logger.logBuffer)
		logger.mu.Unlock()

		assert.Equal(t, 0, bufferSize)

		// Reset log level
		logger.SetLogLevel(LogLevelInfo)
	})

	t.Run("Concurrent logging", func(t *testing.T) {
		token := NewToken("TestToken", "TT", 18, 1000000)
		
		// Clear previous logs
		logger.mu.Lock()
		logger.logBuffer = logger.logBuffer[:0]
		logger.mu.Unlock()

		// Mint initial tokens
		token.Mint("0xConcurrentUser", 10000)

		// Perform concurrent operations
		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func(id int) {
				user := "0xConcurrentUser"
				recipient := "0xRecipient" + string(rune('0'+id))
				token.Transfer(user, recipient, 100)
				done <- true
			}(i)
		}

		// Wait for all operations to complete
		for i := 0; i < 10; i++ {
			<-done
		}

		// Force flush logs
		logger.mu.Lock()
		logger.flushBuffer()
		logger.mu.Unlock()

		// Verify all operations were logged
		files, err := ioutil.ReadDir(tempDir)
		assert.NoError(t, err)
		logFile := filepath.Join(tempDir, files[0].Name())
		content, err := ioutil.ReadFile(logFile)
		assert.NoError(t, err)

		lines := strings.Split(strings.TrimSpace(string(content)), "\n")
		// Should have at least 11 entries (1 mint + 10 transfers)
		assert.GreaterOrEqual(t, len(lines), 11)
	})
}

func TestCreateTokenTransactionLog(t *testing.T) {
	token := NewToken("TestToken", "TT", 18, 1000000)
	
	t.Run("Create log entry with metadata", func(t *testing.T) {
		metadata := map[string]interface{}{
			"tx_hash": "0x123456789",
			"custom_field": "test_value",
		}

		logEntry := CreateTokenTransactionLog(token, "transfer", "0xFrom", "0xTo", 500, "success", metadata)

		assert.Equal(t, "transfer", logEntry.Operation)
		assert.Equal(t, "0xFrom", logEntry.From)
		assert.Equal(t, "0xTo", logEntry.To)
		assert.Equal(t, uint64(500), logEntry.Amount)
		assert.Equal(t, "success", logEntry.Status)
		assert.Equal(t, "TT", logEntry.TokenSymbol)
		assert.Equal(t, "TestToken", logEntry.TokenName)
		assert.Equal(t, uint8(18), logEntry.TokenDecimals)
		assert.Equal(t, "0x123456789", logEntry.TxHash)
		assert.Equal(t, "test_value", logEntry.Metadata["custom_field"])
		assert.NotEmpty(t, logEntry.TransactionID)
		assert.NotZero(t, logEntry.Timestamp)
	})

	t.Run("Create log entry without metadata", func(t *testing.T) {
		logEntry := CreateTokenTransactionLog(token, "mint", "", "0xTo", 1000, "success", nil)

		assert.Equal(t, "mint", logEntry.Operation)
		assert.Equal(t, "", logEntry.From)
		assert.Equal(t, "0xTo", logEntry.To)
		assert.Equal(t, uint64(1000), logEntry.Amount)
		assert.Equal(t, "success", logEntry.Status)
		assert.Nil(t, logEntry.Metadata)
		assert.Empty(t, logEntry.TxHash) // No tx_hash in metadata
	})
}
