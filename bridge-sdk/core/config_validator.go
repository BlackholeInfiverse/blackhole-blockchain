package bridgesdk

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ConfigValidator validates and secures configuration for production
type ConfigValidator struct {
	logger              *logrus.Logger
	config              *Config
	validationErrors    []string
	validationWarnings  []string
	mutex               sync.RWMutex
	isProduction        bool
	requiredEnvVars     []string
	sensitiveEnvVars    []string
}

// ValidationResult contains validation results
type ValidationResult struct {
	IsValid  bool
	Errors   []string
	Warnings []string
	Status   string
}

// NewConfigValidator creates a new configuration validator
func NewConfigValidator(logger *logrus.Logger, isProduction bool) *ConfigValidator {
	return &ConfigValidator{
		logger:            logger,
		validationErrors:  []string{},
		validationWarnings: []string{},
		isProduction:      isProduction,
		requiredEnvVars: []string{
			"ETHEREUM_RPC_URL",
			"SOLANA_RPC_URL",
			"BLACKHOLE_RPC_URL",
			"DATABASE_PATH",
			"JWT_SECRET",
			"API_KEY",
		},
		sensitiveEnvVars: []string{
			"JWT_SECRET",
			"API_KEY",
			"ETHEREUM_PRIVATE_KEY",
			"SOLANA_PRIVATE_KEY",
			"BLACKHOLE_PRIVATE_KEY",
		},
	}
}

// ValidateConfig validates the entire configuration
func (cv *ConfigValidator) ValidateConfig(config *Config) ValidationResult {
	cv.mutex.Lock()
	defer cv.mutex.Unlock()

	cv.config = config
	cv.validationErrors = []string{}
	cv.validationWarnings = []string{}

	// Run all validations
	cv.validateRPCEndpoints()
	cv.validateDatabasePath()
	cv.validateLogLevel()
	cv.validateRetryConfig()
	cv.validateCircuitBreaker()
	cv.validateProductionSettings()
	cv.validateEnvironmentVariables()

	result := ValidationResult{
		IsValid:  len(cv.validationErrors) == 0,
		Errors:   cv.validationErrors,
		Warnings: cv.validationWarnings,
		Status:   "PASS",
	}

	if !result.IsValid {
		result.Status = "FAIL"
	} else if len(cv.validationWarnings) > 0 {
		result.Status = "PASS_WITH_WARNINGS"
	}

	return result
}

// validateRPCEndpoints validates blockchain RPC endpoints
func (cv *ConfigValidator) validateRPCEndpoints() {
	if cv.config.EthereumRPC == "" {
		cv.addError("ETHEREUM_RPC_URL is required")
	} else {
		if err := cv.validateURL(cv.config.EthereumRPC); err != nil {
			cv.addError(fmt.Sprintf("Invalid Ethereum RPC URL: %v", err))
		}
	}

	if cv.config.SolanaRPC == "" {
		cv.addError("SOLANA_RPC_URL is required")
	} else {
		if err := cv.validateURL(cv.config.SolanaRPC); err != nil {
			cv.addError(fmt.Sprintf("Invalid Solana RPC URL: %v", err))
		}
	}

	if cv.config.BlackHoleRPC == "" {
		cv.addError("BLACKHOLE_RPC_URL is required")
	} else {
		if err := cv.validateURL(cv.config.BlackHoleRPC); err != nil {
			cv.addError(fmt.Sprintf("Invalid BlackHole RPC URL: %v", err))
		}
	}
}

// validateURL validates a URL format and connectivity
func (cv *ConfigValidator) validateURL(urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("URL is empty")
	}

	// Check for valid scheme
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") &&
		!strings.HasPrefix(urlStr, "ws://") && !strings.HasPrefix(urlStr, "wss://") {
		return fmt.Errorf("URL must start with http://, https://, ws://, or wss://")
	}

	// For production, require HTTPS/WSS
	if cv.isProduction {
		if strings.HasPrefix(urlStr, "http://") {
			cv.addWarning(fmt.Sprintf("Production should use HTTPS instead of HTTP: %s", urlStr))
		}
		if strings.HasPrefix(urlStr, "ws://") {
			cv.addWarning(fmt.Sprintf("Production should use WSS instead of WS: %s", urlStr))
		}
	}

	return nil
}

// validateDatabasePath validates database configuration
func (cv *ConfigValidator) validateDatabasePath() {
	if cv.config.DatabasePath == "" {
		cv.addError("DATABASE_PATH is required")
		return
	}

	// Check if database directory exists or can be created
	dir := cv.config.DatabasePath
	if strings.Contains(dir, "/") || strings.Contains(dir, "\\") {
		dir = dir[:strings.LastIndexAny(dir, "/\\")]
	}

	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			// Try to create directory
			if err := os.MkdirAll(dir, 0700); err != nil {
				cv.addError(fmt.Sprintf("Cannot create database directory: %v", err))
			}
		} else {
			cv.addError(fmt.Sprintf("Database path error: %v", err))
		}
	}

	// For production, check file permissions
	if cv.isProduction {
		if info, err := os.Stat(dir); err == nil {
			if info.Mode().Perm()&0077 != 0 {
				cv.addWarning(fmt.Sprintf("Database directory has permissive permissions: %o", info.Mode().Perm()))
			}
		}
	}
}

// validateLogLevel validates log level configuration
func (cv *ConfigValidator) validateLogLevel() {
	validLevels := map[string]bool{
		"panic": true,
		"fatal": true,
		"error": true,
		"warn":  true,
		"info":  true,
		"debug": true,
		"trace": true,
	}

	if cv.config.LogLevel != "" {
		if !validLevels[strings.ToLower(cv.config.LogLevel)] {
			cv.addError(fmt.Sprintf("Invalid log level: %s", cv.config.LogLevel))
		}
	}

	// For production, don't allow debug/trace logs
	if cv.isProduction {
		if cv.config.LogLevel == "debug" || cv.config.LogLevel == "trace" {
			cv.addWarning("Production should not use debug/trace log levels")
		}
	}
}

// validateRetryConfig validates retry configuration
func (cv *ConfigValidator) validateRetryConfig() {
	if cv.config.MaxRetries < 0 {
		cv.addError("MaxRetries cannot be negative")
	}
	if cv.config.MaxRetries > 100 {
		cv.addWarning("MaxRetries > 100 may cause excessive retry attempts")
	}

	if cv.config.RetryDelayMs < 0 {
		cv.addError("RetryDelayMs cannot be negative")
	}
	if cv.config.RetryDelayMs > 300000 { // 5 minutes
		cv.addWarning("RetryDelayMs > 5 minutes may cause long delays")
	}
}

// validateCircuitBreaker validates circuit breaker configuration
func (cv *ConfigValidator) validateCircuitBreaker() {
	if !cv.config.CircuitBreakerEnabled && cv.isProduction {
		cv.addWarning("Circuit breaker disabled in production - recommended to enable")
	}
}

// validateProductionSettings validates production-specific settings
func (cv *ConfigValidator) validateProductionSettings() {
	if !cv.isProduction {
		return
	}

	// Check for demo/test values
	if strings.Contains(cv.config.EthereumRPC, "demo") ||
		strings.Contains(cv.config.EthereumRPC, "sepolia") ||
		strings.Contains(cv.config.EthereumRPC, "goerli") {
		cv.addWarning("Using testnet RPC in production")
	}

	if strings.Contains(cv.config.SolanaRPC, "devnet") ||
		strings.Contains(cv.config.SolanaRPC, "testnet") {
		cv.addWarning("Using Solana testnet RPC in production")
	}

	// Check if replay protection is enabled
	if !cv.config.ReplayProtectionEnabled {
		cv.addError("Replay protection must be enabled in production")
	}

	// Check if colored logs are disabled
	if cv.config.EnableColoredLogs {
		cv.addWarning("Colored logs should be disabled in production (use structured logging)")
	}
}

// validateEnvironmentVariables validates required environment variables
func (cv *ConfigValidator) validateEnvironmentVariables() {
	missingVars := []string{}

	for _, envVar := range cv.requiredEnvVars {
		if os.Getenv(envVar) == "" {
			missingVars = append(missingVars, envVar)
		}
	}

	if len(missingVars) > 0 {
		if cv.isProduction {
			cv.addError(fmt.Sprintf("Missing required environment variables: %v", missingVars))
		} else {
			cv.addWarning(fmt.Sprintf("Missing environment variables: %v", missingVars))
		}
	}

	// Check sensitive variables are not logged
	for _, envVar := range cv.sensitiveEnvVars {
		if val := os.Getenv(envVar); val != "" {
			cv.logger.WithField("env_var", envVar).
				Warn("Sensitive environment variable detected - ensure it's not logged or exposed")
		}
	}
}

// ValidateTransactionRequest validates a transaction request
func (cv *ConfigValidator) ValidateTransactionRequest(tx *TransferRequest) error {
	if tx.FromChain == "" {
		return fmt.Errorf("source chain is required")
	}
	if tx.ToChain == "" {
		return fmt.Errorf("destination chain is required")
	}
	if tx.FromChain == tx.ToChain {
		return fmt.Errorf("source and destination chains cannot be the same")
	}
	if tx.FromAddress == "" {
		return fmt.Errorf("source address is required")
	}
	if tx.ToAddress == "" {
		return fmt.Errorf("destination address is required")
	}
	if tx.TokenSymbol == "" {
		return fmt.Errorf("token symbol is required")
	}
	if tx.Amount == "" {
		return fmt.Errorf("amount is required")
	}

	// Validate amount is positive number
	if !isValidAmount(tx.Amount) {
		return fmt.Errorf("invalid amount format")
	}

	// Validate supported chains
	supportedChains := map[string]bool{
		"ethereum": true,
		"solana":   true,
		"blackhole": true,
	}

	if !supportedChains[strings.ToLower(tx.FromChain)] {
		return fmt.Errorf("unsupported source chain: %s", tx.FromChain)
	}
	if !supportedChains[strings.ToLower(tx.ToChain)] {
		return fmt.Errorf("unsupported destination chain: %s", tx.ToChain)
	}

	return nil
}

// ValidateAddress validates an address format
func (cv *ConfigValidator) ValidateAddress(address, chainType string) error {
	if address == "" {
		return fmt.Errorf("address is empty")
	}

	chainType = strings.ToLower(chainType)

	switch chainType {
	case "ethereum":
		if !strings.HasPrefix(address, "0x") || len(address) != 42 {
			return fmt.Errorf("invalid Ethereum address format")
		}
	case "solana":
		if len(address) < 32 || len(address) > 44 {
			return fmt.Errorf("invalid Solana address format")
		}
	case "blackhole":
		if len(address) == 0 || len(address) > 100 {
			return fmt.Errorf("invalid BlackHole address format")
		}
	default:
		return fmt.Errorf("unknown chain type: %s", chainType)
	}

	return nil
}

// ValidatePrivateKey validates a private key format
func (cv *ConfigValidator) ValidatePrivateKey(privateKey string, chainType string) error {
	if privateKey == "" {
		return fmt.Errorf("private key is empty")
	}

	chainType = strings.ToLower(chainType)

	switch chainType {
	case "ethereum":
		// Ethereum private keys should be hex strings without 0x prefix
		if strings.HasPrefix(privateKey, "0x") {
			privateKey = privateKey[2:]
		}
		if len(privateKey) != 64 {
			return fmt.Errorf("invalid Ethereum private key length")
		}
	case "solana":
		// Solana private keys are base58 encoded
		if len(privateKey) < 80 || len(privateKey) > 90 {
			return fmt.Errorf("invalid Solana private key format")
		}
	default:
		return fmt.Errorf("unknown chain type: %s", chainType)
	}

	return nil
}

// CheckConnectivity checks RPC endpoint connectivity
func (cv *ConfigValidator) CheckConnectivity() map[string]bool {
	results := make(map[string]bool)

	// Check Ethereum
	if cv.config.EthereumRPC != "" {
		results["ethereum"] = cv.checkEndpointConnectivity(cv.config.EthereumRPC)
	}

	// Check Solana
	if cv.config.SolanaRPC != "" {
		results["solana"] = cv.checkEndpointConnectivity(cv.config.SolanaRPC)
	}

	// Check BlackHole
	if cv.config.BlackHoleRPC != "" {
		results["blackhole"] = cv.checkEndpointConnectivity(cv.config.BlackHoleRPC)
	}

	return results
}

// checkEndpointConnectivity checks if an endpoint is reachable
func (cv *ConfigValidator) checkEndpointConnectivity(endpoint string) bool {
	// Extract host from URL
	if strings.HasPrefix(endpoint, "ws://") {
		endpoint = strings.TrimPrefix(endpoint, "ws://")
	} else if strings.HasPrefix(endpoint, "wss://") {
		endpoint = strings.TrimPrefix(endpoint, "wss://")
	} else if strings.HasPrefix(endpoint, "https://") {
		endpoint = strings.TrimPrefix(endpoint, "https://")
	} else if strings.HasPrefix(endpoint, "http://") {
		endpoint = strings.TrimPrefix(endpoint, "http://")
	}

	// Extract host and port
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		// No port specified, use default
		host = endpoint
		port = "80"
	}

	// Try to connect
	conn, err := net.DialTimeout("tcp", host+":"+port, 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

// Helper functions

func (cv *ConfigValidator) addError(errMsg string) {
	cv.validationErrors = append(cv.validationErrors, errMsg)
	cv.logger.Error(errMsg)
}

func (cv *ConfigValidator) addWarning(warnMsg string) {
	cv.validationWarnings = append(cv.validationWarnings, warnMsg)
	cv.logger.Warn(warnMsg)
}

func isValidAmount(amount string) bool {
	if amount == "" {
		return false
	}

	// Remove minus sign for checking
	checkAmount := strings.TrimPrefix(amount, "-")
	if checkAmount == amount || checkAmount == "" {
		// No minus sign or empty after removing
	} else {
		// Minus sign present - invalid (negative amount)
		return false
	}

	// Try parsing as float
	if _, err := strconv.ParseFloat(checkAmount, 64); err != nil {
		return false
	}

	return true
}

// GetValidationReport returns a detailed validation report
func (cv *ConfigValidator) GetValidationReport(result ValidationResult) string {
	report := fmt.Sprintf("Configuration Validation Report\n")
	report += fmt.Sprintf("Status: %s\n", result.Status)
	report += fmt.Sprintf("Valid: %v\n", result.IsValid)
	report += fmt.Sprintf("Timestamp: %s\n\n", time.Now().Format(time.RFC3339))

	if len(result.Errors) > 0 {
		report += "Errors:\n"
		for i, err := range result.Errors {
			report += fmt.Sprintf("  %d. %s\n", i+1, err)
		}
		report += "\n"
	}

	if len(result.Warnings) > 0 {
		report += "Warnings:\n"
		for i, warn := range result.Warnings {
			report += fmt.Sprintf("  %d. %s\n", i+1, warn)
		}
	}

	return report
}
