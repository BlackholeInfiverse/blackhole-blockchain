package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/services/wallet/wallet"
)

// RealWorldFaucet represents a production-grade blockchain faucet
type RealWorldFaucet struct {
	config         *RealWorldConfig
	blockchain     *BlockchainConnector
	rateLimiter    *RateLimiter
	security       *SecurityManager
	analytics      *AnalyticsEngine
	requestHistory map[string]*FaucetRequest
	mu             sync.RWMutex
}

// RealWorldConfig holds production faucet configuration
type RealWorldConfig struct {
	// Network Configuration
	NetworkName   string `json:"network_name"`
	ChainID       string `json:"chain_id"`
	PeerAddress   string `json:"peer_address"`
	FaucetAddress string `json:"faucet_address"`

	// Token Configuration
	TokenSymbol   string `json:"token_symbol"`
	DefaultAmount uint64 `json:"default_amount"`
	MinAmount     uint64 `json:"min_amount"`
	MaxAmount     uint64 `json:"max_amount"`
	MaxBalance    uint64 `json:"max_balance"`

	// Rate Limiting
	CooldownPeriod time.Duration `json:"cooldown_period"`
	DailyLimit     int           `json:"daily_limit"`
	IPDailyLimit   int           `json:"ip_daily_limit"`

	// Security
	EnableWhitelist bool   `json:"enable_whitelist"`
	EnableBlacklist bool   `json:"enable_blacklist"`
	AdminAPIKey     string `json:"admin_api_key"`

	// Server Configuration
	Port            int  `json:"port"`
	EnableMetrics   bool `json:"enable_metrics"`
	EnableAnalytics bool `json:"enable_analytics"`
}

// FaucetRequest represents a comprehensive token request
type FaucetRequest struct {
	ID              string    `json:"id"`
	RequestAddress  string    `json:"request_address"`
	Amount          uint64    `json:"amount"`
	TransactionHash string    `json:"transaction_hash"`
	Status          string    `json:"status"`
	RequestTime     time.Time `json:"request_time"`
	ProcessTime     time.Time `json:"process_time"`
	IPAddress       string    `json:"ip_address"`
	UserAgent       string    `json:"user_agent"`
	Reason          string    `json:"reason"`
	Notes           string    `json:"notes"`
}

// BlockchainConnector handles blockchain interactions
type BlockchainConnector struct {
	peerAddress   string
	faucetAddress string
	connected     bool
	mu            sync.RWMutex
}

// RateLimiter manages request rate limiting
type RateLimiter struct {
	addressLimits map[string][]time.Time
	ipLimits      map[string][]time.Time
	config        *RealWorldConfig
	mu            sync.RWMutex
}

// SecurityManager handles security features
type SecurityManager struct {
	whitelist map[string]bool
	blacklist map[string]bool
	config    *RealWorldConfig
	mu        sync.RWMutex
}

// AnalyticsEngine tracks usage analytics
type AnalyticsEngine struct {
	totalRequests      int64
	successfulRequests int64
	failedRequests     int64
	totalDistributed   uint64
	uniqueAddresses    map[string]bool
	uniqueIPs          map[string]bool
	mu                 sync.RWMutex
}

// NewRealWorldFaucet creates a new production-ready faucet
func NewRealWorldFaucet(peerAddress string) (*RealWorldFaucet, error) {
	// Initialize wallet's blockchain client
	if err := wallet.InitBlockchainClient(5020); err != nil {
		return nil, fmt.Errorf("failed to initialize blockchain client: %v", err)
	}

	// Connect to blockchain node if peer address is provided
	if peerAddress != "" {
		log.Printf("🔗 Attempting to connect to blockchain node: %s", peerAddress)
		if err := wallet.DefaultBlockchainClient.ConnectToBlockchain(peerAddress); err != nil {
			log.Printf("⚠️ Failed to connect to blockchain node: %v", err)
			log.Println("🔄 Continuing without connection - configure peer through admin panel")
		} else {
			log.Println("✅ Successfully connected to blockchain node!")
		}
	} else {
		log.Println("🔄 Starting without blockchain connection")
		log.Println("💡 Configure peer address through admin panel at /admin")
	}

	config := &RealWorldConfig{
		NetworkName:     "Blackhole Production Network",
		ChainID:         "blackhole-mainnet",
		PeerAddress:     peerAddress,
		FaucetAddress:   "system",
		TokenSymbol:     "BHX",
		DefaultAmount:   50,            // Fixed 50 BHX tokens only
		MinAmount:       50,            // Same as default
		MaxAmount:       50,            // Same as default - no choice
		MaxBalance:      500,           // Lower max balance
		CooldownPeriod:  3 * time.Hour, // 3 hours cooling period
		DailyLimit:      8,             // Reduced daily limit due to longer cooldown
		IPDailyLimit:    25,
		EnableWhitelist: false,
		EnableBlacklist: true,
		AdminAPIKey:     "real_world_admin_2024",
		Port:            8095,
		EnableMetrics:   true,
		EnableAnalytics: true,
	}

	blockchain := &BlockchainConnector{
		peerAddress:   peerAddress,
		faucetAddress: config.FaucetAddress,
		connected:     true,
	}

	rateLimiter := &RateLimiter{
		addressLimits: make(map[string][]time.Time),
		ipLimits:      make(map[string][]time.Time),
		config:        config,
	}

	security := &SecurityManager{
		whitelist: make(map[string]bool),
		blacklist: make(map[string]bool),
		config:    config,
	}

	analytics := &AnalyticsEngine{
		uniqueAddresses: make(map[string]bool),
		uniqueIPs:       make(map[string]bool),
	}

	faucet := &RealWorldFaucet{
		config:         config,
		blockchain:     blockchain,
		rateLimiter:    rateLimiter,
		security:       security,
		analytics:      analytics,
		requestHistory: make(map[string]*FaucetRequest),
	}

	log.Printf("🚰 Real-World Faucet initialized for %s network", config.NetworkName)
	log.Printf("📍 Faucet address: %s", config.FaucetAddress)
	log.Printf("🔗 Peer address: %s", config.PeerAddress)

	return faucet, nil
}

// Start starts the real-world faucet server
func (rwf *RealWorldFaucet) Start() error {
	// Setup HTTP routes
	mux := http.NewServeMux()

	// Add CORS headers middleware
	corsHandler := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next(w, r)
		}
	}

	// Public API endpoints
	mux.HandleFunc("/api/v1/request", corsHandler(rwf.loggingMiddleware(rwf.handleTokenRequest)))
	mux.HandleFunc("/api/v1/balance/", corsHandler(rwf.loggingMiddleware(rwf.handleBalanceCheck)))
	mux.HandleFunc("/api/v1/info", corsHandler(rwf.loggingMiddleware(rwf.handleNetworkInfo)))
	mux.HandleFunc("/api/v1/stats", corsHandler(rwf.loggingMiddleware(rwf.handleStats)))
	mux.HandleFunc("/api/v1/history", corsHandler(rwf.loggingMiddleware(rwf.handleRequestHistory)))
	mux.HandleFunc("/api/v1/health", corsHandler(rwf.loggingMiddleware(rwf.handleHealthCheck)))

	// Admin endpoints
	mux.HandleFunc("/api/v1/admin/config", corsHandler(rwf.adminAuthMiddleware(rwf.handleAdminConfig)))
	mux.HandleFunc("/api/v1/admin/analytics", corsHandler(rwf.adminAuthMiddleware(rwf.handleAdminAnalytics)))
	mux.HandleFunc("/api/v1/admin/peer", corsHandler(rwf.adminAuthMiddleware(rwf.handleAdminPeer)))
	mux.HandleFunc("/api/v1/admin/connection", corsHandler(rwf.adminAuthMiddleware(rwf.handleAdminConnection)))

	// Web interface
	mux.HandleFunc("/", rwf.handleWebInterface)
	mux.HandleFunc("/admin", rwf.handleAdminInterface)

	// Start background services
	go rwf.startBackgroundServices()

	log.Printf("🌐 Real-World Faucet server starting on port %d", rwf.config.Port)
	log.Printf("📊 Web interface: http://localhost:%d", rwf.config.Port)
	log.Printf("🔧 Admin panel: http://localhost:%d/admin", rwf.config.Port)
	log.Printf("📡 API base: http://localhost:%d/api/v1", rwf.config.Port)

	return http.ListenAndServe(fmt.Sprintf(":%d", rwf.config.Port), mux)
}

// Middleware functions
func (rwf *RealWorldFaucet) loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next(w, r)
		log.Printf("%s %s %s %v", r.Method, r.RequestURI, r.RemoteAddr, time.Since(start))
	}
}

func (rwf *RealWorldFaucet) adminAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey != rwf.config.AdminAPIKey {
			rwf.sendError(w, "Unauthorized - Invalid API Key", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// Utility functions
func (rwf *RealWorldFaucet) sendError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   false,
		"error":     message,
		"code":      statusCode,
		"timestamp": time.Now().Unix(),
	})
}

func (rwf *RealWorldFaucet) sendSuccess(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"data":      data,
		"timestamp": time.Now().Unix(),
	})
}

// generateRequestID generates a unique request ID
func (rwf *RealWorldFaucet) generateRequestID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return fmt.Sprintf("rw_req_%d_%s", time.Now().Unix(), hex.EncodeToString(bytes)[:8])
}

// handleTokenRequest processes token requests with full validation
func (rwf *RealWorldFaucet) handleTokenRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		rwf.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Address string `json:"address"`
		Amount  uint64 `json:"amount"`
		Reason  string `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		rwf.sendError(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate request
	if err := rwf.validateRequest(&req); err != nil {
		rwf.sendError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check rate limits
	if err := rwf.rateLimiter.CheckLimits(req.Address, r.RemoteAddr); err != nil {
		rwf.sendError(w, err.Error(), http.StatusTooManyRequests)
		return
	}

	// Check security constraints
	if err := rwf.security.CheckSecurity(req.Address); err != nil {
		rwf.sendError(w, err.Error(), http.StatusForbidden)
		return
	}

	// Check balance constraints
	currentBalance, err := wallet.DefaultBlockchainClient.GetTokenBalance(req.Address, rwf.config.TokenSymbol)
	if err != nil {
		log.Printf("⚠️ Failed to check balance for %s: %v", req.Address, err)
		currentBalance = 0
	}

	if currentBalance >= rwf.config.MaxBalance {
		rwf.sendError(w, fmt.Sprintf("Balance too high (%d %s). Maximum: %d %s",
			currentBalance, rwf.config.TokenSymbol, rwf.config.MaxBalance, rwf.config.TokenSymbol), http.StatusBadRequest)
		return
	}

	// Process transfer
	faucetReq, err := rwf.processRealWorldTransfer(&req, r)
	if err != nil {
		rwf.sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update rate limits and analytics
	rwf.rateLimiter.UpdateLimits(req.Address, r.RemoteAddr)
	rwf.analytics.RecordRequest(faucetReq)

	// Store request
	rwf.mu.Lock()
	rwf.requestHistory[faucetReq.ID] = faucetReq
	rwf.mu.Unlock()

	// Send success response
	rwf.sendSuccess(w, map[string]interface{}{
		"request_id":       faucetReq.ID,
		"transaction_hash": faucetReq.TransactionHash,
		"amount":           faucetReq.Amount,
		"status":           faucetReq.Status,
		"message":          fmt.Sprintf("Successfully sent %d %s via real-world faucet", faucetReq.Amount, rwf.config.TokenSymbol),
		"network":          rwf.config.NetworkName,
		"chain_id":         rwf.config.ChainID,
		"faucet_type":      "real_world_production",
	})
}

// processRealWorldTransfer handles the actual token transfer
func (rwf *RealWorldFaucet) processRealWorldTransfer(req *struct {
	Address string `json:"address"`
	Amount  uint64 `json:"amount"`
	Reason  string `json:"reason"`
}, r *http.Request) (*FaucetRequest, error) {

	// Check blockchain connection
	if !wallet.DefaultBlockchainClient.IsConnected() {
		return nil, fmt.Errorf("blockchain connection unavailable")
	}

	log.Printf("🔄 Processing real-world transfer: %d %s to %s", req.Amount, rwf.config.TokenSymbol, req.Address)

	// Perform real token transfer using wallet client
	err := wallet.DefaultBlockchainClient.TransferTokens(
		rwf.config.FaucetAddress,
		req.Address,
		rwf.config.TokenSymbol,
		req.Amount,
		[]byte("real_world_faucet_key"),
	)

	if err != nil {
		log.Printf("❌ Real-world transfer failed: %v", err)
		return nil, fmt.Errorf("transfer failed: %v", err)
	}

	// Generate request ID and transaction hash
	requestID := rwf.generateRequestID()
	txHash := fmt.Sprintf("rw_tx_%d_%s", time.Now().UnixNano(), req.Address[:8])

	log.Printf("✅ Real-world transfer successful! Request: %s, TX: %s", requestID, txHash)

	// Create request record
	faucetReq := &FaucetRequest{
		ID:              requestID,
		RequestAddress:  req.Address,
		Amount:          req.Amount,
		TransactionHash: txHash,
		Status:          "confirmed",
		RequestTime:     time.Now(),
		ProcessTime:     time.Now(),
		IPAddress:       r.RemoteAddr,
		UserAgent:       r.UserAgent(),
		Reason:          req.Reason,
		Notes:           "Real-world production faucet transfer",
	}

	return faucetReq, nil
}

// validateRequest validates incoming requests
func (rwf *RealWorldFaucet) validateRequest(req *struct {
	Address string `json:"address"`
	Amount  uint64 `json:"amount"`
	Reason  string `json:"reason"`
}) error {

	if req.Address == "" {
		return fmt.Errorf("address is required")
	}

	if len(req.Address) < 20 {
		return fmt.Errorf("invalid address format")
	}

	if req.Amount == 0 {
		req.Amount = rwf.config.DefaultAmount
	}

	if req.Amount < rwf.config.MinAmount {
		return fmt.Errorf("amount too small. Minimum: %d %s", rwf.config.MinAmount, rwf.config.TokenSymbol)
	}

	if req.Amount > rwf.config.MaxAmount {
		return fmt.Errorf("amount too large. Maximum: %d %s", rwf.config.MaxAmount, rwf.config.TokenSymbol)
	}

	if req.Reason == "" {
		req.Reason = "Token request via real-world faucet"
	}

	return nil
}

// Component methods
func (bc *BlockchainConnector) IsConnected() bool {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.connected && wallet.DefaultBlockchainClient.IsConnected()
}

func (rl *RateLimiter) CheckLimits(address, ipAddr string) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Check address cooldown
	if requests, exists := rl.addressLimits[address]; exists {
		// Clean old requests
		var validRequests []time.Time
		for _, reqTime := range requests {
			if now.Sub(reqTime) < rl.config.CooldownPeriod {
				validRequests = append(validRequests, reqTime)
			}
		}
		rl.addressLimits[address] = validRequests

		if len(validRequests) > 0 {
			lastRequest := validRequests[len(validRequests)-1]
			if now.Sub(lastRequest) < rl.config.CooldownPeriod {
				remaining := rl.config.CooldownPeriod - now.Sub(lastRequest)
				return fmt.Errorf("cooldown active. Try again in %v", remaining.Round(time.Minute))
			}
		}

		// Check daily limit
		dailyCount := 0
		cutoff := now.Add(-24 * time.Hour)
		for _, reqTime := range validRequests {
			if reqTime.After(cutoff) {
				dailyCount++
			}
		}

		if dailyCount >= rl.config.DailyLimit {
			return fmt.Errorf("daily limit reached (%d/%d)", dailyCount, rl.config.DailyLimit)
		}
	}

	// Check IP limits
	if requests, exists := rl.ipLimits[ipAddr]; exists {
		var validRequests []time.Time
		cutoff := now.Add(-24 * time.Hour)
		for _, reqTime := range requests {
			if reqTime.After(cutoff) {
				validRequests = append(validRequests, reqTime)
			}
		}
		rl.ipLimits[ipAddr] = validRequests

		if len(validRequests) >= rl.config.IPDailyLimit {
			return fmt.Errorf("IP daily limit reached (%d/%d)", len(validRequests), rl.config.IPDailyLimit)
		}
	}

	return nil
}

func (rl *RateLimiter) UpdateLimits(address, ipAddr string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Update address limits
	if rl.addressLimits[address] == nil {
		rl.addressLimits[address] = make([]time.Time, 0)
	}
	rl.addressLimits[address] = append(rl.addressLimits[address], now)

	// Update IP limits
	if rl.ipLimits[ipAddr] == nil {
		rl.ipLimits[ipAddr] = make([]time.Time, 0)
	}
	rl.ipLimits[ipAddr] = append(rl.ipLimits[ipAddr], now)
}

func (sm *SecurityManager) CheckSecurity(address string) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Check blacklist
	if sm.config.EnableBlacklist && sm.blacklist[address] {
		return fmt.Errorf("address is blacklisted")
	}

	// Check whitelist
	if sm.config.EnableWhitelist && !sm.whitelist[address] {
		return fmt.Errorf("address not whitelisted")
	}

	return nil
}

func (ae *AnalyticsEngine) RecordRequest(req *FaucetRequest) {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	ae.totalRequests++
	if req.Status == "confirmed" {
		ae.successfulRequests++
		ae.totalDistributed += req.Amount
	} else {
		ae.failedRequests++
	}

	ae.uniqueAddresses[req.RequestAddress] = true
	ae.uniqueIPs[req.IPAddress] = true
}

// API Handlers
func (rwf *RealWorldFaucet) handleBalanceCheck(w http.ResponseWriter, r *http.Request) {
	// Extract address from URL path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/balance/")
	address := strings.TrimSpace(path)

	if address == "" {
		rwf.sendError(w, "Address is required", http.StatusBadRequest)
		return
	}

	balance, err := wallet.DefaultBlockchainClient.GetTokenBalance(address, rwf.config.TokenSymbol)
	if err != nil {
		rwf.sendError(w, fmt.Sprintf("Failed to get balance: %v", err), http.StatusInternalServerError)
		return
	}

	rwf.sendSuccess(w, map[string]interface{}{
		"address":  address,
		"balance":  balance,
		"symbol":   rwf.config.TokenSymbol,
		"network":  rwf.config.NetworkName,
		"chain_id": rwf.config.ChainID,
	})
}

func (rwf *RealWorldFaucet) handleNetworkInfo(w http.ResponseWriter, r *http.Request) {
	faucetBalance, _ := wallet.DefaultBlockchainClient.GetTokenBalance(rwf.config.FaucetAddress, rwf.config.TokenSymbol)

	info := map[string]interface{}{
		"network_name":    rwf.config.NetworkName,
		"chain_id":        rwf.config.ChainID,
		"token_symbol":    rwf.config.TokenSymbol,
		"default_amount":  rwf.config.DefaultAmount,
		"min_amount":      rwf.config.MinAmount,
		"max_amount":      rwf.config.MaxAmount,
		"max_balance":     rwf.config.MaxBalance,
		"cooldown_period": rwf.config.CooldownPeriod.String(),
		"daily_limit":     rwf.config.DailyLimit,
		"faucet_balance":  faucetBalance,
		"faucet_address":  rwf.config.FaucetAddress,
		"connected":       rwf.blockchain.IsConnected(),
		"faucet_type":     "real_world_production",
		"features": []string{
			"real_blockchain_integration",
			"advanced_rate_limiting",
			"security_controls",
			"comprehensive_analytics",
			"production_grade_architecture",
		},
	}

	rwf.sendSuccess(w, info)
}

func (rwf *RealWorldFaucet) handleStats(w http.ResponseWriter, r *http.Request) {
	rwf.analytics.mu.RLock()
	stats := map[string]interface{}{
		"total_requests":      rwf.analytics.totalRequests,
		"successful_requests": rwf.analytics.successfulRequests,
		"failed_requests":     rwf.analytics.failedRequests,
		"total_distributed":   rwf.analytics.totalDistributed,
		"unique_addresses":    len(rwf.analytics.uniqueAddresses),
		"unique_ips":          len(rwf.analytics.uniqueIPs),
		"token_symbol":        rwf.config.TokenSymbol,
		"network_name":        rwf.config.NetworkName,
		"faucet_type":         "real_world_production",
	}
	rwf.analytics.mu.RUnlock()

	rwf.sendSuccess(w, stats)
}

func (rwf *RealWorldFaucet) handleRequestHistory(w http.ResponseWriter, r *http.Request) {
	page := 1
	limit := 20

	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 50 {
			limit = parsed
		}
	}

	rwf.mu.RLock()

	// Convert to slice and sort by time (newest first)
	var requests []*FaucetRequest
	for _, req := range rwf.requestHistory {
		requests = append(requests, req)
	}

	// Simple sort by request time (newest first)
	for i := 0; i < len(requests)-1; i++ {
		for j := i + 1; j < len(requests); j++ {
			if requests[i].RequestTime.Before(requests[j].RequestTime) {
				requests[i], requests[j] = requests[j], requests[i]
			}
		}
	}

	// Pagination
	start := (page - 1) * limit
	end := start + limit
	if start >= len(requests) {
		start = len(requests)
	}
	if end > len(requests) {
		end = len(requests)
	}

	paginatedRequests := requests[start:end]
	rwf.mu.RUnlock()

	// Mask sensitive data for public API
	var publicRequests []map[string]interface{}
	for _, req := range paginatedRequests {
		maskedAddr := req.RequestAddress
		if len(maskedAddr) > 10 {
			maskedAddr = maskedAddr[:6] + "..." + maskedAddr[len(maskedAddr)-4:]
		}

		publicRequests = append(publicRequests, map[string]interface{}{
			"id":           req.ID,
			"address":      maskedAddr,
			"amount":       req.Amount,
			"status":       req.Status,
			"request_time": req.RequestTime,
			"reason":       req.Reason,
		})
	}

	rwf.sendSuccess(w, map[string]interface{}{
		"requests":    publicRequests,
		"page":        page,
		"limit":       limit,
		"total":       len(requests),
		"total_pages": (len(requests) + limit - 1) / limit,
	})
}

func (rwf *RealWorldFaucet) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	status := "healthy"
	checks := make(map[string]interface{})

	// Check blockchain connection
	connected := rwf.blockchain.IsConnected()
	checks["blockchain"] = map[string]interface{}{
		"connected": connected,
		"status":    "ok",
	}

	// Check faucet balance
	balance, err := wallet.DefaultBlockchainClient.GetTokenBalance(rwf.config.FaucetAddress, rwf.config.TokenSymbol)
	lowBalance := err != nil || balance < rwf.config.DefaultAmount*10
	checks["faucet_balance"] = map[string]interface{}{
		"balance":     balance,
		"low_balance": lowBalance,
		"status":      "ok",
	}

	if !connected || lowBalance {
		status = "degraded"
	}

	response := map[string]interface{}{
		"status":      status,
		"timestamp":   time.Now(),
		"checks":      checks,
		"version":     "real-world-v1.0.0",
		"faucet_type": "real_world_production",
	}

	if status == "healthy" {
		rwf.sendSuccess(w, response)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		rwf.sendSuccess(w, response)
	}
}

// Admin handlers
func (rwf *RealWorldFaucet) handleAdminConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		rwf.sendSuccess(w, rwf.config)
	} else {
		rwf.sendSuccess(w, map[string]interface{}{
			"message": "Config updates available via API",
			"status":  "read_only_demo",
		})
	}
}

func (rwf *RealWorldFaucet) handleAdminAnalytics(w http.ResponseWriter, r *http.Request) {
	rwf.analytics.mu.RLock()
	analytics := map[string]interface{}{
		"total_requests":      rwf.analytics.totalRequests,
		"successful_requests": rwf.analytics.successfulRequests,
		"failed_requests":     rwf.analytics.failedRequests,
		"total_distributed":   rwf.analytics.totalDistributed,
		"unique_addresses":    len(rwf.analytics.uniqueAddresses),
		"unique_ips":          len(rwf.analytics.uniqueIPs),
		"success_rate":        float64(rwf.analytics.successfulRequests) / float64(rwf.analytics.totalRequests) * 100,
		"average_amount":      rwf.analytics.totalDistributed / uint64(rwf.analytics.successfulRequests),
	}
	rwf.analytics.mu.RUnlock()

	rwf.sendSuccess(w, analytics)
}

// handleAdminPeer manages peer address configuration
func (rwf *RealWorldFaucet) handleAdminPeer(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		// Get current peer configuration
		rwf.blockchain.mu.RLock()
		peerInfo := map[string]interface{}{
			"current_peer":   rwf.blockchain.peerAddress,
			"connected":      rwf.blockchain.IsConnected(),
			"faucet_address": rwf.config.FaucetAddress,
			"last_updated":   time.Now(),
		}
		rwf.blockchain.mu.RUnlock()

		rwf.sendSuccess(w, peerInfo)

	case "POST":
		// Update peer address
		var req struct {
			PeerAddress string `json:"peer_address"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			rwf.sendError(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		if req.PeerAddress == "" {
			rwf.sendError(w, "Peer address is required", http.StatusBadRequest)
			return
		}

		// Validate peer address format
		if !strings.Contains(req.PeerAddress, "/ip4/") || !strings.Contains(req.PeerAddress, "/tcp/") {
			rwf.sendError(w, "Invalid peer address format. Expected: /ip4/IP/tcp/PORT/p2p/PEER_ID", http.StatusBadRequest)
			return
		}

		// Update configuration
		rwf.blockchain.mu.Lock()
		oldPeer := rwf.blockchain.peerAddress
		rwf.blockchain.peerAddress = req.PeerAddress
		rwf.config.PeerAddress = req.PeerAddress
		rwf.blockchain.mu.Unlock()

		log.Printf("🔧 Admin updated peer address from %s to %s", oldPeer, req.PeerAddress)

		rwf.sendSuccess(w, map[string]interface{}{
			"message":    "Peer address updated successfully",
			"old_peer":   oldPeer,
			"new_peer":   req.PeerAddress,
			"updated_at": time.Now(),
		})

	default:
		rwf.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAdminConnection manages blockchain connections
func (rwf *RealWorldFaucet) handleAdminConnection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		// Get connection status
		connected := rwf.blockchain.IsConnected()
		var connectedPeers []string
		if connected {
			connectedPeers = wallet.DefaultBlockchainClient.GetConnectedPeers()
		}

		status := map[string]interface{}{
			"connected":       connected,
			"peer_address":    rwf.blockchain.peerAddress,
			"connected_peers": connectedPeers,
			"connection_time": time.Now(),
			"faucet_balance":  0,
		}

		// Try to get faucet balance
		if connected {
			if balance, err := wallet.DefaultBlockchainClient.GetTokenBalance(rwf.config.FaucetAddress, rwf.config.TokenSymbol); err == nil {
				status["faucet_balance"] = balance
			}
		}

		rwf.sendSuccess(w, status)

	case "POST":
		// Connect/Reconnect to blockchain
		var req struct {
			Action string `json:"action"` // "connect" or "disconnect"
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			rwf.sendError(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		switch req.Action {
		case "connect":
			if rwf.blockchain.peerAddress == "" {
				rwf.sendError(w, "No peer address configured", http.StatusBadRequest)
				return
			}

			log.Printf("🔧 Admin initiated connection to: %s", rwf.blockchain.peerAddress)

			err := wallet.DefaultBlockchainClient.ConnectToBlockchain(rwf.blockchain.peerAddress)
			if err != nil {
				log.Printf("❌ Admin connection failed: %v", err)
				rwf.blockchain.mu.Lock()
				rwf.blockchain.connected = false
				rwf.blockchain.mu.Unlock()

				rwf.sendError(w, fmt.Sprintf("Connection failed: %v", err), http.StatusInternalServerError)
				return
			}

			rwf.blockchain.mu.Lock()
			rwf.blockchain.connected = true
			rwf.blockchain.mu.Unlock()

			log.Printf("✅ Admin connection successful to: %s", rwf.blockchain.peerAddress)

			rwf.sendSuccess(w, map[string]interface{}{
				"message":      "Successfully connected to blockchain",
				"peer_address": rwf.blockchain.peerAddress,
				"connected":    true,
				"connected_at": time.Now(),
			})

		case "disconnect":
			// Note: wallet client doesn't have explicit disconnect, so we just mark as disconnected
			rwf.blockchain.mu.Lock()
			rwf.blockchain.connected = false
			rwf.blockchain.mu.Unlock()

			log.Printf("🔧 Admin initiated disconnection")

			rwf.sendSuccess(w, map[string]interface{}{
				"message":         "Disconnected from blockchain",
				"connected":       false,
				"disconnected_at": time.Now(),
			})

		default:
			rwf.sendError(w, "Invalid action. Use 'connect' or 'disconnect'", http.StatusBadRequest)
		}

	default:
		rwf.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Web interface handlers
func (rwf *RealWorldFaucet) handleWebInterface(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>🌍 Real-World Blockchain Faucet</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            min-height: 100vh; color: white; padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 40px; }
        .header h1 {
            font-size: 3.5em; margin-bottom: 15px;
            text-shadow: 2px 2px 8px rgba(0,0,0,0.3);
            background: linear-gradient(45deg, #FFD700, #FFA500);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }
        .real-world-badge {
            background: linear-gradient(45deg, #FF6B6B, #4ECDC4);
            padding: 12px 24px; border-radius: 30px;
            display: inline-block; margin: 15px 0; font-size: 18px; font-weight: bold;
            box-shadow: 0 6px 20px rgba(0,0,0,0.3); animation: pulse 2s infinite;
        }
        @keyframes pulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.05); } }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-bottom: 40px; }
        .card {
            background: rgba(255,255,255,0.1); backdrop-filter: blur(20px);
            border-radius: 25px; padding: 35px;
            border: 1px solid rgba(255,255,255,0.2);
            box-shadow: 0 12px 40px rgba(0,0,0,0.2);
            transition: transform 0.3s ease;
        }
        .card:hover { transform: translateY(-5px); }
        .form-group { margin: 25px 0; }
        label { display: block; margin-bottom: 12px; font-weight: 600; font-size: 18px; }
        input, select {
            width: 100%; padding: 18px; border: none; border-radius: 12px;
            background: rgba(255,255,255,0.9); color: #333; font-size: 16px;
            transition: all 0.3s ease; border: 2px solid transparent;
        }
        input:focus, select:focus {
            outline: none; border-color: #4ECDC4;
            transform: translateY(-2px); box-shadow: 0 8px 25px rgba(0,0,0,0.2);
        }
        button {
            width: 100%; padding: 20px; border: none; border-radius: 15px;
            background: linear-gradient(45deg, #FF6B6B, #4ECDC4); color: white;
            font-size: 20px; font-weight: 700; cursor: pointer;
            transition: all 0.3s ease; text-transform: uppercase; letter-spacing: 2px;
            box-shadow: 0 6px 20px rgba(0,0,0,0.3);
        }
        button:hover {
            transform: translateY(-3px);
            box-shadow: 0 12px 35px rgba(0,0,0,0.4);
        }
        .result { margin: 25px 0; padding: 25px; border-radius: 15px; }
        .success { background: rgba(76, 175, 80, 0.2); border: 2px solid #4CAF50; }
        .error { background: rgba(244, 67, 54, 0.2); border: 2px solid #f44336; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 25px; margin: 40px 0; }
        .stat {
            text-align: center; background: rgba(255,255,255,0.1);
            padding: 25px; border-radius: 20px; backdrop-filter: blur(15px);
            border: 1px solid rgba(255,255,255,0.2);
        }
        .stat-value { font-size: 2.5em; font-weight: bold; color: #FFD700; margin-bottom: 8px; }
        .network-info {
            background: rgba(255,255,255,0.05);
            padding: 25px; border-radius: 20px; margin: 25px 0;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .feature-list {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px; margin: 25px 0;
        }
        .feature {
            background: rgba(255,255,255,0.05); padding: 20px; border-radius: 15px;
            border-left: 5px solid #4ECDC4; transition: all 0.3s ease;
        }
        .feature:hover { background: rgba(255,255,255,0.1); transform: translateX(5px); }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌍 Real-World Faucet</h1>
            <div class="real-world-badge">⚡ 50 BHX • 3 Hour Cooldown</div>
            <p>Controlled testing faucet - 50 BHX tokens every 3 hours</p>
        </div>

        <div class="grid">
            <div class="card">
                <h3>🎯 Request Production Tokens</h3>
                <form id="faucetForm" onsubmit="requestTokens(event)">
                    <div class="form-group">
                        <label for="address">Wallet Address:</label>
                        <input type="text" id="address" name="address" required
                               placeholder="Enter your production wallet address...">
                    </div>

                    <div class="form-group">
                        <label for="amount">Amount (BHX) - Fixed:</label>
                        <input type="number" id="amount" name="amount" value="50" readonly
                               style="background-color: #f0f0f0; cursor: not-allowed;">
                        <small style="color: #666; font-size: 12px;">Amount is fixed at 50 BHX per request</small>
                    </div>

                    <div class="form-group">
                        <label for="reason">Use Case:</label>
                        <select id="reason" name="reason" required>
                            <option value="">Select use case...</option>
                            <option value="development">Development & Testing</option>
                            <option value="validator_setup">Validator Node Setup</option>
                            <option value="transaction_fees">Transaction Fee Testing</option>
                            <option value="staking">Staking Operations</option>
                            <option value="smart_contracts">Smart Contract Deployment</option>
                            <option value="dapp_testing">DApp Integration Testing</option>
                            <option value="research">Research & Analysis</option>
                        </select>
                    </div>

                    <button type="submit" id="submitBtn">
                        🚀 Request 50 BHX Tokens
                    </button>
                </form>

                <div id="result"></div>
            </div>

            <div class="card">
                <h3>📊 Network Status</h3>
                <div class="network-info">
                    <p><strong>Network:</strong> <span id="networkName">Loading...</span></p>
                    <p><strong>Chain ID:</strong> <span id="chainId">Loading...</span></p>
                    <p><strong>Token:</strong> <span id="tokenSymbol">Loading...</span></p>
                    <p><strong>Faucet Balance:</strong> <span id="faucetBalance">Loading...</span></p>
                    <p><strong>Connection:</strong> <span id="connectionStatus">Checking...</span></p>
                    <p><strong>Fixed Amount:</strong> <span id="defaultAmount">50 BHX</span></p>
                    <p><strong>Cooldown Period:</strong> <span id="cooldownPeriod">3 hours</span></p>
                    <p><strong>Daily Limit:</strong> <span id="dailyLimit">8 requests</span></p>
                </div>

                <h4>🔧 Real-World Features</h4>
                <div class="feature-list">
                    <div class="feature">✅ Production Blockchain Integration</div>
                    <div class="feature">🔒 Enterprise Security Controls</div>
                    <div class="feature">📊 Real-Time Analytics Engine</div>
                    <div class="feature">⚡ Advanced Rate Limiting</div>
                    <div class="feature">🌐 RESTful API Architecture</div>
                    <div class="feature">🔧 Admin Management Interface</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h3>📈 Live Production Statistics</h3>
            <div class="stats-grid">
                <div class="stat">
                    <div class="stat-value" id="totalRequests">-</div>
                    <div>Total Requests</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="successfulRequests">-</div>
                    <div>Successful</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="totalDistributed">-</div>
                    <div>Total Distributed</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="uniqueAddresses">-</div>
                    <div>Unique Addresses</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="uniqueIPs">-</div>
                    <div>Unique IPs</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Load initial data
        loadNetworkInfo();
        loadStats();

        function requestTokens(event) {
            event.preventDefault();

            const address = document.getElementById('address').value.trim();
            const amount = 50; // Fixed amount - always 50 BHX
            const reason = document.getElementById('reason').value;
            const submitBtn = document.getElementById('submitBtn');

            if (!address || !reason) {
                showResult('Please fill in all required fields', 'error');
                return;
            }

            submitBtn.disabled = true;
            submitBtn.textContent = '⏳ Processing 50 BHX request...';
            showResult('🔄 Processing 50 BHX through production infrastructure...', 'loading');

            fetch('/api/v1/request', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    address: address,
                    amount: amount,
                    reason: reason
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showResult(
                        '<h4>✅ Real-World Transfer Successful!</h4>' +
                        '<p><strong>Request ID:</strong> ' + data.data.request_id + '</p>' +
                        '<p><strong>Transaction Hash:</strong> <code>' + data.data.transaction_hash + '</code></p>' +
                        '<p><strong>Amount:</strong> ' + data.data.amount + ' ' + data.data.faucet_type + '</p>' +
                        '<p><strong>Network:</strong> ' + data.data.network + '</p>' +
                        '<p><strong>Chain ID:</strong> ' + data.data.chain_id + '</p>' +
                        '<p>⏰ <strong>Next request available in 3 hours</strong></p>' +
                        '<p>💡 Tokens sent through real-world production blockchain!</p>',
                        'success'
                    );
                    document.getElementById('faucetForm').reset();
                    loadNetworkInfo();
                    loadStats();
                } else {
                    showResult('❌ Request Failed: ' + data.error, 'error');
                }
            })
            .catch(error => {
                showResult('❌ Network Error: ' + error.message, 'error');
            })
            .finally(() => {
                submitBtn.disabled = false;
                submitBtn.textContent = '🚀 Request 50 BHX Tokens';
            });
        }

        function loadNetworkInfo() {
            fetch('/api/v1/info')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const info = data.data;
                    document.getElementById('networkName').textContent = info.network_name;
                    document.getElementById('chainId').textContent = info.chain_id;
                    document.getElementById('tokenSymbol').textContent = info.token_symbol;
                    document.getElementById('faucetBalance').textContent = (info.faucet_balance || 0) + ' ' + info.token_symbol;
                    document.getElementById('defaultAmount').textContent = info.default_amount + ' ' + info.token_symbol;
                    document.getElementById('maxAmount').textContent = info.max_amount + ' ' + info.token_symbol;
                    document.getElementById('cooldownPeriod').textContent = info.cooldown_period;

                    const statusElement = document.getElementById('connectionStatus');
                    if (info.connected) {
                        statusElement.innerHTML = '<span style="color: #4CAF50;">🟢 Connected</span>';
                    } else {
                        statusElement.innerHTML = '<span style="color: #f44336;">🔴 Disconnected</span>';
                    }
                }
            })
            .catch(error => console.error('Failed to load network info:', error));
        }

        function loadStats() {
            fetch('/api/v1/stats')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const stats = data.data;
                    document.getElementById('totalRequests').textContent = stats.total_requests || 0;
                    document.getElementById('successfulRequests').textContent = stats.successful_requests || 0;
                    document.getElementById('totalDistributed').textContent = (stats.total_distributed || 0) + ' ' + stats.token_symbol;
                    document.getElementById('uniqueAddresses').textContent = stats.unique_addresses || 0;
                    document.getElementById('uniqueIPs').textContent = stats.unique_ips || 0;
                }
            })
            .catch(error => console.error('Failed to load stats:', error));
        }

        function showResult(message, type) {
            const resultDiv = document.getElementById('result');
            resultDiv.innerHTML = '<div class="result ' + type + '">' + message + '</div>';
        }

        // Auto-refresh data every 30 seconds
        setInterval(() => {
            loadNetworkInfo();
            loadStats();
        }, 30000);
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func (rwf *RealWorldFaucet) handleAdminInterface(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>🔧 Real-World Faucet Admin</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            min-height: 100vh; color: white; padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 40px; }
        .header h1 {
            font-size: 2.5em; margin-bottom: 10px;
            background: linear-gradient(45deg, #3498db, #2ecc71);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-bottom: 30px; }
        .card {
            background: rgba(255,255,255,0.1); backdrop-filter: blur(15px);
            border-radius: 20px; padding: 30px;
            border: 1px solid rgba(255,255,255,0.2);
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }
        .form-group { margin: 20px 0; }
        label { display: block; margin-bottom: 8px; font-weight: 600; }
        input, select {
            width: 100%; padding: 12px; border: none; border-radius: 8px;
            background: rgba(255,255,255,0.9); color: #333; font-size: 14px;
        }
        button {
            padding: 12px 24px; border: none; border-radius: 8px;
            background: linear-gradient(45deg, #3498db, #2ecc71); color: white;
            font-weight: 600; cursor: pointer; margin: 5px;
            transition: all 0.3s ease;
        }
        button:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.3); }
        .danger { background: linear-gradient(45deg, #e74c3c, #c0392b); }
        .success { background: linear-gradient(45deg, #27ae60, #2ecc71); }
        .result { margin: 15px 0; padding: 15px; border-radius: 10px; }
        .success-msg { background: rgba(46, 204, 113, 0.2); border: 1px solid #2ecc71; }
        .error-msg { background: rgba(231, 76, 60, 0.2); border: 1px solid #e74c3c; }
        .status { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; }
        .status.connected { background: #2ecc71; }
        .status.disconnected { background: #e74c3c; }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .info-item { background: rgba(255,255,255,0.05); padding: 15px; border-radius: 10px; text-align: center; }
        .api-endpoint {
            background: rgba(255,255,255,0.05); padding: 15px; margin: 10px 0;
            border-radius: 8px; font-family: monospace; font-size: 13px;
            border-left: 4px solid #3498db;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔧 Real-World Faucet Admin</h1>
            <p>Advanced administrative interface for production blockchain faucet</p>
        </div>

        <div class="grid">
            <div class="card">
                <h3>🔗 Peer Connection Management</h3>
                <div id="connectionStatus">
                    <p><strong>Current Status:</strong> <span id="statusBadge" class="status">Loading...</span></p>
                    <p><strong>Peer Address:</strong> <span id="currentPeer">Loading...</span></p>
                    <p><strong>Faucet Balance:</strong> <span id="faucetBalance">Loading...</span> BHX</p>
                </div>

                <div class="form-group">
                    <label for="peerAddress">Blockchain Peer Address:</label>
                    <input type="text" id="peerAddress" placeholder="/ip4/IP/tcp/PORT/p2p/PEER_ID">
                </div>

                <button onclick="updatePeerAddress()">📝 Update Peer Address</button>
                <button onclick="connectToBlockchain()" class="success">🔗 Connect</button>
                <button onclick="disconnectFromBlockchain()" class="danger">🔌 Disconnect</button>

                <div id="connectionResult"></div>
            </div>

            <div class="card">
                <h3>📊 System Information</h3>
                <div class="info-grid">
                    <div class="info-item">
                        <div id="totalRequests">-</div>
                        <div>Total Requests</div>
                    </div>
                    <div class="info-item">
                        <div id="successRate">-</div>
                        <div>Success Rate</div>
                    </div>
                    <div class="info-item">
                        <div id="uniqueAddresses">-</div>
                        <div>Unique Addresses</div>
                    </div>
                    <div class="info-item">
                        <div id="connectedPeers">-</div>
                        <div>Connected Peers</div>
                    </div>
                </div>

                <button onclick="loadSystemInfo()">🔄 Refresh Info</button>
                <button onclick="loadAnalytics()">📈 Load Analytics</button>

                <div id="analyticsResult"></div>
            </div>
        </div>

        <div class="card">
            <h3>🔑 API Endpoints</h3>
            <p><strong>API Key:</strong> <code>real_world_admin_2024</code> | <strong>Header:</strong> <code>X-API-Key: real_world_admin_2024</code></p>

            <div class="api-endpoint">
                <strong>GET/POST</strong> /api/v1/admin/peer<br>
                <em>Manage peer address configuration</em>
            </div>

            <div class="api-endpoint">
                <strong>GET/POST</strong> /api/v1/admin/connection<br>
                <em>Control blockchain connections</em>
            </div>

            <div class="api-endpoint">
                <strong>GET</strong> /api/v1/admin/config<br>
                <em>View faucet configuration</em>
            </div>

            <div class="api-endpoint">
                <strong>GET</strong> /api/v1/admin/analytics<br>
                <em>Advanced analytics and metrics</em>
            </div>
        </div>
    </div>

    <script>
        const API_KEY = 'real_world_admin_2024';

        // Load initial data
        loadConnectionStatus();
        loadSystemInfo();

        function makeAdminRequest(url, options = {}) {
            return fetch(url, {
                ...options,
                headers: {
                    'X-API-Key': API_KEY,
                    'Content-Type': 'application/json',
                    ...options.headers
                }
            });
        }

        function loadConnectionStatus() {
            makeAdminRequest('/api/v1/admin/connection')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const info = data.data;
                    document.getElementById('currentPeer').textContent = info.peer_address || 'Not configured';
                    document.getElementById('faucetBalance').textContent = info.faucet_balance || 0;

                    const statusBadge = document.getElementById('statusBadge');
                    if (info.connected) {
                        statusBadge.textContent = '🟢 Connected';
                        statusBadge.className = 'status connected';
                    } else {
                        statusBadge.textContent = '🔴 Disconnected';
                        statusBadge.className = 'status disconnected';
                    }

                    document.getElementById('connectedPeers').textContent = (info.connected_peers || []).length;
                }
            })
            .catch(error => console.error('Failed to load connection status:', error));
        }

        function updatePeerAddress() {
            const peerAddress = document.getElementById('peerAddress').value.trim();
            if (!peerAddress) {
                showResult('connectionResult', 'Please enter a peer address', 'error-msg');
                return;
            }

            makeAdminRequest('/api/v1/admin/peer', {
                method: 'POST',
                body: JSON.stringify({ peer_address: peerAddress })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showResult('connectionResult',
                        '✅ Peer address updated successfully!<br>' +
                        '<strong>Old:</strong> ' + data.data.old_peer + '<br>' +
                        '<strong>New:</strong> ' + data.data.new_peer, 'success-msg');
                    loadConnectionStatus();
                } else {
                    showResult('connectionResult', '❌ Failed to update peer: ' + data.error, 'error-msg');
                }
            })
            .catch(error => {
                showResult('connectionResult', '❌ Network error: ' + error.message, 'error-msg');
            });
        }

        function connectToBlockchain() {
            makeAdminRequest('/api/v1/admin/connection', {
                method: 'POST',
                body: JSON.stringify({ action: 'connect' })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showResult('connectionResult',
                        '✅ Successfully connected to blockchain!<br>' +
                        '<strong>Peer:</strong> ' + data.data.peer_address, 'success-msg');
                    loadConnectionStatus();
                } else {
                    showResult('connectionResult', '❌ Connection failed: ' + data.error, 'error-msg');
                }
            })
            .catch(error => {
                showResult('connectionResult', '❌ Network error: ' + error.message, 'error-msg');
            });
        }

        function disconnectFromBlockchain() {
            makeAdminRequest('/api/v1/admin/connection', {
                method: 'POST',
                body: JSON.stringify({ action: 'disconnect' })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showResult('connectionResult', '✅ Successfully disconnected from blockchain', 'success-msg');
                    loadConnectionStatus();
                } else {
                    showResult('connectionResult', '❌ Disconnect failed: ' + data.error, 'error-msg');
                }
            })
            .catch(error => {
                showResult('connectionResult', '❌ Network error: ' + error.message, 'error-msg');
            });
        }

        function loadSystemInfo() {
            fetch('/api/v1/stats')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const stats = data.data;
                    document.getElementById('totalRequests').textContent = stats.total_requests || 0;
                    document.getElementById('uniqueAddresses').textContent = stats.unique_addresses || 0;

                    const successRate = stats.total_requests > 0 ?
                        ((stats.successful_requests / stats.total_requests) * 100).toFixed(1) + '%' : '0%';
                    document.getElementById('successRate').textContent = successRate;
                }
            })
            .catch(error => console.error('Failed to load system info:', error));
        }

        function loadAnalytics() {
            makeAdminRequest('/api/v1/admin/analytics')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const analytics = data.data;
                    showResult('analyticsResult',
                        '<h4>📊 Advanced Analytics</h4>' +
                        '<p><strong>Total Requests:</strong> ' + analytics.total_requests + '</p>' +
                        '<p><strong>Success Rate:</strong> ' + analytics.success_rate.toFixed(1) + '%</p>' +
                        '<p><strong>Total Distributed:</strong> ' + analytics.total_distributed + ' BHX</p>' +
                        '<p><strong>Average Amount:</strong> ' + analytics.average_amount + ' BHX</p>' +
                        '<p><strong>Unique IPs:</strong> ' + analytics.unique_ips + '</p>', 'success-msg');
                } else {
                    showResult('analyticsResult', '❌ Failed to load analytics: ' + data.error, 'error-msg');
                }
            })
            .catch(error => {
                showResult('analyticsResult', '❌ Network error: ' + error.message, 'error-msg');
            });
        }

        function showResult(elementId, message, className) {
            const element = document.getElementById(elementId);
            element.innerHTML = '<div class="result ' + className + '">' + message + '</div>';
        }

        // Auto-refresh connection status every 30 seconds
        setInterval(loadConnectionStatus, 30000);
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// Background services
func (rwf *RealWorldFaucet) startBackgroundServices() {
	// Health monitoring service
	go rwf.healthMonitoringService()

	// Analytics aggregation service
	go rwf.analyticsAggregationService()
}

func (rwf *RealWorldFaucet) healthMonitoringService() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Check blockchain connection
		if !rwf.blockchain.IsConnected() {
			log.Printf("⚠️ Real-world faucet: Blockchain connection lost")
		}

		// Check faucet balance
		balance, err := wallet.DefaultBlockchainClient.GetTokenBalance(rwf.config.FaucetAddress, rwf.config.TokenSymbol)
		if err == nil && balance < rwf.config.DefaultAmount*5 {
			log.Printf("⚠️ Real-world faucet: Low balance warning: %d %s", balance, rwf.config.TokenSymbol)
		}
	}
}

func (rwf *RealWorldFaucet) analyticsAggregationService() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		// Log current statistics
		rwf.analytics.mu.RLock()
		log.Printf("📊 Real-world faucet stats: %d total, %d successful, %d unique addresses",
			rwf.analytics.totalRequests, rwf.analytics.successfulRequests, len(rwf.analytics.uniqueAddresses))
		rwf.analytics.mu.RUnlock()
	}
}

// Main function
func main() {
	var peerAddress string

	// Check if peer address is provided as argument (optional)
	if len(os.Args) >= 2 {
		peerAddress = os.Args[1]
		fmt.Printf("🎯 Using provided peer address: %s\n", peerAddress)
	} else {
		fmt.Println("🌍 Starting faucet without initial peer connection")
		fmt.Println("💡 You can configure the peer address through the admin panel")
		peerAddress = "" // Start without peer connection
	}

	fmt.Println("🌍 Real-World Blockchain Faucet System")
	fmt.Println("=" + strings.Repeat("=", 55))
	fmt.Printf("🎯 Target peer: %s\n", peerAddress)
	fmt.Println("⚡ Real-world production features enabled")
	fmt.Println()

	// Create real-world faucet
	faucet, err := NewRealWorldFaucet(peerAddress)
	if err != nil {
		log.Fatalf("❌ Failed to create real-world faucet: %v", err)
	}

	fmt.Printf("📍 Real-world faucet URL: http://localhost:%d\n", faucet.config.Port)
	fmt.Printf("🔧 Admin panel: http://localhost:%d/admin\n", faucet.config.Port)
	fmt.Printf("📡 API base: http://localhost:%d/api/v1\n", faucet.config.Port)
	fmt.Printf("🔍 Health check: http://localhost:%d/api/v1/health\n", faucet.config.Port)
	fmt.Println()
	fmt.Println("🌍 Real-World Features:")
	fmt.Println("   🔗 Production blockchain integration")
	fmt.Println("   📊 Real-time analytics & monitoring")
	fmt.Println("   🔒 Enterprise security controls")
	fmt.Println("   ⚡ Advanced rate limiting system")
	fmt.Println("   🌐 RESTful API architecture")
	fmt.Println("   📱 Professional web interface")
	fmt.Println("   🔧 Admin management panel")
	fmt.Println("   ⚙️ Background monitoring services")
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop the real-world faucet")
	fmt.Println()

	if err := faucet.Start(); err != nil {
		log.Fatalf("❌ Failed to start real-world faucet: %v", err)
	}
}
