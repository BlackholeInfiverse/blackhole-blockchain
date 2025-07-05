package otc

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

// Interfaces to break import cycle
type Token interface {
	BalanceOf(address string) (uint64, error)
	Transfer(from, to string, amount uint64) error
}

type Transaction interface {
	Transfer(token Token, from, to string, amount uint64) error
	Commit() error
	Rollback()
	Hash() string
}

type Blockchain interface {
	TokenRegistry() map[string]Token
	BeginTransaction() Transaction
}

// OTCOrderType represents the type of OTC order
type OTCOrderType string

const (
	OrderTypeBuy  OTCOrderType = "buy"
	OrderTypeSell OTCOrderType = "sell"
)

// OTCOrderStatus represents the status of an OTC order
type OTCOrderStatus string

const (
	OrderStatusOpen      OTCOrderStatus = "open"
	OrderStatusMatched   OTCOrderStatus = "matched"
	OrderStatusCompleted OTCOrderStatus = "completed"
	OrderStatusCancelled OTCOrderStatus = "cancelled"
	OrderStatusExpired   OTCOrderStatus = "expired"
)

// OTCEvent represents an event in the OTC system
type OTCEvent struct {
	Type      OTCEventType `json:"type"`
	OrderID   string       `json:"order_id"`
	Timestamp int64        `json:"timestamp"`
	Data      interface{}  `json:"data"`
}

// OTCEventType represents the type of OTC event
type OTCEventType string

const (
	EventOrderCreated   OTCEventType = "order_created"
	EventOrderMatched   OTCEventType = "order_matched"
	EventOrderCompleted OTCEventType = "order_completed"
	EventOrderCancelled OTCEventType = "order_cancelled"
	EventOrderExpired   OTCEventType = "order_expired"
	EventOrderSigned    OTCEventType = "order_signed"
	EventTransferFailed OTCEventType = "transfer_failed"
)

// OTCEventHandler is a function that handles OTC events
type OTCEventHandler func(event OTCEvent)

// OTCOrder represents an over-the-counter trading order
type OTCOrder struct {
	ID              string          `json:"id"`
	Creator         string          `json:"creator"`
	OrderType       OTCOrderType    `json:"order_type"`
	TokenOffered    string          `json:"token_offered"`
	AmountOffered   uint64          `json:"amount_offered"`
	TokenRequested  string          `json:"token_requested"`
	AmountRequested uint64          `json:"amount_requested"`
	Status          OTCOrderStatus  `json:"status"`
	CreatedAt       int64           `json:"created_at"`
	ExpiresAt       int64           `json:"expires_at"`
	MatchedWith     string          `json:"matched_with,omitempty"`
	MatchedAt       int64           `json:"matched_at,omitempty"`
	CompletedAt     int64           `json:"completed_at,omitempty"`
	EscrowID        string          `json:"escrow_id,omitempty"`
	RequiredSigs    []string        `json:"required_sigs,omitempty"`
	Signatures      map[string]bool `json:"signatures"`
	mu              sync.RWMutex
}

// OTCTrade represents a completed OTC trade
type OTCTrade struct {
	ID              string  `json:"id"`
	OrderID         string  `json:"order_id"`
	Buyer           string  `json:"buyer"`
	Seller          string  `json:"seller"`
	TokenSold       string  `json:"token_sold"`
	AmountSold      uint64  `json:"amount_sold"`
	TokenBought     string  `json:"token_bought"`
	AmountBought    uint64  `json:"amount_bought"`
	Price           float64 `json:"price"` // AmountBought / AmountSold
	CompletedAt     int64   `json:"completed_at"`
	TransactionHash string  `json:"transaction_hash"`
}

// OTCManager manages over-the-counter trading
type OTCManager struct {
	Orders            map[string]*OTCOrder `json:"orders"`
	Trades            map[string]*OTCTrade `json:"trades"`
	Blockchain        *chain.Blockchain    `json:"-"`
	eventHandlers     []OTCEventHandler    `json:"-"`
	MinAmount         uint64               `json:"min_amount"`    // Minimum amount for any token
	MaxPriceDeviation float64              `json:"max_price_dev"` // Maximum allowed price deviation (e.g., 0.1 for 10%)
	mu                sync.RWMutex
}

// NewOTCManager creates a new OTC manager
func NewOTCManager(blockchain *chain.Blockchain) *OTCManager {
	manager := &OTCManager{
		Orders:            make(map[string]*OTCOrder),
		Trades:            make(map[string]*OTCTrade),
		Blockchain:        blockchain,
		eventHandlers:     make([]OTCEventHandler, 0),
		MinAmount:         1000, // Default minimum amount
		MaxPriceDeviation: 0.1,  // Default 10% max price deviation
	}

	// Start background goroutine for order expiration
	go manager.startExpirationChecker()

	return manager
}

// RegisterEventHandler registers a new event handler
func (otc *OTCManager) RegisterEventHandler(handler OTCEventHandler) {
	otc.mu.Lock()
	defer otc.mu.Unlock()
	otc.eventHandlers = append(otc.eventHandlers, handler)
}

// emitEvent emits an event to all registered handlers
func (otc *OTCManager) emitEvent(eventType OTCEventType, orderID string, data interface{}) {
	event := OTCEvent{
		Type:      eventType,
		OrderID:   orderID,
		Timestamp: time.Now().Unix(),
		Data:      data,
	}

	for _, handler := range otc.eventHandlers {
		go handler(event) // Non-blocking event emission
	}
}

// CreateOrder creates a new OTC order
func (otc *OTCManager) CreateOrder(creator, tokenOffered, tokenRequested string, amountOffered, amountRequested uint64, expirationHours int, isMultiSig bool, requiredSigs []string) (*OTCOrder, error) {
	otc.mu.Lock()
	defer otc.mu.Unlock()

	// Validate tokens exist
	if _, exists := otc.Blockchain.TokenRegistry[tokenOffered]; !exists {
		return nil, fmt.Errorf("token %s not found", tokenOffered)
	}
	if _, exists := otc.Blockchain.TokenRegistry[tokenRequested]; !exists {
		return nil, fmt.Errorf("token %s not found", tokenRequested)
	}

	// Validate minimum amounts
	if amountOffered < otc.MinAmount {
		return nil, fmt.Errorf("offered amount %d is below minimum amount %d", amountOffered, otc.MinAmount)
	}
	if amountRequested < otc.MinAmount {
		return nil, fmt.Errorf("requested amount %d is below minimum amount %d", amountRequested, otc.MinAmount)
	}

	// Calculate and validate price
	proposedPrice := float64(amountRequested) / float64(amountOffered)

	// Get recent trades for price comparison
	recentTrades := otc.getRecentTradesForPair(tokenOffered, tokenRequested, 5) // Get last 5 trades
	if len(recentTrades) > 0 {
		avgPrice := 0.0
		for _, trade := range recentTrades {
			avgPrice += trade.Price
		}
		avgPrice /= float64(len(recentTrades))

		// Calculate price deviation
		deviation := (proposedPrice - avgPrice) / avgPrice
		if deviation < -otc.MaxPriceDeviation || deviation > otc.MaxPriceDeviation {
			return nil, fmt.Errorf("price deviation %.2f%% exceeds maximum allowed %.2f%%", deviation*100, otc.MaxPriceDeviation*100)
		}
	}

	// Check creator's balance
	token := otc.Blockchain.TokenRegistry[tokenOffered]
	balance, err := token.BalanceOf(creator)
	if err != nil {
		return nil, fmt.Errorf("failed to check balance: %v", err)
	}

	if balance < amountOffered {
		return nil, fmt.Errorf("insufficient balance: has %d, needs %d", balance, amountOffered)
	}

	// Generate order ID
	orderID := fmt.Sprintf("otc_%d_%s", time.Now().UnixNano(), creator[:8])

	// Determine order type
	orderType := OrderTypeSell // Default: selling tokenOffered for tokenRequested

	// Create order
	order := &OTCOrder{
		ID:              orderID,
		Creator:         creator,
		OrderType:       orderType,
		TokenOffered:    tokenOffered,
		AmountOffered:   amountOffered,
		TokenRequested:  tokenRequested,
		AmountRequested: amountRequested,
		Status:          OrderStatusOpen,
		CreatedAt:       time.Now().Unix(),
		ExpiresAt:       time.Now().Add(time.Duration(expirationHours) * time.Hour).Unix(),
		Signatures:      make(map[string]bool),
	}

	if isMultiSig {
		order.RequiredSigs = requiredSigs
	}

	// Start atomic transaction
	tx := otc.Blockchain.BeginTransaction()

	// Lock offered tokens in OTC contract
	err = tx.Transfer(token, creator, "otc_contract", amountOffered)
	if err != nil {
		tx.Rollback()
		otc.emitEvent(EventTransferFailed, orderID, map[string]interface{}{
			"error":  err.Error(),
			"from":   creator,
			"to":     "otc_contract",
			"amount": amountOffered,
			"token":  tokenOffered,
		})
		return nil, fmt.Errorf("failed to lock tokens: %v", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %v", err)
	}

	otc.Orders[orderID] = order
	otc.emitEvent(EventOrderCreated, orderID, order)

	fmt.Printf("✅ OTC order created: %s (%d %s for %d %s)\n",
		orderID, amountOffered, tokenOffered, amountRequested, tokenRequested)

	return order, nil
}

// MatchOrder matches an order with a counterparty
func (otc *OTCManager) MatchOrder(orderID, counterparty string) error {
	otc.mu.Lock()
	defer otc.mu.Unlock()

	order, exists := otc.Orders[orderID]
	if !exists {
		return fmt.Errorf("order %s not found", orderID)
	}

	order.mu.Lock()
	defer order.mu.Unlock()

	if order.Status != OrderStatusOpen {
		return fmt.Errorf("order is not open for matching")
	}

	// Check if order has expired
	if time.Now().Unix() > order.ExpiresAt {
		order.Status = OrderStatusExpired
		otc.releaseOrderTokens(order)
		return fmt.Errorf("order has expired")
	}

	// Check counterparty's balance
	requestedToken := otc.Blockchain.TokenRegistry[order.TokenRequested]
	balance, err := requestedToken.BalanceOf(counterparty)
	if err != nil {
		return fmt.Errorf("failed to check counterparty balance: %v", err)
	}

	if balance < order.AmountRequested {
		return fmt.Errorf("counterparty has insufficient balance: has %d, needs %d", balance, order.AmountRequested)
	}

	// Lock counterparty's tokens
	err = requestedToken.Transfer(counterparty, "otc_contract", order.AmountRequested)
	if err != nil {
		return fmt.Errorf("failed to lock counterparty tokens: %v", err)
	}

	order.Status = OrderStatusMatched
	order.MatchedWith = counterparty
	order.MatchedAt = time.Now().Unix()

	fmt.Printf("✅ OTC order %s matched with %s\n", orderID, counterparty)

	// If not multi-sig, complete immediately
	if len(order.RequiredSigs) == 0 {
		return otc.completeOrder(order)
	}

	return nil
}

// SignOrder signs a multi-signature OTC order
func (otc *OTCManager) SignOrder(orderID, signer string) error {
	otc.mu.Lock()
	defer otc.mu.Unlock()

	order, exists := otc.Orders[orderID]
	if !exists {
		return fmt.Errorf("order %s not found", orderID)
	}

	order.mu.Lock()
	defer order.mu.Unlock()

	if order.Status != OrderStatusMatched {
		return fmt.Errorf("order must be matched before signing")
	}

	// Check if signer is authorized
	authorized := false
	for _, requiredSig := range order.RequiredSigs {
		if requiredSig == signer {
			authorized = true
			break
		}
	}

	if !authorized {
		return fmt.Errorf("signer %s is not authorized", signer)
	}

	// Add signature
	order.Signatures[signer] = true

	fmt.Printf("✅ OTC order %s signed by %s (%d/%d signatures)\n",
		orderID, signer, len(order.Signatures), len(order.RequiredSigs))

	// Check if we have all required signatures
	if len(order.Signatures) >= len(order.RequiredSigs) {
		return otc.completeOrder(order)
	}

	return nil
}

// completeOrder completes an OTC order
func (otc *OTCManager) completeOrder(order *OTCOrder) error {
	// Start atomic transaction
	tx := otc.Blockchain.BeginTransaction()

	offeredToken := otc.Blockchain.TokenRegistry[order.TokenOffered]
	requestedToken := otc.Blockchain.TokenRegistry[order.TokenRequested]

	// Transfer offered tokens to counterparty within transaction
	err := tx.Transfer(offeredToken, "otc_contract", order.MatchedWith, order.AmountOffered)
	if err != nil {
		tx.Rollback()
		otc.emitEvent(EventTransferFailed, order.ID, map[string]interface{}{
			"error":  err.Error(),
			"from":   "otc_contract",
			"to":     order.MatchedWith,
			"amount": order.AmountOffered,
			"token":  order.TokenOffered,
		})
		return fmt.Errorf("failed to transfer offered tokens: %v", err)
	}

	// Transfer requested tokens to creator within transaction
	err = tx.Transfer(requestedToken, "otc_contract", order.Creator, order.AmountRequested)
	if err != nil {
		tx.Rollback()
		otc.emitEvent(EventTransferFailed, order.ID, map[string]interface{}{
			"error":  err.Error(),
			"from":   "otc_contract",
			"to":     order.Creator,
			"amount": order.AmountRequested,
			"token":  order.TokenRequested,
		})
		return fmt.Errorf("failed to transfer requested tokens: %v", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	order.Status = OrderStatusCompleted
	order.CompletedAt = time.Now().Unix()

	// Create trade record
	tradeID := fmt.Sprintf("trade_%d", time.Now().UnixNano())
	trade := &OTCTrade{
		ID:              tradeID,
		OrderID:         order.ID,
		Buyer:           order.Creator,
		Seller:          order.MatchedWith,
		TokenSold:       order.TokenRequested,
		AmountSold:      order.AmountRequested,
		TokenBought:     order.TokenOffered,
		AmountBought:    order.AmountOffered,
		Price:           float64(order.AmountOffered) / float64(order.AmountRequested),
		CompletedAt:     time.Now().Unix(),
		TransactionHash: tx.Hash(),
	}

	otc.Trades[tradeID] = trade
	otc.emitEvent(EventOrderCompleted, order.ID, map[string]interface{}{
		"trade_id": tradeID,
		"trade":    trade,
	})

	fmt.Printf("✅ OTC order %s completed! Trade ID: %s\n", order.ID, tradeID)
	return nil
}

// CancelOrder cancels an OTC order
func (otc *OTCManager) CancelOrder(orderID, canceller string) error {
	otc.mu.Lock()
	defer otc.mu.Unlock()

	order, exists := otc.Orders[orderID]
	if !exists {
		return fmt.Errorf("order %s not found", orderID)
	}

	order.mu.Lock()
	defer order.mu.Unlock()

	// Check if canceller is authorized (creator or admin)
	if canceller != order.Creator {
		return fmt.Errorf("only order creator can cancel")
	}

	if order.Status != OrderStatusOpen {
		return fmt.Errorf("order cannot be cancelled in current status")
	}

	order.Status = OrderStatusCancelled
	otc.releaseOrderTokens(order)

	fmt.Printf("✅ OTC order %s cancelled\n", orderID)
	return nil
}

// releaseOrderTokens releases locked tokens back to creator
func (otc *OTCManager) releaseOrderTokens(order *OTCOrder) error {
	token := otc.Blockchain.TokenRegistry[order.TokenOffered]
	return token.Transfer("otc_contract", order.Creator, order.AmountOffered)
}

// GetOrder returns an OTC order
func (otc *OTCManager) GetOrder(orderID string) (*OTCOrder, error) {
	otc.mu.RLock()
	defer otc.mu.RUnlock()

	order, exists := otc.Orders[orderID]
	if !exists {
		return nil, fmt.Errorf("order %s not found", orderID)
	}

	// Return a copy
	orderCopy := *order
	return &orderCopy, nil
}

// GetOpenOrders returns all open orders
func (otc *OTCManager) GetOpenOrders() []*OTCOrder {
	otc.mu.RLock()
	defer otc.mu.RUnlock()

	var openOrders []*OTCOrder
	for _, order := range otc.Orders {
		if order.Status == OrderStatusOpen && time.Now().Unix() <= order.ExpiresAt {
			orderCopy := *order
			openOrders = append(openOrders, &orderCopy)
		}
	}

	return openOrders
}

// GetUserOrders returns all orders for a user
func (otc *OTCManager) GetUserOrders(userAddress string) []*OTCOrder {
	otc.mu.RLock()
	defer otc.mu.RUnlock()

	var userOrders []*OTCOrder
	for _, order := range otc.Orders {
		if order.Creator == userAddress || order.MatchedWith == userAddress {
			orderCopy := *order
			userOrders = append(userOrders, &orderCopy)
		}
	}

	return userOrders
}

// GetUserTrades returns all trades for a user
func (otc *OTCManager) GetUserTrades(userAddress string) []*OTCTrade {
	otc.mu.RLock()
	defer otc.mu.RUnlock()

	var userTrades []*OTCTrade
	for _, trade := range otc.Trades {
		if trade.Buyer == userAddress || trade.Seller == userAddress {
			tradeCopy := *trade
			userTrades = append(userTrades, &tradeCopy)
		}
	}

	return userTrades
}

// startExpirationChecker starts a background goroutine that periodically checks for expired orders
func (otc *OTCManager) startExpirationChecker() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			otc.ProcessExpiredOrders()
		}
	}
}

// ProcessExpiredOrders processes expired orders and releases tokens
func (otc *OTCManager) ProcessExpiredOrders() {
	otc.mu.Lock()
	defer otc.mu.Unlock()

	currentTime := time.Now().Unix()
	for _, order := range otc.Orders {
		order.mu.Lock()
		if order.Status == OrderStatusOpen && currentTime > order.ExpiresAt {
			order.Status = OrderStatusExpired
			if err := otc.releaseOrderTokens(order); err != nil {
				fmt.Printf("⚠️ Failed to release tokens for expired order %s: %v\n", order.ID, err)
				continue
			}
			otc.emitEvent(EventOrderExpired, order.ID, order)
			fmt.Printf("⏰ Expired OTC order %s processed\n", order.ID)
		}
		order.mu.Unlock()
	}
}

// getRecentTradesForPair returns the n most recent trades for a token pair
func (otc *OTCManager) getRecentTradesForPair(tokenA, tokenB string, n int) []*OTCTrade {
	otc.mu.RLock()
	defer otc.mu.RUnlock()

	var trades []*OTCTrade
	for _, trade := range otc.Trades {
		// Match trades in either direction (A->B or B->A)
		if (trade.TokenSold == tokenA && trade.TokenBought == tokenB) ||
			(trade.TokenSold == tokenB && trade.TokenBought == tokenA) {
			tradeCopy := *trade
			trades = append(trades, &tradeCopy)
		}
	}

	// Sort trades by completion time (most recent first)
	sort.Slice(trades, func(i, j int) bool {
		return trades[i].CompletedAt > trades[j].CompletedAt
	})

	// Return up to n trades
	if len(trades) > n {
		trades = trades[:n]
	}
	return trades
}

// OrderAnalytics represents analytics data for OTC orders
type OrderAnalytics struct {
	TotalOrders       int     `json:"total_orders"`
	OpenOrders        int     `json:"open_orders"`
	CompletedOrders   int     `json:"completed_orders"`
	CancelledOrders   int     `json:"cancelled_orders"`
	ExpiredOrders     int     `json:"expired_orders"`
	TotalVolume       uint64  `json:"total_volume"`
	AverageOrderSize  float64 `json:"average_order_size"`
	AverageTimeToFill float64 `json:"average_time_to_fill"` // in minutes
	SuccessRate       float64 `json:"success_rate"`         // completed / (completed + expired + cancelled)
}

// TokenPairAnalytics represents analytics data for a specific token pair
type TokenPairAnalytics struct {
	TokenA             string  `json:"token_a"`
	TokenB             string  `json:"token_b"`
	TotalTrades        int     `json:"total_trades"`
	TotalVolumeA       uint64  `json:"total_volume_a"`
	TotalVolumeB       uint64  `json:"total_volume_b"`
	HighestPrice       float64 `json:"highest_price"`
	LowestPrice        float64 `json:"lowest_price"`
	AveragePrice       float64 `json:"average_price"`
	PriceChangePercent float64 `json:"price_change_percent"` // 24h price change
}

// GetOrderAnalytics returns analytics data for all orders
func (otc *OTCManager) GetOrderAnalytics() OrderAnalytics {
	otc.mu.RLock()
	defer otc.mu.RUnlock()

	analytics := OrderAnalytics{}
	var totalAmount uint64

	for _, order := range otc.Orders {
		analytics.TotalOrders++
		totalAmount += order.AmountOffered

		switch order.Status {
		case OrderStatusOpen:
			analytics.OpenOrders++
		case OrderStatusCompleted:
			analytics.CompletedOrders++
			if order.CompletedAt > 0 && order.CreatedAt > 0 {
				timeToFill := float64(order.CompletedAt-order.CreatedAt) / 60 // Convert to minutes
				analytics.AverageTimeToFill += timeToFill
			}
		case OrderStatusCancelled:
			analytics.CancelledOrders++
		case OrderStatusExpired:
			analytics.ExpiredOrders++
		}
	}

	analytics.TotalVolume = totalAmount
	if analytics.TotalOrders > 0 {
		analytics.AverageOrderSize = float64(totalAmount) / float64(analytics.TotalOrders)
		if analytics.CompletedOrders > 0 {
			analytics.AverageTimeToFill /= float64(analytics.CompletedOrders)
		}
	}

	totalFinalized := float64(analytics.CompletedOrders + analytics.ExpiredOrders + analytics.CancelledOrders)
	if totalFinalized > 0 {
		analytics.SuccessRate = float64(analytics.CompletedOrders) / totalFinalized
	}

	return analytics
}

// GetTokenPairAnalytics returns analytics data for a specific token pair
func (otc *OTCManager) GetTokenPairAnalytics(tokenA, tokenB string) TokenPairAnalytics {
	otc.mu.RLock()
	defer otc.mu.RUnlock()

	analytics := TokenPairAnalytics{
		TokenA:       tokenA,
		TokenB:       tokenB,
		HighestPrice: -1,
		LowestPrice:  -1,
	}

	var totalPrice float64
	now := time.Now().Unix()
	dayAgo := now - 24*60*60

	for _, trade := range otc.Trades {
		if (trade.TokenSold == tokenA && trade.TokenBought == tokenB) ||
			(trade.TokenSold == tokenB && trade.TokenBought == tokenA) {

			analytics.TotalTrades++
			price := trade.Price
			if trade.TokenSold == tokenB { // Normalize price direction
				price = 1 / price
			}

			// Update price metrics
			if analytics.HighestPrice == -1 || price > analytics.HighestPrice {
				analytics.HighestPrice = price
			}
			if analytics.LowestPrice == -1 || price < analytics.LowestPrice {
				analytics.LowestPrice = price
			}
			totalPrice += price

			// Update volumes
			if trade.TokenSold == tokenA {
				analytics.TotalVolumeA += trade.AmountSold
				analytics.TotalVolumeB += trade.AmountBought
			} else {
				analytics.TotalVolumeA += trade.AmountBought
				analytics.TotalVolumeB += trade.AmountSold
			}

			// Calculate 24h price change
			if trade.CompletedAt >= dayAgo {
				analytics.PriceChangePercent = ((price / analytics.AveragePrice) - 1) * 100
			}
		}
	}

	if analytics.TotalTrades > 0 {
		analytics.AveragePrice = totalPrice / float64(analytics.TotalTrades)
	}

	return analytics
}
