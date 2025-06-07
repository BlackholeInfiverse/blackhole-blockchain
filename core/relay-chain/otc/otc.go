package otc

import (
	"fmt"
	"sync"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

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

// OTCOrder represents an over-the-counter trading order
type OTCOrder struct {
	ID              string         `json:"id"`
	Creator         string         `json:"creator"`
	OrderType       OTCOrderType   `json:"order_type"`
	TokenOffered    string         `json:"token_offered"`
	AmountOffered   uint64         `json:"amount_offered"`
	TokenRequested  string         `json:"token_requested"`
	AmountRequested uint64         `json:"amount_requested"`
	Status          OTCOrderStatus `json:"status"`
	CreatedAt       int64          `json:"created_at"`
	ExpiresAt       int64          `json:"expires_at"`
	MatchedWith     string         `json:"matched_with,omitempty"`
	MatchedAt       int64          `json:"matched_at,omitempty"`
	CompletedAt     int64          `json:"completed_at,omitempty"`
	EscrowID        string         `json:"escrow_id,omitempty"`
	RequiredSigs    []string       `json:"required_sigs,omitempty"`
	Signatures      map[string]bool `json:"signatures"`
	mu              sync.RWMutex
}

// OTCTrade represents a completed OTC trade
type OTCTrade struct {
	ID              string `json:"id"`
	OrderID         string `json:"order_id"`
	Buyer           string `json:"buyer"`
	Seller          string `json:"seller"`
	TokenSold       string `json:"token_sold"`
	AmountSold      uint64 `json:"amount_sold"`
	TokenBought     string `json:"token_bought"`
	AmountBought    uint64 `json:"amount_bought"`
	Price           float64 `json:"price"` // AmountBought / AmountSold
	CompletedAt     int64  `json:"completed_at"`
	TransactionHash string `json:"transaction_hash"`
}

// OTCManager manages over-the-counter trading
type OTCManager struct {
	Orders     map[string]*OTCOrder `json:"orders"`
	Trades     map[string]*OTCTrade `json:"trades"`
	Blockchain *chain.Blockchain    `json:"-"`
	mu         sync.RWMutex
}

// NewOTCManager creates a new OTC manager
func NewOTCManager(blockchain *chain.Blockchain) *OTCManager {
	return &OTCManager{
		Orders:     make(map[string]*OTCOrder),
		Trades:     make(map[string]*OTCTrade),
		Blockchain: blockchain,
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

	// Lock offered tokens in OTC contract
	err = token.Transfer(creator, "otc_contract", amountOffered)
	if err != nil {
		return nil, fmt.Errorf("failed to lock tokens: %v", err)
	}

	otc.Orders[orderID] = order
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
	// Transfer tokens
	offeredToken := otc.Blockchain.TokenRegistry[order.TokenOffered]
	requestedToken := otc.Blockchain.TokenRegistry[order.TokenRequested]

	// Transfer offered tokens to counterparty
	err := offeredToken.Transfer("otc_contract", order.MatchedWith, order.AmountOffered)
	if err != nil {
		return fmt.Errorf("failed to transfer offered tokens: %v", err)
	}

	// Transfer requested tokens to creator
	err = requestedToken.Transfer("otc_contract", order.Creator, order.AmountRequested)
	if err != nil {
		return fmt.Errorf("failed to transfer requested tokens: %v", err)
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
		TransactionHash: fmt.Sprintf("otc_tx_%d", time.Now().UnixNano()),
	}

	otc.Trades[tradeID] = trade

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

// ProcessExpiredOrders processes expired orders and releases tokens
func (otc *OTCManager) ProcessExpiredOrders() {
	otc.mu.Lock()
	defer otc.mu.Unlock()

	currentTime := time.Now().Unix()
	for _, order := range otc.Orders {
		order.mu.Lock()
		if order.Status == OrderStatusOpen && currentTime > order.ExpiresAt {
			order.Status = OrderStatusExpired
			otc.releaseOrderTokens(order)
			fmt.Printf("⏰ Expired OTC order %s processed\n", order.ID)
		}
		order.mu.Unlock()
	}
}
