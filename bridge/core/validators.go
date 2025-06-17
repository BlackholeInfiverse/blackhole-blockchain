package core

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// EthereumValidator validates Ethereum addresses and transactions
type EthereumValidator struct {
	chainID *big.Int
}

// NewEthereumValidator creates a new Ethereum validator
func NewEthereumValidator(chainID *big.Int) *EthereumValidator {
	return &EthereumValidator{
		chainID: chainID,
	}
}

// ValidateAddress validates an Ethereum address
func (ev *EthereumValidator) ValidateAddress(address string) error {
	if !common.IsHexAddress(address) {
		return fmt.Errorf("invalid Ethereum address format: %s", address)
	}
	
	// Check if it's a valid checksum address
	addr := common.HexToAddress(address)
	if addr.Hex() != address && strings.ToLower(addr.Hex()) != strings.ToLower(address) {
		// If it's mixed case, validate checksum
		if !isValidChecksum(address) {
			return fmt.Errorf("invalid address checksum: %s", address)
		}
	}
	
	return nil
}

// NormalizeAddress normalizes an Ethereum address to checksum format
func (ev *EthereumValidator) NormalizeAddress(address string) (string, error) {
	if err := ev.ValidateAddress(address); err != nil {
		return "", err
	}
	
	addr := common.HexToAddress(address)
	return addr.Hex(), nil
}

// IsContractAddress checks if an address is a contract (placeholder implementation)
func (ev *EthereumValidator) IsContractAddress(address string) (bool, error) {
	// This would require an RPC call to check if the address has code
	// For now, return false (assume EOA)
	return false, nil
}

// isValidChecksum validates Ethereum address checksum
func isValidChecksum(address string) bool {
	address = strings.TrimPrefix(address, "0x")
	hash := crypto.Keccak256Hash([]byte(strings.ToLower(address)))
	
	for i, char := range address {
		if char >= '0' && char <= '9' {
			continue
		}
		
		hashByte := hash[i/2]
		var nibble byte
		if i%2 == 0 {
			nibble = hashByte >> 4
		} else {
			nibble = hashByte & 0x0f
		}
		
		if nibble >= 8 {
			if char < 'A' || char > 'F' {
				return false
			}
		} else {
			if char < 'a' || char > 'f' {
				return false
			}
		}
	}
	
	return true
}

// SolanaValidator validates Solana addresses and transactions
type SolanaValidator struct {
	network string // mainnet, testnet, devnet
}

// NewSolanaValidator creates a new Solana validator
func NewSolanaValidator(network string) *SolanaValidator {
	return &SolanaValidator{
		network: network,
	}
}

// ValidateAddress validates a Solana address (base58 encoded public key)
func (sv *SolanaValidator) ValidateAddress(address string) error {
	// Solana addresses are 32-byte public keys encoded in base58
	// They should be 32-44 characters long
	if len(address) < 32 || len(address) > 44 {
		return fmt.Errorf("invalid Solana address length: %s", address)
	}
	
	// Check if it contains only valid base58 characters
	validBase58 := regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]+$`)
	if !validBase58.MatchString(address) {
		return fmt.Errorf("invalid Solana address format: %s", address)
	}
	
	// Additional validation could include base58 decoding and length check
	// For now, this basic validation is sufficient
	
	return nil
}

// NormalizeAddress normalizes a Solana address (no changes needed for Solana)
func (sv *SolanaValidator) NormalizeAddress(address string) (string, error) {
	if err := sv.ValidateAddress(address); err != nil {
		return "", err
	}
	
	return address, nil
}

// IsContractAddress checks if a Solana address is a program (placeholder implementation)
func (sv *SolanaValidator) IsContractAddress(address string) (bool, error) {
	// This would require an RPC call to check if the address is a program
	// For now, return false (assume regular account)
	return false, nil
}

// BlackHoleValidator validates BlackHole blockchain addresses
type BlackHoleValidator struct {
	addressPrefix string
}

// NewBlackHoleValidator creates a new BlackHole validator
func NewBlackHoleValidator(addressPrefix string) *BlackHoleValidator {
	return &BlackHoleValidator{
		addressPrefix: addressPrefix,
	}
}

// ValidateAddress validates a BlackHole blockchain address
func (bv *BlackHoleValidator) ValidateAddress(address string) error {
	// BlackHole addresses should start with the configured prefix
	if bv.addressPrefix != "" && !strings.HasPrefix(address, bv.addressPrefix) {
		return fmt.Errorf("invalid BlackHole address prefix: %s", address)
	}
	
	// Remove prefix for validation
	addr := address
	if bv.addressPrefix != "" {
		addr = strings.TrimPrefix(address, bv.addressPrefix)
	}
	
	// Check if it's a valid hex string
	if !strings.HasPrefix(addr, "0x") {
		addr = "0x" + addr
	}
	
	// Validate hex format
	if _, err := hex.DecodeString(strings.TrimPrefix(addr, "0x")); err != nil {
		return fmt.Errorf("invalid BlackHole address format: %s", address)
	}
	
	// Check length (should be 20 bytes = 40 hex characters + 0x)
	if len(strings.TrimPrefix(addr, "0x")) != 40 {
		return fmt.Errorf("invalid BlackHole address length: %s", address)
	}
	
	return nil
}

// NormalizeAddress normalizes a BlackHole address
func (bv *BlackHoleValidator) NormalizeAddress(address string) (string, error) {
	if err := bv.ValidateAddress(address); err != nil {
		return "", err
	}
	
	// Ensure consistent format with prefix and lowercase hex
	addr := address
	if bv.addressPrefix != "" {
		addr = strings.TrimPrefix(address, bv.addressPrefix)
	}
	
	if !strings.HasPrefix(addr, "0x") {
		addr = "0x" + addr
	}
	
	addr = strings.ToLower(addr)
	
	if bv.addressPrefix != "" {
		addr = bv.addressPrefix + strings.TrimPrefix(addr, "0x")
	}
	
	return addr, nil
}

// IsContractAddress checks if a BlackHole address is a contract
func (bv *BlackHoleValidator) IsContractAddress(address string) (bool, error) {
	// This would require checking the BlackHole blockchain state
	// For now, return false (assume EOA)
	return false, nil
}

// EthereumFeeCalculator calculates fees for Ethereum transfers
type EthereumFeeCalculator struct {
	gasLimit    uint64
	gasPriceWei *big.Int
	minFeeWei   *big.Int
}

// NewEthereumFeeCalculator creates a new Ethereum fee calculator
func NewEthereumFeeCalculator(gasLimit uint64, gasPriceWei, minFeeWei *big.Int) *EthereumFeeCalculator {
	return &EthereumFeeCalculator{
		gasLimit:    gasLimit,
		gasPriceWei: gasPriceWei,
		minFeeWei:   minFeeWei,
	}
}

// CalculateTransferFee calculates the fee for an Ethereum transfer
func (efc *EthereumFeeCalculator) CalculateTransferFee(req *TransferRequest) (*big.Int, error) {
	if req == nil {
		return nil, fmt.Errorf("transfer request cannot be nil")
	}
	
	// Base gas cost for transfer
	gasUsed := new(big.Int).SetUint64(efc.gasLimit)
	
	// Multiply by gas price
	fee := new(big.Int).Mul(gasUsed, efc.gasPriceWei)
	
	// Ensure minimum fee
	if fee.Cmp(efc.minFeeWei) < 0 {
		fee = new(big.Int).Set(efc.minFeeWei)
	}
	
	// Add bridge fee (0.1% of transfer amount)
	bridgeFee := new(big.Int).Div(req.Amount, big.NewInt(1000))
	fee.Add(fee, bridgeFee)
	
	return fee, nil
}

// EstimateGasPrice estimates current gas price
func (efc *EthereumFeeCalculator) EstimateGasPrice() (*big.Int, error) {
	// This would typically query the network for current gas prices
	// For now, return the configured gas price
	return new(big.Int).Set(efc.gasPriceWei), nil
}

// GetMinimumFee returns the minimum fee
func (efc *EthereumFeeCalculator) GetMinimumFee() *big.Int {
	return new(big.Int).Set(efc.minFeeWei)
}

// SolanaFeeCalculator calculates fees for Solana transfers
type SolanaFeeCalculator struct {
	baseFee    *big.Int
	minFee     *big.Int
	priorityFee *big.Int
}

// NewSolanaFeeCalculator creates a new Solana fee calculator
func NewSolanaFeeCalculator(baseFee, minFee, priorityFee *big.Int) *SolanaFeeCalculator {
	return &SolanaFeeCalculator{
		baseFee:     baseFee,
		minFee:      minFee,
		priorityFee: priorityFee,
	}
}

// CalculateTransferFee calculates the fee for a Solana transfer
func (sfc *SolanaFeeCalculator) CalculateTransferFee(req *TransferRequest) (*big.Int, error) {
	if req == nil {
		return nil, fmt.Errorf("transfer request cannot be nil")
	}
	
	// Base fee + priority fee
	fee := new(big.Int).Add(sfc.baseFee, sfc.priorityFee)
	
	// Ensure minimum fee
	if fee.Cmp(sfc.minFee) < 0 {
		fee = new(big.Int).Set(sfc.minFee)
	}
	
	// Add bridge fee (0.05% of transfer amount)
	bridgeFee := new(big.Int).Div(req.Amount, big.NewInt(2000))
	fee.Add(fee, bridgeFee)
	
	return fee, nil
}

// EstimateGasPrice estimates current transaction fee
func (sfc *SolanaFeeCalculator) EstimateGasPrice() (*big.Int, error) {
	// Solana doesn't use gas, but we return the base fee for consistency
	return new(big.Int).Set(sfc.baseFee), nil
}

// GetMinimumFee returns the minimum fee
func (sfc *SolanaFeeCalculator) GetMinimumFee() *big.Int {
	return new(big.Int).Set(sfc.minFee)
}

// BlackHoleFeeCalculator calculates fees for BlackHole transfers
type BlackHoleFeeCalculator struct {
	baseFee *big.Int
	minFee  *big.Int
}

// NewBlackHoleFeeCalculator creates a new BlackHole fee calculator
func NewBlackHoleFeeCalculator(baseFee, minFee *big.Int) *BlackHoleFeeCalculator {
	return &BlackHoleFeeCalculator{
		baseFee: baseFee,
		minFee:  minFee,
	}
}

// CalculateTransferFee calculates the fee for a BlackHole transfer
func (bfc *BlackHoleFeeCalculator) CalculateTransferFee(req *TransferRequest) (*big.Int, error) {
	if req == nil {
		return nil, fmt.Errorf("transfer request cannot be nil")
	}
	
	// Use base fee
	fee := new(big.Int).Set(bfc.baseFee)
	
	// Ensure minimum fee
	if fee.Cmp(bfc.minFee) < 0 {
		fee = new(big.Int).Set(bfc.minFee)
	}
	
	// BlackHole bridge has lower fees (0.01% of transfer amount)
	bridgeFee := new(big.Int).Div(req.Amount, big.NewInt(10000))
	fee.Add(fee, bridgeFee)
	
	return fee, nil
}

// EstimateGasPrice estimates current gas price for BlackHole
func (bfc *BlackHoleFeeCalculator) EstimateGasPrice() (*big.Int, error) {
	return new(big.Int).Set(bfc.baseFee), nil
}

// GetMinimumFee returns the minimum fee
func (bfc *BlackHoleFeeCalculator) GetMinimumFee() *big.Int {
	return new(big.Int).Set(bfc.minFee)
}

// CreateDefaultValidators creates default validators for all supported chains
func CreateDefaultValidators() map[ChainType]AddressValidator {
	validators := make(map[ChainType]AddressValidator)
	
	// Ethereum validator (mainnet chain ID)
	validators[ChainTypeEthereum] = NewEthereumValidator(big.NewInt(1))
	
	// Solana validator (mainnet)
	validators[ChainTypeSolana] = NewSolanaValidator("mainnet")
	
	// BlackHole validator (with "bh" prefix)
	validators[ChainTypeBlackHole] = NewBlackHoleValidator("bh")
	
	return validators
}

// CreateDefaultFeeCalculators creates default fee calculators for all supported chains
func CreateDefaultFeeCalculators() map[ChainType]FeeCalculator {
	calculators := make(map[ChainType]FeeCalculator)
	
	// Ethereum fee calculator
	// Gas limit: 21000, Gas price: 20 gwei, Min fee: 0.001 ETH
	ethGasLimit := uint64(21000)
	ethGasPrice := new(big.Int).Mul(big.NewInt(20), big.NewInt(1e9)) // 20 gwei
	ethMinFee := new(big.Int).Mul(big.NewInt(1), big.NewInt(1e15))   // 0.001 ETH
	calculators[ChainTypeEthereum] = NewEthereumFeeCalculator(ethGasLimit, ethGasPrice, ethMinFee)
	
	// Solana fee calculator
	// Base fee: 5000 lamports, Min fee: 5000 lamports, Priority fee: 1000 lamports
	solBaseFee := big.NewInt(5000)
	solMinFee := big.NewInt(5000)
	solPriorityFee := big.NewInt(1000)
	calculators[ChainTypeSolana] = NewSolanaFeeCalculator(solBaseFee, solMinFee, solPriorityFee)
	
	// BlackHole fee calculator
	// Base fee: 1000 units, Min fee: 1000 units
	bhBaseFee := big.NewInt(1000)
	bhMinFee := big.NewInt(1000)
	calculators[ChainTypeBlackHole] = NewBlackHoleFeeCalculator(bhBaseFee, bhMinFee)
	
	return calculators
}

// CreateDefaultChainConfigs creates default chain configurations
func CreateDefaultChainConfigs() map[ChainType]*ChainConfig {
	configs := make(map[ChainType]*ChainConfig)
	
	// Ethereum configuration
	configs[ChainTypeEthereum] = &ChainConfig{
		ChainID:      "1",
		Name:         "Ethereum Mainnet",
		RPC:          "https://eth-mainnet.g.alchemy.com/v2/your-api-key",
		WSS:          "wss://eth-mainnet.g.alchemy.com/v2/your-api-key",
		RequiredConf: 12,
		BlockTime:    12 * time.Second,
		MaxGasPrice:  new(big.Int).Mul(big.NewInt(100), big.NewInt(1e9)), // 100 gwei
		NativeToken: TokenInfo{
			Symbol:   "ETH",
			Name:     "Ethereum",
			Decimals: 18,
			Standard: TokenStandardNative,
			ChainID:  "1",
			IsNative: true,
		},
		SupportedTokens: []TokenInfo{
			{
				Symbol:       "USDC",
				Name:         "USD Coin",
				Decimals:     6,
				Standard:     TokenStandardERC20,
				ContractAddr: "0xA0b86a33E6441b8C4505B8C4505B8C4505B8C4505",
				ChainID:      "1",
				IsNative:     false,
			},
		},
		IsTestnet: false,
	}
	
	// Solana configuration
	configs[ChainTypeSolana] = &ChainConfig{
		ChainID:      "mainnet-beta",
		Name:         "Solana Mainnet",
		RPC:          "https://api.mainnet-beta.solana.com",
		RequiredConf: 32,
		BlockTime:    400 * time.Millisecond,
		NativeToken: TokenInfo{
			Symbol:   "SOL",
			Name:     "Solana",
			Decimals: 9,
			Standard: TokenStandardNative,
			ChainID:  "mainnet-beta",
			IsNative: true,
		},
		SupportedTokens: []TokenInfo{
			{
				Symbol:       "USDC",
				Name:         "USD Coin",
				Decimals:     6,
				Standard:     TokenStandardSPL,
				ContractAddr: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
				ChainID:      "mainnet-beta",
				IsNative:     false,
			},
		},
		IsTestnet: false,
	}
	
	// BlackHole configuration
	configs[ChainTypeBlackHole] = &ChainConfig{
		ChainID:      "blackhole-1",
		Name:         "BlackHole Blockchain",
		RPC:          "http://localhost:3000",
		RequiredConf: 6,
		BlockTime:    2 * time.Second,
		NativeToken: TokenInfo{
			Symbol:   "BHX",
			Name:     "BlackHole Token",
			Decimals: 18,
			Standard: TokenStandardBHX,
			ChainID:  "blackhole-1",
			IsNative: true,
		},
		SupportedTokens: []TokenInfo{},
		IsTestnet:       true,
	}
	
	return configs
}
