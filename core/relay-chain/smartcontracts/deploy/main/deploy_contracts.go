package main

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/smartcontracts/deploy"
)

// Configuration holds deployment settings
type Configuration struct {
	RPCEndpoint   string
	OwnerAddress  string
	TokenName     string
	TokenSymbol   string
	TokenDecimals uint8
	InitialSupply *big.Int
}

func main() {
	// Setup logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("🚀 Starting smart contract deployment...")

	// Load configuration
	config := loadConfiguration()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Initialize deployer
	deployer := deploy.NewContractDeployer(config.RPCEndpoint, config.OwnerAddress)

	// Deploy token contract
	log.Printf("📄 Deploying token contract: %s (%s)", config.TokenName, config.TokenSymbol)
	contract, addr, err := deployer.DeployTokenContract(
		ctx,
		config.TokenName,
		config.TokenSymbol,
		config.TokenDecimals,
		config.InitialSupply,
	)
	if err != nil {
		log.Fatalf("❌ Failed to deploy token contract: %v", err)
	}

	// Print deployment results
	log.Println("✅ Contract deployed successfully!")
	log.Printf("📍 Contract address: %s", addr)
	log.Printf("💰 Total supply: %s %s", contract.TotalSupply(ctx).String(), config.TokenSymbol)
	log.Printf("👤 Owner address: %s", config.OwnerAddress)
	log.Printf("🔢 Decimals: %d", config.TokenDecimals)

	// Save deployment info
	saveDeploymentInfo(addr, config)
}

func loadConfiguration() Configuration {
	// Get configuration from environment variables or use defaults
	ownerAddr := getEnvOrDefault("OWNER_ADDRESS", "03e2459b73c0c6522530f6b26e834d992dfc55d170bee35d0bcdc047fe0d61c25b")
	rpcEndpoint := getEnvOrDefault("RPC_ENDPOINT", "http://localhost:8080")
	tokenName := getEnvOrDefault("TOKEN_NAME", "BlackHole Token")
	tokenSymbol := getEnvOrDefault("TOKEN_SYMBOL", "BHT")

	// Calculate initial supply: 1 million tokens with 18 decimals
	initialSupply := new(big.Int).Mul(
		big.NewInt(1000000), // 1 million tokens
		new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil), // 18 decimals
	)

	return Configuration{
		RPCEndpoint:   rpcEndpoint,
		OwnerAddress:  ownerAddr,
		TokenName:     tokenName,
		TokenSymbol:   tokenSymbol,
		TokenDecimals: 18,
		InitialSupply: initialSupply,
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func saveDeploymentInfo(contractAddr string, config Configuration) {
	// Create deployment info
	info := fmt.Sprintf(`
Deployment Information
=====================
Time: %s
Contract Address: %s
Token Name: %s
Token Symbol: %s
Decimals: %d
Initial Supply: %s
Owner Address: %s
RPC Endpoint: %s
`,
		time.Now().Format(time.RFC3339),
		contractAddr,
		config.TokenName,
		config.TokenSymbol,
		config.TokenDecimals,
		config.InitialSupply.String(),
		config.OwnerAddress,
		config.RPCEndpoint,
	)

	// Save to file
	filename := fmt.Sprintf("deployment_info_%s.txt", time.Now().Format("20060102_150405"))
	err := os.WriteFile(filename, []byte(info), 0644)
	if err != nil {
		log.Printf("⚠️ Warning: Failed to save deployment info: %v", err)
		return
	}
	log.Printf("📝 Deployment information saved to: %s", filename)
}
