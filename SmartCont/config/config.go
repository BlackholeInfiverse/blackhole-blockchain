package config

import (
	"os"
)

// NetworkConfig holds blockchain network settings
type NetworkConfig struct {
	Blockchain string // e.g., "near", "polkadot", "cosmwasm"
	RPCURL     string
	AccountID  string // For NEAR; address for others
	PrivateKey string
	ChainID    string // For Cosmos; optional for others
}

// GetConfig returns configuration based on environment
func GetConfig() NetworkConfig {
	blockchain := os.Getenv("BLOCKCHAIN")
	if blockchain == "" {
		blockchain = "near" // Default to NEAR
	}

	switch blockchain {
	case "near":
		if os.Getenv("ENV") == "mainnet" {
			return NetworkConfig{
				Blockchain: "near",
				RPCURL:     "https://rpc.mainnet.near.org",
				AccountID:  os.Getenv("blackinfi12.testnet"), // e.g., youraccount.near
				PrivateKey: os.Getenv("ed25519:3e1a7SCmVgMtVigV1EssfUaGzNsJPGoYXSub8AJ7CvaxP8kKhfB6REGKqd1YMWm3TefyRKCBJTbPiwsU4KcbCNmo"),
			}
		}
		return NetworkConfig{
			Blockchain: "near",
			RPCURL:     "https://rpc.testnet.near.org",
			AccountID:  os.Getenv("blackinfi12.testnet"), // e.g., youraccount.testnet
			PrivateKey: os.Getenv("ed25519:3e1a7SCmVgMtVigV1EssfUaGzNsJPGoYXSub8AJ7CvaxP8kKhfB6REGKqd1YMWm3TefyRKCBJTbPiwsU4KcbCNmo"),
		}
	case "polkadot":
		return NetworkConfig{
			Blockchain: "polkadot",
			RPCURL:     "wss://westend-rpc.polkadot.io",
			AccountID:  os.Getenv("POLKADOT_ADDRESS"),
			PrivateKey: os.Getenv("POLKADOT_PRIVATE_KEY"),
		}
	case "cosmwasm":
		return NetworkConfig{
			Blockchain: "cosmwasm",
			RPCURL:     "https://rpc.malaga-420.cosmwasm.com",
			AccountID:  os.Getenv("COSMOS_ADDRESS"),
			PrivateKey: os.Getenv("COSMOS_PRIVATE_KEY"),
			ChainID:    "malaga-420",
		}
	default:
		panic("Unsupported blockchain: " + blockchain)
	}
}
