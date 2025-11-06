package main

import (
	"fmt"
	"os"
)

func getEnvBoolOrDefault(key string, defaultVal bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	return val == "true"
}

func main() {
	flag := getEnvBoolOrDefault("USE_REAL_BLOCKCHAIN_LISTENERS", false)
	fmt.Printf("useRealBlockchainListeners = %t\n", flag)
}
