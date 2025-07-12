package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

func main() {
	// Generate new ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("Failed to generate key pair:", err)
	}

	// Convert private key to bytes and hex
	privateKeyBytes := privateKey.D.Bytes()
	privateKeyHex := hex.EncodeToString(privateKeyBytes)

	// Get public key in compressed format
	publicKeyBytes := elliptic.MarshalCompressed(privateKey.PublicKey.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)
	publicKeyHex := hex.EncodeToString(publicKeyBytes)

	// Write to a file instead of stdout
	f, err := os.Create("wallet_details.txt")
	if err != nil {
		log.Fatal("Failed to create file:", err)
	}
	defer f.Close()

	fmt.Fprintln(f, "Generated new key pair:")
	fmt.Fprintln(f, "Private Key:", privateKeyHex)
	fmt.Fprintln(f, "Public Key:", publicKeyHex)
	fmt.Fprintln(f, "\nConnection Details:")
	fmt.Fprintln(f, "RPC URL: http://localhost:8080")
	fmt.Fprintln(f, "Contract Address: 0xd3c21bcecceda1000000")

	fmt.Println("Wallet details have been saved to wallet_details.txt")
}
