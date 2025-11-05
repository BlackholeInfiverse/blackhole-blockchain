package tests

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/sirupsen/logrus"
	bridge "github.com/Shivam-Patel-G/blackhole-blockchain/bridge-sdk"
)

// TestSignatureVerificationBasic tests basic signature verification
func TestSignatureVerificationBasic(t *testing.T) {
	logger := logrus.New()
	verifier := bridge.NewSignatureVerifier(logger)

	// Generate a keypair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	publicKeyHex := hex.EncodeToString(publicKey)
	privateKeyHex := hex.EncodeToString(privateKey)

	// Create a test transaction
	tx := &bridge.Transaction{
		ID:            "test_tx_001",
		SourceChain:   "ethereum",
		DestChain:     "solana",
		SourceAddress: "0x742d35Cc6634C0532925a3b8D4C9db96590c6C87",
		DestAddress:   "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
		TokenSymbol:   "USDC",
		Amount:        "100.00",
		Fee:           "1.00",
		Status:        "pending",
	}

	// Create payload and sign it
	payload := &bridge.MessagePayload{
		TransactionID:  tx.ID,
		SourceChain:    tx.SourceChain,
		DestChain:      tx.DestChain,
		SourceAddress:  tx.SourceAddress,
		DestAddress:    tx.DestAddress,
		TokenSymbol:    tx.TokenSymbol,
		Amount:         tx.Amount,
		Fee:            tx.Fee,
		Nonce:          1,
	}

	payloadBytes, err := bridge.SerializePayload(payload)
	if err != nil {
		t.Fatalf("Failed to serialize payload: %v", err)
	}

	signature := ed25519.Sign(privateKey, payloadBytes)
	signatureHex := hex.EncodeToString(signature)

	// Create signed message
	signedMsg := &bridge.SignedBridgeMessage{
		Message:   tx,
		Signature: signatureHex,
		PublicKey: publicKeyHex,
	}

	// Verify signature
	isValid, err := verifier.VerifySignature(signedMsg)
	if err != nil {
		t.Fatalf("Signature verification failed with error: %v", err)
	}

	if !isValid {
		t.Error("Valid signature was rejected")
	}
}

// TestSignatureVerificationInvalidSignature tests rejection of invalid signatures
func TestSignatureVerificationInvalidSignature(t *testing.T) {
	logger := logrus.New()
	verifier := bridge.NewSignatureVerifier(logger)

	// Generate a keypair
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	publicKeyHex := hex.EncodeToString(publicKey)

	// Create a test transaction
	tx := &bridge.Transaction{
		ID:            "test_tx_002",
		SourceChain:   "ethereum",
		DestChain:     "solana",
		SourceAddress: "0x742d35Cc6634C0532925a3b8D4C9db96590c6C87",
		DestAddress:   "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
		TokenSymbol:   "USDC",
		Amount:        "100.00",
	}

	// Create an invalid signature (all zeros)
	invalidSignature := make([]byte, ed25519.SignatureSize)
	invalidSignatureHex := hex.EncodeToString(invalidSignature)

	// Create signed message with invalid signature
	signedMsg := &bridge.SignedBridgeMessage{
		Message:   tx,
		Signature: invalidSignatureHex,
		PublicKey: publicKeyHex,
	}

	// Verify signature - should fail
	isValid, err := verifier.VerifySignature(signedMsg)
	if err != nil {
		// Error is acceptable for invalid signature
		t.Logf("Expected error for invalid signature: %v", err)
	}

	if isValid {
		t.Error("Invalid signature was accepted")
	}
}

// TestSignatureVerificationMalformedKey tests rejection of malformed keys
func TestSignatureVerificationMalformedKey(t *testing.T) {
	logger := logrus.New()
	verifier := bridge.NewSignatureVerifier(logger)

	tx := &bridge.Transaction{
		ID:            "test_tx_003",
		SourceChain:   "ethereum",
		DestChain:     "solana",
	}

	signedMsg := &bridge.SignedBridgeMessage{
		Message:   tx,
		Signature: "0000000000000000000000000000000000000000000000000000000000000000",
		PublicKey: "invalid_hex_string",
	}

	_, err := verifier.VerifySignature(signedMsg)
	if err == nil {
		t.Error("Expected error for malformed public key")
	}
}

// TestPublicKeyRegistration tests registering and verifying with stored keys
func TestPublicKeyRegistration(t *testing.T) {
	logger := logrus.New()
	verifier := bridge.NewSignatureVerifier(logger)

	// Generate keypair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	address := "0x742d35Cc6634C0532925a3b8D4C9db96590c6C87"
	publicKeyHex := hex.EncodeToString(publicKey)

	// Register public key
	err = verifier.RegisterPublicKey(address, publicKeyHex)
	if err != nil {
		t.Fatalf("Failed to register public key: %v", err)
	}

	// Create and sign a transaction
	tx := &bridge.Transaction{
		ID:            "test_tx_004",
		SourceChain:   "ethereum",
		DestChain:     "solana",
		SourceAddress: address,
		Amount:        "50.00",
	}

	payload := &bridge.MessagePayload{
		TransactionID:  tx.ID,
		SourceChain:    tx.SourceChain,
		DestChain:      tx.DestChain,
		SourceAddress:  tx.SourceAddress,
		Amount:         tx.Amount,
		Nonce:          1,
	}

	payloadBytes, _ := bridge.SerializePayload(payload)
	signature := ed25519.Sign(privateKey, payloadBytes)
	signatureHex := hex.EncodeToString(signature)

	signedMsg := &bridge.SignedBridgeMessage{
		Message:   tx,
		Signature: signatureHex,
		PublicKey: publicKeyHex,
	}

	// Verify
	isValid, err := verifier.VerifySignature(signedMsg)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	if !isValid {
		t.Error("Valid registered signature was rejected")
	}
}

// TestSignatureVerificationLog tests logging of verification attempts
func TestSignatureVerificationLog(t *testing.T) {
	logger := logrus.New()
	verifier := bridge.NewSignatureVerifier(logger)

	// Get initial log count
	initialLog := verifier.GetVerificationLog()
	initialCount := len(initialLog)

	// Create a test transaction and attempt verification
	tx := &bridge.Transaction{
		ID:            "test_tx_005",
		SourceAddress: "0xtest",
	}

	signedMsg := &bridge.SignedBridgeMessage{
		Message:   tx,
		Signature: "0000000000000000000000000000000000000000000000000000000000000000",
		PublicKey: "invalid",
	}

	verifier.VerifySignature(signedMsg)

	// Check log was updated
	updatedLog := verifier.GetVerificationLog()
	if len(updatedLog) <= initialCount {
		t.Error("Verification log was not updated")
	}
}

// BenchmarkSignatureVerification benchmarks signature verification performance
func BenchmarkSignatureVerification(b *testing.B) {
	logger := logrus.New()
	verifier := bridge.NewSignatureVerifier(logger)

	// Setup
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	publicKeyHex := hex.EncodeToString(publicKey)

	tx := &bridge.Transaction{
		ID:            "bench_tx",
		SourceChain:   "ethereum",
		DestChain:     "solana",
		SourceAddress: "0x742d35Cc6634C0532925a3b8D4C9db96590c6C87",
		Amount:        "100.00",
	}

	payload := &bridge.MessagePayload{
		TransactionID:  tx.ID,
		SourceChain:    tx.SourceChain,
		DestChain:      tx.DestChain,
		SourceAddress:  tx.SourceAddress,
		Amount:         tx.Amount,
		Nonce:          1,
	}

	payloadBytes, _ := bridge.SerializePayload(payload)
	signature := ed25519.Sign(privateKey, payloadBytes)
	signatureHex := hex.EncodeToString(signature)

	signedMsg := &bridge.SignedBridgeMessage{
		Message:   tx,
		Signature: signatureHex,
		PublicKey: publicKeyHex,
	}

	// Benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifier.VerifySignature(signedMsg)
	}
}
