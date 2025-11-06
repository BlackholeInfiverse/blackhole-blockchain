// Backup created by Agent Mode before modifications

package chain

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PeerIdentity manages persistent P2P node identity
type PeerIdentity struct {
	PrivateKey   ed25519.PrivateKey
	PublicKey    ed25519.PublicKey
	PeerID       string
	MultiAddr    string
	Port         int
	IsMainNode   bool
	IdentityFile string
}

// LoadOrGeneratePeerIdentity loads an existing peer identity or generates a new one
// Only main node (port 3000) gets persistent identity; other nodes generate fresh ones
func LoadOrGeneratePeerIdentity(port int) (*PeerIdentity, error) {
	identity := &PeerIdentity{
		Port:       port,
		IsMainNode: port == 3000, // Only port 3000 is the main node
	}

	// Only persist identity for main node
	if identity.IsMainNode {
		identity.IdentityFile = filepath.Join(".", "peer_identity.key")

		// Try to load existing identity
		if err := identity.Load(); err == nil {
			fmt.Printf("✅ Loaded persistent peer identity from %s\n", identity.IdentityFile)
			return identity, nil
		}

		// Generate new identity and persist it
		if err := identity.Generate(); err != nil {
			return nil, fmt.Errorf("failed to generate peer identity: %w", err)
		}

		if err := identity.Save(); err != nil {
			return nil, fmt.Errorf("failed to save peer identity: %w", err)
		}

		fmt.Printf("✅ Generated and saved new persistent peer identity to %s\n", identity.IdentityFile)
		return identity, nil
	}

	// For non-main nodes, generate fresh identity without persistence
	if err := identity.Generate(); err != nil {
		return nil, fmt.Errorf("failed to generate peer identity: %w", err)
	}

	fmt.Printf("✅ Generated fresh peer identity for node on port %d (not persisted)\n", port)
	return identity, nil
}

// Generate creates a new Ed25519 key pair and derives peer ID
func (pi *PeerIdentity) Generate() error {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("failed to generate ed25519 key: %w", err)
	}

	pi.PublicKey = publicKey
	pi.PrivateKey = privateKey
	pi.PeerID = derivePeerID(publicKey)
	pi.MultiAddr = fmt.Sprintf("/ip4/127.0.0.1/tcp/%d/p2p/%s", pi.Port, pi.PeerID)

	return nil
}

// Save persists the peer identity to disk (only for main node)
func (pi *PeerIdentity) Save() error {
	if !pi.IsMainNode {
		return nil // Skip saving for non-main nodes
	}

	if pi.IdentityFile == "" {
		return fmt.Errorf("identity file path not set")
	}

	// Create identity data in format: privkey_hex|pubkey_hex|peerid|multiaddr
	identityData := fmt.Sprintf("%s|%s|%s|%s",
		hex.EncodeToString(pi.PrivateKey),
		hex.EncodeToString(pi.PublicKey),
		pi.PeerID,
		pi.MultiAddr,
	)

	// Write to file with restricted permissions (owner read/write only)
	if err := os.WriteFile(pi.IdentityFile, []byte(identityData), 0600); err != nil {
		return fmt.Errorf("failed to write identity file: %w", err)
	}

	return nil
}

// Load reads the peer identity from disk (only for main node)
func (pi *PeerIdentity) Load() error {
	if !pi.IsMainNode {
		return fmt.Errorf("only main node can load persistent identity")
	}

	if pi.IdentityFile == "" {
		pi.IdentityFile = filepath.Join(".", "peer_identity.key")
	}

	// Check if file exists
	data, err := os.ReadFile(pi.IdentityFile)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("identity file not found: %s", pi.IdentityFile)
		}
		return fmt.Errorf("failed to read identity file: %w", err)
	}

	// Parse identity data
	parts := strings.Split(string(data), "|")
	if len(parts) != 4 {
		return fmt.Errorf("invalid identity file format")
	}

	// Decode keys
	privKeyBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode private key: %w", err)
	}

	pubKeyBytes, err := hex.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}

	// Validate key lengths
	if len(privKeyBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid private key size: %d (expected %d)", len(privKeyBytes), ed25519.PrivateKeySize)
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: %d (expected %d)", len(pubKeyBytes), ed25519.PublicKeySize)
	}

	pi.PrivateKey = ed25519.PrivateKey(privKeyBytes)
	pi.PublicKey = ed25519.PublicKey(pubKeyBytes)
	pi.PeerID = parts[2]
	pi.MultiAddr = parts[3]

	return nil
}

// derivePeerID creates a deterministic peer ID from public key
// Using simplified approach compatible with libp2p naming
func derivePeerID(pubKey ed25519.PublicKey) string {
	// Create a deterministic ID from public key hash
	// Format: 12D3Kooxxx... (libp2p style)
	keyBytes := pubKey
	if len(keyBytes) > 16 {
		keyBytes = keyBytes[:16]
	}

	// Convert to base32-like representation
	// Using first 8 bytes of public key as basis
	idStr := hex.EncodeToString(keyBytes)

	// Create libp2p-compatible peer ID format
	// Simplified: use Qm + base32 encoded hash
	peerID := fmt.Sprintf("12D3Koo%s", idStr[:20])

	return peerID
}

// GetPeerAddress returns the full multiaddr for this peer
func (pi *PeerIdentity) GetPeerAddress() string {
	return pi.MultiAddr
}

// GetPeerID returns just the peer ID
func (pi *PeerIdentity) GetPeerID() string {
	return pi.PeerID
}

// Delete removes the persistent identity file (useful for cleanup)
func (pi *PeerIdentity) Delete() error {
	if !pi.IsMainNode {
		return nil
	}

	if pi.IdentityFile != "" && fileExists(pi.IdentityFile) {
		if err := os.Remove(pi.IdentityFile); err != nil {
			return fmt.Errorf("failed to delete identity file: %w", err)
		}
		fmt.Printf("🗑️ Deleted persistent peer identity file: %s\n", pi.IdentityFile)
	}

	return nil
}

// Helper function to check if file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
