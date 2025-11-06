package chain

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	libp2pCrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// PeerIdentity manages persistent P2P node identity backed by libp2p keys
type PeerIdentity struct {
	PrivKeyBytes []byte // marshaled libp2p private key (protobuf)
	PeerID       string
	MultiAddr    string
	Port         int
	IsMainNode   bool
	IdentityDir  string
	KeyPath      string // <IdentityDir>/key.pem
	InfoPath     string // <IdentityDir>/peerinfo.json
}

// identityDir determines where to persist identity (env override supported)
func identityDir() string {
	if d := os.Getenv("BLOCKCHAIN_IDENTITY_DIR"); d != "" {
		return d
	}
	// Prefer host-mounted path if available, otherwise local folder
	defaultRoot := filepath.FromSlash("/data/blockchain")
	if st, err := os.Stat(defaultRoot); err == nil && st.IsDir() {
		return filepath.Join(defaultRoot, "identity")
	}
	return filepath.Join(".", "data", "blockchain", "identity")
}

// LoadOrGeneratePeerIdentity loads existing libp2p identity or creates one (persists across runs)
func LoadOrGeneratePeerIdentity(port int) (*PeerIdentity, error) {
pi := &PeerIdentity{Port: port, IsMainNode: port == 3000}
pi.IdentityDir = identityDir()
	pi.KeyPath = filepath.Join(pi.IdentityDir, "key.pem")
	pi.InfoPath = filepath.Join(pi.IdentityDir, "peerinfo.json")

	// Ensure directory exists
	if err := os.MkdirAll(pi.IdentityDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create identity dir: %w", err)
	}

	// Try loading existing key
	if b, err := os.ReadFile(pi.KeyPath); err == nil && len(b) > 0 {
		// Stored as base64 of libp2p protobuf marshaled key
		raw, err := base64.StdEncoding.DecodeString(string(b))
		if err != nil {
			return nil, fmt.Errorf("failed to base64-decode key: %w", err)
		}
		priv, err := libp2pCrypto.UnmarshalPrivateKey(raw)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal libp2p private key: %w", err)
		}
		pub := priv.GetPublic()
		pid, err := peer.IDFromPublicKey(pub)
		if err != nil {
			return nil, fmt.Errorf("failed to derive peer id: %w", err)
		}
		marshaled, _ := libp2pCrypto.MarshalPrivateKey(priv)
		pi.PrivKeyBytes = marshaled
		pi.PeerID = pid.String()
		pi.MultiAddr = fmt.Sprintf("/ip4/127.0.0.1/tcp/%d/p2p/%s", pi.Port, pi.PeerID)
		return pi, nil
	}

	// Generate a new Ed25519 libp2p key and persist it
	priv, _, err := libp2pCrypto.GenerateEd25519Key(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 key: %w", err)
	}
	marshaled, err := libp2pCrypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	if err := os.WriteFile(pi.KeyPath, []byte(base64.StdEncoding.EncodeToString(marshaled)), 0o600); err != nil {
		return nil, fmt.Errorf("failed to write key file: %w", err)
	}
	pub := priv.GetPublic()
	pid, err := peer.IDFromPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to derive peer id: %w", err)
	}
	pi.PrivKeyBytes = marshaled
	pi.PeerID = pid.String()
	pi.MultiAddr = fmt.Sprintf("/ip4/127.0.0.1/tcp/%d/p2p/%s", pi.Port, pi.PeerID)
	return pi, nil
}

// SavePeerInfo writes a JSON containing peerId and multiaddrs for other services to read
func (pi *PeerIdentity) SavePeerInfo(multiaddrs []string, bridgeConnected bool) error {
	info := map[string]interface{}{
		"peerId":          pi.PeerID,
		"multiaddrs":      multiaddrs,
		"bridgeConnected": bridgeConnected,
		"lastSeen":        fmt.Sprintf("%d", os.Getpid()), // placeholder, real timestamp set by writer
	}
	b, _ := json.MarshalIndent(info, "", "  ")
	if err := os.MkdirAll(pi.IdentityDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(pi.InfoPath, b, 0o600)
}

// GetPrivKey returns the libp2p private key (unmarshaled)
func (pi *PeerIdentity) GetPrivKey() (libp2pCrypto.PrivKey, error) {
	return libp2pCrypto.UnmarshalPrivateKey(pi.PrivKeyBytes)
}

// GetPeerAddress returns the full multiaddr for this peer
func (pi *PeerIdentity) GetPeerAddress() string { return pi.MultiAddr }

// GetPeerID returns just the peer ID
func (pi *PeerIdentity) GetPeerID() string { return pi.PeerID }
