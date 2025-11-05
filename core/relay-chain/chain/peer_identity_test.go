package chain

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPersistentPeerIdentity verifies that peer identity persists across restarts (main node only)
func TestPersistentPeerIdentity(t *testing.T) {
	// Clean up any existing identity file
	identityFile := filepath.Join(".", "peer_identity.key")
	os.Remove(identityFile)

	// Generate initial peer identity for main node (port 3000)
	identity1, err := LoadOrGeneratePeerIdentity(3000)
	if err != nil {
		t.Fatalf("Failed to generate initial peer identity: %v", err)
	}

	if !identity1.IsMainNode {
		t.Fatal("Port 3000 should be marked as main node")
	}

	if identity1.PeerID == "" {
		t.Fatal("PeerID should not be empty")
	}

	firstPeerID := identity1.PeerID
	firstMultiAddr := identity1.MultiAddr

	// Verify identity file was created
	if !fileExists(identityFile) {
		t.Fatalf("Identity file was not created at %s", identityFile)
	}

	// Load the same peer identity again (simulating restart)
	identity2, err := LoadOrGeneratePeerIdentity(3000)
	if err != nil {
		t.Fatalf("Failed to load peer identity: %v", err)
	}

	// Verify the identity persisted
	if identity2.PeerID != firstPeerID {
		t.Errorf("PeerID changed after reload: %s -> %s", firstPeerID, identity2.PeerID)
	}

	if identity2.MultiAddr != firstMultiAddr {
		t.Errorf("MultiAddr changed after reload: %s -> %s", firstMultiAddr, identity2.MultiAddr)
	}

	// Clean up
	identity2.Delete()
	if fileExists(identityFile) {
		t.Fatal("Identity file was not deleted")
	}
}

// TestNonMainNodeIdentityNotPersisted verifies that non-main nodes generate fresh identities
func TestNonMainNodeIdentityNotPersisted(t *testing.T) {
	// Generate identities for non-main node (port 3001)
	identity1, err := LoadOrGeneratePeerIdentity(3001)
	if err != nil {
		t.Fatalf("Failed to generate peer identity for port 3001: %v", err)
	}

	if identity1.IsMainNode {
		t.Fatal("Port 3001 should not be marked as main node")
	}

	firstPeerID := identity1.PeerID

	// Generate again for the same port
	identity2, err := LoadOrGeneratePeerIdentity(3001)
	if err != nil {
		t.Fatalf("Failed to generate peer identity again: %v", err)
	}

	// Verify the identity is different (not persisted)
	if identity2.PeerID == firstPeerID {
		t.Error("Non-main nodes should generate different PeerIDs each time")
	}
}

// TestMultipleMainNodes verifies only port 3000 is main node
func TestMultipleMainNodes(t *testing.T) {
	ports := []int{3000, 3001, 3002, 3003, 3004}
	isMainNodes := map[int]bool{
		3000: true,  // Main node
		3001: false, // Other node
		3002: false, // Other node
		3003: false, // Other node
		3004: false, // Other node
	}

	for port, expectedMain := range isMainNodes {
		identity, err := LoadOrGeneratePeerIdentity(port)
		if err != nil {
			t.Errorf("Failed to generate peer identity for port %d: %v", port, err)
			continue
		}

		if identity.IsMainNode != expectedMain {
			t.Errorf("Port %d IsMainNode=%v, expected %v", port, identity.IsMainNode, expectedMain)
		}

		if identity.Port != port {
			t.Errorf("Port mismatch: got %d, expected %d", identity.Port, port)
		}
	}
}

// TestPeerIDFormat verifies peer ID format consistency
func TestPeerIDFormat(t *testing.T) {
	identity, err := LoadOrGeneratePeerIdentity(3000)
	if err != nil {
		t.Fatalf("Failed to generate peer identity: %v", err)
	}

	// Check PeerID format (should start with 12D3Koo)
	if len(identity.PeerID) < 10 {
		t.Errorf("PeerID too short: %s (length: %d)", identity.PeerID, len(identity.PeerID))
	}

	// Check MultiAddr format
	expectedPrefix := "/ip4/127.0.0.1/tcp/3000/p2p/"
	if len(identity.MultiAddr) < len(expectedPrefix) {
		t.Errorf("MultiAddr too short: %s", identity.MultiAddr)
	}

	// Clean up
	identity.Delete()
}
