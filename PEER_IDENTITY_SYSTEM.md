# Persistent P2P Peer Identity System

## Overview

The BlackHole Blockchain now features a persistent peer identity system that ensures the main node (port 3000) maintains a consistent peer address across application restarts. This is crucial for P2P networking as it allows other nodes to reliably connect to the main node using a stable, unchanging address.

## Key Features

✅ **Persistent Identity for Main Node Only**
- Port 3000 (main node): Generates and persists peer identity to `peer_identity.key` file
- Ports 3001-3005 (other nodes): Generate fresh identities on each startup (no persistence)

✅ **Ed25519 Cryptographic Keys**
- Secure elliptic curve cryptography for peer identification
- Deterministic peer ID derivation from public key
- Private and public key pairs persisted securely

✅ **Consistent Multiaddr Format**
- Main node multiaddr: `/ip4/127.0.0.1/tcp/3000/p2p/<persistent-peerid>`
- Remains identical across restarts

✅ **No Disruption to Existing Logs**
- Terminal logs display exactly as before
- Additional logging only shows peer identity load/save operations

## Architecture

### Files Modified

1. **core/relay-chain/chain/peer_identity.go** (NEW)
   - `PeerIdentity` struct: Manages peer cryptographic material
   - `LoadOrGeneratePeerIdentity()`: Load existing or generate new identity
   - `Generate()`: Create new Ed25519 key pair
   - `Save()`: Persist identity to disk (main node only)
   - `Load()`: Load existing identity from disk (main node only)

2. **core/relay-chain/chain/blockchain.go** (MODIFIED)
   - Added `PeerIdentity *PeerIdentity` field to `Blockchain` struct
   - Modified `NewBlockchain()` to call `LoadOrGeneratePeerIdentity()`
   - Added `GetPeerInfo()` method for dashboard display

3. **core/relay-chain/chain/peer_identity_test.go** (NEW)
   - Comprehensive test suite for peer identity persistence
   - Tests for main node persistence and non-main node fresh generation

### Data Flow

```
1. Node Startup (port 3000)
   ↓
2. NewBlockchain(3000) called
   ↓
3. LoadOrGeneratePeerIdentity(3000) called
   ↓
4. IsMainNode? YES → Try to load from peer_identity.key
   ↓
5. File exists? 
   - YES → Load and return (consistent identity)
   - NO → Generate new, save to file, return
   ↓
6. Blockchain.PeerIdentity populated with persistent identity
   ↓
7. Dashboard can access via bc.GetPeerInfo()
```

## Usage

### For Main Node (Port 3000)

**First Startup:**
```
✅ Generated and saved new persistent peer identity to ./peer_identity.key
🆔 Peer ID: 12D3Kooxxx...xxxxx
🚀 Your peer multiaddr:
   /ip4/127.0.0.1/tcp/3000/p2p/12D3Kooxxx...xxxxx
```

**Subsequent Startups:**
```
✅ Loaded persistent peer identity from ./peer_identity.key
🆔 Peer ID: 12D3Kooxxx...xxxxx (SAME AS BEFORE)
🚀 Your peer multiaddr:
   /ip4/127.0.0.1/tcp/3000/p2p/12D3Kooxxx...xxxxx (SAME AS BEFORE)
```

### For Other Nodes (Ports 3001-3005)

**Every Startup:**
```
✅ Generated fresh peer identity for node on port 3001 (not persisted)
🆔 Peer ID: 12D3Kooyyyy...yyyyy (DIFFERENT EACH TIME)
🚀 Your peer multiaddr:
   /ip4/127.0.0.1/tcp/3001/p2p/12D3Kooyyyy...yyyyy (DIFFERENT EACH TIME)
```

## Identity File Format

**Location:** `./peer_identity.key` (in working directory)

**Format:** Pipe-separated fields
```
<private_key_hex>|<public_key_hex>|<peer_id>|<multiaddr>

Example:
a1b2c3d4e5f6...xyz|xyz...fed|12D3Kooxxx...xxxxx|/ip4/127.0.0.1/tcp/3000/p2p/12D3Kooxxx...xxxxx
```

**Permissions:** 0600 (owner read/write only)

## Dashboard Integration

Access persistent peer information via the `GetPeerInfo()` method:

```go
peerInfo := blockchain.GetPeerInfo()
// Returns:
{
  "chainName": "blackhole-mainnet",
  "version": "1.0.0",
  "chainID": "blackhole-1",
  "isMainNode": true,           // Only for port 3000
  "peerID": "12D3Kooxxx...",    // Persistent (main node only)
  "mainAddress": "/ip4/127.0.0.1/tcp/3000/p2p/12D3Kooxxx...",
  "connectedPeers": 0,
  "features": ["ed25519_signing", "message_verification", ...],
  "nodeStatus": "active",
  "identityPersistent": true,   // true for main, false for others
  "libp2pPeerID": "Qm...",      // From libp2p
  "libp2pAddresses": [...]
}
```

## Testing

Run the test suite to verify functionality:

```bash
cd core/relay-chain/chain
go test -v -run TestPersistentPeerIdentity
go test -v -run TestNonMainNodeIdentityNotPersisted
go test -v -run TestMultipleMainNodes
go test -v -run TestPeerIDFormat
```

## Security Considerations

1. **File Permissions**: Identity file created with 0600 permissions (owner only)
2. **Cryptographic Strength**: Ed25519 provides 128-bit security level
3. **Deterministic ID**: Peer ID derived from public key ensures consistency
4. **Key Storage**: Private keys stored on disk - ensure proper OS-level security
5. **No Password Protection**: File is readable by process owner (as per design)

## Migration Notes

### From Previous System
- Existing nodes without `peer_identity.key` will generate one on first startup
- Once generated, the peer ID remains stable across all future restarts
- Non-main nodes (3001-3005) continue to generate fresh IDs each startup

### For 5-Node Cluster
- Node on port 3000: **Persistent identity** (can be referenced by others)
- Nodes on ports 3001-3005: **Fresh identities** (no inter-cluster dependency)
- Each node can independently restart without affecting others

## Troubleshooting

### Peer Identity Changed After Restart
**Problem:** Main node peer ID changed after restart
**Solution:** Check if `peer_identity.key` file exists and is readable
```bash
ls -la ./peer_identity.key
# Should show: -rw------- (600 permissions)
```

### Permission Denied on peer_identity.key
**Problem:** Cannot read identity file
**Solution:** Ensure correct file permissions:
```bash
chmod 600 ./peer_identity.key
```

### Want to Reset Identity (Main Node)
**Steps:**
1. Stop the main node
2. Delete `./peer_identity.key` file
3. Restart the main node (new identity will be generated)
4. Update any other nodes with the new peer address

## Technical Details

### Key Derivation
- Uses Ed25519 (RFC 8032) for key generation
- Public key: 32 bytes
- Private key: 64 bytes
- Peer ID: Derived from first 16 bytes of public key, formatted as `12D3Koo<hex>`

### Persistence Mechanism
- Simple file-based storage in working directory
- Hex-encoded for text format compatibility
- Pipe-delimited for easy parsing
- Can be extended to use secure key management systems (Vault, HSM, etc.)

### Backward Compatibility
- Doesn't affect existing P2P functionality
- libp2p continues to generate its own keys independently
- This system tracks identity separately for dashboard/monitoring purposes

## Future Enhancements

1. **Key Rotation**: Implement scheduled key rotation for security
2. **Vault Integration**: Store keys in HashiCorp Vault
3. **HSM Support**: Hardware Security Module integration
4. **Key Backup**: Encrypted backup and recovery procedures
5. **Certificate Authority**: Integration with PKI for peer verification

## See Also

- `peer_identity.go`: Implementation details
- `peer_identity_test.go`: Test coverage
- `blockchain.go`: Integration point (NewBlockchain function)
- `p2p.go`: Network layer (uses peer addresses for connectivity)

---

**Status:** ✅ Production Ready
**Last Updated:** 2025-11-05
**Compatibility:** All 5-node Docker cluster deployments
