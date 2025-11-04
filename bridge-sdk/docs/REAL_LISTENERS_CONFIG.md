# Real Blockchain Listeners Configuration

This document explains how to configure the bridge SDK to use real blockchain listeners instead of mock implementations.

## Environment Variables

To enable real blockchain listeners, set the following environment variable:

```bash
USE_REAL_BLOCKCHAIN_LISTENERS=true
```

By default, this is set to `false` which uses the mock listeners for development and testing.

## Configuration in Code

The bridge SDK checks this environment variable when initializing and will automatically use the appropriate listener implementation:

- When `USE_REAL_BLOCKCHAIN_LISTENERS=true`: Uses real blockchain connections via RPC endpoints
- When `USE_REAL_BLOCKCHAIN_LISTENERS=false` (default): Uses mock event generation for development

## Required Environment Variables

When using real blockchain listeners, ensure these additional environment variables are set:

```bash
ETHEREUM_RPC=https://mainnet.infura.io/v3/YOUR_PROJECT_ID
SOLANA_RPC=https://api.mainnet-beta.solana.com
BLACKHOLE_RPC=ws://your-blackhole-node:8545
```

## Usage Example

```go
// Load configuration
config := bridgesdk.LoadEnvironmentConfig()

// Create SDK instance	sdk := bridgesdk.NewBridgeSDK(config, nil)

// The SDK will automatically use real or mock listeners
// based on the USE_REAL_BLOCKCHAIN_LISTENERS environment variable

// Start listeners
ctx := context.Background()
go sdk.StartEthereumListener(ctx)
go sdk.StartSolanaListener(ctx)
```

## Testing

You can test both modes:

**Mock Mode (Default)**
```bash
# No special variables needed - uses defaults
./bridge-sdk
```

**Real Mode**
```bash
USE_REAL_BLOCKCHAIN_LISTENERS=true \
ETHEREUM_RPC=https://eth-mainnet.alchemyapi.io/v2/your-key \
SOLANA_RPC=https://solana-api.projectserum.com \
./bridge-sdk
```

## Implementation Details

The `StartEthereumListener` and `StartSolanaListener` methods check the `useRealBlockchainListeners` flag and delegate to the appropriate implementation:

- `core.RealBlockchainListener` for real blockchain connections
- Mock implementation for development/testing

This allows seamless switching between modes without code changes.