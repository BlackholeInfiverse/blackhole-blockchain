# Blackhole Blockchain - Module Functionality Documentation

## 🔧 Core Blockchain Modules

### 1. 🌐 Blockchain Core (`core/relay-chain/chain/`)

#### blockchain.go - Main Blockchain Engine
**Purpose**: Central blockchain management and state coordination

**Key Functions**:
- `NewBlockchain(port)`: Initialize blockchain with genesis block
- `AddBlock(block)`: Validate and add blocks to chain
- `MineBlock(validator)`: Create new blocks with pending transactions
- `BroadcastBlock(block)`: Distribute blocks via P2P network
- `GetBlockchainInfo()`: Return current blockchain statistics

**Features**:
- ✅ Genesis block initialization with system tokens
- ✅ Block validation and chain integrity
- ✅ Transaction pool management
- ✅ State persistence with LevelDB
- ✅ P2P block broadcasting
- ✅ Token registry management

**Data Structures**:
```go
type Blockchain struct {
    Blocks           []*Block
    PendingTxs       []*Transaction
    StakeLedger      *StakeLedger
    TokenRegistry    map[string]*Token
    GlobalState      map[string]*AccountState
    P2PNode          *Node
    DB               *leveldb.DB
}
```

#### transaction.go - Transaction Processing
**Purpose**: Handle all transaction types and validation

**Transaction Types**:
- `TokenTransfer`: Standard token transfers
- `StakeDeposit`: Staking tokens for validation
- `StakeWithdraw`: Unstaking tokens
- `Reward`: Validator block rewards

**Key Functions**:
- `CalculateHash()`: Generate transaction hash
- `IsValid()`: Validate transaction structure
- `ApplyTransaction()`: Execute transaction on blockchain state

**Validation Rules**:
- ✅ Balance validation before transfers
- ✅ Signature verification (simplified)
- ✅ Nonce checking for replay protection
- ✅ Token existence validation

#### stakeledger.go - Staking System
**Purpose**: Manage validator stakes and rewards

**Key Functions**:
- `AddStake(address, amount)`: Add stake for validator
- `RemoveStake(address, amount)`: Remove stake from validator
- `GetStake(address)`: Get current stake amount
- `GetAllStakes()`: Return all validator stakes

**Features**:
- ✅ Token locking mechanism
- ✅ Validator eligibility tracking
- ✅ Stake-weighted validator selection
- ✅ Reward distribution

#### p2p.go - P2P Networking
**Purpose**: Handle peer-to-peer communication

**Key Functions**:
- `NewNode(port)`: Create P2P node
- `Connect(peerAddr)`: Connect to peer
- `BroadcastMessage(msg)`: Send message to all peers
- `handleStream()`: Process incoming P2P messages

**Message Types**:
- `MessageTypeTx`: Transaction broadcasting
- `MessageTypeBlock`: Block broadcasting
- `MessageTypeSync`: Chain synchronization

### 2. 🏛️ Consensus Module (`core/relay-chain/consensus/`)

#### pos.go - Proof of Stake
**Purpose**: Validator selection and block validation

**Key Functions**:
- `SelectValidator()`: Choose validator based on stake weight
- `ValidateBlock()`: Verify block meets consensus rules
- `CalculateReward()`: Determine block rewards

**Consensus Rules**:
- ✅ Stake-weighted random selection
- ✅ Block time interval validation
- ✅ Longest chain rule
- ✅ Fork resolution

**Validator Selection Algorithm**:
```go
// Weighted random selection based on stake
totalStake := sum(allStakes)
selection := random(0, totalStake)
runningTotal := 0
for validator, stake := range stakes {
    runningTotal += stake
    if runningTotal > selection {
        return validator
    }
}
```

### 3. 🪙 Token System (`core/relay-chain/token/`)

#### token.go - Core Token Implementation
**Purpose**: ERC-20 compatible token system

**Key Functions**:
- `NewToken(name, symbol, decimals, supply)`: Create new token
- `Transfer(from, to, amount)`: Transfer tokens
- `Mint(to, amount)`: Create new tokens
- `Burn(from, amount)`: Destroy tokens
- `BalanceOf(address)`: Get token balance

**Features**:
- ✅ Multiple token support
- ✅ Overflow protection
- ✅ Event emission
- ✅ Allowance system
- ✅ Thread-safe operations

**Security Features**:
- Overflow/underflow protection
- Address validation
- Balance verification
- Atomic operations with mutex locks

### 4. 💱 DEX Module (`core/relay-chain/dex/`)

#### dex.go - Automated Market Maker
**Purpose**: Decentralized exchange with liquidity pools

**Key Functions**:
- `CreatePair(tokenA, tokenB)`: Create trading pair
- `AddLiquidity(tokenA, tokenB, amountA, amountB)`: Add liquidity
- `Swap(tokenIn, tokenOut, amountIn)`: Execute token swap
- `GetQuote(tokenIn, tokenOut, amountIn)`: Get swap quote

**AMM Formula**: `x * y = k` (constant product)

**Features**:
- ✅ Multiple trading pairs
- ✅ Liquidity provider rewards
- ✅ Slippage protection
- ✅ Price impact calculation

### 5. 🔒 Escrow Module (`core/relay-chain/escrow/`)

#### escrow.go - Multi-Party Escrow
**Purpose**: Secure multi-party transactions

**Key Functions**:
- `CreateEscrow()`: Create escrow contract
- `ConfirmEscrow()`: Confirm escrow terms
- `ReleaseEscrow()`: Release funds to recipient
- `CancelEscrow()`: Cancel and refund escrow

**Escrow States**:
- `Created`: Initial state
- `Confirmed`: All parties confirmed
- `Released`: Funds released
- `Cancelled`: Escrow cancelled

### 6. 🔐 Multi-Signature Module (`core/relay-chain/multisig/`)

#### multisig.go - Multi-Signature Wallets
**Purpose**: N-of-M signature requirement wallets

**Key Functions**:
- `CreateWallet(owners, requiredSigs)`: Create multi-sig wallet
- `ProposeTransaction()`: Propose transaction
- `SignTransaction()`: Sign proposed transaction
- `ExecuteTransaction()`: Execute when enough signatures

**Features**:
- ✅ Configurable signature thresholds
- ✅ Transaction proposals with expiration
- ✅ Automatic execution when threshold met
- ✅ Owner management

### 7. 🤝 OTC Trading Module (`core/relay-chain/otc/`)

#### otc.go - Over-The-Counter Trading
**Purpose**: Peer-to-peer trading with optional multi-sig

**Key Functions**:
- `CreateOrder()`: Create OTC order
- `MatchOrder()`: Match with counterparty
- `SignOrder()`: Multi-sig order signing
- `CancelOrder()`: Cancel open order

**Order Types**:
- Simple P2P orders
- Multi-signature orders
- Time-limited orders

### 8. 🌉 Cross-Chain Modules

#### bridge/bridge.go - Cross-Chain Bridge
**Purpose**: Mock cross-chain token transfers

**Key Functions**:
- `InitiateBridge()`: Start cross-chain transfer
- `ProcessBridge()`: Handle bridge transaction
- `GetBridgeStatus()`: Check transfer status

#### interoperability/cross_chain.go - Cross-Chain Protocols
**Purpose**: Cross-chain communication protocols

**Supported Chains**:
- Blackhole (native)
- Ethereum (mock)
- Polkadot (mock)

## 🔧 Service Modules

### 9. 💼 Wallet Service (`services/wallet/`)

#### wallet/wallet.go - Wallet Management
**Purpose**: User accounts and wallet creation

**Key Functions**:
- `RegisterUser()`: Create user account
- `AuthenticateUser()`: Login user
- `GenerateWalletFromMnemonic()`: Create HD wallet
- `ImportWalletFromPrivateKey()`: Import existing wallet
- `GetWalletDetails()`: Retrieve wallet information

**Security Features**:
- ✅ Argon2id password hashing
- ✅ AES-256-GCM wallet encryption
- ✅ BIP32/BIP39 HD wallet generation
- ✅ Secure key derivation

#### wallet/blockchain_client.go - Blockchain Connection
**Purpose**: P2P connection to blockchain nodes

**Key Functions**:
- `NewBlockchainClient()`: Create P2P client
- `ConnectToBlockchain()`: Connect to blockchain node
- `TransferTokens()`: Send token transfer transaction
- `StakeTokens()`: Send staking transaction

**Connection Features**:
- ✅ Command-line peer address support
- ✅ Offline mode capability
- ✅ Connection status monitoring
- ✅ Transaction broadcasting

#### wallet/token_operations.go - Token Operations
**Purpose**: Wallet token functionality

**Key Functions**:
- `CheckTokenBalance()`: Get token balance
- `TransferTokens()`: Transfer tokens
- `StakeTokens()`: Stake tokens for validation

#### wallet/transaction_history.go - Transaction Tracking
**Purpose**: Transaction history and monitoring

**Key Functions**:
- `RecordTransaction()`: Save transaction record
- `GetWalletTransactionHistory()`: Get wallet transactions
- `UpdateTransactionStatus()`: Update transaction status

### 10. 🌐 API Module (`core/relay-chain/api/`)

#### server.go - HTTP API & Dashboard
**Purpose**: REST API and real-time HTML dashboard

**API Endpoints**:
- `GET /api/blockchain/info`: Blockchain statistics
- `GET /api/node/info`: Node peer information
- `POST /api/admin/add-tokens`: Admin token management
- `GET /api/wallets`: Wallet information

**Dashboard Features**:
- ✅ Real-time blockchain monitoring
- ✅ Token balance visualization
- ✅ Staking information display
- ✅ Admin panel for testing
- ✅ Auto-refresh every 3 seconds

## 🔄 Module Interactions

### Transaction Flow
```
Wallet CLI → P2P Client → Blockchain Node → Transaction Pool → Mining → Block Addition → State Update
```

### Staking Flow
```
Wallet → Stake Transaction → Blockchain → Stake Ledger → Validator Selection → Block Rewards
```

### DEX Trading Flow
```
User → DEX Order → Liquidity Pool → AMM Calculation → Token Swap → Balance Update
```

### Cross-Chain Flow
```
Source Chain → Bridge Contract → Relay Network → Destination Chain → Token Mint/Burn
```
