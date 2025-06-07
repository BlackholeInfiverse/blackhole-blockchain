# Blackhole Blockchain - Project Workflow Documentation

## 🌊 Complete System Workflow

### 🚀 System Startup Sequence

#### 1. Blockchain Node Initialization
```bash
cd core/relay-chain/cmd/relay
go run main.go 3000
```

**Startup Process**:
1. **Genesis Block Creation**: Initialize blockchain with system tokens
2. **P2P Node Setup**: Create libp2p host on port 3000
3. **Database Initialization**: Open LevelDB for blockchain storage
4. **Stake Ledger Setup**: Initialize with genesis validator
5. **Token Registry**: Create native BHX token
6. **API Server Start**: Launch HTTP server on port 8080
7. **Mining Loop**: Begin block production every 6 seconds
8. **Peer Discovery**: Display multiaddr for wallet connections

**Output Example**:
```
🚀 Your peer multiaddr:
   /ip4/127.0.0.1/tcp/3000/p2p/12D3KooWEHMeACYKmddCU7yvY7FSN78CnhC3bENFmkCcouwu1z8R
🌐 API Server starting on port 8080
🌐 Open http://localhost:8080 in your browser
```

#### 2. Wallet Service Initialization
```bash
cd services/wallet
go run main.go -peerAddr /ip4/127.0.0.1/tcp/3000/p2p/12D3KooW...
```

**Startup Process**:
1. **Command-line Parsing**: Parse peer address flag
2. **MongoDB Connection**: Connect to wallet database
3. **P2P Client Setup**: Create blockchain client on port 5000+
4. **Blockchain Connection**: Connect to blockchain node via P2P
5. **CLI Interface**: Start interactive wallet interface

## 🔄 Core Operational Workflows

### 1. 👤 User Registration & Wallet Creation

```mermaid
graph TD
    A[User Starts Wallet CLI] --> B[Choose Register]
    B --> C[Enter Username/Password]
    C --> D[Argon2id Password Hashing]
    D --> E[Store User in MongoDB]
    E --> F[Login User]
    F --> G[Generate Wallet from Mnemonic]
    G --> H[BIP39 Mnemonic Generation]
    H --> I[BIP32 HD Key Derivation]
    I --> J[AES-256-GCM Encryption]
    J --> K[Store Encrypted Wallet]
    K --> L[Display Wallet Address]
```

**Detailed Steps**:
1. **User Registration**: Secure password hashing with Argon2id
2. **Wallet Generation**: BIP39 mnemonic → BIP32 HD keys → Address
3. **Encryption**: Private keys encrypted with user password
4. **Storage**: Encrypted wallet data stored in MongoDB

### 2. 💰 Token Transfer Workflow

```mermaid
graph TD
    A[User Initiates Transfer] --> B[Enter Wallet Details]
    B --> C[Decrypt Private Key]
    C --> D[Create Transaction]
    D --> E[Sign Transaction]
    E --> F[Send via P2P to Blockchain]
    F --> G[Blockchain Validates Transaction]
    G --> H[Add to Transaction Pool]
    H --> I[Mining Process Includes TX]
    I --> J[Block Added to Chain]
    J --> K[State Updated]
    K --> L[Balance Changes Reflected]
```

**Transaction Lifecycle**:
1. **Creation**: User creates transaction with recipient and amount
2. **Validation**: Wallet validates balance and transaction format
3. **Signing**: Transaction signed with private key (simplified)
4. **Broadcasting**: Sent to blockchain node via P2P
5. **Pool Addition**: Added to pending transaction pool
6. **Mining**: Included in next mined block
7. **Execution**: Applied to blockchain state
8. **Confirmation**: Balance updates reflected

### 3. 🏛️ Staking Workflow

```mermaid
graph TD
    A[User Stakes Tokens] --> B[Create Stake Transaction]
    B --> C[Validate Stake Amount]
    C --> D[Lock Tokens in Staking Contract]
    D --> E[Update Stake Ledger]
    E --> F[Validator Pool Updated]
    F --> G[Weighted Validator Selection]
    G --> H[Block Mining by Validator]
    H --> I[Validator Receives Rewards]
    I --> J[Stake Ledger Updated with Rewards]
```

**Staking Process**:
1. **Token Locking**: Tokens moved to staking_contract address
2. **Stake Recording**: Amount recorded in stake ledger
3. **Validator Eligibility**: Address becomes eligible for validation
4. **Selection Algorithm**: Stake-weighted random selection
5. **Block Rewards**: Validators earn BHX tokens for mining blocks

### 4. ⛏️ Mining & Consensus Workflow

```mermaid
graph TD
    A[Mining Timer Triggers] --> B[Check Pending Transactions]
    B --> C{Transactions Available?}
    C -->|No| D[Skip Mining Round]
    C -->|Yes| E[Select Validator]
    E --> F[Create Block with Transactions]
    F --> G[Validate Block]
    G --> H[Broadcast Block to Network]
    H --> I[Add Block to Chain]
    I --> J[Apply Transactions to State]
    J --> K[Mint Validator Rewards]
    K --> L[Update Stake Ledger]
    L --> M[Log Blockchain State]
```

**Mining Details**:
- **Frequency**: Every 6 seconds (configurable)
- **Validator Selection**: Stake-weighted random selection
- **Block Rewards**: 10 BHX per block
- **Transaction Processing**: All pending transactions included

### 5. 💱 DEX Trading Workflow

```mermaid
graph TD
    A[User Wants to Trade] --> B[Check Available Pairs]
    B --> C[Select Trading Pair]
    C --> D[Get Swap Quote]
    D --> E[Confirm Trade]
    E --> F[Validate Token Balances]
    F --> G[Execute AMM Swap]
    G --> H[Update Liquidity Pool]
    H --> I[Transfer Tokens]
    I --> J[Update User Balances]
```

**DEX Features**:
- **AMM Model**: Constant product formula (x * y = k)
- **Liquidity Pools**: User-provided liquidity
- **Slippage Protection**: Price impact calculation
- **Multiple Pairs**: Support for any token pair

### 6. 🔒 Escrow Workflow

```mermaid
graph TD
    A[Create Escrow] --> B[Define Terms]
    B --> C[Lock Funds]
    C --> D[Notify Parties]
    D --> E[Parties Confirm]
    E --> F{All Confirmed?}
    F -->|No| G[Wait for Confirmations]
    F -->|Yes| H[Release Funds]
    H --> I[Transfer to Recipient]
    I --> J[Close Escrow]
```

**Escrow States**:
- **Created**: Initial escrow setup
- **Confirmed**: All parties agreed
- **Released**: Funds transferred
- **Cancelled**: Escrow terminated

### 7. 🔐 Multi-Signature Workflow

```mermaid
graph TD
    A[Create Multi-Sig Wallet] --> B[Define Owners & Threshold]
    B --> C[Propose Transaction]
    C --> D[Collect Signatures]
    D --> E{Threshold Met?}
    E -->|No| F[Wait for More Signatures]
    E -->|Yes| G[Execute Transaction]
    G --> H[Update Balances]
```

**Multi-Sig Features**:
- **N-of-M Signatures**: Configurable signature requirements
- **Transaction Proposals**: Time-limited proposals
- **Automatic Execution**: When threshold reached

## 🌐 P2P Network Workflow

### Peer Discovery & Connection
```mermaid
graph TD
    A[Blockchain Node Starts] --> B[Generate Peer ID]
    B --> C[Listen on P2P Port]
    C --> D[Display Multiaddr]
    D --> E[Wallet Connects with Multiaddr]
    E --> F[Establish P2P Connection]
    F --> G[Exchange Protocol Handshake]
    G --> H[Ready for Message Exchange]
```

### Message Broadcasting
```mermaid
graph TD
    A[Transaction Created] --> B[Encode as P2P Message]
    B --> C[Send to All Connected Peers]
    C --> D[Peers Validate Message]
    D --> E[Add to Transaction Pool]
    E --> F[Broadcast to Their Peers]
```

## 📊 Data Flow Architecture

### 1. Wallet → Blockchain Flow
```
User Input → Wallet CLI → MongoDB (user data) → P2P Client → Blockchain Node → LevelDB (blockchain data)
```

### 2. Blockchain → Dashboard Flow
```
Blockchain State → API Server → HTTP Response → HTML Dashboard → Real-time Updates
```

### 3. Mining Flow
```
Transaction Pool → Validator Selection → Block Creation → State Application → Database Storage → P2P Broadcasting
```

## 🔄 State Management

### Blockchain State
- **Blocks**: Immutable block history
- **Transactions**: All transaction records
- **Balances**: Token balances per address
- **Stakes**: Validator stake amounts
- **Pools**: DEX liquidity pools

### Wallet State
- **Users**: Encrypted user accounts
- **Wallets**: Encrypted wallet data
- **History**: Transaction history records

## 🚨 Error Handling Workflows

### Connection Failures
```mermaid
graph TD
    A[Connection Attempt] --> B{Connection Successful?}
    B -->|Yes| C[Normal Operation]
    B -->|No| D[Display Error Message]
    D --> E[Enter Offline Mode]
    E --> F[Limited Functionality]
```

### Transaction Failures
```mermaid
graph TD
    A[Transaction Submitted] --> B{Valid Transaction?}
    B -->|Yes| C[Add to Pool]
    B -->|No| D[Reject Transaction]
    D --> E[Return Error to User]
    E --> F[User Corrects Issue]
```

### Consensus Failures
```mermaid
graph TD
    A[Block Received] --> B{Valid Block?}
    B -->|Yes| C[Add to Chain]
    B -->|No| D[Reject Block]
    D --> E[Continue with Current Chain]
```

## 🔧 Configuration Workflows

### Environment Setup
1. **MongoDB**: Start database service
2. **Go Dependencies**: Install required modules
3. **Network Ports**: Ensure ports 3000, 8080 available
4. **File Permissions**: Ensure database write access

### Multi-Node Setup
1. **Start First Node**: `go run main.go 3000`
2. **Copy Peer Address**: From first node output
3. **Start Second Node**: `go run main.go 3001 <peer_address>`
4. **Verify Connection**: Check P2P connection logs

This workflow documentation provides a comprehensive understanding of how all components interact to create a complete blockchain ecosystem.
