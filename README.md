# blackhole-bitcoin

# BlackHole Blockchain

Decentralized blockchain for OTC transactions, token management, and DEX, as per the BlackHole Blockchain White Paper.

## Folder Structure
- `relay-chain/`: Proof-of-Stake consensus, token minting, interoperability.
- `parachains/`: OTC Transactions, Token/Wallet, DEX parachains.
- `wallet-backend/`: Server-side wallet logic (cryptography, API clients).
- `wallet-frontend/`: Web-based wallet interface.
- `docs/`: Documentation (white paper, API specs).
- `scripts/`: Setup and deployment scripts.

## Setup
1. Clone the repository: `git clone https://github.com/Shivam-Patel-G/blackhole-blockchain.git`
2. Initialize Go modules in each project directory (e.g., `cd relay-chain && go mod init ...`).
3. Follow `docs/developer-guide.md` for detailed setup.

## Development
Start with `relay-chain/consensus/pos.go` and `api/server.go` to build the minimal Relay Chain.