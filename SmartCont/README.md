# NEAR Smart Contract: kvstore.wasm

This README provides step-by-step instructions to set up, build, deploy, and interact with the `kvstore.wasm` smart contract on the NEAR testnet.

---

## 🚀 Prerequisites

- [Node.js](https://nodejs.org/) (v14+ recommended)
- [NEAR CLI](https://docs.near.org/tools/near-cli) (`npm install -g near-cli`)
- NEAR testnet account ([Create one here](https://wallet.testnet.near.org/))
- Contract source code and compiled `kvstore.wasm` file

---

## 1. Setup

1. **Clone the repository (if not already):**
   ```bash
   git clone <your-repo-url>
   cd SmartCont
   ```

2. **Install NEAR CLI (if not already):**
   ```bash
   npm install -g near-cli
   ```

3. **Login to NEAR testnet:**
   ```bash
   near login
   ```
   - This will open a browser window. Authorize the CLI to access your account.

---

## 2. Build Contract

If you have Rust source code:

```bash
# Install Rust (if not already)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add wasm target
rustup target add wasm32-unknown-unknown

# Build contract (from contract source directory)
cargo build --target wasm32-unknown-unknown --release

# Copy the .wasm file to SmartCont/contract/
cp target/wasm32-unknown-unknown/release/kvstore.wasm SmartCont/contract/
```

If you already have `kvstore.wasm`, skip this step.

---

## 3. Deploy Contract

1. **Set your NEAR account ID:**
   - Replace `<your-account>.testnet` with your actual testnet account.

2. **Deploy using NEAR CLI:**
   ```bash
   near deploy <your-account>.testnet contract/kvstore.wasm -v
   ```
   - If redeploying, NEAR CLI will ask for confirmation if a contract already exists.

---

## 4. Interact with the Contract

### Call a View Method (Read)
```bash
near view <your-account>.testnet get '{"key": "somekey"}'
```

### Call a Change Method (Write)
```bash
near call <your-account>.testnet set '{"key": "somekey", "value": "somevalue"}' --accountId <your-account>.testnet
```

---

## 5. Useful Links
- [NEAR CLI Docs](https://docs.near.org/tools/near-cli)
- [NEAR Testnet Explorer](https://testnet.nearblocks.io/)
- [NEAR Wallet (Testnet)](https://wallet.testnet.near.org/)

---

## 6. Example Deployment Output

```
near deploy blackinfi12.testnet contract/kvstore.wasm -v
# ...
# Done deploying to blackinfi12.testnet
# Transaction Id ...
# Open the explorer for more info: https://testnet.nearblocks.io/txns/<transaction_id>
```

---

## 7. Troubleshooting
- Make sure your NEAR CLI is logged in to the correct account.
- Ensure you have enough testnet NEAR tokens for deployment.
- If you see errors about contract already deployed, confirm with 'y' to overwrite.

---

**Happy Hacking!** 