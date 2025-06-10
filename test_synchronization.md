# 🧪 Blockchain Synchronization Test Guide

## Test the Token Balance Synchronization Fix

### **Step 1: Start the Blockchain Node**
```bash
cd core/relay-chain/cmd/relay
go run main.go 3000
```
**Expected Output:**
- ✅ Blockchain initialized with BHX token
- ✅ API server running on port 8080
- ✅ P2P node running on port 3000

### **Step 2: Start the Wallet Service**
```bash
cd services/wallet
go run main.go -web -port 9000 -peerAddr /ip4/127.0.0.1/tcp/3000/p2p/[PEER_ID]
```
**Expected Output:**
- ✅ Connected to blockchain peer
- ✅ Wallet UI available on port 9000

### **Step 3: Test Token Balance Synchronization**

#### **3.1 Add Tokens via Admin Panel**
1. Open http://localhost:8080
2. Go to Admin Panel
3. Add tokens:
   - Address: `test_address_123`
   - Token: `BHX`
   - Amount: `1000`
4. Click "Add Tokens"

**Expected Result:**
- ✅ Success message: "Tokens added successfully!"
- ✅ Token Balances section shows: `test_address_123: 1000 BHX`

#### **3.2 Query Balance via Wallet**
1. Open http://localhost:9000
2. Create a wallet with address `test_address_123` (or use existing)
3. Check balance for BHX tokens

**Expected Result:**
- ✅ Wallet shows: `1000 BHX` (same as admin panel)
- ✅ No more placeholder values

#### **3.3 Test Direct API Query**
```bash
curl -X POST http://localhost:8080/api/balance/query \
  -H "Content-Type: application/json" \
  -d '{"address": "test_address_123", "token_symbol": "BHX"}'
```

**Expected Response:**
```json
{
  "success": true,
  "data": {
    "address": "test_address_123",
    "token_symbol": "BHX",
    "balance": 1000
  }
}
```

### **Step 4: Test Staking Integration**

#### **4.1 Stake Tokens via Wallet**
1. In wallet UI, stake 500 BHX tokens
2. Check dashboard staking section

**Expected Results:**
- ✅ Wallet balance decreases: `1000 → 500 BHX`
- ✅ Staking contract balance increases: `+500 BHX`
- ✅ Dashboard shows staking info: `test_address_123: 500 staked`

#### **4.2 Verify Token Movement**
1. Check admin dashboard Token Balances
2. Look for `staking_contract` entry

**Expected Result:**
- ✅ `staking_contract: 500 BHX`
- ✅ `test_address_123: 500 BHX` (remaining)

### **Step 5: Test Real-Time Updates**

#### **5.1 Add More Tokens**
1. Add 2000 more BHX to `test_address_123` via admin panel
2. Immediately check wallet balance

**Expected Result:**
- ✅ Wallet balance updates: `500 → 2500 BHX`
- ✅ No delay or cache issues

#### **5.2 Test Mining Rewards**
1. Wait for a few blocks to be mined
2. Check if validator addresses receive BHX rewards
3. Verify staking information updates

**Expected Results:**
- ✅ Validators receive 10 BHX per block
- ✅ Stake amounts increase with rewards
- ✅ Dashboard shows updated staking info

## 🔍 Debugging Output

### **Wallet Balance Query Debug Output:**
```
🔍 Querying balance for address test_address_123, token BHX
🔄 Trying dedicated balance query endpoint on port 8080...
   📡 Querying dedicated endpoint: http://localhost:8080/api/balance/query
   ✅ Dedicated endpoint returned balance: 1000.000000
✅ Retrieved balance from dedicated endpoint: 1000 BHX for address test_address_123
```

### **Blockchain API Debug Output:**
```
🔍 Balance query: address=test_address_123, token=BHX
✅ Balance found: 1000 BHX for address test_address_123
```

## ✅ Success Criteria

- [ ] Admin panel and wallet show **identical** BHX balances
- [ ] Staking operations properly **move** BHX tokens
- [ ] Dashboard staking info **updates** in real-time
- [ ] No more **placeholder** balance values
- [ ] All services query the **same** token registry

## ❌ Failure Indicators

- ❌ Wallet shows 0 BHX when admin panel shows 1000 BHX
- ❌ Staking doesn't reduce wallet balance
- ❌ Dashboard shows outdated staking information
- ❌ Wallet returns placeholder 1000 balance
- ❌ API queries fail with connection errors

## 🔧 Troubleshooting

### **If Balance Query Fails:**
1. Check if blockchain node is running on port 8080
2. Verify P2P connection between wallet and blockchain
3. Check console output for API errors

### **If Staking Doesn't Work:**
1. Verify wallet has sufficient BHX balance
2. Check if staking transaction is created properly
3. Look for token transfer errors in blockchain logs

### **If Dashboard Doesn't Update:**
1. Refresh the dashboard (auto-refresh every 3 seconds)
2. Check if blockchain is mining new blocks
3. Verify token registry is properly initialized
