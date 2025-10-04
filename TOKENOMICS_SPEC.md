# 🌌 BlackHole Blockchain Tokenomics Specification
**Version 1.0 - Locked Specification**

## 📊 **Total Supply & Distribution**

### **Native Token: BHX (BlackHole)**
- **Total Max Supply**: `1,000,000,000` BHX (1 Billion)
- **Initial Circulating Supply**: `350,000,000` BHX (35%)
- **Decimals**: `18`

### **Initial Distribution Breakdown**
| Category | Allocation | Tokens | Percentage | Vesting |
|----------|------------|--------|------------|---------|
| **Private Sale/Seed** | 100,000,000 BHX | 10% | Immediate unlock |
| **Public Sale** | 200,000,000 BHX | 20% | Immediate unlock |
| **Development Fund** | 150,000,000 BHX | 15% | 24-month linear vest |
| **Staking Rewards** | 100,000,000 BHX | 10% | Released via staking |
| **Team & Advisors** | 150,000,000 BHX | 15% | 12-month cliff, 36-month vest |
| **Ecosystem Incentives** | 150,000,000 BHX | 15% | 6-month cliff, 18-month vest |
| **Reserve Fund** | 150,000,000 BHX | 15% | DAO controlled |

## 💰 **Economic Parameters**

### **Fee Structure**
- **Small Transactions (< 100 BHX)**: FREE (subsidized)
- **Medium Transactions (100-10,000 BHX)**: `0.01%` fee
- **Large Transactions (> 10,000 BHX)**: `0.05%` fee
- **DEX Trading Fee**: `0.3%` (split: 0.25% to LPs, 0.05% to treasury)
- **Bridge Fee**: `0.1%` per cross-chain transfer

### **Fee Burn Mechanism**
- **Burn Rate**: `0.1%` of all transaction fees
- **Treasury Split**: `60%` to validator rewards, `30%` to fee subsidy, `10%` burned
- **Target Annual Deflation**: `1-3%` of circulating supply

### **Staking & Validation**
- **Minimum Validator Stake**: `100,000` BHX
- **Annual Staking Rewards**: `5-12%` APR (dynamic based on participation)
- **Unbonding Period**: `21` days
- **Slashing Penalties**: 
  - Downtime: `0.01%` of stake
  - Double signing: `5%` of stake
  - Malicious behavior: `100%` of stake

### **Inflation Model**
- **Year 1**: `8%` annual inflation for staking rewards
- **Year 2-5**: Decreasing by `1%` per year (7%, 6%, 5%, 4%)
- **Year 6+**: Fixed `3%` annual inflation
- **Fee Subsidy Pool**: `2%` of annual inflation

## 🏛️ **Governance Parameters**

### **Voting Requirements**
- **Proposal Deposit**: `10,000` BHX (refunded if passed)
- **Voting Period**: `7` days
- **Quorum**: `40%` of bonded tokens must vote
- **Pass Threshold**: `50%` of votes (excluding abstain)
- **Veto Threshold**: `33.4%` no-with-veto to reject

### **Proposal Types**
1. **Parameter Change**: Modify economic parameters
2. **Software Upgrade**: Network protocol upgrades  
3. **Treasury Spend**: Allocate funds from treasury
4. **Emergency**: Fast-track critical fixes (24-hour voting)

## 🌉 **Bridge & Cross-Chain**

### **Supported Chains**
- **Ethereum**: BHX ERC20 (1:1 wrapped)
- **Polygon**: BHX ERC20 (1:1 wrapped) 
- **Solana**: BHX SPL (1:1 wrapped)
- **BSC**: BHX BEP20 (1:1 wrapped)

### **Bridge Parameters**
- **Minimum Bridge Amount**: `10` BHX
- **Maximum Daily Bridge**: `1,000,000` BHX per chain
- **Confirmation Requirements**:
  - Ethereum: `12` blocks
  - Polygon: `128` blocks  
  - Solana: `31` slots
  - BSC: `15` blocks

## 💱 **DEX Parameters**

### **AMM Configuration**
- **Trading Fee**: `0.3%` per swap
- **Minimum Liquidity**: `1000` BHX equivalent
- **Price Impact Warning**: `5%`
- **Maximum Slippage**: `50%`
- **LP Token Ratio**: `1:1` for equal value deposits

### **Liquidity Mining**
- **Total Rewards Pool**: `50,000,000` BHX (from Ecosystem Incentives)
- **Reward Distribution**: 18 months linear
- **Tier 1 Pools** (40% of rewards): BHX/USDC, BHX/ETH
- **Tier 2 Pools** (30% of rewards): BHX/MATIC, BHX/BNB  
- **Tier 3 Pools** (30% of rewards): Community-voted pairs

## 🔒 **Security & Risk Parameters**

### **Circuit Breakers**
- **Max Block Size**: `10MB`
- **Max Transaction Size**: `1MB`
- **Rate Limits**: 
  - API: `1000` requests/minute/IP
  - Bridge: `100` transfers/hour/address
  - Relayer: `50` meta-tx/minute/address

### **Emergency Controls**
- **Pause Bridge**: 3/5 multisig can pause for 48 hours
- **Emergency Upgrade**: 4/5 multisig + 24-hour timelock
- **Treasury Access**: 3/5 multisig for emergency funds

## 📅 **Timeline & Milestones**

### **Phase 0**: Specification Lock ✅
- Lock all parameters above
- Deploy updated contracts
- Publish distribution schedule

### **Phase 1**: Private Devnet (Week 1-2)
- 3-node local network
- All parameters implemented
- Meta-transaction system

### **Phase 2**: Public Testnet (Week 3-7)
- Public validators
- Faucet with rate limits
- Bridge integration

### **Phase 3**: Mainnet Launch (Week 8-12)
- Genesis with locked distribution
- Validator onboarding
- Exchange integrations

## 🎯 **Key Performance Indicators**

### **Network Health**
- Block time: `3` seconds average
- Transaction finality: `6` seconds (2 block confirmations)
- Network uptime: `99.9%` target

### **Economic Targets**
- Daily active addresses: `10,000+` by Month 3
- Daily transaction volume: `$100,000+` by Month 6
- Total Value Locked (TVL): `$10,000,000+` by Year 1

### **Decentralization Metrics**
- Number of validators: `100+` by Month 6
- Geographic distribution: `5+` continents
- Nakamoto coefficient: `20+` by Year 1

---

**🔒 This specification is LOCKED and will be implemented exactly as defined above.**

*Last updated: 2025-01-27*  
*Next review: After mainnet launch*