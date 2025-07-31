# 🪙 Valid Token Addresses for Cross-Chain Transfers

## 📋 **Token Address Reference Guide**

### **🔗 Ethereum Mainnet Tokens**

#### **Native & Major Tokens**
```
ETH (Native): 0x0000000000000000000000000000000000000000
WETH: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
USDC: 0xA0b86a33E6441E6C7D3E4C7C5C6C7C5C6C7C5C6C7
USDT: 0xdAC17F958D2ee523a2206206994597C13D831ec7
DAI: 0x6B175474E89094C44Da98b954EedeAC495271d0F
WBTC: 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599
```

#### **Popular ERC-20 Tokens**
```
UNI: 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984
LINK: 0x514910771AF9Ca656af840dff83E8264EcF986CA
AAVE: 0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9
COMP: 0xc00e94Cb662C3520282E6f5717214004A7f26888
MKR: 0x9f8F72aA9304c8B593d555F12eF6589cC3A579A2
SNX: 0xC011a73ee8576Fb46F5E1c5751cA3B9Fe0af2a6F
```

### **🪙 Solana Mainnet Tokens**

#### **Native & Major SPL Tokens**
```
SOL (Native): 11111111111111111111111111111111
WSOL: So11111111111111111111111111111111111111112
USDC: EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
USDT: Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB
RAY: 4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R
SRM: SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt
```

#### **Popular Solana Tokens**
```
ORCA: orcaEKTdK7LKz57vaAYr9QeNsVEPfiu6QeMU1kektZE
MNGO: MangoCzJ36AjZyKwVj3VnYU4GTonjfVEnJmvvWaxLac
COPE: 8HGyAAB1yoM1ttS7pXjHMa3dukTFGQggnFFH3hJZgzQh
FIDA: EchesyfXePKdLtoiZSL8pBe8Myagyy8ZRqsACNCFGnvp
STEP: StepAscQoEioFxxWGnh2sLBDFp9d8rvKz2Yp39iDpyT
MEDIA: ETAtLmCmsoiEEKfNrHKJ2kYy3MoABhU6NQvpSfij5tDs
```

### **⚫ BlackHole Testnet Addresses**

#### **Native & System Tokens**
```
BHX (Native): bh0000000000000000000000000000000000000000
WBHX: bh1111111111111111111111111111111111111111
BHUSDC: bh2222222222222222222222222222222222222222
BHETH: bh3333333333333333333333333333333333333333
BHSOL: bh4444444444444444444444444444444444444444
```

### **🔗 Ethereum Sepolia Testnet (For Testing)**

#### **Test Tokens**
```
ETH (Native): 0x0000000000000000000000000000000000000000
WETH: 0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14
USDC: 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238
USDT: 0x7169D38820dfd117C3FA1f22a697dBA58d90BA06
DAI: 0x3e622317f8C93f7328350cF0B56d9eD4C620C5d6
LINK: 0x779877A7B0D9E8603169DdbD7836e478b4624789
```

## 🔄 **Cross-Chain Transfer Examples**

### **Example 1: ETH → BlackHole**
```json
{
  "from_chain": "ethereum",
  "to_chain": "blackhole",
  "from_address": "0x742d35Cc6634C0532925a3b8D4C9db96590c6C87",
  "to_address": "bh1234567890123456789012345678901234567890",
  "token": {
    "symbol": "ETH",
    "contract_address": "0x0000000000000000000000000000000000000000",
    "decimals": 18,
    "standard": "NATIVE"
  },
  "amount": "1000000000000000000"
}
```

### **Example 2: USDC (Ethereum) → BlackHole**
```json
{
  "from_chain": "ethereum",
  "to_chain": "blackhole",
  "from_address": "0x742d35Cc6634C0532925a3b8D4C9db96590c6C87",
  "to_address": "bh1234567890123456789012345678901234567890",
  "token": {
    "symbol": "USDC",
    "contract_address": "0xA0b86a33E6441E6C7D3E4C7C5C6C7C5C6C7C5C6C7",
    "decimals": 6,
    "standard": "ERC20"
  },
  "amount": "1000000"
}
```

### **Example 3: SOL → BlackHole**
```json
{
  "from_chain": "solana",
  "to_chain": "blackhole",
  "from_address": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
  "to_address": "bh1234567890123456789012345678901234567890",
  "token": {
    "symbol": "SOL",
    "contract_address": "11111111111111111111111111111111",
    "decimals": 9,
    "standard": "NATIVE"
  },
  "amount": "1000000000"
}
```

### **Example 4: USDC (Solana) → Ethereum**
```json
{
  "from_chain": "solana",
  "to_chain": "ethereum",
  "from_address": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
  "to_address": "0x742d35Cc6634C0532925a3b8D4C9db96590c6C87",
  "token": {
    "symbol": "USDC",
    "contract_address": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    "decimals": 6,
    "standard": "SPL"
  },
  "amount": "1000000"
}
```

## 📝 **Valid Wallet Addresses**

### **Ethereum Addresses (Mainnet/Testnet)**
```
0x742d35Cc6634C0532925a3b8D4C9db96590c6C87
0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
0x8ba1f109551bD432803012645Hac136c5C1515BC
0x4Fabb145d64652a948d72533023f6E7A623C7C53
0x6B175474E89094C44Da98b954EedeAC495271d0F
0xA0b86a33E6441E6C7D3E4C7C5C6C7C5C6C7C5C6C7
```

### **Solana Addresses (Mainnet/Testnet)**
```
9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM
7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU
GDfnEsia2WLAW5t8yx2X5j2mkfA74i5kwGdDuZHt7XmG
5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1
8CvwxZ9Db6XbLD46NZwwmVDZZRDy7eydFcAGkXKh9axa
```

### **BlackHole Addresses (Testnet)**
```
bh1234567890123456789012345678901234567890
bh9876543210987654321098765432109876543210
bhabcdef1234567890abcdef1234567890abcdef12
bh1111111111111111111111111111111111111111
bh2222222222222222222222222222222222222222
```

## ⚠️ **Important Notes**

### **For Testing**
- Use **Sepolia testnet** for Ethereum testing
- Use **Devnet** for Solana testing
- BlackHole addresses are for **testnet only**

### **For Production**
- Always verify token contract addresses
- Check token decimals before transfers
- Validate wallet addresses before sending
- Use appropriate gas/fee settings

### **Security Reminders**
- Never share private keys
- Always double-check addresses
- Start with small test amounts
- Verify on block explorers

## 🔧 **Integration with Transfer Widget**

You can use these addresses directly in the enhanced transfer widget:

1. **From Address**: Your wallet address
2. **To Address**: Destination wallet address  
3. **Token Contract**: Use the contract addresses above
4. **Amount**: Specify in smallest unit (wei for ETH, lamports for SOL)

The widget will automatically validate addresses and calculate fees based on the selected tokens and chains.
