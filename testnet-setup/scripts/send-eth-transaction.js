const { ethers } = require("ethers");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

async function sendEthereumTransaction() {
    console.log("🔥 Sending Ethereum Bridge Transaction on Sepolia...");
    
    // Load deployment config
    const configPath = path.join(__dirname, "../config/ethereum-sepolia.json");
    if (!fs.existsSync(configPath)) {
        console.error("❌ Ethereum deployment config not found. Please deploy contract first.");
        console.log("Run: cd ../ethereum-contracts && npm run deploy:sepolia");
        return;
    }
    
    const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
    console.log("📋 Using deployed contract:", config.contractAddress);
    
    // Connect to Sepolia
    const provider = new ethers.JsonRpcProvider("https://ethereum-sepolia-rpc.publicnode.com");
    
    if (!process.env.PRIVATE_KEY) {
        console.error("❌ PRIVATE_KEY not found in environment variables");
        console.log("Create .env file with your private key (without 0x prefix)");
        return;
    }
    
    const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
    console.log("📝 Sending from:", wallet.address);
    
    // Check balance
    const balance = await provider.getBalance(wallet.address);
    console.log("💰 ETH Balance:", ethers.formatEther(balance));
    
    if (balance < ethers.parseEther("0.001")) {
        console.log("⚠️  Low ETH balance. Get Sepolia ETH from https://sepoliafaucet.com/");
        return;
    }
    
    // Contract ABI
    const contractABI = [
        "function bridgeTransfer(string destinationChain, string destinationAddress, uint256 amount) returns (bytes32)",
        "function transfer(address to, uint256 amount) returns (bool)",
        "function balanceOf(address account) view returns (uint256)",
        "function name() view returns (string)",
        "function symbol() view returns (string)",
        "event BridgeTransfer(address indexed from, string indexed destinationChain, string destinationAddress, uint256 amount, bytes32 indexed bridgeId)"
    ];
    
    const contract = new ethers.Contract(config.contractAddress, contractABI, wallet);
    
    // Check token balance
    const tokenBalance = await contract.balanceOf(wallet.address);
    console.log("🪙 Token Balance:", ethers.formatEther(tokenBalance), config.tokenSymbol);
    
    if (tokenBalance < ethers.parseEther("1")) {
        console.log("⚠️  Low token balance. You need tokens to bridge.");
        return;
    }
    
    try {
        console.log("\n🌉 Initiating Bridge Transfer...");
        
        // Bridge transfer parameters
        const destinationChain = "solana";
        const destinationAddress = "SolanaRecipientAddress123456789"; // Placeholder
        const amount = ethers.parseEther("5"); // 5 tokens (reduced for demo)
        
        console.log("📋 Bridge Transfer Details:");
        console.log("   Destination Chain:", destinationChain);
        console.log("   Destination Address:", destinationAddress);
        console.log("   Amount:", ethers.formatEther(amount), config.tokenSymbol);
        
        // Estimate gas
        const gasEstimate = await contract.bridgeTransfer.estimateGas(
            destinationChain,
            destinationAddress,
            amount
        );
        console.log("⛽ Estimated Gas:", gasEstimate.toString());
        
        // Send transaction
        const tx = await contract.bridgeTransfer(
            destinationChain,
            destinationAddress,
            amount,
            {
                gasLimit: gasEstimate * 120n / 100n // Add 20% buffer
            }
        );
        
        console.log("📤 Transaction sent:", tx.hash);
        console.log("🔗 View on Etherscan:", `https://sepolia.etherscan.io/tx/${tx.hash}`);
        
        // Wait for confirmation
        console.log("⏳ Waiting for confirmation...");
        const receipt = await tx.wait();
        
        console.log("✅ Transaction confirmed!");
        console.log("📊 Gas Used:", receipt.gasUsed.toString());
        console.log("🧾 Block Number:", receipt.blockNumber);
        
        // Parse events
        const bridgeEvents = receipt.logs
            .filter(log => log.address.toLowerCase() === config.contractAddress.toLowerCase())
            .map(log => {
                try {
                    return contract.interface.parseLog(log);
                } catch (e) {
                    return null;
                }
            })
            .filter(event => event && event.name === "BridgeTransfer");
        
        if (bridgeEvents.length > 0) {
            const bridgeEvent = bridgeEvents[0];
            console.log("\n🎉 Bridge Event Emitted:");
            console.log("   Bridge ID:", bridgeEvent.args.bridgeId);
            console.log("   From:", bridgeEvent.args.from);
            console.log("   Destination Chain:", bridgeEvent.args.destinationChain);
            console.log("   Destination Address:", bridgeEvent.args.destinationAddress);
            console.log("   Amount:", ethers.formatEther(bridgeEvent.args.amount));
            
            // Save transaction info for monitoring
            const txInfo = {
                network: "ethereum-sepolia",
                transactionHash: tx.hash,
                bridgeId: bridgeEvent.args.bridgeId,
                from: bridgeEvent.args.from,
                destinationChain: bridgeEvent.args.destinationChain,
                destinationAddress: bridgeEvent.args.destinationAddress,
                amount: bridgeEvent.args.amount.toString(),
                blockNumber: receipt.blockNumber,
                timestamp: new Date().toISOString(),
                etherscanUrl: `https://sepolia.etherscan.io/tx/${tx.hash}`
            };
            
            const txPath = path.join(__dirname, "../config/latest-eth-transaction.json");
            fs.writeFileSync(txPath, JSON.stringify(txInfo, null, 2));
            console.log("💾 Transaction info saved to:", txPath);
        }
        
        // Check updated balance
        const newTokenBalance = await contract.balanceOf(wallet.address);
        console.log("\n📊 Updated Token Balance:", ethers.formatEther(newTokenBalance), config.tokenSymbol);
        
        console.log("\n🎯 Next Steps:");
        console.log("1. Monitor bridge dashboard: http://localhost:8084");
        console.log("2. Check if bridge detected this transaction");
        console.log("3. Verify relay to Solana devnet");
        console.log("4. Check Go blockchain for minted tokens");
        
    } catch (error) {
        console.error("❌ Transaction failed:", error);
        
        if (error.code === "INSUFFICIENT_FUNDS") {
            console.log("💡 Solution: Get more Sepolia ETH from https://sepoliafaucet.com/");
        } else if (error.message.includes("insufficient allowance")) {
            console.log("💡 Solution: Approve token spending first");
        } else if (error.message.includes("execution reverted")) {
            console.log("💡 Solution: Check contract state and parameters");
        }
    }
}

// Run if called directly
if (require.main === module) {
    sendEthereumTransaction().catch(console.error);
}

module.exports = { sendEthereumTransaction };
