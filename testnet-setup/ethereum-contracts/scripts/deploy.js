const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
    console.log("🚀 Deploying BlackHole Bridge Token to Sepolia Testnet...");
    
    // Get deployer account
    const [deployer] = await ethers.getSigners();
    console.log("📝 Deploying with account:", deployer.address);
    
    // Check balance
    const balance = await ethers.provider.getBalance(deployer.address);
    console.log("💰 Account balance:", ethers.formatEther(balance), "ETH");
    
    if (balance < ethers.parseEther("0.01")) {
        console.log("⚠️  Warning: Low balance. Get Sepolia ETH from https://sepoliafaucet.com/");
    }
    
    // Deploy contract
    const BlackHoleBridgeToken = await ethers.getContractFactory("BlackHoleBridgeToken");
    
    const tokenName = "BlackHole Bridge Token";
    const tokenSymbol = "BHBT";
    const initialSupply = ethers.parseEther("1000000"); // 1 million tokens
    
    console.log("📋 Token Details:");
    console.log("   Name:", tokenName);
    console.log("   Symbol:", tokenSymbol);
    console.log("   Initial Supply:", ethers.formatEther(initialSupply));
    
    const token = await BlackHoleBridgeToken.deploy(
        tokenName,
        tokenSymbol,
        initialSupply
    );
    
    await token.waitForDeployment();
    const tokenAddress = await token.getAddress();
    
    console.log("✅ BlackHole Bridge Token deployed to:", tokenAddress);
    
    // Verify deployment
    const deployedName = await token.name();
    const deployedSymbol = await token.symbol();
    const deployedSupply = await token.totalSupply();
    const deployerBalance = await token.balanceOf(deployer.address);
    
    console.log("🔍 Verification:");
    console.log("   Name:", deployedName);
    console.log("   Symbol:", deployedSymbol);
    console.log("   Total Supply:", ethers.formatEther(deployedSupply));
    console.log("   Deployer Balance:", ethers.formatEther(deployerBalance));
    
    // Save deployment info
    const deploymentInfo = {
        network: "sepolia",
        contractAddress: tokenAddress,
        deployerAddress: deployer.address,
        tokenName: deployedName,
        tokenSymbol: deployedSymbol,
        totalSupply: deployedSupply.toString(),
        deploymentTime: new Date().toISOString(),
        transactionHash: token.deploymentTransaction()?.hash,
        blockNumber: await ethers.provider.getBlockNumber()
    };
    
    // Create config directory if it doesn't exist
    const configDir = path.join(__dirname, "../../config");
    if (!fs.existsSync(configDir)) {
        fs.mkdirSync(configDir, { recursive: true });
    }
    
    // Save to config file
    const configPath = path.join(configDir, "ethereum-sepolia.json");
    fs.writeFileSync(configPath, JSON.stringify(deploymentInfo, null, 2));
    
    console.log("💾 Deployment info saved to:", configPath);
    
    // Generate sample transaction script
    const sampleScript = `
// Sample transaction script for deployed token
const { ethers } = require("ethers");

const TOKEN_ADDRESS = "${tokenAddress}";
const DEPLOYER_ADDRESS = "${deployer.address}";

// Connect to Sepolia
const provider = new ethers.JsonRpcProvider("https://ethereum-sepolia-rpc.publicnode.com");
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);

// Token ABI (minimal)
const TOKEN_ABI = [
    "function transfer(address to, uint256 amount) returns (bool)",
    "function balanceOf(address account) view returns (uint256)",
    "function bridgeTransfer(string destinationChain, string destinationAddress, uint256 amount) returns (bytes32)"
];

async function sendTestTransaction() {
    const token = new ethers.Contract(TOKEN_ADDRESS, TOKEN_ABI, wallet);
    
    // Send bridge transfer
    const tx = await token.bridgeTransfer(
        "solana",
        "SolanaAddressHere123456789",
        ethers.parseEther("10")
    );
    
    console.log("Transaction sent:", tx.hash);
    await tx.wait();
    console.log("Transaction confirmed!");
}

// Uncomment to run:
// sendTestTransaction().catch(console.error);
`;
    
    const scriptPath = path.join(__dirname, "sample-transaction.js");
    fs.writeFileSync(scriptPath, sampleScript);
    
    console.log("📝 Sample transaction script created:", scriptPath);
    
    console.log("\n🎉 Deployment Complete!");
    console.log("📋 Next Steps:");
    console.log("1. Verify contract on Etherscan (optional):");
    console.log(`   npx hardhat verify --network sepolia ${tokenAddress} "${tokenName}" "${tokenSymbol}" "${initialSupply}"`);
    console.log("2. Add contract to MetaMask:");
    console.log(`   Token Address: ${tokenAddress}`);
    console.log("3. Start bridge monitoring:");
    console.log("   cd ../../bridge-sdk/example && go run main.go");
    console.log("4. Send test transactions:");
    console.log("   node scripts/sample-transaction.js");
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error("❌ Deployment failed:", error);
        process.exit(1);
    });
