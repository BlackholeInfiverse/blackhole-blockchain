const { ethers } = require("hardhat");

async function main() {
    console.log("🚀 Deploying BHX Token Contract...");
    
    // Get deployer account
    const [deployer] = await ethers.getSigners();
    console.log("📝 Deploying with account:", deployer.address);
    
    // Check balance
    const balance = await deployer.getBalance();
    console.log("💰 Account balance:", ethers.utils.formatEther(balance), "ETH");
    
    // Deploy BHX Token
    console.log("\n🔨 Deploying BHXToken...");
    const BHXToken = await ethers.getContractFactory("BHXToken");
    const bhxToken = await BHXToken.deploy();
    
    await bhxToken.deployed();
    
    console.log("✅ BHXToken deployed to:", bhxToken.address);
    console.log("🔗 Transaction hash:", bhxToken.deployTransaction.hash);
    
    // Wait for confirmations
    console.log("⏳ Waiting for confirmations...");
    await bhxToken.deployTransaction.wait(5);
    
    // Get token info
    const tokenInfo = await bhxToken.getTokenInfo();
    console.log("\n📊 Token Information:");
    console.log("   Name:", tokenInfo.name);
    console.log("   Symbol:", tokenInfo.symbol);
    console.log("   Decimals:", tokenInfo.decimals);
    console.log("   Total Supply:", ethers.utils.formatEther(tokenInfo.totalSupply), "BHX");
    console.log("   Max Supply:", ethers.utils.formatEther(tokenInfo.maxSupply), "BHX");
    console.log("   Paused:", tokenInfo.paused);
    console.log("   Limits Enabled:", tokenInfo.limitsEnabled);
    
    // Verify deployer is bridge operator
    const isBridgeOperator = await bhxToken.isBridgeOperator(deployer.address);
    console.log("   Deployer is Bridge Operator:", isBridgeOperator);
    
    console.log("\n🎉 Deployment completed successfully!");
    console.log("\n📋 Next Steps:");
    console.log("1. Verify contract on block explorer");
    console.log("2. Add to DEX (PancakeSwap/Uniswap)");
    console.log("3. Provide initial liquidity");
    console.log("4. Configure bridge operators");
    
    // Save deployment info
    const deploymentInfo = {
        network: network.name,
        contractAddress: bhxToken.address,
        deployerAddress: deployer.address,
        transactionHash: bhxToken.deployTransaction.hash,
        blockNumber: bhxToken.deployTransaction.blockNumber,
        timestamp: new Date().toISOString(),
        tokenInfo: {
            name: tokenInfo.name,
            symbol: tokenInfo.symbol,
            decimals: tokenInfo.decimals.toString(),
            totalSupply: tokenInfo.totalSupply.toString(),
            maxSupply: tokenInfo.maxSupply.toString()
        }
    };
    
    const fs = require('fs');
    const deploymentPath = `deployments/${network.name}-bhx-deployment.json`;
    
    // Create deployments directory if it doesn't exist
    if (!fs.existsSync('deployments')) {
        fs.mkdirSync('deployments');
    }
    
    fs.writeFileSync(deploymentPath, JSON.stringify(deploymentInfo, null, 2));
    console.log(`💾 Deployment info saved to: ${deploymentPath}`);
    
    return {
        contract: bhxToken,
        address: bhxToken.address,
        deploymentInfo
    };
}

// Handle deployment
if (require.main === module) {
    main()
        .then(() => process.exit(0))
        .catch((error) => {
            console.error("❌ Deployment failed:", error);
            process.exit(1);
        });
}

module.exports = main;
