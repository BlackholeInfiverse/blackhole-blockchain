const { ethers } = require("hardhat");

async function main() {
    console.log("🔍 Getting wallet address from private key...");
    
    try {
        const [deployer] = await ethers.getSigners();
        console.log("✅ Wallet Address:", deployer.address);
        console.log("💰 Current Balance:", ethers.utils.formatEther(await deployer.getBalance()), "MATIC");
        
        console.log("\n🎁 Fund this address with FREE Mumbai MATIC:");
        console.log("1. Visit: https://faucet.polygon.technology/");
        console.log("2. Enter address:", deployer.address);
        console.log("3. Get 0.5 test MATIC");
        
    } catch (error) {
        console.error("❌ Error:", error.message);
    }
}

main();