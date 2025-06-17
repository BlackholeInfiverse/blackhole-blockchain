const {
    Connection,
    PublicKey,
    Keypair,
    Transaction,
    sendAndConfirmTransaction,
    LAMPORTS_PER_SOL
} = require('@solana/web3.js');

const {
    transfer,
    getOrCreateAssociatedTokenAccount,
    getAccount
} = require('@solana/spl-token');

const fs = require('fs');
const path = require('path');
require('dotenv').config();

async function sendSolanaTransaction() {
    console.log("🔥 Sending Solana SPL Token Transaction on Devnet...");
    
    // Load deployment config
    const configPath = path.join(__dirname, "../config/solana-devnet.json");
    if (!fs.existsSync(configPath)) {
        console.error("❌ Solana deployment config not found. Please deploy SPL token first.");
        console.log("Run: cd ../solana-contracts && npm run deploy:devnet");
        return;
    }
    
    const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
    console.log("📋 Using deployed token:", config.mintAddress);
    
    // Connect to Solana Devnet
    const connection = new Connection('https://api.devnet.solana.com', 'confirmed');
    
    // Load wallet
    const walletPath = path.join(__dirname, "../solana-contracts/wallet.json");
    if (!fs.existsSync(walletPath)) {
        console.error("❌ Wallet not found. Please deploy SPL token first.");
        return;
    }
    
    const walletData = JSON.parse(fs.readFileSync(walletPath, 'utf8'));
    const wallet = Keypair.fromSecretKey(new Uint8Array(walletData));
    
    console.log("📝 Sending from:", wallet.publicKey.toString());
    
    // Check SOL balance
    const solBalance = await connection.getBalance(wallet.publicKey);
    console.log("💰 SOL Balance:", solBalance / LAMPORTS_PER_SOL);
    
    if (solBalance < 0.001 * LAMPORTS_PER_SOL) {
        console.log("⚠️  Low SOL balance. Requesting airdrop...");
        try {
            const airdropSignature = await connection.requestAirdrop(
                wallet.publicKey,
                1 * LAMPORTS_PER_SOL
            );
            await connection.confirmTransaction(airdropSignature);
            console.log("✅ Airdrop successful!");
        } catch (error) {
            console.log("❌ Airdrop failed. Please request manually:");
            console.log(`   solana airdrop 1 ${wallet.publicKey.toString()} --url devnet`);
            return;
        }
    }
    
    try {
        const mint = new PublicKey(config.mintAddress);
        
        // Get source token account
        const sourceAccount = await getOrCreateAssociatedTokenAccount(
            connection,
            wallet,
            mint,
            wallet.publicKey
        );
        
        console.log("🏦 Source Token Account:", sourceAccount.address.toString());
        
        // Check token balance
        const tokenAccountInfo = await getAccount(connection, sourceAccount.address);
        const tokenBalance = Number(tokenAccountInfo.amount) / Math.pow(10, config.decimals);
        
        console.log("🪙 Token Balance:", tokenBalance, config.tokenSymbol);
        
        if (tokenBalance < 1) {
            console.log("⚠️  Low token balance. You need tokens to transfer.");
            return;
        }
        
        console.log("\n🌉 Initiating SPL Token Transfer...");
        
        // Create a dummy recipient (for demo, we'll create a new keypair)
        const recipient = Keypair.generate();
        console.log("📝 Recipient Address:", recipient.publicKey.toString());
        
        // Get or create recipient token account
        const destAccount = await getOrCreateAssociatedTokenAccount(
            connection,
            wallet,
            mint,
            recipient.publicKey
        );
        
        console.log("🏦 Destination Token Account:", destAccount.address.toString());
        
        // Transfer amount (2 tokens)
        const transferAmount = 2 * Math.pow(10, config.decimals);
        
        console.log("📋 Transfer Details:");
        console.log("   From:", wallet.publicKey.toString());
        console.log("   To:", recipient.publicKey.toString());
        console.log("   Amount:", transferAmount / Math.pow(10, config.decimals), config.tokenSymbol);
        
        // Send transfer transaction
        console.log("📤 Sending transaction...");
        
        const signature = await transfer(
            connection,
            wallet,
            sourceAccount.address,
            destAccount.address,
            wallet.publicKey,
            transferAmount
        );
        
        console.log("📤 Transaction sent:", signature);
        console.log("🔗 View on Solana Explorer:", `https://explorer.solana.com/tx/${signature}?cluster=devnet`);
        
        // Wait for confirmation
        console.log("⏳ Waiting for confirmation...");
        const confirmation = await connection.confirmTransaction(signature, 'confirmed');
        
        if (confirmation.value.err) {
            console.error("❌ Transaction failed:", confirmation.value.err);
            return;
        }
        
        console.log("✅ Transaction confirmed!");
        
        // Get transaction details
        const txDetails = await connection.getTransaction(signature, {
            commitment: 'confirmed'
        });
        
        if (txDetails) {
            console.log("📊 Transaction Details:");
            console.log("   Slot:", txDetails.slot);
            console.log("   Block Time:", new Date(txDetails.blockTime * 1000).toISOString());
            console.log("   Fee:", txDetails.meta.fee / LAMPORTS_PER_SOL, "SOL");
        }
        
        // Check updated balances
        const updatedSourceInfo = await getAccount(connection, sourceAccount.address);
        const updatedDestInfo = await getAccount(connection, destAccount.address);
        
        console.log("\n📊 Updated Balances:");
        console.log("   Source:", Number(updatedSourceInfo.amount) / Math.pow(10, config.decimals), config.tokenSymbol);
        console.log("   Destination:", Number(updatedDestInfo.amount) / Math.pow(10, config.decimals), config.tokenSymbol);
        
        // Save transaction info for monitoring
        const txInfo = {
            network: "solana-devnet",
            signature: signature,
            from: wallet.publicKey.toString(),
            to: recipient.publicKey.toString(),
            mintAddress: config.mintAddress,
            sourceTokenAccount: sourceAccount.address.toString(),
            destTokenAccount: destAccount.address.toString(),
            amount: transferAmount,
            decimals: config.decimals,
            slot: txDetails?.slot,
            blockTime: txDetails?.blockTime,
            timestamp: new Date().toISOString(),
            explorerUrl: `https://explorer.solana.com/tx/${signature}?cluster=devnet`
        };
        
        const txPath = path.join(__dirname, "../config/latest-sol-transaction.json");
        fs.writeFileSync(txPath, JSON.stringify(txInfo, null, 2));
        console.log("💾 Transaction info saved to:", txPath);
        
        console.log("\n🎯 Next Steps:");
        console.log("1. Monitor bridge dashboard: http://localhost:8084");
        console.log("2. Check if bridge detected this transaction");
        console.log("3. Verify relay to Ethereum or Go blockchain");
        console.log("4. Check cross-chain token minting");
        
    } catch (error) {
        console.error("❌ Transaction failed:", error);
        
        if (error.message.includes("insufficient funds")) {
            console.log("💡 Solution: Get more SOL from devnet faucet");
        } else if (error.message.includes("insufficient token balance")) {
            console.log("💡 Solution: Mint more tokens first");
        } else if (error.message.includes("TokenAccountNotFoundError")) {
            console.log("💡 Solution: Create token account first");
        }
    }
}

// Run if called directly
if (require.main === module) {
    sendSolanaTransaction().catch(console.error);
}

module.exports = { sendSolanaTransaction };
