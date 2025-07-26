const {
    Connection,
    Keypair,
    PublicKey,
    Transaction,
    sendAndConfirmTransaction,
    SystemProgram,
    LAMPORTS_PER_SOL
} = require('@solana/web3.js');

const {
    createMint,
    getOrCreateAssociatedTokenAccount,
    mintTo,
    createSetAuthorityInstruction,
    AuthorityType,
    TOKEN_PROGRAM_ID
} = require('@solana/spl-token');

const fs = require('fs');
const path = require('path');
require('dotenv').config();

async function main() {
    console.log('🚀 Deploying BlackHole Bridge SPL Token to Solana Devnet...');
    
    // Connect to Solana Devnet
    const connection = new Connection('https://api.devnet.solana.com', 'confirmed');
    
    // Create or load wallet
    let wallet;
    const walletPath = path.join(__dirname, '../wallet.json');
    
    if (fs.existsSync(walletPath)) {
        console.log('📂 Loading existing wallet...');
        const walletData = JSON.parse(fs.readFileSync(walletPath, 'utf8'));
        wallet = Keypair.fromSecretKey(new Uint8Array(walletData));
    } else {
        console.log('🔑 Creating new wallet...');
        wallet = Keypair.generate();
        fs.writeFileSync(walletPath, JSON.stringify(Array.from(wallet.secretKey)));
    }
    
    console.log('📝 Wallet Address:', wallet.publicKey.toString());
    
    // Check balance
    const balance = await connection.getBalance(wallet.publicKey);
    console.log('💰 Wallet Balance:', balance / LAMPORTS_PER_SOL, 'SOL');
    
    if (balance < 0.1 * LAMPORTS_PER_SOL) {
        console.log('⚠️  Low balance! Requesting airdrop...');
        try {
            const airdropSignature = await connection.requestAirdrop(
                wallet.publicKey,
                2 * LAMPORTS_PER_SOL
            );
            await connection.confirmTransaction(airdropSignature);
            console.log('✅ Airdrop successful!');
        } catch (error) {
            console.log('❌ Airdrop failed. Please request manually:');
            console.log(`   solana airdrop 2 ${wallet.publicKey.toString()} --url devnet`);
            return;
        }
    }
    
    try {
        console.log('🪙 Creating SPL Token Mint...');
        
        // Create mint account
        const mint = await createMint(
            connection,
            wallet,           // Payer
            wallet.publicKey, // Mint authority
            wallet.publicKey, // Freeze authority
            9                 // Decimals (9 is standard for SPL tokens)
        );
        
        console.log('✅ Token Mint Created:', mint.toString());
        
        // Create associated token account for the wallet
        console.log('🏦 Creating token account...');
        const tokenAccount = await getOrCreateAssociatedTokenAccount(
            connection,
            wallet,
            mint,
            wallet.publicKey
        );
        
        console.log('✅ Token Account Created:', tokenAccount.address.toString());
        
        // Mint initial supply (1 million tokens)
        const initialSupply = 1000000 * Math.pow(10, 9); // 1M tokens with 9 decimals
        console.log('💰 Minting initial supply...');
        
        await mintTo(
            connection,
            wallet,
            mint,
            tokenAccount.address,
            wallet.publicKey,
            initialSupply
        );
        
        console.log('✅ Minted', initialSupply / Math.pow(10, 9), 'BHBT tokens');
        
        // Get token account info
        const tokenAccountInfo = await connection.getTokenAccountBalance(tokenAccount.address);
        console.log('🔍 Token Account Balance:', tokenAccountInfo.value.uiAmount, 'BHBT');
        
        // Save deployment info
        const deploymentInfo = {
            network: 'devnet',
            mintAddress: mint.toString(),
            tokenAccountAddress: tokenAccount.address.toString(),
            walletAddress: wallet.publicKey.toString(),
            tokenName: 'BlackHole Bridge Token',
            tokenSymbol: 'BHBT',
            decimals: 9,
            initialSupply: initialSupply,
            deploymentTime: new Date().toISOString(),
            rpcEndpoint: 'https://api.devnet.solana.com'
        };
        
        // Create config directory if it doesn't exist
        const configDir = path.join(__dirname, '../../config');
        if (!fs.existsSync(configDir)) {
            fs.mkdirSync(configDir, { recursive: true });
        }
        
        // Save to config file
        const configPath = path.join(configDir, 'solana-devnet.json');
        fs.writeFileSync(configPath, JSON.stringify(deploymentInfo, null, 2));
        
        console.log('💾 Deployment info saved to:', configPath);
        
        // Generate sample transaction script
        const sampleScript = `
// Sample transaction script for deployed SPL token
const { Connection, PublicKey, Keypair, Transaction } = require('@solana/web3.js');
const { transfer, getOrCreateAssociatedTokenAccount } = require('@solana/spl-token');
const fs = require('fs');

const MINT_ADDRESS = "${mint.toString()}";
const WALLET_PATH = "${walletPath}";

async function sendTestTransaction() {
    const connection = new Connection('https://api.devnet.solana.com', 'confirmed');
    
    // Load wallet
    const walletData = JSON.parse(fs.readFileSync(WALLET_PATH, 'utf8'));
    const wallet = Keypair.fromSecretKey(new Uint8Array(walletData));
    
    // Create recipient (for demo, using same wallet)
    const recipient = wallet.publicKey;
    
    // Get token accounts
    const sourceAccount = await getOrCreateAssociatedTokenAccount(
        connection, wallet, new PublicKey(MINT_ADDRESS), wallet.publicKey
    );
    
    const destAccount = await getOrCreateAssociatedTokenAccount(
        connection, wallet, new PublicKey(MINT_ADDRESS), recipient
    );
    
    // Send transfer
    const signature = await transfer(
        connection,
        wallet,
        sourceAccount.address,
        destAccount.address,
        wallet.publicKey,
        1000000000 // 1 token (9 decimals)
    );
    
    console.log('Transaction sent:', signature);
}

// Uncomment to run:
// sendTestTransaction().catch(console.error);
`;
        
        const scriptPath = path.join(__dirname, 'sample-transaction.js');
        fs.writeFileSync(scriptPath, sampleScript);
        
        console.log('📝 Sample transaction script created:', scriptPath);
        
        console.log('\n🎉 SPL Token Deployment Complete!');
        console.log('📋 Token Details:');
        console.log('   Mint Address:', mint.toString());
        console.log('   Token Account:', tokenAccount.address.toString());
        console.log('   Decimals: 9');
        console.log('   Initial Supply: 1,000,000 BHBT');
        
        console.log('\n📋 Next Steps:');
        console.log('1. Add token to Phantom wallet:');
        console.log(`   Mint Address: ${mint.toString()}`);
        console.log('2. Start bridge monitoring:');
        console.log('   cd ../../bridge-sdk/example && go run main.go');
        console.log('3. Send test transactions:');
        console.log('   node scripts/sample-transaction.js');
        
    } catch (error) {
        console.error('❌ Deployment failed:', error);
        process.exit(1);
    }
}

main();
