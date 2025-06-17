const { ethers } = require("ethers");
const { Connection, PublicKey } = require('@solana/web3.js');
const fs = require('fs');
const path = require('path');

class BridgeMonitor {
    constructor() {
        this.ethProvider = new ethers.JsonRpcProvider("https://ethereum-sepolia-rpc.publicnode.com");
        this.solConnection = new Connection('https://api.devnet.solana.com', 'confirmed');
        this.bridgeApiUrl = "http://localhost:8084";
        this.isMonitoring = false;
        this.stats = {
            ethTransactions: 0,
            solTransactions: 0,
            bridgeEvents: 0,
            relayedTransactions: 0,
            startTime: new Date()
        };
    }

    async loadConfigs() {
        const ethConfigPath = path.join(__dirname, "../config/ethereum-sepolia.json");
        const solConfigPath = path.join(__dirname, "../config/solana-devnet.json");
        
        if (fs.existsSync(ethConfigPath)) {
            this.ethConfig = JSON.parse(fs.readFileSync(ethConfigPath, 'utf8'));
        }
        
        if (fs.existsSync(solConfigPath)) {
            this.solConfig = JSON.parse(fs.readFileSync(solConfigPath, 'utf8'));
        }
    }

    async startMonitoring() {
        console.log("🔍 Starting Bridge Monitor...");
        await this.loadConfigs();
        
        this.isMonitoring = true;
        
        // Monitor Ethereum events
        if (this.ethConfig) {
            this.monitorEthereumEvents();
        }
        
        // Monitor Solana transactions
        if (this.solConfig) {
            this.monitorSolanaTransactions();
        }
        
        // Monitor bridge API
        this.monitorBridgeAPI();
        
        // Display stats periodically
        this.displayStats();
        
        console.log("✅ Bridge monitoring started!");
        console.log("📊 Dashboard: http://localhost:8084");
        console.log("🛑 Press Ctrl+C to stop monitoring");
    }

    async monitorEthereumEvents() {
        if (!this.ethConfig) return;
        
        console.log("👁️  Monitoring Ethereum Sepolia events...");
        
        const contractABI = [
            "event BridgeTransfer(address indexed from, string indexed destinationChain, string destinationAddress, uint256 amount, bytes32 indexed bridgeId)",
            "event Transfer(address indexed from, address indexed to, uint256 value)"
        ];
        
        const contract = new ethers.Contract(
            this.ethConfig.contractAddress,
            contractABI,
            this.ethProvider
        );
        
        // Listen for bridge events
        contract.on("BridgeTransfer", (from, destinationChain, destinationAddress, amount, bridgeId, event) => {
            this.stats.bridgeEvents++;
            console.log("\n🌉 Ethereum Bridge Event Detected:");
            console.log("   From:", from);
            console.log("   Destination Chain:", destinationChain);
            console.log("   Amount:", ethers.formatEther(amount), this.ethConfig.tokenSymbol);
            console.log("   Bridge ID:", bridgeId);
            console.log("   Transaction:", event.transactionHash);
            console.log("   Block:", event.blockNumber);
            
            this.logEvent({
                type: "ethereum_bridge",
                from,
                destinationChain,
                amount: ethers.formatEther(amount),
                bridgeId,
                transactionHash: event.transactionHash,
                blockNumber: event.blockNumber,
                timestamp: new Date().toISOString()
            });
        });
        
        // Listen for regular transfers
        contract.on("Transfer", (from, to, value, event) => {
            this.stats.ethTransactions++;
            console.log("\n💸 Ethereum Transfer Detected:");
            console.log("   From:", from);
            console.log("   To:", to);
            console.log("   Amount:", ethers.formatEther(value), this.ethConfig.tokenSymbol);
            console.log("   Transaction:", event.transactionHash);
        });
    }

    async monitorSolanaTransactions() {
        if (!this.solConfig) return;
        
        console.log("👁️  Monitoring Solana Devnet transactions...");
        
        const mintPubkey = new PublicKey(this.solConfig.mintAddress);
        
        // Subscribe to account changes (simplified monitoring)
        setInterval(async () => {
            try {
                // Get recent signatures for the mint account
                const signatures = await this.solConnection.getSignaturesForAddress(
                    mintPubkey,
                    { limit: 5 }
                );
                
                for (const sigInfo of signatures) {
                    if (this.isNewTransaction(sigInfo.signature)) {
                        this.stats.solTransactions++;
                        
                        const txDetails = await this.solConnection.getTransaction(
                            sigInfo.signature,
                            { commitment: 'confirmed' }
                        );
                        
                        if (txDetails) {
                            console.log("\n🪙 Solana Transaction Detected:");
                            console.log("   Signature:", sigInfo.signature);
                            console.log("   Slot:", txDetails.slot);
                            console.log("   Status:", sigInfo.err ? "Failed" : "Success");
                            
                            this.logEvent({
                                type: "solana_transaction",
                                signature: sigInfo.signature,
                                slot: txDetails.slot,
                                status: sigInfo.err ? "failed" : "success",
                                timestamp: new Date().toISOString()
                            });
                        }
                    }
                }
            } catch (error) {
                // Silently handle errors to avoid spam
            }
        }, 10000); // Check every 10 seconds
    }

    async monitorBridgeAPI() {
        console.log("👁️  Monitoring Bridge API...");
        
        setInterval(async () => {
            try {
                const response = await fetch(`${this.bridgeApiUrl}/stats`);
                if (response.ok) {
                    const bridgeStats = await response.json();
                    this.stats.relayedTransactions = bridgeStats.total_transactions || 0;
                }
            } catch (error) {
                // Bridge API might not be running
            }
        }, 5000); // Check every 5 seconds
    }

    displayStats() {
        setInterval(() => {
            const uptime = Math.floor((new Date() - this.stats.startTime) / 1000);
            
            console.log("\n📊 Bridge Monitor Statistics:");
            console.log("   Uptime:", this.formatUptime(uptime));
            console.log("   Ethereum Transactions:", this.stats.ethTransactions);
            console.log("   Ethereum Bridge Events:", this.stats.bridgeEvents);
            console.log("   Solana Transactions:", this.stats.solTransactions);
            console.log("   Bridge Relayed:", this.stats.relayedTransactions);
            console.log("   Last Update:", new Date().toLocaleTimeString());
        }, 30000); // Display every 30 seconds
    }

    formatUptime(seconds) {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;
        return `${hours}h ${minutes}m ${secs}s`;
    }

    isNewTransaction(signature) {
        // Simple check to avoid duplicate processing
        // In production, you'd use a proper database
        const logPath = path.join(__dirname, "../logs/processed_transactions.txt");
        
        if (!fs.existsSync(path.dirname(logPath))) {
            fs.mkdirSync(path.dirname(logPath), { recursive: true });
        }
        
        let processed = [];
        if (fs.existsSync(logPath)) {
            processed = fs.readFileSync(logPath, 'utf8').split('\n').filter(Boolean);
        }
        
        if (processed.includes(signature)) {
            return false;
        }
        
        // Add to processed list
        fs.appendFileSync(logPath, signature + '\n');
        return true;
    }

    logEvent(event) {
        const logPath = path.join(__dirname, "../logs/bridge_events.jsonl");
        
        if (!fs.existsSync(path.dirname(logPath))) {
            fs.mkdirSync(path.dirname(logPath), { recursive: true });
        }
        
        fs.appendFileSync(logPath, JSON.stringify(event) + '\n');
    }

    stop() {
        console.log("\n🛑 Stopping Bridge Monitor...");
        this.isMonitoring = false;
        
        // Save final stats
        const finalStats = {
            ...this.stats,
            endTime: new Date(),
            totalUptime: Math.floor((new Date() - this.stats.startTime) / 1000)
        };
        
        const statsPath = path.join(__dirname, "../logs/final_stats.json");
        fs.writeFileSync(statsPath, JSON.stringify(finalStats, null, 2));
        
        console.log("📊 Final statistics saved to:", statsPath);
        console.log("✅ Bridge Monitor stopped");
    }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
    if (global.monitor) {
        global.monitor.stop();
    }
    process.exit(0);
});

// Run if called directly
if (require.main === module) {
    global.monitor = new BridgeMonitor();
    global.monitor.startMonitoring().catch(console.error);
}

module.exports = { BridgeMonitor };
