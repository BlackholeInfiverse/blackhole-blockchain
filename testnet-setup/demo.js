#!/usr/bin/env node

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const { sendEthereumTransaction } = require('./scripts/send-eth-transaction');
const { sendSolanaTransaction } = require('./scripts/send-sol-transaction');
const { BridgeMonitor } = require('./scripts/monitor-bridge');

class EndToEndDemo {
    constructor() {
        this.bridgeProcess = null;
        this.monitor = null;
        this.demoSteps = [
            'setup',
            'deploy-contracts',
            'start-bridge',
            'start-monitoring',
            'send-transactions',
            'verify-results',
            'cleanup'
        ];
        this.currentStep = 0;
    }

    async runDemo() {
        console.log("🎬 Starting BlackHole Bridge End-to-End Demo");
        console.log("=" * 60);
        
        try {
            for (const step of this.demoSteps) {
                await this.executeStep(step);
                this.currentStep++;
                
                // Pause between steps for demo purposes
                if (step !== 'cleanup') {
                    await this.pause(2000);
                }
            }
            
            console.log("\n🎉 Demo completed successfully!");
            
        } catch (error) {
            console.error("❌ Demo failed:", error);
            await this.cleanup();
        }
    }

    async executeStep(step) {
        console.log(`\n📋 Step ${this.currentStep + 1}: ${step.toUpperCase()}`);
        console.log("-".repeat(40));
        
        switch (step) {
            case 'setup':
                await this.setup();
                break;
            case 'deploy-contracts':
                await this.deployContracts();
                break;
            case 'start-bridge':
                await this.startBridge();
                break;
            case 'start-monitoring':
                await this.startMonitoring();
                break;
            case 'send-transactions':
                await this.sendTransactions();
                break;
            case 'verify-results':
                await this.verifyResults();
                break;
            case 'cleanup':
                await this.cleanup();
                break;
        }
    }

    async setup() {
        console.log("🔧 Setting up demo environment...");
        
        // Check prerequisites
        const checks = [
            { name: "Node.js", command: "node --version" },
            { name: "Go", command: "go version" },
            { name: "Git", command: "git --version" }
        ];
        
        for (const check of checks) {
            try {
                await this.runCommand(check.command);
                console.log(`✅ ${check.name} is installed`);
            } catch (error) {
                throw new Error(`❌ ${check.name} is not installed or not in PATH`);
            }
        }
        
        // Create necessary directories
        const dirs = ['logs', 'config', 'screenshots'];
        for (const dir of dirs) {
            const dirPath = path.join(__dirname, dir);
            if (!fs.existsSync(dirPath)) {
                fs.mkdirSync(dirPath, { recursive: true });
                console.log(`📁 Created directory: ${dir}`);
            }
        }
        
        console.log("✅ Environment setup complete");
    }

    async deployContracts() {
        console.log("🚀 Deploying testnet contracts...");
        
        // Check if contracts are already deployed
        const ethConfigPath = path.join(__dirname, "config/ethereum-sepolia.json");
        const solConfigPath = path.join(__dirname, "config/solana-devnet.json");
        
        if (!fs.existsSync(ethConfigPath)) {
            console.log("📝 Deploying Ethereum ERC-20 contract...");
            console.log("⚠️  Note: This requires a private key in .env file");
            console.log("⚠️  Note: This requires Sepolia ETH in your wallet");
            console.log("💡 Get Sepolia ETH from: https://sepoliafaucet.com/");
            
            // In a real demo, you would deploy here
            console.log("🔄 Skipping Ethereum deployment for demo (requires manual setup)");
        } else {
            console.log("✅ Ethereum contract already deployed");
        }
        
        if (!fs.existsSync(solConfigPath)) {
            console.log("📝 Deploying Solana SPL token...");
            console.log("🔄 Skipping Solana deployment for demo (requires manual setup)");
        } else {
            console.log("✅ Solana SPL token already deployed");
        }
        
        console.log("💡 To deploy contracts manually:");
        console.log("   Ethereum: cd ethereum-contracts && npm install && npm run deploy:sepolia");
        console.log("   Solana: cd solana-contracts && npm install && npm run deploy:devnet");
    }

    async startBridge() {
        console.log("🌉 Starting BlackHole Bridge system...");
        
        const bridgePath = path.join(__dirname, "../bridge-sdk/example");
        
        console.log("📍 Bridge location:", bridgePath);
        
        if (!fs.existsSync(path.join(bridgePath, "main.go"))) {
            throw new Error("Bridge main.go not found. Please check the path.");
        }
        
        // Start bridge in background
        this.bridgeProcess = spawn('go', ['run', 'main.go'], {
            cwd: bridgePath,
            stdio: ['pipe', 'pipe', 'pipe']
        });
        
        // Log bridge output
        this.bridgeProcess.stdout.on('data', (data) => {
            const output = data.toString();
            console.log("🌉 Bridge:", output.trim());
            
            // Save bridge logs
            const logPath = path.join(__dirname, "logs/bridge.log");
            fs.appendFileSync(logPath, `[${new Date().toISOString()}] ${output}`);
        });
        
        this.bridgeProcess.stderr.on('data', (data) => {
            console.error("🌉 Bridge Error:", data.toString().trim());
        });
        
        // Wait for bridge to start
        console.log("⏳ Waiting for bridge to initialize...");
        await this.pause(10000); // 10 seconds
        
        // Check if bridge is running
        try {
            const response = await fetch("http://localhost:8084/health");
            if (response.ok) {
                console.log("✅ Bridge is running and healthy");
                console.log("📊 Dashboard: http://localhost:8084");
            } else {
                throw new Error("Bridge health check failed");
            }
        } catch (error) {
            console.log("⚠️  Bridge might still be starting up...");
        }
    }

    async startMonitoring() {
        console.log("👁️  Starting bridge monitoring...");
        
        this.monitor = new BridgeMonitor();
        await this.monitor.startMonitoring();
        
        console.log("✅ Monitoring started");
    }

    async sendTransactions() {
        console.log("💸 Sending test transactions...");
        
        // Check if we have deployed contracts
        const ethConfigPath = path.join(__dirname, "config/ethereum-sepolia.json");
        const solConfigPath = path.join(__dirname, "config/solana-devnet.json");
        
        if (fs.existsSync(ethConfigPath) && process.env.PRIVATE_KEY) {
            console.log("📤 Sending Ethereum transaction...");
            try {
                await sendEthereumTransaction();
                console.log("✅ Ethereum transaction sent");
            } catch (error) {
                console.log("⚠️  Ethereum transaction failed:", error.message);
            }
        } else {
            console.log("⚠️  Skipping Ethereum transaction (no config or private key)");
        }
        
        if (fs.existsSync(solConfigPath)) {
            console.log("📤 Sending Solana transaction...");
            try {
                await sendSolanaTransaction();
                console.log("✅ Solana transaction sent");
            } catch (error) {
                console.log("⚠️  Solana transaction failed:", error.message);
            }
        } else {
            console.log("⚠️  Skipping Solana transaction (no config)");
        }
        
        // Wait for transactions to be processed
        console.log("⏳ Waiting for bridge to process transactions...");
        await this.pause(30000); // 30 seconds
    }

    async verifyResults() {
        console.log("🔍 Verifying demo results...");
        
        // Check bridge stats
        try {
            const response = await fetch("http://localhost:8084/stats");
            if (response.ok) {
                const stats = await response.json();
                console.log("📊 Bridge Statistics:");
                console.log("   Total Transactions:", stats.total_transactions || 0);
                console.log("   Successful Relays:", stats.successful_relays || 0);
                console.log("   Failed Events:", stats.failed_events || 0);
                console.log("   Replay Protection Events:", stats.processed_events_total || 0);
            }
        } catch (error) {
            console.log("⚠️  Could not fetch bridge stats");
        }
        
        // Check log files
        const logFiles = ['bridge.log', 'bridge_events.jsonl'];
        for (const logFile of logFiles) {
            const logPath = path.join(__dirname, "logs", logFile);
            if (fs.existsSync(logPath)) {
                const stats = fs.statSync(logPath);
                console.log(`📄 ${logFile}: ${stats.size} bytes`);
            }
        }
        
        console.log("✅ Results verification complete");
        console.log("📋 Check the following for detailed results:");
        console.log("   - Bridge Dashboard: http://localhost:8084");
        console.log("   - Log files in: ./logs/");
        console.log("   - Config files in: ./config/");
    }

    async cleanup() {
        console.log("🧹 Cleaning up demo...");
        
        // Stop monitoring
        if (this.monitor) {
            this.monitor.stop();
        }
        
        // Stop bridge process
        if (this.bridgeProcess) {
            this.bridgeProcess.kill('SIGTERM');
            console.log("🛑 Bridge process stopped");
        }
        
        console.log("✅ Cleanup complete");
    }

    async runCommand(command) {
        return new Promise((resolve, reject) => {
            const [cmd, ...args] = command.split(' ');
            const process = spawn(cmd, args, { stdio: 'pipe' });
            
            let output = '';
            process.stdout.on('data', (data) => {
                output += data.toString();
            });
            
            process.on('close', (code) => {
                if (code === 0) {
                    resolve(output.trim());
                } else {
                    reject(new Error(`Command failed with code ${code}`));
                }
            });
        });
    }

    async pause(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
    console.log("\n🛑 Demo interrupted");
    if (global.demo) {
        global.demo.cleanup().then(() => process.exit(0));
    } else {
        process.exit(0);
    }
});

// Run demo if called directly
if (require.main === module) {
    global.demo = new EndToEndDemo();
    global.demo.runDemo().catch(console.error);
}

module.exports = { EndToEndDemo };
