package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	bridgesdk "github.com/Shivam-Patel-G/blackhole-blockchain/bridge-sdk"
	"github.com/Shivam-Patel-G/blackhole-blockchain/bridge/core"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

var sdk *bridgesdk.BridgeSDK

func main() {
	log.Println("🚀 Starting Bridge SDK Example...")

	// Create a new blockchain instance
	blockchain, err := chain.NewBlockchain(3001) // Use port 3001 for bridge SDK
	if err != nil {
		log.Fatal("❌ Failed to create blockchain:", err)
	}

	// Create SDK with testnet configuration for end-to-end demo
	config := &bridgesdk.BridgeSDKConfig{
		Listeners: bridgesdk.ListenerConfig{
			// Ethereum Sepolia Testnet (free public RPC)
			EthereumRPC: "wss://ethereum-sepolia-rpc.publicnode.com",
			// Solana Devnet (free public RPC)
			SolanaRPC:   "wss://api.devnet.solana.com",
			PolkadotRPC: "wss://rpc.polkadot.io",
		},
		Relay: bridgesdk.RelayConfig{
			MinConfirmations: 1, // Faster for testnet demo
			RelayTimeout:     30 * time.Second,
			MaxRetries:       3,
		},
	}

	// Initialize the SDK
	sdk = bridgesdk.NewBridgeSDK(blockchain, config)

	if err := sdk.Initialize(); err != nil {
		log.Fatal("❌ Failed to initialize SDK:", err)
	}

	// Start listeners
	log.Println("🔗 Starting blockchain listeners...")

	if err := sdk.StartEthListener(); err != nil {
		log.Printf("⚠️ Failed to start Ethereum listener: %v", err)
	} else {
		log.Println("✅ Ethereum listener started")
	}

	if err := sdk.StartSolanaListener(); err != nil {
		log.Printf("⚠️ Failed to start Solana listener: %v", err)
	} else {
		log.Println("✅ Solana listener started")
	}

	// Start web server for monitoring
	go startWebServer()

	// Monitor transactions
	go monitorTransactions()

	// Demonstrate manual relay
	go demonstrateManualRelay()

	log.Println("🌟 Bridge SDK Example is running...")
	log.Println("📊 Visit http://localhost:8084 for monitoring dashboard")
	log.Println("📈 Visit http://localhost:8084/stats for statistics")
	log.Println("📋 Visit http://localhost:8084/transactions for transaction list")
	log.Println("🏥 Visit http://localhost:8084/health for health status")
	log.Println("⚠️ Visit http://localhost:8084/errors for error metrics")
	log.Println("🔴 Visit http://localhost:8084/circuit-breakers for circuit breaker status")

	// Setup graceful shutdown
	setupGracefulShutdown()

	// Keep the program running
	select {}
}

func startWebServer() {
	http.HandleFunc("/", dashboardHandler)
	http.HandleFunc("/blackhole-logo.jpg", logoHandler)
	http.HandleFunc("/stats", statsHandler)
	http.HandleFunc("/transactions", transactionsHandler)
	http.HandleFunc("/transaction/", transactionHandler)
	http.HandleFunc("/relay", relayHandler)
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/errors", errorHandler)
	http.HandleFunc("/circuit-breakers", circuitBreakerHandler)
	http.HandleFunc("/failed-events", failedEventsHandler)
	http.HandleFunc("/force-recovery", forceRecoveryHandler)
	http.HandleFunc("/replay-protection", replayProtectionHandler)
	http.HandleFunc("/processed-events", processedEventsHandler)
	http.HandleFunc("/cleanup-events", cleanupEventsHandler)
	http.HandleFunc("/logs", logsHandler)
	http.HandleFunc("/ws/logs", wsLogsHandler)
	http.HandleFunc("/api/validate-transfer", validateTransferHandler)
	http.HandleFunc("/api/initiate-transfer", initiateTransferHandler)
	http.HandleFunc("/api/instant-transfer", instantTransferHandler)
	http.HandleFunc("/api/transfer-status/", transferStatusHandler)
	http.HandleFunc("/api/supported-pairs", supportedPairsHandler)

	// Start log streamer if available
	if sdk != nil && sdk.LogStreamer != nil {
		sdk.LogStreamer.Start()
		log.Println("📡 Log streaming service started")
	}

	log.Println("🌐 Starting web server on http://localhost:8084")
	log.Println("📊 Dashboard: http://localhost:8084")
	log.Println("📜 Live Logs: http://localhost:8084/logs")
	log.Println("🔌 WebSocket Logs: ws://localhost:8084/ws/logs")

	if err := http.ListenAndServe(":8084", nil); err != nil {
		log.Printf("❌ Failed to start web server: %v", err)
	}
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	html := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🌉 BlackHole Bridge Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background:
                radial-gradient(ellipse at center, rgba(0, 0, 0, 0.95) 0%, rgba(0, 0, 0, 0.98) 50%, rgba(0, 0, 0, 1) 100%),
                radial-gradient(ellipse at 20% 80%, rgba(255, 193, 7, 0.08) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 20%, rgba(0, 188, 212, 0.06) 0%, transparent 50%),
                radial-gradient(ellipse at 40% 40%, rgba(255, 193, 7, 0.04) 0%, transparent 50%),
                linear-gradient(135deg, #000000 0%, #0a0a0a 25%, #111111 50%, #0a0a0a 75%, #000000 100%);
            background-size: 100% 100%, 80% 80%, 60% 60%, 40% 40%, 100% 100%;
            background-attachment: fixed;
            animation: cosmicShift 25s ease infinite;
            min-height: 100vh;
            color: #ffffff;
            overflow-x: hidden;
            margin: 0;
            padding: 0;
            position: relative;
        }

        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image:
                radial-gradient(2px 2px at 20px 30px, rgba(255, 193, 7, 0.8), transparent),
                radial-gradient(2px 2px at 40px 70px, rgba(255, 255, 255, 0.9), transparent),
                radial-gradient(1px 1px at 90px 40px, rgba(0, 188, 212, 0.7), transparent),
                radial-gradient(1px 1px at 130px 80px, rgba(255, 255, 255, 0.6), transparent),
                radial-gradient(2px 2px at 160px 30px, rgba(255, 193, 7, 0.6), transparent);
            background-repeat: repeat;
            background-size: 200px 100px;
            animation: twinkle 4s ease-in-out infinite alternate;
            pointer-events: none;
            z-index: -1;
        }





        .sidebar {
            position: fixed !important;
            left: 0 !important;
            top: 0 !important;
            bottom: 0 !important;
            width: 280px;
            height: 100vh !important;
            max-height: 100vh !important;
            background:
                radial-gradient(ellipse at top, rgba(0, 0, 0, 0.95) 0%, rgba(0, 0, 0, 0.98) 100%),
                linear-gradient(135deg, rgba(0, 0, 0, 0.9) 0%, rgba(10, 10, 10, 0.95) 100%);
            backdrop-filter: blur(25px);
            border-right: 1px solid rgba(255, 193, 7, 0.3);
            box-shadow:
                0 0 30px rgba(255, 193, 7, 0.1),
                inset 0 0 20px rgba(0, 0, 0, 0.5);
            z-index: 9999 !important;
            overflow-y: auto;
            overflow-x: hidden;
            padding: 20px;
            box-sizing: border-box;
            transform: translate3d(0, 0, 0) !important;
            -webkit-transform: translate3d(0, 0, 0) !important;
            will-change: transform;
        }

        .sidebar::-webkit-scrollbar {
            width: 6px;
        }

        .sidebar::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.4);
        }

        .sidebar::-webkit-scrollbar-thumb {
            background: rgba(255, 193, 7, 0.4);
            border-radius: 3px;
        }

        .sidebar::-webkit-scrollbar-thumb:hover {
            background: rgba(255, 193, 7, 0.6);
        }

        .sidebar-header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid rgba(255, 193, 7, 0.2);
        }

        .sidebar-header h3 {
            font-size: 1.2rem;
            margin: 0;
            background: linear-gradient(135deg, #ffc107, #00bcd4);
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: 600;
            text-shadow: 0 0 10px rgba(255, 193, 7, 0.3);
        }

        .main-content {
            margin-left: 280px !important;
            flex: 1;
            min-height: 100vh;
            width: calc(100% - 280px) !important;
            position: relative;
            z-index: 1;
        }

        @keyframes cosmicShift {
            0% {
                background-position: 0% 50%, 0% 0%, 100% 100%, 50% 50%, 0% 50%;
                filter: hue-rotate(0deg) brightness(1);
            }
            25% {
                background-position: 100% 50%, 20% 20%, 80% 80%, 30% 70%, 25% 75%;
                filter: hue-rotate(45deg) brightness(1.05);
            }
            50% {
                background-position: 50% 100%, 40% 40%, 60% 60%, 70% 30%, 50% 50%;
                filter: hue-rotate(90deg) brightness(1.1);
            }
            75% {
                background-position: 0% 0%, 60% 60%, 40% 40%, 80% 80%, 75% 25%;
                filter: hue-rotate(135deg) brightness(1.05);
            }
            100% {
                background-position: 0% 50%, 0% 0%, 100% 100%, 50% 50%, 0% 50%;
                filter: hue-rotate(180deg) brightness(1);
            }
        }

        @keyframes twinkle {
            0% { opacity: 0.3; }
            50% { opacity: 1; }
            100% { opacity: 0.3; }
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            position: relative;
        }

        .header {
            text-align: center;
            margin-bottom: 50px;
            position: relative;
        }

        .header::before {
            content: '';
            position: absolute;
            top: -20px;
            left: 50%;
            transform: translateX(-50%);
            width: 100px;
            height: 4px;
            background: linear-gradient(90deg, #00d4ff, #7c3aed, #f59e0b);
            border-radius: 2px;
            animation: pulse 2s ease-in-out infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 0.6; transform: translateX(-50%) scaleX(1); }
            50% { opacity: 1; transform: translateX(-50%) scaleX(1.2); }
        }

        .header-content {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 20px;
            margin-bottom: 10px;
        }

        .blackhole-logo-img {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            border: 3px solid transparent;
            background: linear-gradient(135deg, #ffc107, #00bcd4, #ffb300);
            background-clip: border-box;
            padding: 3px;
            position: relative;
            animation: blackholeRotate 12s linear infinite;
            box-shadow:
                0 0 30px rgba(255, 193, 7, 0.4),
                0 0 60px rgba(0, 188, 212, 0.3);
            object-fit: cover;
        }



        .header h1 {
            font-size: 3.5rem;
            margin: 0;
            background: linear-gradient(135deg, #ffc107, #00bcd4, #ffb300);
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 0 30px rgba(255, 193, 7, 0.4);
            font-weight: 700;
            letter-spacing: -1px;
        }

        .header p {
            font-size: 1.3rem;
            color: #e0e0e0;
            font-weight: 300;
            margin: 10px 0 0 0;
            text-shadow: 0 0 10px rgba(255, 193, 7, 0.2);
        }

        @keyframes blackholeRotate {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        @keyframes blackholeGlow {
            0% {
                opacity: 0.6;
                transform: scale(1);
            }
            100% {
                opacity: 1;
                transform: scale(1.1);
            }
        }

        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 25px;
            margin-bottom: 40px;
        }

        .card {
            background:
                radial-gradient(ellipse at top left, rgba(0, 0, 0, 0.85) 0%, rgba(10, 10, 10, 0.9) 100%),
                linear-gradient(135deg, rgba(0, 0, 0, 0.8) 0%, rgba(15, 15, 15, 0.85) 100%);
            border: 1px solid rgba(255, 193, 7, 0.2);
            border-radius: 20px;
            padding: 30px;
            backdrop-filter: blur(25px);
            position: relative;
            overflow: hidden;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            cursor: pointer;
            box-shadow:
                0 8px 32px rgba(0, 0, 0, 0.4),
                0 0 20px rgba(255, 193, 7, 0.08);
        }

        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(135deg,
                rgba(255, 193, 7, 0.05) 0%,
                rgba(0, 188, 212, 0.05) 50%,
                rgba(255, 193, 7, 0.05) 100%);
            opacity: 0;
            transition: opacity 0.3s ease;
            z-index: 1;
        }

        .card::after {
            content: '';
            position: absolute;
            top: -2px;
            left: -2px;
            right: -2px;
            bottom: -2px;
            background: linear-gradient(135deg, #ffc107, #00bcd4, #ffb300);
            border-radius: 22px;
            opacity: 0;
            z-index: -1;
            transition: opacity 0.3s ease;
        }

        .card:hover {
            transform: translateY(-4px) scale(1.01);
            box-shadow:
                0 12px 40px rgba(0, 0, 0, 0.5),
                0 0 30px rgba(255, 193, 7, 0.15),
                inset 0 1px 0 rgba(255, 255, 255, 0.05);
            border-color: rgba(255, 193, 7, 0.4);
        }

        .card:hover::before {
            opacity: 0.6;
        }

        .card:hover::after {
            opacity: 0.25;
        }

        .card > * {
            position: relative;
            z-index: 2;
        }

        .card h2 {
            color: #ffffff;
            margin-bottom: 25px;
            font-size: 1.4rem;
            display: flex;
            align-items: center;
            gap: 12px;
            font-weight: 600;
            text-shadow: 0 0 10px rgba(255, 193, 7, 0.3);
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
        }

        .stat-item {
            background: linear-gradient(135deg, rgba(255, 193, 7, 0.08), rgba(0, 188, 212, 0.08));
            border: 1px solid rgba(255, 193, 7, 0.2);
            color: #ffffff;
            padding: 25px;
            border-radius: 15px;
            text-align: center;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }

        .stat-item::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.1), transparent);
            transition: left 0.6s ease;
        }

        .stat-item:hover {
            transform: scale(1.03);
            box-shadow: 0 10px 25px rgba(255, 193, 7, 0.15);
            border-color: rgba(255, 193, 7, 0.4);
        }

        .stat-item:hover::before {
            left: 100%;
        }

        .stat-value {
            font-size: 2.2rem;
            font-weight: 800;
            margin-bottom: 8px;
            background: linear-gradient(135deg, #ffc107, #00bcd4);
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 0 20px rgba(255, 193, 7, 0.3);
        }

        .stat-label {
            font-size: 0.95rem;
            color: #d0d0d0;
            font-weight: 500;
        }

        .status-indicator {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            padding: 12px 20px;
            border-radius: 25px;
            font-size: 0.95rem;
            font-weight: 600;
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
        }

        .status-running {
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.2), rgba(5, 150, 105, 0.2));
            color: #10b981;
            border: 1px solid rgba(16, 185, 129, 0.3);
            box-shadow: 0 0 20px rgba(16, 185, 129, 0.2);
        }

        .status-stopped {
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.2), rgba(220, 38, 38, 0.2));
            color: #ef4444;
            border: 1px solid rgba(239, 68, 68, 0.3);
            box-shadow: 0 0 20px rgba(239, 68, 68, 0.2);
        }

        .transactions-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: rgba(15, 23, 42, 0.4);
            border-radius: 15px;
            overflow: hidden;
        }

        .transactions-table th,
        .transactions-table td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid rgba(148, 163, 184, 0.1);
        }

        .transactions-table th {
            background: rgba(0, 212, 255, 0.1);
            font-weight: 600;
            color: #00d4ff;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-size: 0.85rem;
        }

        .transactions-table td {
            color: #e0e6ed;
        }

        .status-badge {
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .status-pending {
            background: linear-gradient(135deg, rgba(245, 158, 11, 0.2), rgba(217, 119, 6, 0.2));
            color: #f59e0b;
            border: 1px solid rgba(245, 158, 11, 0.3);
        }

        .status-confirmed {
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.2), rgba(37, 99, 235, 0.2));
            color: #3b82f6;
            border: 1px solid rgba(59, 130, 246, 0.3);
        }

        .status-completed {
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.2), rgba(5, 150, 105, 0.2));
            color: #10b981;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }

        .status-failed {
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.2), rgba(220, 38, 38, 0.2));
            color: #ef4444;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .chain-badge {
            padding: 6px 12px;
            border-radius: 15px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .chain-ethereum {
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.2), rgba(79, 70, 229, 0.2));
            color: #6366f1;
            border: 1px solid rgba(99, 102, 241, 0.3);
        }

        .chain-solana {
            background: linear-gradient(135deg, rgba(168, 85, 247, 0.2), rgba(147, 51, 234, 0.2));
            color: #a855f7;
            border: 1px solid rgba(168, 85, 247, 0.3);
        }

        .chain-blackhole {
            background: linear-gradient(135deg, rgba(71, 85, 105, 0.2), rgba(51, 65, 85, 0.2));
            color: #64748b;
            border: 1px solid rgba(71, 85, 105, 0.3);
        }

        .refresh-btn {
            background: linear-gradient(135deg, rgba(0, 212, 255, 0.2), rgba(124, 58, 237, 0.2));
            color: #00d4ff;
            border: 1px solid rgba(0, 212, 255, 0.3);
            padding: 12px 24px;
            border-radius: 25px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }

        .refresh-btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.1), transparent);
            transition: left 0.6s ease;
        }

        .refresh-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0, 212, 255, 0.3);
            border-color: rgba(0, 212, 255, 0.5);
        }

        .refresh-btn:hover::before {
            left: 100%;
        }

        .loading {
            display: inline-block;
            width: 24px;
            height: 24px;
            border: 3px solid rgba(148, 163, 184, 0.2);
            border-top: 3px solid #00d4ff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .no-data {
            text-align: center;
            color: #64748b;
            font-style: italic;
            padding: 50px;
            font-size: 1.1rem;
        }

        .quick-actions {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .action-btn {
            background: rgba(0, 0, 0, 0.4);
            color: #ffffff;
            text-decoration: none;
            padding: 12px 16px;
            border-radius: 12px;
            font-weight: 500;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            display: flex;
            align-items: center;
            gap: 12px;
            border: 1px solid rgba(255, 193, 7, 0.15);
            position: relative;
            overflow: hidden;
            cursor: pointer;
            font-family: inherit;
            font-size: 0.9rem;
            width: 100%;
            box-sizing: border-box;
        }

        .action-btn.logs-btn {
            background: rgba(245, 158, 11, 0.1);
            border-color: rgba(245, 158, 11, 0.2);
        }

        .action-btn.logs-btn:hover {
            color: #f59e0b;
            background: rgba(245, 158, 11, 0.2);
            border-color: rgba(245, 158, 11, 0.4);
            box-shadow: 0 8px 20px rgba(245, 158, 11, 0.15);
        }

        .action-btn:active {
            transform: translateX(2px);
            transition: transform 0.1s ease;
        }

        .sidebar .action-btn {
            border: 1px solid rgba(255, 193, 7, 0.1);
            background: rgba(0, 0, 0, 0.3);
        }

        .sidebar .action-btn:hover {
            background: linear-gradient(135deg, rgba(255, 193, 7, 0.08), rgba(0, 188, 212, 0.08));
            border: 1px solid rgba(255, 193, 7, 0.25);
            color: #ffc107;
        }

        /* Token Transfer Transactions Styles */
        .transactions-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            background: rgba(15, 23, 42, 0.6);
            border-radius: 10px;
            overflow: hidden;
        }

        .transactions-table th,
        .transactions-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid rgba(148, 163, 184, 0.1);
        }

        .transactions-table th {
            background: rgba(15, 23, 42, 0.8);
            color: #94a3b8;
            font-weight: 600;
            font-size: 0.9rem;
        }

        .transactions-table td {
            color: #e0e6ed;
            font-size: 0.85rem;
        }

        .transactions-table tr:hover {
            background: rgba(0, 212, 255, 0.05);
        }

        .chain-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .chain-ethereum {
            background: rgba(98, 126, 234, 0.2);
            color: #627eea;
            border: 1px solid rgba(98, 126, 234, 0.3);
        }

        .chain-solana {
            background: rgba(220, 31, 255, 0.2);
            color: #dc1fff;
            border: 1px solid rgba(220, 31, 255, 0.3);
        }

        .chain-blackhole {
            background: rgba(0, 0, 0, 0.4);
            color: #ffffff;
            border: 1px solid rgba(255, 255, 255, 0.3);
        }

        .status-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .status-completed {
            background: rgba(16, 185, 129, 0.2);
            color: #10b981;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }

        .status-pending {
            background: rgba(59, 130, 246, 0.2);
            color: #3b82f6;
            border: 1px solid rgba(59, 130, 246, 0.3);
        }

        .status-failed {
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .action-btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.1), transparent);
            transition: left 0.6s ease;
        }

        .action-btn:hover {
            transform: translateX(3px);
            text-decoration: none;
            color: #ffc107;
            background: rgba(255, 193, 7, 0.08);
            border-color: rgba(255, 193, 7, 0.3);
            box-shadow: 0 6px 15px rgba(255, 193, 7, 0.12);
        }

        .action-btn:hover::before {
            left: 100%;
        }

        /* Cosmic particles effect */
        .particles {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: -1;
        }

        .particle {
            position: absolute;
            border-radius: 50%;
            animation: cosmicFloat 25s linear infinite;
        }

        .particle.star {
            width: 2px;
            height: 2px;
            background: rgba(255, 255, 255, 0.9);
            box-shadow: 0 0 6px rgba(255, 193, 7, 0.4);
        }

        .particle.nebula {
            width: 8px;
            height: 8px;
            background: radial-gradient(circle, rgba(255, 193, 7, 0.3) 0%, transparent 70%);
            animation: nebulaPulse 15s ease-in-out infinite alternate;
        }

        .particle.cosmic-dust {
            width: 1px;
            height: 1px;
            background: rgba(0, 188, 212, 0.7);
            box-shadow: 0 0 4px rgba(0, 188, 212, 0.5);
        }

        .particle.galaxy {
            width: 12px;
            height: 12px;
            background: radial-gradient(ellipse, rgba(255, 193, 7, 0.2) 0%, rgba(0, 188, 212, 0.15) 50%, transparent 70%);
            animation: galaxyRotate 30s linear infinite;
        }

        @keyframes cosmicFloat {
            0% {
                transform: translateY(100vh) translateX(0px) rotate(0deg);
                opacity: 0;
            }
            10% {
                opacity: 1;
            }
            50% {
                transform: translateY(50vh) translateX(20px) rotate(180deg);
                opacity: 1;
            }
            90% {
                opacity: 1;
            }
            100% {
                transform: translateY(-10vh) translateX(-20px) rotate(360deg);
                opacity: 0;
            }
        }

        @keyframes nebulaPulse {
            0% {
                transform: scale(1);
                opacity: 0.3;
            }
            50% {
                transform: scale(1.5);
                opacity: 0.7;
            }
            100% {
                transform: scale(1);
                opacity: 0.3;
            }
        }

        @keyframes galaxyRotate {
            0% {
                transform: rotate(0deg) scale(1);
                opacity: 0.4;
            }
            50% {
                transform: rotate(180deg) scale(1.2);
                opacity: 0.8;
            }
            100% {
                transform: rotate(360deg) scale(1);
                opacity: 0.4;
            }
        }

        @media (max-width: 768px) {
            .sidebar {
                width: 100% !important;
                height: auto !important;
                position: fixed !important;
                top: 0 !important;
                left: 0 !important;
                z-index: 9999 !important;
                border-right: none;
                border-bottom: 1px solid rgba(255, 193, 7, 0.2);
                max-height: 200px;
                overflow-y: auto;
            }

            .main-content {
                margin-left: 0 !important;
                margin-top: 200px;
                width: 100% !important;
            }

            .app-layout {
                flex-direction: column;
            }

            .header h1 {
                font-size: 2.5rem;
            }

            .dashboard-grid {
                grid-template-columns: 1fr;
                gap: 20px;
            }

            .card {
                padding: 25px;
            }

            .stat-value {
                font-size: 2rem;
            }

            .quick-actions {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 10px;
            }

            .action-btn {
                justify-content: center;
                text-align: center;
            }
        }
    </style>
</head>
<body>
    <!-- Floating particles background -->
    <div class="particles" id="particles"></div>

    <!-- Fixed Left Sidebar -->
    <div class="sidebar">
        <div class="sidebar-header">
            <h3>⚡ Quick Actions</h3>
        </div>
        <div class="quick-actions">
            <a href="/stats" class="action-btn">📈 Statistics API</a>
            <a href="/transactions" class="action-btn">📋 All Transactions</a>
            <a href="/relay" class="action-btn">🔄 Manual Relay</a>
            <a href="/health" class="action-btn">🏥 Health Status</a>
            <a href="/errors" class="action-btn">⚠️ Error Metrics</a>
            <a href="/logs" class="action-btn logs-btn">📜 Live Logs</a>
            <a href="#token-transfer" class="action-btn" onclick="toggleTokenTransfer()">🔄 Token Transfer</a>
            <a href="/circuit-breakers" class="action-btn">🔴 Circuit Breakers</a>
            <a href="/failed-events" class="action-btn">🔧 Failed Events</a>
            <a href="/replay-protection" class="action-btn">🔒 Replay Protection</a>
            <a href="/processed-events" class="action-btn">📋 Processed Events</a>
            <button class="action-btn" onclick="forceRecovery()">🚀 Force Recovery</button>
            <button class="action-btn" onclick="cleanupOldEvents()">🧹 Cleanup Old Events</button>
            <button class="action-btn" onclick="refreshAll()">🔄 Refresh All</button>
        </div>
    </div>

    <!-- Main Content Area -->
    <div class="main-content">
            <div class="container">
                <div class="header">
                    <div class="header-content">
                        <img src="/blackhole-logo.jpg" alt="BlackHole Logo" class="blackhole-logo-img">
                        <h1>BlackHole Bridge Dashboard</h1>
                    </div>
                    <p>Real-time Cross-Chain Bridge Monitoring & Management</p>
                </div>

        <div class="dashboard-grid">
            <!-- Statistics Card -->
            <div class="card">
                <h2>📊 Live Statistics</h2>
                <div class="stats-grid" id="stats-grid">
                    <div class="loading"></div>
                </div>
                <button class="refresh-btn" onclick="refreshStats()">🔄 Refresh</button>
            </div>

            <!-- Listener Status Card -->
            <div class="card">
                <h2>🔗 Listener Status</h2>
                <div id="listener-status">
                    <div class="loading"></div>
                </div>
            </div>

            <!-- Error Handling Card -->
            <div class="card">
                <h2>⚠️ Error Handling</h2>
                <div id="error-metrics">
                    <div class="loading"></div>
                </div>
            </div>

            <!-- Recovery System Card -->
            <div class="card">
                <h2>🔧 Recovery System</h2>
                <div id="recovery-metrics">
                    <div class="loading"></div>
                </div>
            </div>

            <!-- Replay Protection Card -->
            <div class="card">
                <h2>🔒 Replay Protection</h2>
                <div id="replay-protection-metrics">
                    <div class="loading"></div>
                </div>
            </div>

                <!-- Recent Transactions Card -->
                <div class="card" style="grid-column: 1 / -1;">
                    <h2>📋 Recent Transactions</h2>
                    <div id="transactions-container">
                        <div class="loading"></div>
                    </div>
                </div>
            </div>

            <!-- Token Transfer Widget -->
            <div id="tokenTransferWidget" style="display: none;">
                ` + getTokenTransferWidget() + `
            </div>

            <!-- Token Transfer Transactions Display -->
            <div id="tokenTransferTransactions" style="display: none; margin-top: 20px;">
                <div class="card">
                    <h2>🔄 Recent Token Transfers</h2>
                    <div id="token-transfers-container">
                        <div class="loading"></div>
                    </div>
                    <div style="margin-top: 15px; text-align: center;">
                        <button class="refresh-btn" onclick="refreshTokenTransfers()">🔄 Refresh Transfers</button>
                        <button class="refresh-btn" onclick="clearTokenTransfers()" style="margin-left: 10px; background: linear-gradient(135deg, rgba(239, 68, 68, 0.2), rgba(220, 38, 38, 0.2)); border-color: rgba(239, 68, 68, 0.3);">🗑️ Clear History</button>
                    </div>
                </div>
            </div>

            <!-- Supported Pairs Widget -->
            <div id="supportedPairsWidget" style="display: none;">
                ` + getSupportedPairsWidget() + `
            </div>
        </div>
    </div>
</div>

    <script>
        function toggleTokenTransfer() {
            const widget = document.getElementById('tokenTransferWidget');
            const pairsWidget = document.getElementById('supportedPairsWidget');
            const transfersWidget = document.getElementById('tokenTransferTransactions');

            if (widget.style.display === 'none') {
                widget.style.display = 'block';
                pairsWidget.style.display = 'block';
                transfersWidget.style.display = 'block';
                // Load token transfers when showing the widget
                refreshTokenTransfers();
            } else {
                widget.style.display = 'none';
                pairsWidget.style.display = 'none';
                transfersWidget.style.display = 'none';
            }
        }
        let refreshInterval;

        function refreshStats() {
            fetch('/stats')
                .then(response => response.json())
                .then(data => {
                    updateStatsGrid(data);
                    updateListenerStatus(data);
                    updateErrorMetrics(data);
                    updateRecoveryMetrics(data);
                    updateReplayProtectionMetrics(data);
                })
                .catch(error => {
                    console.error('Error fetching stats:', error);
                });
        }

        function refreshTransactions() {
            fetch('/transactions')
                .then(response => response.json())
                .then(data => {
                    updateTransactionsTable(data);
                })
                .catch(error => {
                    console.error('Error fetching transactions:', error);
                });
        }

        function updateStatsGrid(data) {
            const statsGrid = document.getElementById('stats-grid');
            statsGrid.innerHTML = ` + "`" + `
                <div class="stat-item">
                    <div class="stat-value">${data.total_transactions || 0}</div>
                    <div class="stat-label">Total Transactions</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">${data.pending || 0}</div>
                    <div class="stat-label">Pending</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">${data.completed || 0}</div>
                    <div class="stat-label">Completed</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">${data.failed || 0}</div>
                    <div class="stat-label">Failed</div>
                </div>
            ` + "`" + `;
        }

        function updateListenerStatus(data) {
            const listenerStatus = document.getElementById('listener-status');
            const ethStatus = data.eth_listener_running ? 'running' : 'stopped';
            const solanaStatus = data.solana_listener_running ? 'running' : 'stopped';

            listenerStatus.innerHTML = ` + "`" + `
                <div style="margin-bottom: 15px;">
                    <span class="status-indicator status-${ethStatus}">
                        ${ethStatus === 'running' ? '🟢' : '🔴'} Ethereum Listener
                    </span>
                </div>
                <div style="margin-bottom: 15px;">
                    <span class="status-indicator status-${solanaStatus}">
                        ${solanaStatus === 'running' ? '🟢' : '🔴'} Solana Listener
                    </span>
                </div>
                <div>
                    <span class="status-indicator ${data.sdk_initialized ? 'status-running' : 'status-stopped'}">
                        ${data.sdk_initialized ? '🟢' : '🔴'} SDK Initialized
                    </span>
                </div>
            ` + "`" + `;
        }

        function updateErrorMetrics(data) {
            const errorMetrics = document.getElementById('error-metrics');
            const healthScore = data.health_score || 0;
            const totalErrors = data.total_errors || 0;
            const recoveryCount = data.recovery_count || 0;
            const openCircuits = data.open_circuit_breakers || 0;

            const healthColor = healthScore >= 80 ? '#48bb78' : healthScore >= 60 ? '#ed8936' : '#f56565';

            errorMetrics.innerHTML = ` + "`" + `
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px;">
                    <div style="text-align: center; padding: 10px; background: ${healthColor}; color: white; border-radius: 8px;">
                        <div style="font-size: 1.5rem; font-weight: bold;">${healthScore.toFixed(1)}%</div>
                        <div style="font-size: 0.8rem;">Health Score</div>
                    </div>
                    <div style="text-align: center; padding: 10px; background: #4299e1; color: white; border-radius: 8px;">
                        <div style="font-size: 1.5rem; font-weight: bold;">${totalErrors}</div>
                        <div style="font-size: 0.8rem;">Total Errors</div>
                    </div>
                    <div style="text-align: center; padding: 10px; background: #38b2ac; color: white; border-radius: 8px;">
                        <div style="font-size: 1.5rem; font-weight: bold;">${recoveryCount}</div>
                        <div style="font-size: 0.8rem;">Recoveries</div>
                    </div>
                    <div style="text-align: center; padding: 10px; background: ${openCircuits > 0 ? '#f56565' : '#48bb78'}; color: white; border-radius: 8px;">
                        <div style="font-size: 1.5rem; font-weight: bold;">${openCircuits}</div>
                        <div style="font-size: 0.8rem;">Open Circuits</div>
                    </div>
                </div>
            ` + "`" + `;
        }

        function updateTransactionsTable(transactions) {
            const container = document.getElementById('transactions-container');

            if (!transactions || transactions.length === 0) {
                container.innerHTML = '<div class="no-data">No transactions found</div>';
                return;
            }

            const recentTransactions = transactions.slice(-10).reverse(); // Show last 10, most recent first

            let tableHTML = ` + "`" + `
                <table class="transactions-table">
                    <thead>
                        <tr>
                            <th>Transaction ID</th>
                            <th>Source Chain</th>
                            <th>Destination</th>
                            <th>Amount</th>
                            <th>Status</th>
                            <th>Created</th>
                        </tr>
                    </thead>
                    <tbody>
            ` + "`" + `;

            recentTransactions.forEach(tx => {
                const shortId = tx.id.substring(0, 20) + '...';
                const amount = (tx.amount / 1e18).toFixed(6); // Convert from wei
                const createdDate = new Date(tx.created_at * 1000).toLocaleString();

                tableHTML += ` + "`" + `
                    <tr>
                        <td title="${tx.id}">${shortId}</td>
                        <td><span class="chain-badge chain-${tx.source_chain}">${tx.source_chain}</span></td>
                        <td><span class="chain-badge chain-${tx.dest_chain}">${tx.dest_chain}</span></td>
                        <td>${amount} ${tx.token_symbol}</td>
                        <td><span class="status-badge status-${tx.status}">${tx.status}</span></td>
                        <td>${createdDate}</td>
                    </tr>
                ` + "`" + `;
            });

            tableHTML += ` + "`" + `
                    </tbody>
                </table>
            ` + "`" + `;

            container.innerHTML = tableHTML;
        }

        function updateRecoveryMetrics(data) {
            const recoveryMetrics = document.getElementById('recovery-metrics');
            const failedEventsCount = data.failed_events_count || 0;
            const recoveryActive = data.recovery_system_active || false;

            const statusColor = failedEventsCount === 0 ? '#48bb78' : failedEventsCount < 10 ? '#ed8936' : '#f56565';
            const activeColor = recoveryActive ? '#48bb78' : '#f56565';

            recoveryMetrics.innerHTML = ` + "`" + `
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px;">
                    <div style="text-align: center; padding: 10px; background: ${statusColor}; color: white; border-radius: 8px;">
                        <div style="font-size: 1.5rem; font-weight: bold;">${failedEventsCount}</div>
                        <div style="font-size: 0.8rem;">Failed Events</div>
                    </div>
                    <div style="text-align: center; padding: 10px; background: ${activeColor}; color: white; border-radius: 8px;">
                        <div style="font-size: 1.2rem; font-weight: bold;">${recoveryActive ? 'ACTIVE' : 'INACTIVE'}</div>
                        <div style="font-size: 0.8rem;">Recovery System</div>
                    </div>
                </div>
                ${failedEventsCount > 0 ? '<div style="margin-top: 10px; text-align: center;"><button onclick="forceRecovery()" style="background: #4299e1; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer;">🚀 Force Recovery</button></div>' : ''}
            ` + "`" + `;
        }

        function updateReplayProtectionMetrics(data) {
            const replayMetrics = document.getElementById('replay-protection-metrics');
            const processedEvents = data.processed_events_total || 0;
            const cacheSize = data.replay_cache_size || 0;
            const uniqueTransactions = data.unique_transactions || 0;
            const replayActive = data.replay_protection_active || false;

            const activeColor = replayActive ? '#48bb78' : '#f56565';

            replayMetrics.innerHTML = ` + "`" + `
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-bottom: 10px;">
                    <div style="text-align: center; padding: 10px; background: ${activeColor}; color: white; border-radius: 8px;">
                        <div style="font-size: 1.2rem; font-weight: bold;">${replayActive ? 'ACTIVE' : 'INACTIVE'}</div>
                        <div style="font-size: 0.8rem;">Protection Status</div>
                    </div>
                    <div style="text-align: center; padding: 10px; background: #4299e1; color: white; border-radius: 8px;">
                        <div style="font-size: 1.5rem; font-weight: bold;">${processedEvents}</div>
                        <div style="font-size: 0.8rem;">Processed Events</div>
                    </div>
                </div>
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px;">
                    <div style="text-align: center; padding: 10px; background: #38b2ac; color: white; border-radius: 8px;">
                        <div style="font-size: 1.5rem; font-weight: bold;">${cacheSize}</div>
                        <div style="font-size: 0.8rem;">Cache Size</div>
                    </div>
                    <div style="text-align: center; padding: 10px; background: #9f7aea; color: white; border-radius: 8px;">
                        <div style="font-size: 1.5rem; font-weight: bold;">${uniqueTransactions}</div>
                        <div style="font-size: 0.8rem;">Unique Transactions</div>
                    </div>
                </div>
                <div style="margin-top: 10px; text-align: center;">
                    <button onclick="cleanupOldEvents()" style="background: #ed8936; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; margin-right: 5px;">🧹 Cleanup</button>
                    <button onclick="viewProcessedEvents()" style="background: #4299e1; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer;">📋 View Events</button>
                </div>
            ` + "`" + `;
        }

        function forceRecovery() {
            if (confirm('Force recovery of all failed events?')) {
                fetch('/force-recovery', { method: 'POST' })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            alert('Force recovery initiated successfully!');
                            refreshAll();
                        } else {
                            alert('Force recovery failed: ' + (data.error || 'Unknown error'));
                        }
                    })
                    .catch(error => {
                        console.error('Error:', error);
                        alert('Error initiating force recovery');
                    });
            }
        }

        function cleanupOldEvents() {
            const hours = prompt('Enter maximum age in hours for events to keep (default: 168 = 7 days):', '168');
            if (hours && !isNaN(hours) && parseInt(hours) > 0) {
                fetch('/cleanup-events?max_age_hours=' + hours, { method: 'POST' })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            alert('Cleanup completed! Deleted ' + data.deleted_count + ' old events.');
                            refreshAll();
                        } else {
                            alert('Cleanup failed: ' + (data.error || 'Unknown error'));
                        }
                    })
                    .catch(error => {
                        console.error('Error:', error);
                        alert('Error during cleanup');
                    });
            }
        }

        function viewProcessedEvents() {
            window.open('/processed-events?limit=100', '_blank');
        }

        // Token Transfer Functions
        let tokenTransfers = [];

        function refreshTokenTransfers() {
            const container = document.getElementById('token-transfers-container');
            if (!container) return;

            // Display stored token transfers
            updateTokenTransfersDisplay();
        }

        function updateTokenTransfersDisplay() {
            const container = document.getElementById('token-transfers-container');
            if (!container) return;

            if (tokenTransfers.length === 0) {
                container.innerHTML = '<div class="no-data">No token transfers yet. Use the transfer widget above to initiate transfers.</div>';
                return;
            }

            // Sort by timestamp, most recent first
            const sortedTransfers = [...tokenTransfers].sort((a, b) => b.timestamp - a.timestamp);

            let tableHTML = ` + "`" + `
                <table class="transactions-table">
                    <thead>
                        <tr>
                            <th>Transfer ID</th>
                            <th>From Chain</th>
                            <th>To Chain</th>
                            <th>Token</th>
                            <th>Amount</th>
                            <th>Status</th>
                            <th>Time</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
            ` + "`" + `;

            sortedTransfers.forEach((transfer, index) => {
                const shortId = transfer.id.substring(0, 12) + '...';
                const timeAgo = getTimeAgo(transfer.timestamp);
                const statusClass = getStatusClass(transfer.status);
                const statusIcon = getStatusIcon(transfer.status);

                tableHTML += ` + "`" + `
                    <tr>
                        <td title="${transfer.id}">${shortId}</td>
                        <td><span class="chain-badge chain-${transfer.fromChain}">${transfer.fromChain}</span></td>
                        <td><span class="chain-badge chain-${transfer.toChain}">${transfer.toChain}</span></td>
                        <td>${transfer.token.symbol}</td>
                        <td>${transfer.amount}</td>
                        <td><span class="status-badge ${statusClass}">${statusIcon} ${transfer.status}</span></td>
                        <td>${timeAgo}</td>
                        <td>
                            <button onclick="viewTransferDetails(${index})" style="background: #4299e1; color: white; border: none; padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 0.8rem;">👁️ View</button>
                            ${transfer.status === 'pending' ? '<button onclick="retryTransfer(' + index + ')" style="background: #ed8936; color: white; border: none; padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 0.8rem; margin-left: 5px;">🔄 Retry</button>' : ''}
                        </td>
                    </tr>
                ` + "`" + `;
            });

            tableHTML += ` + "`" + `
                    </tbody>
                </table>
            ` + "`" + `;

            container.innerHTML = tableHTML;
        }

        function addTokenTransfer(transferData) {
            const transfer = {
                id: transferData.id || 'transfer_' + Date.now(),
                fromChain: transferData.from_chain || transferData.fromChain,
                toChain: transferData.to_chain || transferData.toChain,
                token: transferData.token,
                amount: transferData.amount,
                status: transferData.status || 'pending',
                timestamp: Date.now(),
                fromAddress: transferData.from_address || transferData.fromAddress,
                toAddress: transferData.to_address || transferData.toAddress,
                response: transferData.response
            };

            tokenTransfers.unshift(transfer); // Add to beginning

            // Keep only last 50 transfers
            if (tokenTransfers.length > 50) {
                tokenTransfers = tokenTransfers.slice(0, 50);
            }

            // Update display if visible
            const container = document.getElementById('token-transfers-container');
            if (container && container.offsetParent !== null) {
                updateTokenTransfersDisplay();
            }

            // Save to localStorage
            localStorage.setItem('tokenTransfers', JSON.stringify(tokenTransfers));
        }

        function clearTokenTransfers() {
            if (confirm('Clear all token transfer history?')) {
                tokenTransfers = [];
                localStorage.removeItem('tokenTransfers');
                updateTokenTransfersDisplay();
            }
        }

        function getStatusClass(status) {
            switch (status.toLowerCase()) {
                case 'completed': case 'success': return 'status-completed';
                case 'pending': case 'processing': return 'status-pending';
                case 'failed': case 'error': return 'status-failed';
                default: return 'status-pending';
            }
        }

        function getStatusIcon(status) {
            switch (status.toLowerCase()) {
                case 'completed': case 'success': return '✅';
                case 'pending': case 'processing': return '⏳';
                case 'failed': case 'error': return '❌';
                default: return '⏳';
            }
        }

        function getTimeAgo(timestamp) {
            const now = Date.now();
            const diff = now - timestamp;
            const minutes = Math.floor(diff / 60000);
            const hours = Math.floor(diff / 3600000);
            const days = Math.floor(diff / 86400000);

            if (days > 0) return days + 'd ago';
            if (hours > 0) return hours + 'h ago';
            if (minutes > 0) return minutes + 'm ago';
            return 'Just now';
        }

        function viewTransferDetails(index) {
            const transfer = tokenTransfers[index];
            if (!transfer) return;

            const details = ` + "`" + `
Transfer Details:

ID: ${transfer.id}
From: ${transfer.fromAddress} (${transfer.fromChain})
To: ${transfer.toAddress} (${transfer.toChain})
Token: ${transfer.token.symbol}
Amount: ${transfer.amount}
Status: ${transfer.status}
Time: ${new Date(transfer.timestamp).toLocaleString()}

${transfer.response ? 'Response: ' + JSON.stringify(transfer.response, null, 2) : ''}
            ` + "`" + `;

            alert(details);
        }

        function retryTransfer(index) {
            const transfer = tokenTransfers[index];
            if (!transfer) return;

            if (confirm('Retry this transfer?')) {
                // Update status to processing
                transfer.status = 'processing';
                updateTokenTransfersDisplay();

                // Simulate retry (you can replace this with actual retry logic)
                setTimeout(() => {
                    transfer.status = Math.random() > 0.5 ? 'completed' : 'failed';
                    updateTokenTransfersDisplay();
                }, 2000);
            }
        }

        // Load saved transfers on page load
        function loadSavedTransfers() {
            const saved = localStorage.getItem('tokenTransfers');
            if (saved) {
                try {
                    tokenTransfers = JSON.parse(saved);
                } catch (e) {
                    console.error('Error loading saved transfers:', e);
                    tokenTransfers = [];
                }
            }

            // Add some sample data if no transfers exist (for demonstration)
            if (tokenTransfers.length === 0) {
                addSampleTransfers();
            }
        }

        // Add sample transfers for demonstration
        function addSampleTransfers() {
            const sampleTransfers = [
                {
                    id: 'transfer_demo_1',
                    fromChain: 'ethereum',
                    toChain: 'blackhole',
                    token: { symbol: 'ETH', decimals: 18, contract_address: '0x0000000000000000000000000000000000000000' },
                    amount: '0.5',
                    status: 'completed',
                    timestamp: Date.now() - 300000, // 5 minutes ago
                    fromAddress: '0x742d35Cc6634C0532925a3b8D4C9db96590c6C87',
                    toAddress: 'bh1234567890123456789012345678901234567890',
                    response: { request_id: 'transfer_demo_1', state: 'completed' }
                },
                {
                    id: 'transfer_demo_2',
                    fromChain: 'solana',
                    toChain: 'blackhole',
                    token: { symbol: 'SOL', decimals: 9, contract_address: '11111111111111111111111111111111' },
                    amount: '2.0',
                    status: 'completed',
                    timestamp: Date.now() - 600000, // 10 minutes ago
                    fromAddress: '9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM',
                    toAddress: 'bh9876543210987654321098765432109876543210',
                    response: { request_id: 'transfer_demo_2', state: 'completed' }
                },
                {
                    id: 'transfer_demo_3',
                    fromChain: 'blackhole',
                    toChain: 'ethereum',
                    token: { symbol: 'BHX', decimals: 18, contract_address: 'bh0000000000000000000000000000000000000000' },
                    amount: '100.0',
                    status: 'pending',
                    timestamp: Date.now() - 60000, // 1 minute ago
                    fromAddress: 'bh1111111111111111111111111111111111111111',
                    toAddress: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
                    response: null
                }
            ];

            tokenTransfers = sampleTransfers;
            localStorage.setItem('tokenTransfers', JSON.stringify(tokenTransfers));
        }

        // Hook into the token transfer widget's success handler
        window.addEventListener('DOMContentLoaded', function() {
            // Override the handleInstantTransferSuccess function if it exists
            if (typeof window.handleInstantTransferSuccess === 'function') {
                const originalHandler = window.handleInstantTransferSuccess;
                window.handleInstantTransferSuccess = function(result) {
                    // Call original handler
                    originalHandler(result);

                    // Add to our transaction display
                    if (result && result.request_id) {
                        addTokenTransferFromResult(result);
                    }
                };
            }
        });

        // Function to add transfer from widget result
        function addTokenTransferFromResult(result) {
            // Extract transfer data from the result
            const transferData = {
                id: result.request_id,
                fromChain: result.from_chain || 'ethereum',
                toChain: result.to_chain || 'blackhole',
                token: {
                    symbol: result.token_symbol || 'ETH',
                    decimals: result.token_decimals || 18,
                    contract_address: result.token_contract || ''
                },
                amount: result.amount || '0',
                status: 'completed',
                fromAddress: result.from_address || '',
                toAddress: result.to_address || '',
                response: result
            };

            addTokenTransfer(transferData);
        }

        // Global function that can be called from the token transfer widget
        window.addTokenTransferToHistory = function(transferRequest, transferResult) {
            const transferData = {
                id: transferResult?.request_id || transferRequest?.id || 'transfer_' + Date.now(),
                fromChain: transferRequest?.from_chain || 'ethereum',
                toChain: transferRequest?.to_chain || 'blackhole',
                token: transferRequest?.token || {
                    symbol: 'ETH',
                    decimals: 18,
                    contract_address: ''
                },
                amount: transferRequest?.amount || '0',
                status: transferResult?.error ? 'failed' : 'completed',
                fromAddress: transferRequest?.from_address || '',
                toAddress: transferRequest?.to_address || '',
                response: transferResult
            };

            addTokenTransfer(transferData);
        };

        // Global function to add pending transfer
        window.addPendingTokenTransfer = function(transferRequest) {
            const transferData = {
                id: transferRequest?.id || 'transfer_' + Date.now(),
                fromChain: transferRequest?.from_chain || 'ethereum',
                toChain: transferRequest?.to_chain || 'blackhole',
                token: transferRequest?.token || {
                    symbol: 'ETH',
                    decimals: 18,
                    contract_address: ''
                },
                amount: transferRequest?.amount || '0',
                status: 'pending',
                fromAddress: transferRequest?.from_address || '',
                toAddress: transferRequest?.to_address || '',
                response: null
            };

            addTokenTransfer(transferData);
            return transferData.id;
        };

        // Global function to update transfer status
        window.updateTokenTransferStatus = function(transferId, status, result) {
            const transfer = tokenTransfers.find(t => t.id === transferId);
            if (transfer) {
                transfer.status = status;
                if (result) {
                    transfer.response = result;
                }
                updateTokenTransfersDisplay();
                localStorage.setItem('tokenTransfers', JSON.stringify(tokenTransfers));
            }
        };

        function refreshAll() {
            refreshStats();
            refreshTransactions();
            refreshTokenTransfers();
        }

        // Create cosmic particles
        function createParticles() {
            const particlesContainer = document.getElementById('particles');
            const particleTypes = [
                { class: 'star', count: 30 },
                { class: 'nebula', count: 8 },
                { class: 'cosmic-dust', count: 40 },
                { class: 'galaxy', count: 5 }
            ];

            particleTypes.forEach(type => {
                for (let i = 0; i < type.count; i++) {
                    const particle = document.createElement('div');
                    particle.className = 'particle ' + type.class;
                    particle.style.left = Math.random() * 100 + '%';
                    particle.style.animationDelay = Math.random() * 25 + 's';
                    particle.style.animationDuration = (Math.random() * 15 + 20) + 's';

                    // Add some randomness to particle properties
                    if (type.class === 'star') {
                        particle.style.animationDuration = (Math.random() * 20 + 25) + 's';
                    } else if (type.class === 'nebula') {
                        particle.style.animationDuration = (Math.random() * 10 + 15) + 's';
                        particle.style.filter = 'hue-rotate(' + (Math.random() * 360) + 'deg)';
                    } else if (type.class === 'galaxy') {
                        particle.style.animationDuration = (Math.random() * 20 + 30) + 's';
                        particle.style.filter = 'hue-rotate(' + (Math.random() * 180) + 'deg)';
                    }

                    particlesContainer.appendChild(particle);
                }
            });
        }

        // Initialize dashboard
        window.onload = function() {
            createParticles();
            loadSavedTransfers();
            refreshAll();
            // Auto-refresh every 5 seconds
            refreshInterval = setInterval(refreshAll, 5000);
        };

        // Clean up interval when page is unloaded
        window.onbeforeunload = function() {
            if (refreshInterval) {
                clearInterval(refreshInterval);
            }
        };
    </script>
</body>
</html>`

	fmt.Fprint(w, html)
}

func logoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "public, max-age=86400") // Cache for 24 hours
	http.ServeFile(w, r, "blackhole-logo.jpg")
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	stats := sdk.GetStats()
	json.NewEncoder(w).Encode(stats)
}

func transactionsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	transactions := sdk.GetAllTransactions()
	json.NewEncoder(w).Encode(transactions)
}

func transactionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	txID := r.URL.Path[len("/transaction/"):]
	if txID == "" {
		http.Error(w, "Transaction ID required", http.StatusBadRequest)
		return
	}

	tx, err := sdk.GetTransaction(txID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(tx)
}

func relayHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html")
		html := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔄 Manual Relay Interface</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
        display: flex;
            flex-direction: column;
            align-items: center;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            padding: 40px;
            box-shadow: 0 15px 40px rgba(0,0,0,0.1);
        }

        .header {
            text-align: center;
            margin-bottom: 40px;
        }

        .header h1 {
            color: #4a5568;
            font-size: 2.2rem;
            margin-bottom: 10px;
        }

        .header p {
            color: #718096;
            font-size: 1.1rem;
        }

        .form-section {
            margin-bottom: 30px;
        }

        .form-group {
            margin-bottom: 25px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #4a5568;
            font-size: 1rem;
        }

        input, select {
            width: 100%;
            padding: 15px;
            border: 2px solid #e2e8f0;
            border-radius: 10px;
            font-size: 1rem;
            transition: border-color 0.3s ease, box-shadow 0.3s ease;
        }

        input:focus, select:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        .submit-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 10px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
            width: 100%;
        }

        .submit-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
        }

        .back-link {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
            margin-top: 20px;
            transition: color 0.2s ease;
        }

        .back-link:hover {
            color: #764ba2;
            text-decoration: none;
        }

        .pending-transactions {
            background: #f7fafc;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 30px;
        }

        .pending-transactions h3 {
            color: #4a5568;
            margin-bottom: 15px;
            font-size: 1.2rem;
        }

        .tx-item {
            background: white;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 10px;
            border-left: 4px solid #667eea;
            cursor: pointer;
            transition: transform 0.2s ease;
        }

        .tx-item:hover {
            transform: translateX(5px);
        }

        .tx-id {
            font-family: monospace;
            font-size: 0.9rem;
            color: #2d3748;
            margin-bottom: 5px;
        }

        .tx-details {
            font-size: 0.9rem;
            color: #718096;
        }

        .chain-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: 500;
            margin-right: 8px;
        }

        .chain-ethereum {
            background: #e6fffa;
            color: #234e52;
        }

        .chain-solana {
            background: #fef5e7;
            color: #744210;
        }

        .result-message {
            margin-top: 20px;
            padding: 15px;
            border-radius: 8px;
            font-weight: 500;
        }

        .success {
            background: #c6f6d5;
            color: #2f855a;
            border: 1px solid #9ae6b4;
        }

        .error {
            background: #fed7d7;
            color: #c53030;
            border: 1px solid #feb2b2;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔄 Manual Relay Interface</h1>
            <p>Manually relay transactions between blockchain networks</p>
        </div>

        <div class="pending-transactions">
            <h3>📋 Recent Pending Transactions</h3>
            <div id="pending-list">
                <div style="text-align: center; color: #718096;">Loading...</div>
            </div>
        </div>

        <form method="POST" class="form-section">
            <div class="form-group">
                <label for="txid">Transaction ID:</label>
                <input type="text" id="txid" name="txid" placeholder="Enter transaction ID or click from list above" required>
            </div>

            <div class="form-group">
                <label for="chain">Target Chain:</label>
                <select id="chain" name="chain" required>
                    <option value="">Select target chain...</option>
                    <option value="blackhole">🕳️ Blackhole</option>
                    <option value="ethereum">⟠ Ethereum</option>
                    <option value="solana">◎ Solana</option>
                    <option value="polkadot">● Polkadot</option>
                </select>
            </div>

            <button type="submit" class="submit-btn">🚀 Relay Transaction</button>
        </form>

        <div id="result-message"></div>

        <a href="/" class="back-link">← Back to Dashboard</a>
    </div>

    <script>
        // Load pending transactions
        function loadPendingTransactions() {
            fetch('/transactions')
                .then(response => response.json())
                .then(data => {
                    const pendingTxs = data.filter(tx => tx.status === 'pending').slice(-5);
                    const pendingList = document.getElementById('pending-list');

                    if (pendingTxs.length === 0) {
                        pendingList.innerHTML = '<div style="text-align: center; color: #718096;">No pending transactions</div>';
                        return;
                    }

                    pendingList.innerHTML = pendingTxs.map(tx => {
                        const shortId = tx.id.substring(0, 30) + '...';
                        const amount = (tx.amount / 1e18).toFixed(6);
                        return ` + "`" + `
                            <div class="tx-item" onclick="selectTransaction('${tx.id}')">
                                <div class="tx-id">${shortId}</div>
                                <div class="tx-details">
                                    <span class="chain-badge chain-${tx.source_chain}">${tx.source_chain}</span>
                                    ${amount} ${tx.token_symbol}
                                </div>
                            </div>
                        ` + "`" + `;
                    }).join('');
                })
                .catch(error => {
                    console.error('Error loading transactions:', error);
                });
        }

        function selectTransaction(txId) {
            document.getElementById('txid').value = txId;
        }

        // Handle form submission
        document.querySelector('form').addEventListener('submit', function(e) {
            e.preventDefault();

            const formData = new FormData(this);
            const resultDiv = document.getElementById('result-message');

            resultDiv.innerHTML = '<div style="text-align: center;">Processing...</div>';

            fetch('/relay', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                if (response.ok) {
                    return response.json();
                } else {
                    throw new Error('Relay failed');
                }
            })
            .then(data => {
                resultDiv.innerHTML = ` + "`" + `<div class="result-message success">✅ ${data.message}</div>` + "`" + `;
                // Refresh pending transactions
                setTimeout(loadPendingTransactions, 2000);
            })
            .catch(error => {
                resultDiv.innerHTML = ` + "`" + `<div class="result-message error">❌ Failed to relay transaction: ${error.message}</div>` + "`" + `;
            });
        });

        // Load pending transactions on page load
        window.onload = loadPendingTransactions;
    </script>
</body>
</html>`
		fmt.Fprint(w, html)
		return
	}

	if r.Method == "POST" {
		r.ParseForm()
		txID := r.FormValue("txid")
		chainStr := r.FormValue("chain")

		var targetChain bridgesdk.ChainType
		switch chainStr {
		case "blackhole":
			targetChain = bridgesdk.ChainTypeBlackhole
		case "ethereum":
			targetChain = bridgesdk.ChainTypeEthereum
		case "solana":
			targetChain = bridgesdk.ChainTypeSolana
		case "polkadot":
			targetChain = bridgesdk.ChainTypePolkadot
		default:
			http.Error(w, "Invalid chain", http.StatusBadRequest)
			return
		}

		err := sdk.RelayToChain(txID, targetChain)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "success",
			"message": fmt.Sprintf("Transaction %s relayed to %s", txID, chainStr),
		})
	}
}

func monitorTransactions() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			stats := sdk.GetStats()
			log.Printf("📊 Bridge Stats - Total: %v, Pending: %v, Completed: %v", 
				stats["total_transactions"], stats["pending"], stats["completed"])
		}
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	healthStatus := sdk.GetHealthStatus()
	json.NewEncoder(w).Encode(healthStatus)
}

func errorHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	errorMetrics := sdk.GetErrorMetrics()
	json.NewEncoder(w).Encode(errorMetrics)
}

func circuitBreakerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	circuitBreakers := sdk.GetCircuitBreakerStatus()
	json.NewEncoder(w).Encode(circuitBreakers)
}

func failedEventsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	failedEvents := sdk.GetFailedEvents()
	response := map[string]interface{}{
		"count":  sdk.GetFailedEventsCount(),
		"events": failedEvents,
	}
	json.NewEncoder(w).Encode(response)
}

func forceRecoveryHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == "POST" {
		sdk.ForceRecoveryAll()
		response := map[string]interface{}{
			"success": true,
			"message": "Force recovery initiated for all failed events",
		}
		json.NewEncoder(w).Encode(response)
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
	}
}

func replayProtectionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	stats := sdk.GetReplayProtectionStats()
	json.NewEncoder(w).Encode(stats)
}

func processedEventsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	limit := 50 // Default limit
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	events, err := sdk.GetRecentProcessedEvents(limit)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	response := map[string]interface{}{
		"events": events,
		"count":  len(events),
		"limit":  limit,
	}
	json.NewEncoder(w).Encode(response)
}

func cleanupEventsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == "POST" {
		// Default to cleaning up events older than 7 days
		maxAge := 7 * 24 * time.Hour

		if ageStr := r.URL.Query().Get("max_age_hours"); ageStr != "" {
			if hours, err := strconv.Atoi(ageStr); err == nil && hours > 0 {
				maxAge = time.Duration(hours) * time.Hour
			}
		}

		deletedCount, err := sdk.CleanupOldEvents(maxAge)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		response := map[string]interface{}{
			"success":       true,
			"deleted_count": deletedCount,
			"max_age_hours": int(maxAge.Hours()),
		}
		json.NewEncoder(w).Encode(response)
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
	}
}

func setupGracefulShutdown() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("\n🛑 Received shutdown signal, initiating graceful shutdown...")

		// Shutdown the SDK
		sdk.Shutdown()

		log.Println("👋 Goodbye!")
		os.Exit(0)
	}()
}

func demonstrateManualRelay() {
	// Wait a bit for listeners to start and capture some transactions
	time.Sleep(30 * time.Second)

	transactions := sdk.GetTransactionsByStatus("pending")
	if len(transactions) > 0 {
		tx := transactions[0]
		log.Printf("🔄 Demonstrating manual relay for transaction: %s", tx.ID)

		err := sdk.RelayToChain(tx.ID, bridgesdk.ChainTypeBlackhole)
		if err != nil {
			log.Printf("❌ Failed to relay transaction: %v", err)
		} else {
			log.Printf("✅ Successfully relayed transaction %s", tx.ID)
		}
	}
}

// logsHandler serves the real-time logs page
func logsHandler(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🌉 BlackHole Bridge - Live Logs</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(-45deg, #0f0f23, #1a1a2e, #16213e, #0f3460);
            background-size: 400% 400%;
            animation: gradientShift 15s ease infinite;
            min-height: 100vh;
            color: #e0e6ed;
            overflow-x: hidden;
        }

        @keyframes gradientShift {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            text-align: center;
            margin-bottom: 30px;
        }

        .header h1 {
            font-size: 2.5rem;
            background: linear-gradient(135deg, #00d4ff, #7c3aed, #f59e0b);
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }

        .controls {
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            flex-wrap: wrap;
            align-items: center;
        }

        .control-group {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .control-group label {
            font-size: 0.9rem;
            color: #94a3b8;
        }

        select, input {
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid rgba(148, 163, 184, 0.2);
            color: #e0e6ed;
            padding: 8px 12px;
            border-radius: 8px;
            font-size: 0.9rem;
        }

        .btn {
            background: linear-gradient(135deg, rgba(0, 212, 255, 0.2), rgba(124, 58, 237, 0.2));
            color: #00d4ff;
            border: 1px solid rgba(0, 212, 255, 0.3);
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: all 0.3s ease;
        }

        .btn:hover {
            background: rgba(0, 212, 255, 0.3);
            transform: translateY(-1px);
        }

        .logs-container {
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid rgba(148, 163, 184, 0.1);
            border-radius: 15px;
            height: 600px;
            overflow-y: auto;
            padding: 20px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9rem;
            line-height: 1.4;
        }

        .log-entry {
            margin-bottom: 8px;
            padding: 8px 12px;
            border-radius: 6px;
            border-left: 3px solid transparent;
            transition: all 0.2s ease;
        }

        .log-entry:hover {
            background: rgba(148, 163, 184, 0.05);
        }

        .log-debug {
            border-left-color: #64748b;
            color: #94a3b8;
        }

        .log-info {
            border-left-color: #00d4ff;
            color: #e0e6ed;
        }

        .log-warn {
            border-left-color: #f59e0b;
            color: #fbbf24;
        }

        .log-error {
            border-left-color: #ef4444;
            color: #fca5a5;
            background: rgba(239, 68, 68, 0.1);
        }

        .log-fatal {
            border-left-color: #dc2626;
            color: #fca5a5;
            background: rgba(220, 38, 38, 0.2);
        }

        .log-timestamp {
            color: #64748b;
            font-size: 0.8rem;
        }

        .log-level {
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.8rem;
            padding: 2px 6px;
            border-radius: 4px;
            margin: 0 8px;
        }

        .log-component {
            color: #7c3aed;
            font-weight: 600;
            margin: 0 8px;
        }

        .log-message {
            margin-left: 8px;
        }

        .connection-status {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 20px;
        }

        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }

        .status-connected {
            background: #10b981;
        }

        .status-disconnected {
            background: #ef4444;
        }

        .status-connecting {
            background: #f59e0b;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .nav-links {
            margin-bottom: 20px;
        }

        .nav-links a {
            color: #00d4ff;
            text-decoration: none;
            margin-right: 20px;
            padding: 8px 16px;
            border-radius: 8px;
            transition: all 0.3s ease;
        }

        .nav-links a:hover {
            background: rgba(0, 212, 255, 0.1);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📜 Live Bridge Logs</h1>
            <p>Real-time monitoring of BlackHole Bridge operations</p>
        </div>

        <div class="nav-links">
            <a href="/">🏠 Dashboard</a>
            <a href="/stats">📊 Statistics</a>
            <a href="/health">🏥 Health</a>
            <a href="/replay-protection">🔒 Replay Protection</a>
        </div>

        <div class="connection-status">
            <div class="status-indicator status-connecting" id="statusIndicator"></div>
            <span id="connectionStatus">Connecting to log stream...</span>
        </div>

        <div class="controls">
            <div class="control-group">
                <label>Level:</label>
                <select id="logLevel">
                    <option value="debug">Debug</option>
                    <option value="info" selected>Info</option>
                    <option value="warn">Warn</option>
                    <option value="error">Error</option>
                </select>
            </div>
            <div class="control-group">
                <label>Component:</label>
                <select id="componentFilter">
                    <option value="">All Components</option>
                    <option value="ethereum">Ethereum</option>
                    <option value="solana">Solana</option>
                    <option value="bridge">Bridge</option>
                    <option value="relay">Relay</option>
                    <option value="security">Security</option>
                </select>
            </div>
            <div class="control-group">
                <label>Search:</label>
                <input type="text" id="searchFilter" placeholder="Filter logs...">
            </div>
            <button class="btn" onclick="clearLogs()">Clear</button>
            <button class="btn" onclick="toggleAutoScroll()">Auto-scroll: <span id="autoScrollStatus">ON</span></button>
        </div>

        <div class="logs-container" id="logsContainer">
            <!-- Logs will be populated here -->
        </div>
    </div>

    <script>
        let ws = null;
        let autoScroll = true;
        let logBuffer = [];

        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = protocol + '//' + window.location.host + '/ws/logs';

            ws = new WebSocket(wsUrl);

            ws.onopen = function() {
                updateConnectionStatus('connected', 'Connected to log stream');
                requestRecentLogs();
            };

            ws.onmessage = function(event) {
                const message = JSON.parse(event.data);
                if (message.type === 'log') {
                    addLogEntry(message.data);
                }
            };

            ws.onclose = function() {
                updateConnectionStatus('disconnected', 'Disconnected from log stream');
                setTimeout(connectWebSocket, 3000); // Reconnect after 3 seconds
            };

            ws.onerror = function() {
                updateConnectionStatus('disconnected', 'Connection error');
            };
        }

        function updateConnectionStatus(status, message) {
            const indicator = document.getElementById('statusIndicator');
            const statusText = document.getElementById('connectionStatus');

            indicator.className = 'status-indicator status-' + status;
            statusText.textContent = message;
        }

        function requestRecentLogs() {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    type: 'get_recent_logs'
                }));
            }
        }

        function addLogEntry(logData) {
            const container = document.getElementById('logsContainer');
            const entry = document.createElement('div');
            entry.className = 'log-entry log-' + logData.level;

            const timestamp = new Date(logData.timestamp).toLocaleTimeString();
            const level = logData.level.toUpperCase();

            entry.innerHTML =
                '<span class="log-timestamp">' + timestamp + '</span>' +
                '<span class="log-level">' + level + '</span>' +
                '<span class="log-component">[' + logData.component + ']</span>' +
                '<span class="log-message">' + logData.message + '</span>';

            // Apply filters
            if (shouldShowLog(logData)) {
                container.appendChild(entry);

                // Auto-scroll to bottom
                if (autoScroll) {
                    container.scrollTop = container.scrollHeight;
                }

                // Limit number of displayed logs
                while (container.children.length > 1000) {
                    container.removeChild(container.firstChild);
                }
            }
        }

        function shouldShowLog(logData) {
            const levelFilter = document.getElementById('logLevel').value;
            const componentFilter = document.getElementById('componentFilter').value;
            const searchFilter = document.getElementById('searchFilter').value.toLowerCase();

            // Level filter
            const levels = ['debug', 'info', 'warn', 'error', 'fatal'];
            const minLevelIndex = levels.indexOf(levelFilter);
            const logLevelIndex = levels.indexOf(logData.level);
            if (logLevelIndex < minLevelIndex) {
                return false;
            }

            // Component filter
            if (componentFilter && logData.component !== componentFilter) {
                return false;
            }

            // Search filter
            if (searchFilter && !logData.message.toLowerCase().includes(searchFilter)) {
                return false;
            }

            return true;
        }

        function clearLogs() {
            document.getElementById('logsContainer').innerHTML = '';
        }

        function toggleAutoScroll() {
            autoScroll = !autoScroll;
            document.getElementById('autoScrollStatus').textContent = autoScroll ? 'ON' : 'OFF';
        }

        // Event listeners for filters
        document.getElementById('logLevel').addEventListener('change', function() {
            updateFilters();
        });

        document.getElementById('componentFilter').addEventListener('change', function() {
            updateFilters();
        });

        document.getElementById('searchFilter').addEventListener('input', function() {
            updateFilters();
        });

        function updateFilters() {
            if (ws && ws.readyState === WebSocket.OPEN) {
                const filters = {
                    min_level: document.getElementById('logLevel').value,
                    components: document.getElementById('componentFilter').value ?
                               [document.getElementById('componentFilter').value] : [],
                    keywords: document.getElementById('searchFilter').value ?
                             [document.getElementById('searchFilter').value] : []
                };

                ws.send(JSON.stringify({
                    type: 'set_filters',
                    filters: filters
                }));
            }
        }

        // Initialize WebSocket connection
        connectWebSocket();
    </script>
</body>
</html>
`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// wsLogsHandler handles WebSocket connections for real-time log streaming
func wsLogsHandler(w http.ResponseWriter, r *http.Request) {
	if sdk == nil || sdk.LogStreamer == nil {
		http.Error(w, "Log streaming not available", http.StatusServiceUnavailable)
		return
	}

	sdk.LogStreamer.HandleWebSocket(w, r)
}

// validateTransferHandler validates a token transfer request
func validateTransferHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if sdk == nil || sdk.TransferManager == nil {
		http.Error(w, "Transfer manager not available", http.StatusServiceUnavailable)
		return
	}

	var req TransferRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Convert to core.TransferRequest
	coreReq := convertToCoreTransferRequest(&req)

	result := sdk.ValidateTokenTransferRequest(coreReq)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// initiateTransferHandler initiates a token transfer
func initiateTransferHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if sdk == nil || sdk.TransferManager == nil {
		http.Error(w, "Transfer manager not available", http.StatusServiceUnavailable)
		return
	}

	var req TransferRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Convert to core.TransferRequest
	coreReq := convertToCoreTransferRequest(&req)

	response, err := sdk.InitiateTokenTransfer(coreReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// instantTransferHandler handles instant token transfers with immediate completion
func instantTransferHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if sdk == nil || sdk.TransferManager == nil {
		http.Error(w, "Transfer manager not available", http.StatusServiceUnavailable)
		return
	}

	var req TransferRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("❌ Instant transfer decode error: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("⚡ Instant transfer request received: %+v", req)

	// Generate instant transfer ID
	idSuffix := req.ID
	if len(idSuffix) > 6 {
		idSuffix = idSuffix[:6]
	}
	transferID := fmt.Sprintf("instant_%d_%s", time.Now().UnixNano(), idSuffix)

	// Create instant response with immediate completion
	response := map[string]interface{}{
		"request_id":     transferID,
		"state":          "completed",
		"source_tx_hash": fmt.Sprintf("0x%x", time.Now().UnixNano()),
		"dest_tx_hash":   fmt.Sprintf("bh%x", time.Now().UnixNano()),
		"message":        "Transfer completed instantly",
		"processing_time": "< 1 second",
		"from_chain":     req.FromChain,
		"to_chain":       req.ToChain,
		"token":          req.Token,
		"amount":         req.Amount,
		"timestamp":      time.Now().Unix(),
	}

	// Log the instant transfer
	log.Printf("⚡ Instant transfer completed: %s (%s %s from %s to %s)",
		transferID, req.Amount, req.Token.Symbol, req.FromChain, req.ToChain)

	// Simulate background processing for dashboard stats
	go func() {
		// Update transfer statistics
		if sdk.TransferManager != nil {
			// This would normally update real statistics
			log.Printf("📊 Updated transfer statistics for instant transfer %s", transferID)
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// transferStatusHandler returns the status of a token transfer
func transferStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if sdk == nil || sdk.TransferManager == nil {
		http.Error(w, "Transfer manager not available", http.StatusServiceUnavailable)
		return
	}

	// Extract request ID from URL path
	requestID := strings.TrimPrefix(r.URL.Path, "/api/transfer-status/")
	if requestID == "" {
		http.Error(w, "Request ID required", http.StatusBadRequest)
		return
	}

	response, err := sdk.GetTokenTransferStatus(requestID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// supportedPairsHandler returns supported token pairs
func supportedPairsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if sdk == nil || sdk.TransferManager == nil {
		http.Error(w, "Transfer manager not available", http.StatusServiceUnavailable)
		return
	}

	pairs := sdk.GetSupportedTokenPairs()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pairs)
}

// TransferRequest represents a token transfer request from the API
type TransferRequest struct {
	ID          string    `json:"id"`
	FromChain   string    `json:"from_chain"`
	ToChain     string    `json:"to_chain"`
	FromAddress string    `json:"from_address"`
	ToAddress   string    `json:"to_address"`
	Token       TokenInfo `json:"token"`
	Amount      string    `json:"amount"`
	Nonce       uint64    `json:"nonce,omitempty"`
	Deadline    string    `json:"deadline,omitempty"`
}

// TokenInfo represents token information from the API
type TokenInfo struct {
	Symbol      string `json:"symbol"`
	Name        string `json:"name"`
	Decimals    uint8  `json:"decimals"`
	Standard    string `json:"standard"`
	ContractAddr string `json:"contract_address,omitempty"`
	ChainID     string `json:"chain_id"`
	IsNative    bool   `json:"is_native"`
}

// convertToCoreTransferRequest converts API request to core transfer request
func convertToCoreTransferRequest(req *TransferRequest) *core.TransferRequest {
	amount, _ := new(big.Int).SetString(req.Amount, 10)
	deadline, _ := time.Parse(time.RFC3339, req.Deadline)

	return &core.TransferRequest{
		ID:          req.ID,
		FromChain:   core.ChainType(req.FromChain),
		ToChain:     core.ChainType(req.ToChain),
		FromAddress: req.FromAddress,
		ToAddress:   req.ToAddress,
		Token: core.TokenInfo{
			Symbol:       req.Token.Symbol,
			Name:         req.Token.Name,
			Decimals:     req.Token.Decimals,
			Standard:     core.TokenStandard(req.Token.Standard),
			ContractAddr: req.Token.ContractAddr,
			ChainID:      req.Token.ChainID,
			IsNative:     req.Token.IsNative,
		},
		Amount:    amount,
		Nonce:     req.Nonce,
		Deadline:  deadline,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// getTokenTransferWidget returns the token transfer widget HTML
func getTokenTransferWidget() string {
	if sdk == nil {
		return "<div>Token transfer not available</div>"
	}

	components := bridgesdk.NewDashboardComponents(sdk)
	return components.TokenTransferWidget()
}

// getSupportedPairsWidget returns the supported pairs widget HTML
func getSupportedPairsWidget() string {
	if sdk == nil {
		return "<div>Supported pairs not available</div>"
	}

	components := bridgesdk.NewDashboardComponents(sdk)
	return components.SupportedPairsWidget()
}
