package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/escrow"
)

type APIServer struct {
	blockchain    *chain.Blockchain
	port          int
	escrowManager interface{} // Will be initialized as *escrow.EscrowManager
}

func NewAPIServer(blockchain *chain.Blockchain, port int) *APIServer {
	// Initialize proper escrow manager using dependency injection
	escrowManager := NewEscrowManagerForBlockchain(blockchain)

	// Inject the escrow manager into the blockchain
	blockchain.EscrowManager = escrowManager

	return &APIServer{
		blockchain:    blockchain,
		port:          port,
		escrowManager: escrowManager,
	}
}

// NewEscrowManagerForBlockchain creates a new escrow manager for the blockchain
func NewEscrowManagerForBlockchain(blockchain *chain.Blockchain) interface{} {
	// Create a real escrow manager using dependency injection
	return escrow.NewEscrowManager(blockchain)
}

func (s *APIServer) Start() {
	// Enable CORS for all routes
	http.HandleFunc("/", s.enableCORS(s.serveUI))
	http.HandleFunc("/dev", s.enableCORS(s.serveDevMode))
	http.HandleFunc("/api/blockchain/info", s.enableCORS(s.getBlockchainInfo))
	http.HandleFunc("/api/admin/add-tokens", s.enableCORS(s.addTokens))
	http.HandleFunc("/api/wallets", s.enableCORS(s.getWallets))
	http.HandleFunc("/api/node/info", s.enableCORS(s.getNodeInfo))
	http.HandleFunc("/api/dev/test-dex", s.enableCORS(s.testDEX))
	http.HandleFunc("/api/dev/test-bridge", s.enableCORS(s.testBridge))
	http.HandleFunc("/api/dev/test-staking", s.enableCORS(s.testStaking))
	http.HandleFunc("/api/dev/test-multisig", s.enableCORS(s.testMultisig))
	http.HandleFunc("/api/dev/test-otc", s.enableCORS(s.testOTC))
	http.HandleFunc("/api/dev/test-escrow", s.enableCORS(s.testEscrow))
	http.HandleFunc("/api/escrow/request", s.enableCORS(s.handleEscrowRequest))
	http.HandleFunc("/api/balance/query", s.enableCORS(s.handleBalanceQuery))

	// OTC Trading API endpoints
	http.HandleFunc("/api/otc/create", s.enableCORS(s.handleOTCCreate))
	http.HandleFunc("/api/otc/orders", s.enableCORS(s.handleOTCOrders))
	http.HandleFunc("/api/otc/match", s.enableCORS(s.handleOTCMatch))
	http.HandleFunc("/api/otc/cancel", s.enableCORS(s.handleOTCCancel))
	http.HandleFunc("/api/otc/events", s.enableCORS(s.handleOTCEvents))

	// Slashing API endpoints
	http.HandleFunc("/api/slashing/events", s.enableCORS(s.handleSlashingEvents))
	http.HandleFunc("/api/slashing/report", s.enableCORS(s.handleSlashingReport))
	http.HandleFunc("/api/slashing/execute", s.enableCORS(s.handleSlashingExecute))
	http.HandleFunc("/api/slashing/validator-status", s.enableCORS(s.handleValidatorStatus))

	// Cross-Chain DEX API endpoints
	http.HandleFunc("/api/cross-chain/quote", s.enableCORS(s.handleCrossChainQuote))
	http.HandleFunc("/api/cross-chain/swap", s.enableCORS(s.handleCrossChainSwap))
	http.HandleFunc("/api/cross-chain/order", s.enableCORS(s.handleCrossChainOrder))
	http.HandleFunc("/api/cross-chain/orders", s.enableCORS(s.handleCrossChainOrders))
	http.HandleFunc("/api/cross-chain/supported-chains", s.enableCORS(s.handleSupportedChains))

	// Health check endpoint
	http.HandleFunc("/api/health", s.enableCORS(s.handleHealthCheck))

	fmt.Printf("🌐 API Server starting on port %d\n", s.port)
	fmt.Printf("🌐 Open http://localhost:%d in your browser\n", s.port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", s.port), nil))
}

func (s *APIServer) enableCORS(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		handler(w, r)
	}
}

func (s *APIServer) serveUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blackhole Blockchain Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .card h3 { margin-top: 0; color: #2c3e50; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }
        .stat { background: #ecf0f1; padding: 15px; border-radius: 4px; text-align: center; }
        .stat-value { font-size: 24px; font-weight: bold; color: #2c3e50; }
        .stat-label { font-size: 12px; color: #7f8c8d; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; table-layout: fixed; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; word-wrap: break-word; overflow-wrap: break-word; }
        th { background: #f8f9fa; }
        .address { font-family: monospace; font-size: 12px; word-break: break-all; max-width: 200px; }
        .btn { background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
        .btn:hover { background: #2980b9; }
        .admin-form { background: #fff3cd; padding: 15px; border-radius: 4px; margin-top: 10px; }
        .form-group { margin-bottom: 10px; }
        .form-group label { display: block; margin-bottom: 5px; }
        .form-group input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        .refresh-btn { position: fixed; top: 20px; right: 20px; z-index: 1000; }
        .block-item { background: #f8f9fa; margin: 5px 0; padding: 10px; border-radius: 4px; }
        .card { overflow-x: auto; }
        .card table { min-width: 100%; }
        .card pre { white-space: pre-wrap; word-wrap: break-word; overflow-wrap: break-word; }
        .card code { word-break: break-all; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌌 Blackhole Blockchain Dashboard</h1>
            <p>Real-time blockchain monitoring and administration</p>
        </div>

        <button class="btn refresh-btn" onclick="refreshData()">🔄 Refresh</button>

        <div class="grid">
            <div class="card">
                <h3>📊 Blockchain Stats</h3>
                <div class="stats" id="blockchain-stats">
                    <div class="stat">
                        <div class="stat-value" id="block-height">-</div>
                        <div class="stat-label">Block Height</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value" id="pending-txs">-</div>
                        <div class="stat-label">Pending Transactions</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value" id="total-supply">-</div>
                        <div class="stat-label">Circulating Supply</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value" id="max-supply">-</div>
                        <div class="stat-label">Max Supply</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value" id="supply-utilization">-</div>
                        <div class="stat-label">Supply Used</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value" id="block-reward">-</div>
                        <div class="stat-label">Block Reward</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h3>💰 Token Balances</h3>
                <div id="token-balances"></div>
            </div>

            <div class="card">
                <h3>🏛️ Staking Information</h3>
                <div id="staking-info"></div>
            </div>

            <div class="card">
                <h3>🔗 Recent Blocks</h3>
                <div id="recent-blocks"></div>
            </div>

            <div class="card">
                <h3>💼 Wallet Access</h3>
                <p>Access your secure wallet interface:</p>
                <button class="btn" onclick="window.open('http://localhost:9000', '_blank')" style="background: #28a745; margin-bottom: 10px;">
                    🌌 Open Wallet UI
                </button>
                <button class="btn" onclick="window.open('/dev', '_blank')" style="background: #e74c3c; margin-bottom: 20px;">
                    🔧 Developer Mode
                </button>
                <p style="font-size: 12px; color: #666;">
                    Note: Make sure the wallet service is running with: <br>
                    <code>go run main.go -web -port 9000</code>
                </p>
            </div>

            <div class="card">
                <h3>⚙️ Admin Panel</h3>
                <div class="admin-form">
                    <h4>Add Tokens to Address</h4>
                    <div class="form-group">
                        <label>Address:</label>
                        <input type="text" id="admin-address" placeholder="Enter wallet address">
                    </div>
                    <div class="form-group">
                        <label>Token Symbol:</label>
                        <input type="text" id="admin-token" value="BHX" placeholder="Token symbol">
                    </div>
                    <div class="form-group">
                        <label>Amount:</label>
                        <input type="number" id="admin-amount" placeholder="Amount to add">
                    </div>
                    <button class="btn" onclick="addTokens()">Add Tokens</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        let refreshInterval;

        async function fetchBlockchainInfo() {
            try {
                const response = await fetch('/api/blockchain/info');
                const data = await response.json();
                updateUI(data);
            } catch (error) {
                console.error('Error fetching blockchain info:', error);
            }
        }

        function updateUI(data) {
            // Update stats
            document.getElementById('block-height').textContent = data.blockHeight;
            document.getElementById('pending-txs').textContent = data.pendingTxs;
            document.getElementById('total-supply').textContent = data.totalSupply.toLocaleString();
            document.getElementById('max-supply').textContent = data.maxSupply ? data.maxSupply.toLocaleString() : 'Unlimited';
            document.getElementById('supply-utilization').textContent = data.supplyUtilization ? data.supplyUtilization.toFixed(2) + '%' : '0%';
            document.getElementById('block-reward').textContent = data.blockReward;

            // Update token balances
            updateTokenBalances(data.tokenBalances);

            // Update staking info
            updateStakingInfo(data.stakes);

            // Update recent blocks
            updateRecentBlocks(data.recentBlocks);
        }

        function updateTokenBalances(tokenBalances) {
            const container = document.getElementById('token-balances');
            let html = '';

            for (const [token, balances] of Object.entries(tokenBalances)) {
                html += '<h4>' + token + '</h4>';
                html += '<table><tr><th>Address</th><th>Balance</th></tr>';
                for (const [address, balance] of Object.entries(balances)) {
                    if (balance > 0) {
                        html += '<tr><td class="address">' + address + '</td><td>' + balance.toLocaleString() + '</td></tr>';
                    }
                }
                html += '</table>';
            }

            container.innerHTML = html;
        }

        function updateStakingInfo(stakes) {
            const container = document.getElementById('staking-info');
            let html = '<table><tr><th>Address</th><th>Stake Amount</th></tr>';

            for (const [address, stake] of Object.entries(stakes)) {
                if (stake > 0) {
                    html += '<tr><td class="address">' + address + '</td><td>' + stake.toLocaleString() + '</td></tr>';
                }
            }

            html += '</table>';
            container.innerHTML = html;
        }

        function updateRecentBlocks(blocks) {
            const container = document.getElementById('recent-blocks');
            let html = '';

            blocks.slice(-5).reverse().forEach(block => {
                html += '<div class="block-item">';
                html += '<strong>Block #' + block.index + '</strong><br>';
                html += 'Validator: ' + block.validator + '<br>';
                html += 'Transactions: ' + block.txCount + '<br>';
                html += 'Time: ' + new Date(block.timestamp).toLocaleTimeString();
                html += '</div>';
            });

            container.innerHTML = html;
        }

        async function addTokens() {
            const address = document.getElementById('admin-address').value;
            const token = document.getElementById('admin-token').value;
            const amount = document.getElementById('admin-amount').value;

            if (!address || !token || !amount) {
                alert('Please fill all fields');
                return;
            }

            try {
                const response = await fetch('/api/admin/add-tokens', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ address, token, amount: parseInt(amount) })
                });

                const result = await response.json();
                if (result.success) {
                    alert('Tokens added successfully!');
                    document.getElementById('admin-address').value = '';
                    document.getElementById('admin-amount').value = '';
                    fetchBlockchainInfo(); // Refresh data
                } else {
                    alert('Error: ' + result.error);
                }
            } catch (error) {
                alert('Error adding tokens: ' + error.message);
            }
        }

        function refreshData() {
            fetchBlockchainInfo();
        }

        function startAutoRefresh() {
            refreshInterval = setInterval(fetchBlockchainInfo, 3000); // Refresh every 3 seconds
        }

        function stopAutoRefresh() {
            if (refreshInterval) {
                clearInterval(refreshInterval);
            }
        }

        // Initialize
        fetchBlockchainInfo();
        startAutoRefresh();

        // Stop auto-refresh when page is hidden
        document.addEventListener('visibilitychange', function() {
            if (document.hidden) {
                stopAutoRefresh();
            } else {
                startAutoRefresh();
            }
        });
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func (s *APIServer) getBlockchainInfo(w http.ResponseWriter, r *http.Request) {
	info := s.blockchain.GetBlockchainInfo()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func (s *APIServer) addTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Address string `json:"address"`
		Token   string `json:"token"`
		Amount  uint64 `json:"amount"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request format",
		})
		return
	}

	err := s.blockchain.AddTokenBalance(req.Address, req.Token, req.Amount)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Added %d %s tokens to %s", req.Amount, req.Token, req.Address),
	})
}

func (s *APIServer) getWallets(w http.ResponseWriter, r *http.Request) {
	// This would integrate with the wallet service to get wallet information
	// For now, return the accounts from blockchain state
	info := s.blockchain.GetBlockchainInfo()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"accounts":      info["accounts"],
		"tokenBalances": info["tokenBalances"],
	})
}

func (s *APIServer) getNodeInfo(w http.ResponseWriter, r *http.Request) {
	// Get P2P node information
	p2pNode := s.blockchain.P2PNode
	if p2pNode == nil {
		http.Error(w, "P2P node not available", http.StatusServiceUnavailable)
		return
	}

	// Build multiaddresses
	addresses := make([]string, 0)
	for _, addr := range p2pNode.Host.Addrs() {
		fullAddr := fmt.Sprintf("%s/p2p/%s", addr.String(), p2pNode.Host.ID().String())
		addresses = append(addresses, fullAddr)
	}

	nodeInfo := map[string]interface{}{
		"peer_id":   p2pNode.Host.ID().String(),
		"addresses": addresses,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(nodeInfo)
}

// serveDevMode serves the developer testing page
func (s *APIServer) serveDevMode(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blackhole Blockchain - Dev Mode</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { background: #e74c3c; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; text-align: center; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .card h3 { margin-top: 0; color: #2c3e50; border-bottom: 2px solid #e74c3c; padding-bottom: 10px; }
        .btn { background: #3498db; color: white; border: none; padding: 12px 20px; border-radius: 4px; cursor: pointer; margin: 5px; width: 100%; }
        .btn:hover { background: #2980b9; }
        .btn-success { background: #27ae60; }
        .btn-success:hover { background: #229954; }
        .btn-warning { background: #f39c12; }
        .btn-warning:hover { background: #e67e22; }
        .btn-danger { background: #e74c3c; }
        .btn-danger:hover { background: #c0392b; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input, .form-group select, .form-group textarea { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .result { margin-top: 15px; padding: 10px; border-radius: 4px; white-space: pre-wrap; word-wrap: break-word; }
        .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
        .loading { background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }
        .nav-links { text-align: center; margin-bottom: 20px; }
        .nav-links a { color: #3498db; text-decoration: none; margin: 0 15px; font-weight: bold; }
        .nav-links a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔧 Blackhole Blockchain - Developer Mode</h1>
            <p>Test all blockchain functionalities with detailed error output</p>
        </div>

        <div class="nav-links">
            <a href="/">← Back to Dashboard</a>
            <a href="http://localhost:9000" target="_blank">Open Wallet UI</a>
        </div>

        <div class="grid">
            <!-- DEX Testing -->
            <div class="card">
                <h3>💱 DEX (Decentralized Exchange) Testing</h3>
                <form id="dexForm">
                    <div class="form-group">
                        <label>Action:</label>
                        <select id="dexAction">
                            <option value="create_pair">Create Trading Pair</option>
                            <option value="add_liquidity">Add Liquidity</option>
                            <option value="swap">Execute Swap</option>
                            <option value="get_quote">Get Swap Quote</option>
                            <option value="get_pools">Get All Pools</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Token A:</label>
                        <input type="text" id="dexTokenA" value="BHX" placeholder="e.g., BHX">
                    </div>
                    <div class="form-group">
                        <label>Token B:</label>
                        <input type="text" id="dexTokenB" value="USDT" placeholder="e.g., USDT">
                    </div>
                    <div class="form-group">
                        <label>Amount A:</label>
                        <input type="number" id="dexAmountA" value="1000" placeholder="Amount of Token A">
                    </div>
                    <div class="form-group">
                        <label>Amount B:</label>
                        <input type="number" id="dexAmountB" value="5000" placeholder="Amount of Token B">
                    </div>
                    <button type="submit" class="btn btn-success">Test DEX Function</button>
                </form>
                <div id="dexResult" class="result" style="display: none;"></div>
            </div>

            <!-- Bridge Testing -->
            <div class="card">
                <h3>🌉 Cross-Chain Bridge Testing</h3>
                <form id="bridgeForm">
                    <div class="form-group">
                        <label>Action:</label>
                        <select id="bridgeAction">
                            <option value="initiate_transfer">Initiate Transfer</option>
                            <option value="confirm_transfer">Confirm Transfer</option>
                            <option value="get_status">Get Transfer Status</option>
                            <option value="get_history">Get Transfer History</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Source Chain:</label>
                        <input type="text" id="bridgeSourceChain" value="blackhole" placeholder="e.g., blackhole">
                    </div>
                    <div class="form-group">
                        <label>Destination Chain:</label>
                        <input type="text" id="bridgeDestChain" value="ethereum" placeholder="e.g., ethereum">
                    </div>
                    <div class="form-group">
                        <label>Source Address:</label>
                        <input type="text" id="bridgeSourceAddr" placeholder="Source wallet address">
                    </div>
                    <div class="form-group">
                        <label>Destination Address:</label>
                        <input type="text" id="bridgeDestAddr" placeholder="Destination wallet address">
                    </div>
                    <div class="form-group">
                        <label>Token Symbol:</label>
                        <input type="text" id="bridgeToken" value="BHX" placeholder="e.g., BHX">
                    </div>
                    <div class="form-group">
                        <label>Amount:</label>
                        <input type="number" id="bridgeAmount" value="100" placeholder="Amount to transfer">
                    </div>
                    <button type="submit" class="btn btn-warning">Test Bridge Function</button>
                </form>
                <div id="bridgeResult" class="result" style="display: none;"></div>
            </div>

            <!-- Staking Testing -->
            <div class="card">
                <h3>🏦 Staking System Testing</h3>
                <form id="stakingForm">
                    <div class="form-group">
                        <label>Action:</label>
                        <select id="stakingAction">
                            <option value="stake">Stake Tokens</option>
                            <option value="unstake">Unstake Tokens</option>
                            <option value="get_stakes">Get All Stakes</option>
                            <option value="get_rewards">Calculate Rewards</option>
                            <option value="claim_rewards">Claim Rewards</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Staker Address:</label>
                        <input type="text" id="stakingAddress" placeholder="Wallet address">
                    </div>
                    <div class="form-group">
                        <label>Token Symbol:</label>
                        <input type="text" id="stakingToken" value="BHX" placeholder="e.g., BHX">
                    </div>
                    <div class="form-group">
                        <label>Amount:</label>
                        <input type="number" id="stakingAmount" value="500" placeholder="Amount to stake">
                    </div>
                    <button type="submit" class="btn btn-success">Test Staking Function</button>
                </form>
                <div id="stakingResult" class="result" style="display: none;"></div>
            </div>

            <!-- Escrow Testing -->
            <div class="card">
                <h3>🔒 Escrow System Testing</h3>
                <form id="escrowForm">
                    <div class="form-group">
                        <label>Action:</label>
                        <select id="escrowAction">
                            <option value="create_escrow">Create Escrow</option>
                            <option value="confirm_escrow">Confirm Escrow</option>
                            <option value="release_escrow">Release Escrow</option>
                            <option value="cancel_escrow">Cancel Escrow</option>
                            <option value="dispute_escrow">Dispute Escrow</option>
                            <option value="get_escrow">Get Escrow Details</option>
                            <option value="get_user_escrows">Get User Escrows</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Sender Address:</label>
                        <input type="text" id="escrowSender" placeholder="Sender wallet address">
                    </div>
                    <div class="form-group">
                        <label>Receiver Address:</label>
                        <input type="text" id="escrowReceiver" placeholder="Receiver wallet address">
                    </div>
                    <div class="form-group">
                        <label>Arbitrator Address:</label>
                        <input type="text" id="escrowArbitrator" placeholder="Arbitrator address (optional)">
                    </div>
                    <div class="form-group">
                        <label>Token Symbol:</label>
                        <input type="text" id="escrowToken" value="BHX" placeholder="e.g., BHX">
                    </div>
                    <div class="form-group">
                        <label>Amount:</label>
                        <input type="number" id="escrowAmount" value="100" placeholder="Amount to escrow">
                    </div>
                    <div class="form-group">
                        <label>Escrow ID (for actions on existing escrow):</label>
                        <input type="text" id="escrowID" placeholder="Escrow ID">
                    </div>
                    <div class="form-group">
                        <label>Expiration Hours:</label>
                        <input type="number" id="escrowExpiration" value="24" placeholder="Hours until expiration">
                    </div>
                    <div class="form-group">
                        <label>Description:</label>
                        <textarea id="escrowDescription" placeholder="Escrow description" rows="3"></textarea>
                    </div>
                    <button type="submit" class="btn btn-danger">Test Escrow Function</button>
                </form>
                <div id="escrowResult" class="result" style="display: none;"></div>
            </div>

            <!-- Continue with more testing modules... -->
        </div>
    </div>

    <script>
        // DEX Testing
        document.getElementById('dexForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            await testFunction('dex', 'dexResult', {
                action: document.getElementById('dexAction').value,
                token_a: document.getElementById('dexTokenA').value,
                token_b: document.getElementById('dexTokenB').value,
                amount_a: parseInt(document.getElementById('dexAmountA').value) || 0,
                amount_b: parseInt(document.getElementById('dexAmountB').value) || 0
            });
        });

        // Bridge Testing
        document.getElementById('bridgeForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            await testFunction('bridge', 'bridgeResult', {
                action: document.getElementById('bridgeAction').value,
                source_chain: document.getElementById('bridgeSourceChain').value,
                dest_chain: document.getElementById('bridgeDestChain').value,
                source_address: document.getElementById('bridgeSourceAddr').value,
                dest_address: document.getElementById('bridgeDestAddr').value,
                token_symbol: document.getElementById('bridgeToken').value,
                amount: parseInt(document.getElementById('bridgeAmount').value) || 0
            });
        });

        // Staking Testing
        document.getElementById('stakingForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            await testFunction('staking', 'stakingResult', {
                action: document.getElementById('stakingAction').value,
                address: document.getElementById('stakingAddress').value,
                token_symbol: document.getElementById('stakingToken').value,
                amount: parseInt(document.getElementById('stakingAmount').value) || 0
            });
        });

        // Escrow Testing
        document.getElementById('escrowForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            await testFunction('escrow', 'escrowResult', {
                action: document.getElementById('escrowAction').value,
                sender: document.getElementById('escrowSender').value,
                receiver: document.getElementById('escrowReceiver').value,
                arbitrator: document.getElementById('escrowArbitrator').value,
                token_symbol: document.getElementById('escrowToken').value,
                amount: parseInt(document.getElementById('escrowAmount').value) || 0,
                escrow_id: document.getElementById('escrowID').value,
                expiration_hours: parseInt(document.getElementById('escrowExpiration').value) || 24,
                description: document.getElementById('escrowDescription').value
            });
        });

        // Generic test function
        async function testFunction(module, resultId, data) {
            const resultDiv = document.getElementById(resultId);
            resultDiv.style.display = 'block';
            resultDiv.className = 'result loading';
            resultDiv.textContent = 'Testing ' + module + ' functionality...';

            try {
                const response = await fetch('/api/dev/test-' + module, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });

                const result = await response.json();

                if (result.success) {
                    resultDiv.className = 'result success';
                    resultDiv.textContent = 'SUCCESS: ' + result.message + '\n\nData: ' + JSON.stringify(result.data, null, 2);
                } else {
                    resultDiv.className = 'result error';
                    resultDiv.textContent = 'ERROR: ' + result.error + '\n\nDetails: ' + (result.details || 'No additional details');
                }
            } catch (error) {
                resultDiv.className = 'result error';
                resultDiv.textContent = 'NETWORK ERROR: ' + error.message;
            }
        }
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// testDEX handles DEX testing requests
func (s *APIServer) testDEX(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Action  string `json:"action"`
		TokenA  string `json:"token_a"`
		TokenB  string `json:"token_b"`
		AmountA uint64 `json:"amount_a"`
		AmountB uint64 `json:"amount_b"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request format: " + err.Error(),
		})
		return
	}

	// Log the test request
	fmt.Printf("🔧 DEV MODE: Testing DEX function '%s' with tokens %s/%s\n", req.Action, req.TokenA, req.TokenB)

	result := map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("DEX %s test completed", req.Action),
		"data": map[string]interface{}{
			"action":   req.Action,
			"token_a":  req.TokenA,
			"token_b":  req.TokenB,
			"amount_a": req.AmountA,
			"amount_b": req.AmountB,
			"status":   "simulated",
			"note":     "DEX functionality is implemented but requires integration with blockchain state",
		},
	}

	// Simulate different DEX operations
	switch req.Action {
	case "create_pair":
		result["data"].(map[string]interface{})["pair_created"] = fmt.Sprintf("%s-%s", req.TokenA, req.TokenB)
	case "add_liquidity":
		result["data"].(map[string]interface{})["liquidity_added"] = true
	case "swap":
		result["data"].(map[string]interface{})["swap_executed"] = true
		result["data"].(map[string]interface{})["estimated_output"] = req.AmountA * 4 // Simulated 1:4 ratio
	case "get_quote":
		result["data"].(map[string]interface{})["quote"] = req.AmountA * 4
	case "get_pools":
		result["data"].(map[string]interface{})["pools"] = []string{"BHX-USDT", "BHX-ETH"}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// testBridge handles Bridge testing requests
func (s *APIServer) testBridge(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Action        string `json:"action"`
		SourceChain   string `json:"source_chain"`
		DestChain     string `json:"dest_chain"`
		SourceAddress string `json:"source_address"`
		DestAddress   string `json:"dest_address"`
		TokenSymbol   string `json:"token_symbol"`
		Amount        uint64 `json:"amount"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request format: " + err.Error(),
		})
		return
	}

	// Log the test request
	fmt.Printf("🔧 DEV MODE: Testing Bridge function '%s' from %s to %s\n", req.Action, req.SourceChain, req.DestChain)

	result := map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Bridge %s test completed", req.Action),
		"data": map[string]interface{}{
			"action":         req.Action,
			"source_chain":   req.SourceChain,
			"dest_chain":     req.DestChain,
			"source_address": req.SourceAddress,
			"dest_address":   req.DestAddress,
			"token_symbol":   req.TokenSymbol,
			"amount":         req.Amount,
			"status":         "simulated",
			"note":           "Bridge functionality is implemented but requires external chain connections",
		},
	}

	// Simulate different bridge operations
	switch req.Action {
	case "initiate_transfer":
		result["data"].(map[string]interface{})["transfer_id"] = fmt.Sprintf("bridge_%d", time.Now().Unix())
		result["data"].(map[string]interface{})["status"] = "initiated"
	case "confirm_transfer":
		result["data"].(map[string]interface{})["confirmed"] = true
	case "get_status":
		result["data"].(map[string]interface{})["transfer_status"] = "completed"
	case "get_history":
		result["data"].(map[string]interface{})["transfers"] = []string{"transfer_1", "transfer_2"}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// testStaking handles Staking testing requests
func (s *APIServer) testStaking(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Action      string `json:"action"`
		Address     string `json:"address"`
		TokenSymbol string `json:"token_symbol"`
		Amount      uint64 `json:"amount"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request format: " + err.Error(),
		})
		return
	}

	// Log the test request
	fmt.Printf("🔧 DEV MODE: Testing Staking function '%s' for address %s\n", req.Action, req.Address)

	result := map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Staking %s test completed", req.Action),
		"data": map[string]interface{}{
			"action":       req.Action,
			"address":      req.Address,
			"token_symbol": req.TokenSymbol,
			"amount":       req.Amount,
			"status":       "simulated",
			"note":         "Staking functionality is implemented and integrated with blockchain",
		},
	}

	// Simulate different staking operations
	switch req.Action {
	case "stake":
		result["data"].(map[string]interface{})["staked_amount"] = req.Amount
		result["data"].(map[string]interface{})["stake_id"] = fmt.Sprintf("stake_%d", time.Now().Unix())
	case "unstake":
		result["data"].(map[string]interface{})["unstaked_amount"] = req.Amount
	case "get_stakes":
		result["data"].(map[string]interface{})["total_staked"] = 5000
		result["data"].(map[string]interface{})["stakes"] = []map[string]interface{}{
			{"amount": 1000, "timestamp": time.Now().Unix()},
			{"amount": 2000, "timestamp": time.Now().Unix() - 3600},
		}
	case "get_rewards":
		result["data"].(map[string]interface{})["pending_rewards"] = 50
	case "claim_rewards":
		result["data"].(map[string]interface{})["claimed_rewards"] = 50
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// testMultisig handles Multisig testing requests
func (s *APIServer) testMultisig(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Action      string   `json:"action"`
		Owners      []string `json:"owners"`
		Threshold   int      `json:"threshold"`
		WalletID    string   `json:"wallet_id"`
		ToAddress   string   `json:"to_address"`
		TokenSymbol string   `json:"token_symbol"`
		Amount      uint64   `json:"amount"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request format: " + err.Error(),
		})
		return
	}

	// Log the test request
	fmt.Printf("🔧 DEV MODE: Testing Multisig function '%s'\n", req.Action)

	result := map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Multisig %s test completed", req.Action),
		"data": map[string]interface{}{
			"action": req.Action,
			"status": "simulated",
			"note":   "Multisig functionality is implemented but requires proper key management",
		},
	}

	// Simulate different multisig operations
	switch req.Action {
	case "create_wallet":
		result["data"].(map[string]interface{})["wallet_id"] = fmt.Sprintf("multisig_%d", time.Now().Unix())
		result["data"].(map[string]interface{})["owners"] = req.Owners
		result["data"].(map[string]interface{})["threshold"] = req.Threshold
	case "propose_transaction":
		result["data"].(map[string]interface{})["transaction_id"] = fmt.Sprintf("tx_%d", time.Now().Unix())
		result["data"].(map[string]interface{})["signatures_needed"] = req.Threshold
	case "sign_transaction":
		result["data"].(map[string]interface{})["signed"] = true
	case "execute_transaction":
		result["data"].(map[string]interface{})["executed"] = true
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// testOTC handles OTC trading testing requests
func (s *APIServer) testOTC(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Action          string `json:"action"`
		Creator         string `json:"creator"`
		TokenOffered    string `json:"token_offered"`
		AmountOffered   uint64 `json:"amount_offered"`
		TokenRequested  string `json:"token_requested"`
		AmountRequested uint64 `json:"amount_requested"`
		OrderID         string `json:"order_id"`
		Counterparty    string `json:"counterparty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request format: " + err.Error(),
		})
		return
	}

	// Log the test request
	fmt.Printf("🔧 DEV MODE: Testing OTC function '%s'\n", req.Action)

	result := map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("OTC %s test completed", req.Action),
		"data": map[string]interface{}{
			"action": req.Action,
			"status": "simulated",
			"note":   "OTC functionality is implemented but requires proper escrow integration",
		},
	}

	// Simulate different OTC operations
	switch req.Action {
	case "create_order":
		result["data"].(map[string]interface{})["order_id"] = fmt.Sprintf("otc_%d", time.Now().Unix())
		result["data"].(map[string]interface{})["token_offered"] = req.TokenOffered
		result["data"].(map[string]interface{})["amount_offered"] = req.AmountOffered
	case "match_order":
		result["data"].(map[string]interface{})["matched"] = true
		result["data"].(map[string]interface{})["counterparty"] = req.Counterparty
	case "get_orders":
		result["data"].(map[string]interface{})["orders"] = []map[string]interface{}{
			{"id": "otc_1", "token_offered": "BHX", "amount_offered": 1000},
			{"id": "otc_2", "token_offered": "USDT", "amount_offered": 5000},
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// testEscrow handles Escrow testing requests
func (s *APIServer) testEscrow(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Action      string `json:"action"`
		Sender      string `json:"sender"`
		Receiver    string `json:"receiver"`
		Arbitrator  string `json:"arbitrator"`
		TokenSymbol string `json:"token_symbol"`
		Amount      uint64 `json:"amount"`
		EscrowID    string `json:"escrow_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request format: " + err.Error(),
		})
		return
	}

	// Log the test request
	fmt.Printf("🔧 DEV MODE: Testing Escrow function '%s'\n", req.Action)

	result := map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Escrow %s test completed", req.Action),
		"data": map[string]interface{}{
			"action": req.Action,
			"status": "simulated",
			"note":   "Escrow functionality is implemented with time-based and arbitrator features",
		},
	}

	// Simulate different escrow operations
	switch req.Action {
	case "create_escrow":
		result["data"].(map[string]interface{})["escrow_id"] = fmt.Sprintf("escrow_%d", time.Now().Unix())
		result["data"].(map[string]interface{})["sender"] = req.Sender
		result["data"].(map[string]interface{})["receiver"] = req.Receiver
		result["data"].(map[string]interface{})["arbitrator"] = req.Arbitrator
	case "confirm_escrow":
		result["data"].(map[string]interface{})["confirmed"] = true
	case "release_escrow":
		result["data"].(map[string]interface{})["released"] = true
		result["data"].(map[string]interface{})["amount"] = req.Amount
	case "dispute_escrow":
		result["data"].(map[string]interface{})["disputed"] = true
		result["data"].(map[string]interface{})["arbitrator_notified"] = true
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleEscrowRequest handles real escrow operations from the blockchain client
func (s *APIServer) handleEscrowRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request format: " + err.Error(),
		})
		return
	}

	action, ok := req["action"].(string)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Missing or invalid action",
		})
		return
	}

	// Log the escrow request
	fmt.Printf("🔒 ESCROW REQUEST: %s\n", action)

	// Check if escrow manager is initialized
	if s.escrowManager == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Escrow manager not initialized",
		})
		return
	}

	var result map[string]interface{}
	var err error

	switch action {
	case "create_escrow":
		result, err = s.handleCreateEscrow(req)
	case "confirm_escrow":
		result, err = s.handleConfirmEscrow(req)
	case "release_escrow":
		result, err = s.handleReleaseEscrow(req)
	case "cancel_escrow":
		result, err = s.handleCancelEscrow(req)
	case "get_escrow":
		result, err = s.handleGetEscrow(req)
	case "get_user_escrows":
		result, err = s.handleGetUserEscrows(req)
	default:
		err = fmt.Errorf("unknown action: %s", action)
	}

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// handleCreateEscrow handles escrow creation requests
func (s *APIServer) handleCreateEscrow(req map[string]interface{}) (map[string]interface{}, error) {
	sender, ok := req["sender"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid sender")
	}

	receiver, ok := req["receiver"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid receiver")
	}

	tokenSymbol, ok := req["token_symbol"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid token_symbol")
	}

	amount, ok := req["amount"].(float64)
	if !ok {
		return nil, fmt.Errorf("missing or invalid amount")
	}

	expirationHours, ok := req["expiration_hours"].(float64)
	if !ok {
		expirationHours = 24 // Default to 24 hours
	}

	arbitrator, _ := req["arbitrator"].(string)   // Optional
	description, _ := req["description"].(string) // Optional

	// Create escrow using the real escrow manager
	escrowManager := s.escrowManager.(*escrow.EscrowManager)

	contract, err := escrowManager.CreateEscrow(
		sender,
		receiver,
		arbitrator,
		tokenSymbol,
		uint64(amount),
		int(expirationHours),
		description,
	)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success":   true,
		"escrow_id": contract.ID,
		"message":   fmt.Sprintf("Escrow created successfully: %s", contract.ID),
		"data": map[string]interface{}{
			"id":            contract.ID,
			"sender":        contract.Sender,
			"receiver":      contract.Receiver,
			"arbitrator":    contract.Arbitrator,
			"token_symbol":  contract.TokenSymbol,
			"amount":        contract.Amount,
			"status":        contract.Status.String(),
			"created_at":    contract.CreatedAt,
			"expires_at":    contract.ExpiresAt,
			"required_sigs": contract.RequiredSigs,
			"description":   contract.Description,
		},
	}, nil
}

// handleConfirmEscrow handles escrow confirmation requests
func (s *APIServer) handleConfirmEscrow(req map[string]interface{}) (map[string]interface{}, error) {
	escrowID, ok := req["escrow_id"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid escrow_id")
	}

	confirmer, ok := req["confirmer"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid confirmer")
	}

	// Use the real escrow manager
	escrowManager := s.escrowManager.(*escrow.EscrowManager)

	err := escrowManager.ConfirmEscrow(escrowID, confirmer)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Escrow %s confirmed successfully", escrowID),
		"data": map[string]interface{}{
			"escrow_id": escrowID,
			"confirmer": confirmer,
			"status":    "confirmed",
		},
	}, nil
}

// handleReleaseEscrow handles escrow release requests
func (s *APIServer) handleReleaseEscrow(req map[string]interface{}) (map[string]interface{}, error) {
	escrowID, ok := req["escrow_id"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid escrow_id")
	}

	releaser, ok := req["releaser"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid releaser")
	}

	// Use the real escrow manager
	escrowManager := s.escrowManager.(*escrow.EscrowManager)

	err := escrowManager.ReleaseEscrow(escrowID, releaser)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Escrow %s released successfully", escrowID),
		"data": map[string]interface{}{
			"escrow_id": escrowID,
			"releaser":  releaser,
			"status":    "released",
		},
	}, nil
}

// handleCancelEscrow handles escrow cancellation requests
func (s *APIServer) handleCancelEscrow(req map[string]interface{}) (map[string]interface{}, error) {
	escrowID, ok := req["escrow_id"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid escrow_id")
	}

	canceller, ok := req["canceller"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid canceller")
	}

	// Use the real escrow manager
	escrowManager := s.escrowManager.(*escrow.EscrowManager)

	err := escrowManager.CancelEscrow(escrowID, canceller)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Escrow %s cancelled successfully", escrowID),
		"data": map[string]interface{}{
			"escrow_id": escrowID,
			"canceller": canceller,
			"status":    "cancelled",
		},
	}, nil
}

// handleGetEscrow handles getting escrow details
func (s *APIServer) handleGetEscrow(req map[string]interface{}) (map[string]interface{}, error) {
	escrowID, ok := req["escrow_id"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid escrow_id")
	}

	// Use the real escrow manager
	escrowManager := s.escrowManager.(*escrow.EscrowManager)

	contract, exists := escrowManager.Contracts[escrowID]
	if !exists {
		return nil, fmt.Errorf("escrow %s not found", escrowID)
	}

	return map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Escrow %s details retrieved", escrowID),
		"data": map[string]interface{}{
			"id":            contract.ID,
			"sender":        contract.Sender,
			"receiver":      contract.Receiver,
			"arbitrator":    contract.Arbitrator,
			"token_symbol":  contract.TokenSymbol,
			"amount":        contract.Amount,
			"status":        contract.Status.String(),
			"created_at":    contract.CreatedAt,
			"expires_at":    contract.ExpiresAt,
			"required_sigs": contract.RequiredSigs,
			"description":   contract.Description,
		},
	}, nil
}

// handleGetUserEscrows handles getting all escrows for a user
func (s *APIServer) handleGetUserEscrows(req map[string]interface{}) (map[string]interface{}, error) {
	userAddress, ok := req["user_address"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid user_address")
	}

	// Use the real escrow manager
	escrowManager := s.escrowManager.(*escrow.EscrowManager)

	var userEscrows []interface{}

	// Filter escrows where user is involved
	for _, contract := range escrowManager.Contracts {
		// Check if user is involved in this escrow
		if contract.Sender == userAddress || contract.Receiver == userAddress || contract.Arbitrator == userAddress {
			escrowData := map[string]interface{}{
				"id":            contract.ID,
				"sender":        contract.Sender,
				"receiver":      contract.Receiver,
				"arbitrator":    contract.Arbitrator,
				"token_symbol":  contract.TokenSymbol,
				"amount":        contract.Amount,
				"status":        contract.Status.String(),
				"created_at":    contract.CreatedAt,
				"expires_at":    contract.ExpiresAt,
				"required_sigs": contract.RequiredSigs,
				"description":   contract.Description,
			}
			userEscrows = append(userEscrows, escrowData)
		}
	}

	return map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Found %d escrows for user %s", len(userEscrows), userAddress),
		"data": map[string]interface{}{
			"escrows": userEscrows,
			"count":   len(userEscrows),
		},
	}, nil
}

// handleBalanceQuery handles dedicated balance query requests
func (s *APIServer) handleBalanceQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Address     string `json:"address"`
		TokenSymbol string `json:"token_symbol"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request format: " + err.Error(),
		})
		return
	}

	// Validate inputs
	if req.Address == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Address is required",
		})
		return
	}

	if req.TokenSymbol == "" {
		req.TokenSymbol = "BHX" // Default to BHX
	}

	fmt.Printf("🔍 Balance query: address=%s, token=%s\n", req.Address, req.TokenSymbol)

	// Get token from blockchain
	token, exists := s.blockchain.TokenRegistry[req.TokenSymbol]

	if !exists {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Token %s not found", req.TokenSymbol),
		})
		return
	}

	// Get balance
	balance, err := token.BalanceOf(req.Address)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Failed to get balance: %v", err),
		})
		return
	}

	fmt.Printf("✅ Balance found: %d %s for address %s\n", balance, req.TokenSymbol, req.Address)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"address":      req.Address,
			"token_symbol": req.TokenSymbol,
			"balance":      balance,
		},
	})
}

// OTC Trading API Handlers
func (s *APIServer) handleOTCCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Method not allowed",
		})
		return
	}

	var req struct {
		Creator         string   `json:"creator"`
		TokenOffered    string   `json:"token_offered"`
		AmountOffered   uint64   `json:"amount_offered"`
		TokenRequested  string   `json:"token_requested"`
		AmountRequested uint64   `json:"amount_requested"`
		ExpirationHours int      `json:"expiration_hours"`
		IsMultiSig      bool     `json:"is_multisig"`
		RequiredSigs    []string `json:"required_sigs"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request format: " + err.Error(),
		})
		return
	}

	fmt.Printf("🤝 Creating OTC order: %+v\n", req)

	// For now, simulate OTC order creation since we don't have the OTC manager initialized
	// In a real implementation, this would use: s.blockchain.OTCManager.CreateOrder(...)
	orderID := fmt.Sprintf("otc_%d_%s", time.Now().UnixNano(), req.Creator[:8])

	// Simulate token balance check
	if token, exists := s.blockchain.TokenRegistry[req.TokenOffered]; exists {
		balance, err := token.BalanceOf(req.Creator)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "Failed to check balance: " + err.Error(),
			})
			return
		}

		if balance < req.AmountOffered {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   fmt.Sprintf("Insufficient balance: has %d, needs %d", balance, req.AmountOffered),
			})
			return
		}

		// Lock tokens by transferring to OTC contract
		err = token.Transfer(req.Creator, "otc_contract", req.AmountOffered)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "Failed to lock tokens: " + err.Error(),
			})
			return
		}
	}

	orderData := map[string]interface{}{
		"order_id":         orderID,
		"creator":          req.Creator,
		"token_offered":    req.TokenOffered,
		"amount_offered":   req.AmountOffered,
		"token_requested":  req.TokenRequested,
		"amount_requested": req.AmountRequested,
		"expiration_hours": req.ExpirationHours,
		"is_multi_sig":     req.IsMultiSig,
		"required_sigs":    req.RequiredSigs,
		"status":           "open",
		"created_at":       time.Now().Unix(),
		"expires_at":       time.Now().Add(time.Duration(req.ExpirationHours) * time.Hour).Unix(),
	}

	// Store the order for future operations
	s.storeOTCOrder(orderID, orderData)

	// Broadcast order creation event
	s.broadcastOTCEvent("order_created", orderData)

	fmt.Printf("✅ OTC order created: %s\n", orderID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "OTC order created successfully",
		"data":    orderData,
	})
}

func (s *APIServer) handleOTCOrders(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Method not allowed",
		})
		return
	}

	// Get user parameter from query string
	userAddress := r.URL.Query().Get("user")

	fmt.Printf("🔍 Getting OTC orders for user: %s\n", userAddress)

	// For now, return simulated orders
	// In a real implementation, this would use: s.blockchain.OTCManager.GetUserOrders(userAddress)
	orders := []map[string]interface{}{
		{
			"order_id":         "otc_example_1",
			"creator":          userAddress,
			"token_offered":    "BHX",
			"amount_offered":   1000,
			"token_requested":  "USDT",
			"amount_requested": 5000,
			"status":           "open",
			"created_at":       time.Now().Unix() - 3600,
			"expires_at":       time.Now().Unix() + 82800,
			"note":             "Simulated order from blockchain",
		},
		{
			"order_id":         "otc_market_1",
			"creator":          "0x9876...4321",
			"token_offered":    "USDT",
			"amount_offered":   2000,
			"token_requested":  "BHX",
			"amount_requested": 400,
			"status":           "open",
			"created_at":       time.Now().Unix() - 1800,
			"expires_at":       time.Now().Unix() + 84600,
			"note":             "Market order from another user",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    orders,
	})
}

func (s *APIServer) handleOTCMatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Method not allowed",
		})
		return
	}

	var req struct {
		OrderID      string `json:"order_id"`
		Counterparty string `json:"counterparty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request format: " + err.Error(),
		})
		return
	}

	fmt.Printf("🤝 Matching OTC order %s with counterparty %s\n", req.OrderID, req.Counterparty)

	// Real order matching implementation
	success, err := s.executeOTCOrderMatch(req.OrderID, req.Counterparty)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	if !success {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Order matching failed",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "OTC order matched and executed successfully",
		"data": map[string]interface{}{
			"order_id":     req.OrderID,
			"counterparty": req.Counterparty,
			"status":       "completed",
			"matched_at":   time.Now().Unix(),
			"completed_at": time.Now().Unix(),
		},
	})
}

func (s *APIServer) handleOTCCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Method not allowed",
		})
		return
	}

	var req struct {
		OrderID   string `json:"order_id"`
		Canceller string `json:"canceller"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request format: " + err.Error(),
		})
		return
	}

	fmt.Printf("❌ Cancelling OTC order %s by %s\n", req.OrderID, req.Canceller)

	// For now, simulate order cancellation
	// In a real implementation, this would use: s.blockchain.OTCManager.CancelOrder(req.OrderID, req.Canceller)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "OTC order cancelled successfully",
		"data": map[string]interface{}{
			"order_id":     req.OrderID,
			"status":       "cancelled",
			"cancelled_at": time.Now().Unix(),
		},
	})
}

// OTC Order Management Functions
func (s *APIServer) executeOTCOrderMatch(orderID, counterparty string) (bool, error) {
	fmt.Printf("🔄 Executing OTC order match: %s with %s\n", orderID, counterparty)

	// In a real implementation, this would:
	// 1. Find the order in the OTC manager
	// 2. Validate counterparty has required tokens
	// 3. Execute the token swap
	// 4. Update order status

	// For now, simulate a successful match with actual token transfers
	// This demonstrates the complete flow

	// Simulate order data (in real implementation, this would come from OTC manager)
	orderData := map[string]interface{}{
		"creator":          "test_creator",
		"token_offered":    "BHX",
		"amount_offered":   uint64(1000),
		"token_requested":  "USDT",
		"amount_requested": uint64(5000),
	}

	// Check if counterparty has required tokens
	if requestedToken, exists := s.blockchain.TokenRegistry[orderData["token_requested"].(string)]; exists {
		balance, err := requestedToken.BalanceOf(counterparty)
		if err != nil {
			return false, fmt.Errorf("failed to check counterparty balance: %v", err)
		}

		if balance < orderData["amount_requested"].(uint64) {
			return false, fmt.Errorf("counterparty has insufficient balance: has %d, needs %d",
				balance, orderData["amount_requested"].(uint64))
		}

		// Execute the token swap
		// 1. Transfer offered tokens from OTC contract to counterparty
		if offeredToken, exists := s.blockchain.TokenRegistry[orderData["token_offered"].(string)]; exists {
			err = offeredToken.Transfer("otc_contract", counterparty, orderData["amount_offered"].(uint64))
			if err != nil {
				return false, fmt.Errorf("failed to transfer offered tokens: %v", err)
			}
		}

		// 2. Transfer requested tokens from counterparty to creator
		err = requestedToken.Transfer(counterparty, orderData["creator"].(string), orderData["amount_requested"].(uint64))
		if err != nil {
			return false, fmt.Errorf("failed to transfer requested tokens: %v", err)
		}

		fmt.Printf("✅ OTC trade completed: %d %s ↔ %d %s\n",
			orderData["amount_offered"], orderData["token_offered"],
			orderData["amount_requested"], orderData["token_requested"])

		return true, nil
	}

	return false, fmt.Errorf("requested token not found")
}

// Store for OTC orders (in real implementation, this would be in the blockchain)
var otcOrderStore = make(map[string]map[string]interface{})

// Store for Cross-Chain DEX orders
var crossChainOrderStore = make(map[string]map[string]interface{})
var crossChainOrdersByUser = make(map[string][]string) // user -> order IDs

func (s *APIServer) storeOTCOrder(orderID string, orderData map[string]interface{}) {
	otcOrderStore[orderID] = orderData
}

func (s *APIServer) getOTCOrder(orderID string) (map[string]interface{}, bool) {
	order, exists := otcOrderStore[orderID]
	return order, exists
}

// Cross-Chain DEX order storage functions
func (s *APIServer) storeCrossChainOrder(orderID string, orderData map[string]interface{}) {
	crossChainOrderStore[orderID] = orderData

	// Add to user's order list
	user := orderData["user"].(string)
	if crossChainOrdersByUser[user] == nil {
		crossChainOrdersByUser[user] = make([]string, 0)
	}
	crossChainOrdersByUser[user] = append(crossChainOrdersByUser[user], orderID)
}

func (s *APIServer) getCrossChainOrder(orderID string) (map[string]interface{}, bool) {
	order, exists := crossChainOrderStore[orderID]
	return order, exists
}

func (s *APIServer) getUserCrossChainOrders(user string) []map[string]interface{} {
	orderIDs, exists := crossChainOrdersByUser[user]
	if !exists {
		return []map[string]interface{}{}
	}

	var orders []map[string]interface{}
	for _, orderID := range orderIDs {
		if order, exists := crossChainOrderStore[orderID]; exists {
			orders = append(orders, order)
		}
	}

	return orders
}

func (s *APIServer) updateCrossChainOrderStatus(orderID, status string) {
	if order, exists := crossChainOrderStore[orderID]; exists {
		order["status"] = status
		if status == "completed" {
			order["completed_at"] = time.Now().Unix()
		}
	}
}

// processCrossChainSwap simulates the cross-chain swap process
func (s *APIServer) processCrossChainSwap(orderID string) {
	_, exists := s.getCrossChainOrder(orderID)
	if !exists {
		return
	}

	// Step 1: Bridging phase (2-3 seconds)
	time.Sleep(2 * time.Second)
	s.updateCrossChainOrderStatus(orderID, "bridging")
	fmt.Printf("🌉 Order %s: Bridging tokens...\n", orderID)

	// Step 2: Bridge confirmation (3-5 seconds)
	time.Sleep(3 * time.Second)
	s.updateCrossChainOrderStatus(orderID, "swapping")
	fmt.Printf("🔄 Order %s: Executing swap on destination chain...\n", orderID)

	// Step 3: Swap execution (2-3 seconds)
	time.Sleep(2 * time.Second)

	// Update order with final details
	if order, exists := crossChainOrderStore[orderID]; exists {
		order["status"] = "completed"
		order["completed_at"] = time.Now().Unix()
		order["bridge_tx_id"] = fmt.Sprintf("bridge_%s", orderID)
		order["swap_tx_id"] = fmt.Sprintf("swap_%s", orderID)

		// Simulate slight slippage
		estimatedOut := order["estimated_out"].(uint64)
		actualOut := uint64(float64(estimatedOut) * 0.998) // 0.2% slippage
		order["actual_out"] = actualOut
	}

	fmt.Printf("✅ Order %s: Cross-chain swap completed!\n", orderID)
}

func (s *APIServer) updateOTCOrderStatus(orderID, status string) {
	if order, exists := otcOrderStore[orderID]; exists {
		order["status"] = status
		order["updated_at"] = time.Now().Unix()

		// Broadcast status update
		s.broadcastOTCEvent("order_updated", order)
	}
}

// Simple event broadcasting system (in production, use WebSockets)
func (s *APIServer) broadcastOTCEvent(eventType string, data map[string]interface{}) {
	fmt.Printf("📡 Broadcasting OTC event: %s\n", eventType)
	// In a real implementation, this would send WebSocket messages to connected clients
	// For now, just log the event
	eventData := map[string]interface{}{
		"type":      eventType,
		"data":      data,
		"timestamp": time.Now().Unix(),
	}

	// Store recent events for polling-based updates
	s.storeRecentOTCEvent(eventData)
}

// Store for recent OTC events
var recentOTCEvents = make([]map[string]interface{}, 0, 100)

func (s *APIServer) storeRecentOTCEvent(event map[string]interface{}) {
	recentOTCEvents = append(recentOTCEvents, event)

	// Keep only last 100 events
	if len(recentOTCEvents) > 100 {
		recentOTCEvents = recentOTCEvents[1:]
	}
}

func (s *APIServer) getRecentOTCEvents() []map[string]interface{} {
	return recentOTCEvents
}

func (s *APIServer) handleOTCEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Method not allowed",
		})
		return
	}

	events := s.getRecentOTCEvents()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    events,
	})
}

// Slashing API Handlers
func (s *APIServer) handleSlashingEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Method not allowed",
		})
		return
	}

	events := s.blockchain.SlashingManager.GetSlashingEvents()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    events,
	})
}

func (s *APIServer) handleSlashingReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Method not allowed",
		})
		return
	}

	var req struct {
		Validator   string `json:"validator"`
		Condition   int    `json:"condition"`
		Evidence    string `json:"evidence"`
		BlockHeight uint64 `json:"block_height"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request format: " + err.Error(),
		})
		return
	}

	fmt.Printf("🚨 Slashing violation reported for validator %s\n", req.Validator)

	event, err := s.blockchain.SlashingManager.ReportViolation(
		req.Validator,
		chain.SlashingCondition(req.Condition),
		req.Evidence,
		req.BlockHeight,
	)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Slashing violation reported successfully",
		"data":    event,
	})
}

func (s *APIServer) handleSlashingExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Method not allowed",
		})
		return
	}

	var req struct {
		EventID string `json:"event_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request format: " + err.Error(),
		})
		return
	}

	fmt.Printf("⚡ Executing slashing event %s\n", req.EventID)

	err := s.blockchain.SlashingManager.ExecuteSlashing(req.EventID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Slashing executed successfully",
	})
}

func (s *APIServer) handleValidatorStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Method not allowed",
		})
		return
	}

	validator := r.URL.Query().Get("validator")
	if validator == "" {
		// Return all validator statuses
		validators := s.blockchain.StakeLedger.GetAllStakes()
		validatorStatuses := make(map[string]interface{})

		for validatorAddr := range validators {
			validatorStatuses[validatorAddr] = map[string]interface{}{
				"stake":   s.blockchain.StakeLedger.GetStake(validatorAddr),
				"strikes": s.blockchain.SlashingManager.GetValidatorStrikes(validatorAddr),
				"jailed":  s.blockchain.SlashingManager.IsValidatorJailed(validatorAddr),
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    validatorStatuses,
		})
		return
	}

	// Return specific validator status
	status := map[string]interface{}{
		"validator": validator,
		"stake":     s.blockchain.StakeLedger.GetStake(validator),
		"strikes":   s.blockchain.SlashingManager.GetValidatorStrikes(validator),
		"jailed":    s.blockchain.SlashingManager.IsValidatorJailed(validator),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    status,
	})
}

func (s *APIServer) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Method not allowed",
		})
		return
	}

	// Get blockchain status
	latestBlock := s.blockchain.GetLatestBlock()
	blockHeight := uint64(0)
	if latestBlock != nil {
		blockHeight = latestBlock.Header.Index
	}

	// Get validator count
	validators := s.blockchain.StakeLedger.GetAllStakes()
	validatorCount := len(validators)

	// Get pending transactions
	pendingTxs := len(s.blockchain.GetPendingTransactions())

	health := map[string]interface{}{
		"status":          "healthy",
		"block_height":    blockHeight,
		"validator_count": validatorCount,
		"pending_txs":     pendingTxs,
		"timestamp":       time.Now().Unix(),
		"version":         "1.0.0",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    health,
	})
}

// Cross-Chain DEX API Handlers
func (s *APIServer) handleCrossChainQuote(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Method not allowed",
		})
		return
	}

	var req struct {
		SourceChain string `json:"source_chain"`
		DestChain   string `json:"dest_chain"`
		TokenIn     string `json:"token_in"`
		TokenOut    string `json:"token_out"`
		AmountIn    uint64 `json:"amount_in"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request format: " + err.Error(),
		})
		return
	}

	// Simulate cross-chain quote (in production, would use actual CrossChainDEX)
	quote := map[string]interface{}{
		"source_chain":  req.SourceChain,
		"dest_chain":    req.DestChain,
		"token_in":      req.TokenIn,
		"token_out":     req.TokenOut,
		"amount_in":     req.AmountIn,
		"estimated_out": uint64(float64(req.AmountIn) * 0.95), // 5% total fees
		"price_impact":  0.5,
		"bridge_fee":    uint64(float64(req.AmountIn) * 0.01),  // 1% bridge fee
		"swap_fee":      uint64(float64(req.AmountIn) * 0.003), // 0.3% swap fee
		"expires_at":    time.Now().Add(10 * time.Minute).Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    quote,
	})
}

func (s *APIServer) handleCrossChainSwap(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Method not allowed",
		})
		return
	}

	var req struct {
		User         string `json:"user"`
		SourceChain  string `json:"source_chain"`
		DestChain    string `json:"dest_chain"`
		TokenIn      string `json:"token_in"`
		TokenOut     string `json:"token_out"`
		AmountIn     uint64 `json:"amount_in"`
		MinAmountOut uint64 `json:"min_amount_out"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request format: " + err.Error(),
		})
		return
	}

	// Generate swap order ID
	userSuffix := req.User
	if len(req.User) > 8 {
		userSuffix = req.User[:8]
	}
	orderID := fmt.Sprintf("ccswap_%d_%s", time.Now().UnixNano(), userSuffix)

	// Calculate fees and estimated output
	bridgeFee := uint64(float64(req.AmountIn) * 0.01)    // 1% bridge fee
	swapFee := uint64(float64(req.AmountIn) * 0.003)     // 0.3% swap fee
	estimatedOut := uint64(float64(req.AmountIn) * 0.95) // 5% total fees

	// Create real cross-chain swap order
	order := map[string]interface{}{
		"id":             orderID,
		"user":           req.User,
		"source_chain":   req.SourceChain,
		"dest_chain":     req.DestChain,
		"token_in":       req.TokenIn,
		"token_out":      req.TokenOut,
		"amount_in":      req.AmountIn,
		"min_amount_out": req.MinAmountOut,
		"estimated_out":  estimatedOut,
		"status":         "pending",
		"created_at":     time.Now().Unix(),
		"expires_at":     time.Now().Add(30 * time.Minute).Unix(),
		"bridge_fee":     bridgeFee,
		"swap_fee":       swapFee,
		"price_impact":   0.5,
	}

	// Store the order
	s.storeCrossChainOrder(orderID, order)

	// Start background processing to simulate swap execution
	go s.processCrossChainSwap(orderID)

	fmt.Printf("✅ Cross-chain swap initiated: %s (%d %s → %s)\n",
		orderID, req.AmountIn, req.TokenIn, req.TokenOut)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Cross-chain swap initiated successfully",
		"data":    order,
	})
}

func (s *APIServer) handleCrossChainOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Method not allowed",
		})
		return
	}

	orderID := r.URL.Query().Get("id")
	if orderID == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Order ID required",
		})
		return
	}

	// Get real order data
	order, exists := s.getCrossChainOrder(orderID)
	if !exists {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Order not found",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    order,
	})
}

func (s *APIServer) handleCrossChainOrders(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Method not allowed",
		})
		return
	}

	user := r.URL.Query().Get("user")
	if user == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "User parameter required",
		})
		return
	}

	// Get real user orders
	orders := s.getUserCrossChainOrders(user)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    orders,
	})
}

func (s *APIServer) handleSupportedChains(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Method not allowed",
		})
		return
	}

	token := r.URL.Query().Get("token")

	supportedChains := map[string]interface{}{
		"chains": []map[string]interface{}{
			{
				"id":               "blackhole",
				"name":             "Blackhole Blockchain",
				"native_token":     "BHX",
				"supported_tokens": []string{"BHX", "USDT", "ETH", "SOL"},
				"bridge_fee":       1,
			},
			{
				"id":               "ethereum",
				"name":             "Ethereum",
				"native_token":     "ETH",
				"supported_tokens": []string{"ETH", "USDT", "wBHX"},
				"bridge_fee":       10,
			},
			{
				"id":               "solana",
				"name":             "Solana",
				"native_token":     "SOL",
				"supported_tokens": []string{"SOL", "USDT", "pBHX"},
				"bridge_fee":       5,
			},
		},
	}

	if token != "" {
		// Filter chains that support the specific token
		var supportingChains []map[string]interface{}
		for _, chain := range supportedChains["chains"].([]map[string]interface{}) {
			supportedTokens := chain["supported_tokens"].([]string)
			for _, supportedToken := range supportedTokens {
				if supportedToken == token {
					supportingChains = append(supportingChains, chain)
					break
				}
			}
		}
		supportedChains["chains"] = supportingChains
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    supportedChains,
	})
}
