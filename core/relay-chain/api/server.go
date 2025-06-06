package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

type APIServer struct {
	blockchain *chain.Blockchain
	port       int
}

func NewAPIServer(blockchain *chain.Blockchain, port int) *APIServer {
	return &APIServer{
		blockchain: blockchain,
		port:       port,
	}
}

func (s *APIServer) Start() {
	// Enable CORS for all routes
	http.HandleFunc("/", s.enableCORS(s.serveUI))
	http.HandleFunc("/api/blockchain/info", s.enableCORS(s.getBlockchainInfo))
	http.HandleFunc("/api/admin/add-tokens", s.enableCORS(s.addTokens))
	http.HandleFunc("/api/wallets", s.enableCORS(s.getWallets))

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
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; }
        .address { font-family: monospace; font-size: 12px; }
        .btn { background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
        .btn:hover { background: #2980b9; }
        .admin-form { background: #fff3cd; padding: 15px; border-radius: 4px; margin-top: 10px; }
        .form-group { margin-bottom: 10px; }
        .form-group label { display: block; margin-bottom: 5px; }
        .form-group input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        .refresh-btn { position: fixed; top: 20px; right: 20px; z-index: 1000; }
        .block-item { background: #f8f9fa; margin: 5px 0; padding: 10px; border-radius: 4px; }
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
                        <div class="stat-label">Total Supply</div>
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
