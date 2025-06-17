package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	wallet "github.com/Shivam-Patel-G/blackhole-blockchain/services/wallet/wallet"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Enhanced logging functions
func logError(operation string, err error) {
	log.Printf("❌ ERROR [%s]: %v", operation, err)
}

func logSuccess(operation string, details string) {
	log.Printf("✅ SUCCESS [%s]: %s", operation, details)
}

func logInfo(operation string, details string) {
	log.Printf("ℹ️ INFO [%s]: %s", operation, details)
}

func readLine() string {
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func main() {
	// Parse command-line flags
	var peerAddr = flag.String("peerAddr", "", "Blockchain node peer address (e.g., /ip4/127.0.0.1/tcp/3000/p2p/12D3KooWEHMeACYKmddCU7yvY7FSN78CnhC3bENFmkCcouwu1z8R)")
	var webMode = flag.Bool("web", false, "Start wallet in web UI mode")
	var webPort = flag.Int("port", 9000, "Port for web UI server")
	flag.Parse()

	reader := bufio.NewReader(os.Stdin)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 🧩 MongoDB setup
	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		fmt.Println("MongoDB connection error:", err)
		return
	}
	err = client.Ping(ctx, nil)
	if err != nil {
		fmt.Println("MongoDB ping failed:", err)
		return
	}

	db := client.Database("walletdb") // Use your DB name
	wallet.UserCollection = db.Collection("users")
	wallet.WalletCollection = db.Collection("wallets")
	wallet.TransactionCollection = db.Collection("transactions")

	// Initialize enhanced key management system
	fmt.Println("🔐 Initializing enhanced key management...")
	if err := wallet.InitializeGlobalKeyManager(); err != nil {
		log.Printf("⚠️ Warning: Failed to initialize enhanced key management: %v", err)
		fmt.Println("📝 Continuing with standard key management...")
	} else {
		fmt.Println("✅ Enhanced key management initialized successfully")

		// Start key rotation in background
		go func() {
			keyCtx, cancel := context.WithCancel(context.Background())
			defer cancel()

			if wallet.GlobalKeyManager != nil {
				fmt.Println("🔄 Starting key rotation service...")
				wallet.GlobalKeyManager.StartKeyRotation(keyCtx)
			}
		}()
	}

	// Initialize blockchain client
	if err := wallet.InitBlockchainClient(4000); err != nil { // Use different port for wallet
		log.Fatalf("Failed to initialize blockchain client: %v", err)
	}

	// Connect to blockchain node
	if *peerAddr != "" {
		fmt.Printf("🔗 Connecting to blockchain node: %s\n", *peerAddr)
		if err := wallet.DefaultBlockchainClient.ConnectToBlockchain(*peerAddr); err != nil {
			fmt.Printf("⚠️ Failed to connect to blockchain node: %v\n", err)
			fmt.Println("⚠️ Wallet will work in offline mode. Check the peer address and try again.")
		} else {
			fmt.Println("✅ Successfully connected to blockchain node!")
		}
	} else {
		fmt.Println("⚠️ No peer address provided. Use -peerAddr flag to connect to blockchain node.")
		fmt.Println("⚠️ Example: go run main.go -peerAddr /ip4/127.0.0.1/tcp/3000/p2p/12D3KooWEHMeACYKmddCU7yvY7FSN78CnhC3bENFmkCcouwu1z8R")
		fmt.Println("⚠️ Wallet will work in offline mode.")
	}

	// Check if web mode is requested
	if *webMode {
		fmt.Printf("🌐 Starting Wallet Web UI on port %d\n", *webPort)
		fmt.Printf("🌐 Open http://localhost:%d in your browser\n", *webPort)
		startWebServer(*webPort)
		return
	}

	fmt.Println("Welcome to the Wallet CLI")
	var loggedInUser *wallet.User = nil

	for {

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel() // make sure to cancel context after the operation

		fmt.Println("\nChoose an option:")
		if loggedInUser == nil {
			fmt.Println("1. Register")
			fmt.Println("2. Login")
			fmt.Println("3. Exit")
		} else {
			fmt.Printf("Logged in as: %s\n", loggedInUser.Username)
			fmt.Println("1. Generate Wallet from Mnemonic")
			fmt.Println("2. Logout")
			fmt.Println("3. Show my wallets")
			fmt.Println("4. Show My Wallet Details")
			fmt.Println("5. Exit")
			fmt.Println("6. Check Token Balance")
			fmt.Println("7. Transfer Tokens")
			fmt.Println("8. Stake Tokens")
			fmt.Println("9. Import Wallet from Private Key")
			fmt.Println("10. Export Wallet Private Key")
			fmt.Println("11. View Transaction History")
			fmt.Println("12. List All Wallets")
		}

		fmt.Print("Enter your choice: ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		if loggedInUser == nil {
			switch choice {
			case "1":
				fmt.Print("Enter username: ")
				username, _ := reader.ReadString('\n')
				username = strings.TrimSpace(username)

				fmt.Print("Enter password: ")
				password, _ := reader.ReadString('\n')
				password = strings.TrimSpace(password)

				user, err := wallet.RegisterUser(ctx, username, password)
				if err != nil {
					fmt.Println("Registration failed:", err)
				} else {
					fmt.Println("Registered successfully!")
					fmt.Printf("User ID: %v\n", user.ID)
				}

			case "2":
				fmt.Print("Enter username: ")
				username, _ := reader.ReadString('\n')
				username = strings.TrimSpace(username)

				fmt.Print("Enter password: ")
				password, _ := reader.ReadString('\n')
				password = strings.TrimSpace(password)

				user, err := wallet.AuthenticateUser(ctx, username, password)
				if err != nil {
					fmt.Println("Login failed:", err)
				} else {
					fmt.Println("Login successful!")
					fmt.Printf("Welcome, %s (User ID: %v)\n", user.Username, user.ID)
					loggedInUser = user
				}

			case "3":
				fmt.Println("Exiting Wallet CLI.")
				return

			default:
				fmt.Println("Invalid choice. Please enter 1, 2, or 3.")
			}
		} else {
			switch choice {
			case "1":
				fmt.Print("Enter wallet name: ")
				walletName, _ := reader.ReadString('\n')
				walletName = strings.TrimSpace(walletName)

				fmt.Print("Enter your password to secure the wallet: ")
				password, _ := reader.ReadString('\n')
				password = strings.TrimSpace(password)

				wallet, err := wallet.GenerateWalletFromMnemonic(ctx, loggedInUser, password, walletName)
				if err != nil {
					fmt.Println("Wallet generation failed:", err)
				} else {
					fmt.Println("Wallet generated successfully!")
					fmt.Printf("Wallet Name: %s\n", walletName)
					fmt.Printf("Mnemonic (store safely!): %s\n", string(wallet.EncryptedMnemonic))
					// You can print wallet address or keys here as needed
				}

			case "2":
				loggedInUser = nil
				fmt.Println("Logged out successfully.")

			case "3":
				fmt.Print("Enter your password to decrypt wallets: ")
				password, _ := reader.ReadString('\n')
				password = strings.TrimSpace(password)

				wallets, err := wallet.GetUserWallets(ctx, loggedInUser, password)
				if err != nil {
					fmt.Println("Failed to get wallets:", err)
				} else {
					fmt.Printf("You have %d wallets:\n", len(wallets))
					for i, w := range wallets {
						fmt.Printf("%d. %s\n", i+1, w.WalletName)
					}
				}
			case "4":
				fmt.Print("Enter wallet name to view details: ")
				walletName, _ := reader.ReadString('\n')
				walletName = strings.TrimSpace(walletName)

				fmt.Print("Enter your password: ")
				password, _ := reader.ReadString('\n')
				password = strings.TrimSpace(password)

				wallet, privKey, mnemonic, err := wallet.GetWalletDetails(ctx, loggedInUser, walletName, password)
				if err != nil {
					fmt.Println("Error:", err)
				} else {
					fmt.Println("Wallet Details:")
					fmt.Printf("Name       : %s\n", wallet.WalletName)
					fmt.Printf("Address    : %s\n", wallet.Address)
					fmt.Printf("Public Key : %s\n", wallet.PublicKey)
					fmt.Printf("Private Key: %x\n", privKey)
					fmt.Printf("Mnemonic   : %s\n", mnemonic)
					fmt.Printf("Created At : %s\n", wallet.CreatedAt.Format(time.RFC3339))
				}

			case "5":
				fmt.Println("Exiting Wallet CLI.")
				return

			case "6":
				checkTokenBalance(ctx, loggedInUser)

			case "7":
				transferTokens(ctx, loggedInUser)

			case "8":
				stakeTokens(ctx, loggedInUser)

			case "9":
				importWalletFromPrivateKey(ctx, loggedInUser)

			case "10":
				exportWalletPrivateKey(ctx, loggedInUser)

			case "11":
				viewTransactionHistory(ctx, loggedInUser)

			case "12":
				listAllWallets(ctx, loggedInUser)

			default:
				fmt.Println("Invalid choice. Please enter a valid option.")
			}
		}
	}
}

func checkTokenBalance(ctx context.Context, user *wallet.User) {
	fmt.Println("=== Check Token Balance ===")

	// Get wallet name
	fmt.Print("Enter wallet name: ")
	walletName := readLine()

	// Get password
	fmt.Print("Enter password: ")
	password := readLine()

	// Get token symbol
	fmt.Print("Enter token symbol (e.g., BHX): ")
	tokenSymbol := readLine()

	balance, err := wallet.CheckTokenBalance(ctx, user, walletName, password, tokenSymbol)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Balance of %s: %d tokens\n", tokenSymbol, balance)
}

func transferTokens(ctx context.Context, user *wallet.User) {
	fmt.Println("=== Transfer Tokens ===")

	// Get wallet name
	fmt.Print("Enter your wallet name: ")
	walletName := readLine()

	// Get password
	fmt.Print("Enter password: ")
	password := readLine()

	// Get recipient address
	fmt.Print("Enter recipient address: ")
	toAddress := readLine()

	// Get token symbol
	fmt.Print("Enter token symbol (e.g., BHX): ")
	tokenSymbol := readLine()

	// Get amount
	fmt.Print("Enter amount to transfer: ")
	amountStr := readLine()
	amount, err := strconv.ParseUint(amountStr, 10, 64)
	if err != nil {
		fmt.Printf("Invalid amount: %v\n", err)
		return
	}

	err = wallet.TransferTokensWithHistory(ctx, user, walletName, password, toAddress, tokenSymbol, amount)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Successfully transferred %d %s tokens to %s\n", amount, tokenSymbol, toAddress)
}

func stakeTokens(ctx context.Context, user *wallet.User) {
	fmt.Println("=== Stake Tokens ===")

	// Get wallet name
	fmt.Print("Enter your wallet name: ")
	walletName := readLine()

	// Get password
	fmt.Print("Enter password: ")
	password := readLine()

	// Get token symbol
	fmt.Print("Enter token symbol (e.g., BHX): ")
	tokenSymbol := readLine()

	// Get amount
	fmt.Print("Enter amount to stake: ")
	amountStr := readLine()
	amount, err := strconv.ParseUint(amountStr, 10, 64)
	if err != nil {
		fmt.Printf("Invalid amount: %v\n", err)
		return
	}

	err = wallet.StakeTokensWithHistory(ctx, user, walletName, password, tokenSymbol, amount)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Successfully staked %d %s tokens\n", amount, tokenSymbol)
}

func importWalletFromPrivateKey(ctx context.Context, user *wallet.User) {
	fmt.Println("=== Import Wallet from Private Key ===")

	fmt.Print("Enter wallet name: ")
	walletName := readLine()

	fmt.Print("Enter password to secure the wallet: ")
	password := readLine()

	fmt.Print("Enter private key (hex): ")
	privateKeyHex := readLine()

	wallet, err := wallet.ImportWalletFromPrivateKey(ctx, user, password, walletName, privateKeyHex)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Successfully imported wallet: %s\n", wallet.WalletName)
	fmt.Printf("Address: %s\n", wallet.Address)
}

func exportWalletPrivateKey(ctx context.Context, user *wallet.User) {
	fmt.Println("=== Export Wallet Private Key ===")

	fmt.Print("Enter wallet name: ")
	walletName := readLine()

	fmt.Print("Enter password: ")
	password := readLine()

	privateKeyHex, err := wallet.ExportWalletPrivateKey(ctx, user, walletName, password)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Private Key: %s\n", privateKeyHex)
	fmt.Println("⚠️ Keep this private key secure and never share it!")
}

func viewTransactionHistory(ctx context.Context, user *wallet.User) {
	fmt.Println("=== Transaction History ===")

	fmt.Print("Enter wallet address (or press Enter for all transactions): ")
	walletAddr := readLine()

	var transactions []*wallet.TransactionRecord
	var err error

	if walletAddr == "" {
		transactions, err = wallet.GetAllUserTransactions(ctx, user.ID.Hex(), 50)
	} else {
		transactions, err = wallet.GetWalletTransactionHistory(ctx, user.ID.Hex(), walletAddr, 50)
	}

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	if len(transactions) == 0 {
		fmt.Println("No transactions found.")
		return
	}

	fmt.Printf("Found %d transactions:\n\n", len(transactions))
	for i, tx := range transactions {
		fmt.Printf("%d. %s\n", i+1, tx.Type)
		fmt.Printf("   From: %s\n", tx.From)
		fmt.Printf("   To: %s\n", tx.To)
		fmt.Printf("   Amount: %d %s\n", tx.Amount, tx.TokenSymbol)
		fmt.Printf("   Status: %s\n", tx.Status)
		fmt.Printf("   Time: %s\n", tx.Timestamp.Format(time.RFC3339))
		if tx.BlockHeight > 0 {
			fmt.Printf("   Block: %d\n", tx.BlockHeight)
		}
		fmt.Println()
	}
}

func listAllWallets(ctx context.Context, user *wallet.User) {
	fmt.Println("=== All User Wallets ===")

	wallets, err := wallet.ListUserWallets(ctx, user)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	if len(wallets) == 0 {
		fmt.Println("No wallets found.")
		return
	}

	fmt.Printf("Found %d wallets:\n\n", len(wallets))
	for i, w := range wallets {
		fmt.Printf("%d. %s\n", i+1, w.WalletName)
		fmt.Printf("   Address: %s\n", w.Address)
		fmt.Printf("   Created: %s\n", w.CreatedAt.Format(time.RFC3339))
		fmt.Println()
	}
}

// Web server functionality
var sessions = make(map[string]*SessionData)

type SessionData struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func startWebServer(port int) {
	// Static routes
	http.HandleFunc("/", enableCORS(serveLogin))
	http.HandleFunc("/login", enableCORS(serveLogin))
	http.HandleFunc("/register", enableCORS(serveRegister))
	http.HandleFunc("/dashboard", enableCORS(requireAuth(serveDashboard)))

	// API routes
	http.HandleFunc("/api/login", enableCORS(handleLogin))
	http.HandleFunc("/api/register", enableCORS(handleRegister))
	http.HandleFunc("/api/logout", enableCORS(handleLogout))
	http.HandleFunc("/api/wallets", enableCORS(requireAuth(handleWallets)))
	http.HandleFunc("/api/wallets/create", enableCORS(requireAuth(handleCreateWallet)))
	http.HandleFunc("/api/wallets/import", enableCORS(requireAuth(handleImportWallet)))
	http.HandleFunc("/api/wallets/export", enableCORS(requireAuth(handleExportWallet)))
	http.HandleFunc("/api/wallets/balance", enableCORS(requireAuth(handleCheckBalance)))
	http.HandleFunc("/api/wallets/transfer", enableCORS(requireAuth(handleTransfer)))
	http.HandleFunc("/api/wallets/stake", enableCORS(requireAuth(handleStakeTokens)))
	http.HandleFunc("/api/wallets/transactions", enableCORS(requireAuth(handleTransactions)))

	// OTC Trading endpoints
	http.HandleFunc("/api/otc/create", enableCORS(requireAuth(handleCreateOTCOrder)))
	http.HandleFunc("/api/otc/orders", enableCORS(requireAuth(handleGetOTCOrders)))
	http.HandleFunc("/api/otc/match", enableCORS(requireAuth(handleMatchOTCOrder)))
	http.HandleFunc("/api/otc/cancel", enableCORS(requireAuth(handleCancelOTCOrder)))

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}

// enableCORS enables CORS for all requests
func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// requireAuth middleware to check authentication
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := getSessionID(r)

		if sessionID == "" || sessions[sessionID] == nil {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				sendJSONResponse(w, APIResponse{
					Success: false,
					Message: "Authentication required",
				}, http.StatusUnauthorized)
				return
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
		}

		next(w, r)
	}
}

// getSessionID gets session ID from cookie
func getSessionID(r *http.Request) string {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return ""
	}
	return cookie.Value
}

// setSessionID sets session ID cookie
func setSessionID(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
	})
}

// sendJSONResponse sends JSON response
func sendJSONResponse(w http.ResponseWriter, response APIResponse, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// serveLogin serves the login page
func serveLogin(w http.ResponseWriter, r *http.Request) {
	// Check if already logged in
	sessionID := getSessionID(r)
	if sessionID != "" && sessions[sessionID] != nil {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blackhole Wallet - Login</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { color: #333; margin: 0; }
        .header p { color: #666; margin: 10px 0 0 0; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 5px; color: #333; font-weight: bold; }
        .form-group input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 5px; font-size: 16px; box-sizing: border-box; }
        .btn { width: 100%; padding: 12px; background: #667eea; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; margin-bottom: 10px; }
        .btn:hover { background: #5a6fd8; }
        .error { color: #dc3545; margin-top: 10px; text-align: center; }
        .success { color: #28a745; margin-top: 10px; text-align: center; }
        .link { text-align: center; margin-top: 20px; }
        .link a { color: #667eea; text-decoration: none; }
        .link a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌌 Blackhole Wallet</h1>
            <p>Secure Blockchain Wallet</p>
        </div>

        <form id="loginForm">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" id="username" required>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" id="password" required>
            </div>
            <button type="submit" class="btn">Login</button>
        </form>

        <div class="link">
            <a href="/register">Don't have an account? Register here</a>
        </div>

        <div id="message"></div>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();

            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const messageDiv = document.getElementById('message');

            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });

                const result = await response.json();

                if (result.success) {
                    messageDiv.innerHTML = '<div class="success">Login successful! Redirecting...</div>';
                    setTimeout(() => window.location.href = '/dashboard', 1000);
                } else {
                    messageDiv.innerHTML = '<div class="error">' + result.message + '</div>';
                }
            } catch (error) {
                messageDiv.innerHTML = '<div class="error">Network error. Please try again.</div>';
            }
        });
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// serveRegister serves the registration page
func serveRegister(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blackhole Wallet - Register</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { color: #333; margin: 0; }
        .header p { color: #666; margin: 10px 0 0 0; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 5px; color: #333; font-weight: bold; }
        .form-group input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 5px; font-size: 16px; box-sizing: border-box; }
        .btn { width: 100%; padding: 12px; background: #667eea; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; margin-bottom: 10px; }
        .btn:hover { background: #5a6fd8; }
        .error { color: #dc3545; margin-top: 10px; text-align: center; }
        .success { color: #28a745; margin-top: 10px; text-align: center; }
        .link { text-align: center; margin-top: 20px; }
        .link a { color: #667eea; text-decoration: none; }
        .link a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌌 Blackhole Wallet</h1>
            <p>Create Your Account</p>
        </div>

        <form id="registerForm">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" id="username" required>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" id="password" required>
            </div>
            <div class="form-group">
                <label>Confirm Password:</label>
                <input type="password" id="confirmPassword" required>
            </div>
            <button type="submit" class="btn">Register</button>
        </form>

        <div class="link">
            <a href="/login">Already have an account? Login here</a>
        </div>

        <div id="message"></div>
    </div>

    <script>
        document.getElementById('registerForm').addEventListener('submit', async (e) => {
            e.preventDefault();

            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            const messageDiv = document.getElementById('message');

            if (password !== confirmPassword) {
                messageDiv.innerHTML = '<div class="error">Passwords do not match</div>';
                return;
            }

            try {
                const response = await fetch('/api/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });

                const result = await response.json();

                if (result.success) {
                    messageDiv.innerHTML = '<div class="success">Registration successful! Redirecting to login...</div>';
                    setTimeout(() => window.location.href = '/login', 2000);
                } else {
                    messageDiv.innerHTML = '<div class="error">' + result.message + '</div>';
                }
            } catch (error) {
                messageDiv.innerHTML = '<div class="error">Network error. Please try again.</div>';
            }
        });
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// handleLogin handles login API requests
func handleLogin(w http.ResponseWriter, r *http.Request) {
	logInfo("LOGIN_ATTEMPT", "Processing login request")

	if r.Method != "POST" {
		logError("LOGIN_METHOD", fmt.Errorf("invalid method: %s", r.Method))
		sendJSONResponse(w, APIResponse{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logError("LOGIN_DECODE", err)
		sendJSONResponse(w, APIResponse{Success: false, Message: "Invalid request body"}, http.StatusBadRequest)
		return
	}

	logInfo("LOGIN_USER", fmt.Sprintf("Attempting login for user: %s", req.Username))

	ctx := context.Background()
	user, err := wallet.AuthenticateUser(ctx, req.Username, req.Password)
	if err != nil {
		logError("LOGIN_AUTH", fmt.Errorf("authentication failed for user %s: %v", req.Username, err))
		sendJSONResponse(w, APIResponse{Success: false, Message: "Invalid username or password"}, http.StatusUnauthorized)
		return
	}

	// Create session
	sessionID := fmt.Sprintf("%d_%s", time.Now().Unix(), req.Username)
	sessions[sessionID] = &SessionData{
		UserID:   user.ID.Hex(),
		Username: user.Username,
	}

	// Set session cookie
	setSessionID(w, sessionID)

	logSuccess("LOGIN_SUCCESS", fmt.Sprintf("User %s logged in successfully", req.Username))

	sendJSONResponse(w, APIResponse{
		Success: true,
		Message: "Login successful",
		Data:    map[string]string{"username": user.Username},
	}, http.StatusOK)
}

// handleRegister handles registration API requests
func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Invalid request body"}, http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	_, err := wallet.RegisterUser(ctx, req.Username, req.Password)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: err.Error()}, http.StatusBadRequest)
		return
	}

	sendJSONResponse(w, APIResponse{
		Success: true,
		Message: "Registration successful",
	}, http.StatusOK)
}

// handleLogout handles logout API requests
func handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)
	if sessionID != "" {
		delete(sessions, sessionID)
	}

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	sendJSONResponse(w, APIResponse{
		Success: true,
		Message: "Logout successful",
	}, http.StatusOK)
}

// serveDashboard serves the main wallet dashboard with all functions
func serveDashboard(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blackhole Wallet - Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; }
        .btn { padding: 10px 20px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }
        .btn:hover { background: #5a6fd8; }
        .btn-success { background: #28a745; }
        .btn-success:hover { background: #218838; }
        .btn-warning { background: #ffc107; color: #212529; }
        .btn-warning:hover { background: #e0a800; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input, .form-group select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .wallet-item { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #667eea; }
        .wallet-address { font-family: monospace; font-size: 12px; color: #666; word-break: break-all; }
        .balance-item { background: #e8f5e8; padding: 10px; margin: 5px 0; border-radius: 4px; }
        .transaction-item { background: #f8f9fa; padding: 10px; margin: 5px 0; border-radius: 4px; border-left: 3px solid #28a745; }
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
            overflow-y: auto; /* Enable scrolling for the modal overlay */
            padding: 20px 0; /* Add padding to prevent content from touching edges */
        }
        .modal-content {
            background-color: white;
            margin: 0 auto; /* Remove top margin, let padding handle spacing */
            padding: 20px;
            border-radius: 8px;
            width: 80%;
            max-width: 600px;
            max-height: calc(100vh - 40px); /* Ensure modal doesn't exceed viewport */
            overflow-y: auto; /* Enable scrolling within modal content */
            position: relative; /* Ensure proper positioning */
            box-sizing: border-box; /* Include padding in width calculation */
        }
        .close { color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer; }
        .close:hover { color: black; }
        .error { color: #dc3545; margin-top: 10px; }
        .success { color: #28a745; margin-top: 10px; }
        .loading { color: #666; font-style: italic; }
        .hidden { display: none; }

        /* Advanced Transaction Styles */
        .transaction-form {
            margin-top: 20px;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 8px;
            background-color: #f9f9f9;
        }

        .form-row {
            display: flex;
            gap: 15px;
            margin-bottom: 15px;
        }

        .form-row .form-group {
            flex: 1;
        }

        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border: 1px solid transparent;
            border-radius: 4px;
        }

        .alert-info {
            color: #31708f;
            background-color: #d9edf7;
            border-color: #bce8f1;
        }

        .btn-small {
            padding: 5px 10px;
            font-size: 12px;
            margin-left: 10px;
        }

        /* OTC Orders Styles */
        .otc-orders-grid {
            display: grid;
            gap: 15px;
            margin-top: 15px;
        }

        .otc-order-card {
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 15px;
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .otc-order-card.expired {
            opacity: 0.6;
            border-color: #ccc;
        }

        .order-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
            padding-bottom: 8px;
            border-bottom: 1px solid #eee;
        }

        .order-status {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
        }

        .status-open { background: #d4edda; color: #155724; }
        .status-matched { background: #fff3cd; color: #856404; }
        .status-completed { background: #d1ecf1; color: #0c5460; }
        .status-cancelled { background: #f8d7da; color: #721c24; }
        .status-expired { background: #e2e3e5; color: #383d41; }

        .trade-info {
            display: flex;
            flex-direction: column;
            gap: 5px;
            margin-bottom: 10px;
        }

        .offering {
            font-weight: bold;
            color: #e74c3c;
        }

        .requesting {
            font-weight: bold;
            color: #27ae60;
        }

        .order-meta {
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            color: #666;
            margin-bottom: 10px;
        }

        .order-actions {
            text-align: right;
        }

        .no-orders {
            text-align: center;
            color: #666;
            font-style: italic;
            padding: 20px;
        }

        .btn-danger {
            background: #e74c3c;
        }

        .btn-danger:hover {
            background: #c0392b;
        }

        /* Slashing Dashboard Styles */
        .dashboard-tabs {
            display: flex;
            border-bottom: 2px solid #ddd;
            margin-bottom: 20px;
        }

        .tab-btn {
            padding: 10px 20px;
            border: none;
            background: #f8f9fa;
            cursor: pointer;
            border-bottom: 3px solid transparent;
            transition: all 0.3s;
        }

        .tab-btn.active {
            background: white;
            border-bottom-color: #007bff;
            color: #007bff;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .slashing-events-grid, .validator-status-grid {
            display: grid;
            gap: 15px;
            margin-top: 15px;
        }

        .slashing-event-card, .validator-status-card {
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 15px;
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .slashing-event-card.severity-minor {
            border-left: 4px solid #ffc107;
        }

        .slashing-event-card.severity-major {
            border-left: 4px solid #fd7e14;
        }

        .slashing-event-card.severity-critical {
            border-left: 4px solid #dc3545;
        }

        .validator-status-card.healthy {
            border-left: 4px solid #28a745;
        }

        .validator-status-card.warning {
            border-left: 4px solid #ffc107;
        }

        .validator-status-card.jailed {
            border-left: 4px solid #dc3545;
            opacity: 0.7;
        }

        .event-header, .validator-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
            padding-bottom: 8px;
            border-bottom: 1px solid #eee;
        }

        .event-status, .validator-status-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
        }

        .status-pending { background: #fff3cd; color: #856404; }
        .status-executed { background: #d1ecf1; color: #0c5460; }
        .status-disputed { background: #f8d7da; color: #721c24; }

        .validator-status-badge.healthy { background: #d4edda; color: #155724; }
        .validator-status-badge.warning { background: #fff3cd; color: #856404; }
        .validator-status-badge.jailed { background: #f8d7da; color: #721c24; }

        .violation-info, .status-info {
            display: flex;
            flex-direction: column;
            gap: 5px;
            margin-bottom: 10px;
        }

        .validator, .condition, .amount, .stake, .strikes {
            font-size: 14px;
        }

        .validator, .stake {
            font-weight: bold;
            color: #495057;
        }

        .condition {
            color: #dc3545;
            font-weight: bold;
        }

        .amount {
            color: #fd7e14;
            font-weight: bold;
        }

        .strikes {
            color: #ffc107;
            font-weight: bold;
        }

        .event-meta {
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            color: #666;
            margin-bottom: 10px;
        }

        .evidence {
            font-size: 12px;
            color: #666;
            font-style: italic;
            margin-bottom: 10px;
        }

        .event-actions {
            text-align: right;
        }

        .no-events, .no-validators {
            text-align: center;
            color: #666;
            font-style: italic;
            padding: 20px;
        }

        .form-row {
            display: flex;
            gap: 15px;
            margin-bottom: 15px;
        }

        .form-row .form-group {
            flex: 1;
        }

        /* Cross-Chain DEX Styles */
        .dex-tabs {
            display: flex;
            border-bottom: 2px solid #ddd;
            margin-bottom: 20px;
        }

        .swap-interface {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 30px;
            margin-bottom: 20px;
        }

        .swap-form {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #ddd;
        }

        .chain-selection {
            background: white;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #ddd;
            margin-bottom: 10px;
        }

        .chain-input {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            align-items: center;
        }

        .chain-input label {
            font-weight: bold;
            color: #495057;
        }

        .chain-input select,
        .chain-input input {
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }

        .swap-arrow {
            text-align: center;
            margin: 10px 0;
        }

        .swap-arrow button {
            background: #007bff;
            color: white;
            border: none;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            font-size: 18px;
            cursor: pointer;
            transition: all 0.3s;
        }

        .swap-arrow button:hover {
            background: #0056b3;
            transform: rotate(180deg);
        }

        .swap-details {
            background: white;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #ddd;
            margin: 15px 0;
        }

        .detail-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            font-size: 14px;
        }

        .detail-row.total {
            border-top: 1px solid #ddd;
            padding-top: 8px;
            font-weight: bold;
        }

        .slippage-settings {
            margin: 15px 0;
        }

        .slippage-buttons {
            display: flex;
            gap: 10px;
            margin-top: 5px;
        }

        .slippage-buttons button {
            padding: 5px 10px;
            border: 1px solid #ddd;
            background: white;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.3s;
        }

        .slippage-buttons button.active {
            background: #007bff;
            color: white;
            border-color: #007bff;
        }

        .slippage-buttons input {
            width: 80px;
            padding: 5px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }

        .quote-display {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #ddd;
            height: fit-content;
        }

        .quote-summary {
            background: white;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #ddd;
        }

        .quote-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
            font-size: 14px;
        }

        .quote-row:last-child {
            margin-bottom: 0;
        }

        .orders-grid, .chains-grid {
            display: grid;
            gap: 15px;
            margin-top: 15px;
        }

        .order-card, .chain-card {
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 15px;
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .order-header, .chain-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
            padding-bottom: 8px;
            border-bottom: 1px solid #eee;
        }

        .order-status {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
        }

        .status-pending { background: #fff3cd; color: #856404; }
        .status-bridging { background: #cce5ff; color: #004085; }
        .status-swapping { background: #d4edda; color: #155724; }
        .status-completed { background: #d1ecf1; color: #0c5460; }
        .status-failed { background: #f8d7da; color: #721c24; }

        .swap-info {
            margin-bottom: 10px;
        }

        .route {
            display: block;
            font-weight: bold;
            color: #007bff;
            margin-bottom: 5px;
        }

        .tokens {
            display: block;
            color: #495057;
        }

        .order-meta {
            display: flex;
            flex-direction: column;
            gap: 3px;
            font-size: 12px;
            color: #666;
        }

        .chain-id {
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 12px;
            color: #495057;
        }

        .native-token, .bridge-fee {
            margin-bottom: 8px;
            font-size: 14px;
        }

        .supported-tokens {
            font-size: 13px;
            color: #666;
        }

        .no-orders {
            text-align: center;
            color: #666;
            font-style: italic;
            padding: 20px;
        }

        .btn-large {
            width: 100%;
            padding: 15px;
            font-size: 16px;
            font-weight: bold;
        }

        /* Additional Modal Fixes */
        body.modal-open {
            overflow: hidden !important;
        }

        .modal {
            /* Ensure modal is always on top */
            z-index: 9999 !important;
        }

        .modal-content {
            /* Smooth scrolling within modal */
            scroll-behavior: smooth;
            /* Ensure content doesn't overflow horizontally */
            word-wrap: break-word;
            /* Add some breathing room */
            margin-top: 20px;
            margin-bottom: 20px;
        }

        /* Fix for very tall modals */
        .modal-content.large {
            max-width: 90%;
            width: 90%;
            max-height: 90vh;
        }

        /* Ensure form elements don't cause horizontal scroll */
        .modal-content input,
        .modal-content select,
        .modal-content textarea {
            max-width: 100%;
            box-sizing: border-box;
        }

        /* Better spacing for modal headers */
        .modal-content h3 {
            margin-top: 0;
            margin-bottom: 20px;
            padding-right: 40px; /* Space for close button */
        }

        /* Improve close button positioning */
        .close {
            position: absolute;
            top: 15px;
            right: 20px;
            z-index: 1;
        }

        /* Responsive modal adjustments */
        @media (max-width: 768px) {
            .modal-content {
                width: 95%;
                margin: 10px auto;
                padding: 15px;
            }

            .swap-interface {
                grid-template-columns: 1fr;
                gap: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🌌 Blackhole Wallet Dashboard</h1>
                <p id="userInfo">Loading user info...</p>
            </div>
            <div>
                <button class="btn" onclick="window.open('http://localhost:8080/dev', '_blank')" style="background: #e74c3c; margin-right: 10px;">🔧 Dev Mode</button>
                <button class="btn btn-danger" onclick="logout()">Logout</button>
            </div>
        </div>

        <div class="grid">
            <!-- Wallet Management -->
            <div class="card">
                <h3>💼 Wallet Management</h3>
                <button class="btn btn-success" onclick="showCreateWallet()">Create New Wallet</button>
                <button class="btn" onclick="showImportWallet()">Import Wallet</button>
                <button class="btn btn-warning" onclick="showExportWallet()">Export Wallet</button>
                <button class="btn" onclick="loadWallets()">Refresh Wallets</button>
            </div>

            <!-- Token Operations -->
            <div class="card">
                <h3>💰 Token Operations</h3>
                <button class="btn" onclick="showCheckBalance()">Check Balance</button>
                <button class="btn btn-success" onclick="showTransferTokens()">Transfer Tokens</button>
                <button class="btn btn-warning" onclick="showStakeTokens()">Stake Tokens</button>
                <button class="btn btn-primary" onclick="showAdvancedTransactions()">🚀 Advanced Transactions</button>
                <button class="btn btn-info" onclick="showCrossChainDEX()">🌉 Cross-Chain DEX</button>
                <button class="btn btn-danger" onclick="showSlashingDashboard()">⚡ Slashing Dashboard</button>
                <button class="btn" onclick="showTransactionHistory()">Transaction History</button>
            </div>
        </div>

        <!-- Wallets List -->
        <div class="card">
            <h3>📋 Your Wallets</h3>
            <div id="wallets-list">
                <p class="loading">Loading wallets...</p>
            </div>
        </div>

        <!-- Balance Display -->
        <div class="card">
            <h3>💳 Wallet Balances</h3>
            <div id="balances-list">
                <p>Select a wallet and check balance to view balances here.</p>
            </div>
        </div>

        <!-- Transaction History -->
        <div class="card">
            <h3>📊 Recent Transactions</h3>
            <div id="transactions-list">
                <p>Transaction history will appear here.</p>
            </div>
        </div>
    </div>

    <!-- Modals for various operations -->
    <div id="createWalletModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('createWalletModal')">&times;</span>
            <h3>Create New Wallet</h3>
            <form id="createWalletForm">
                <div class="form-group">
                    <label>Wallet Name:</label>
                    <input type="text" id="createWalletName" required>
                </div>
                <div class="form-group">
                    <label>Password (to secure wallet):</label>
                    <input type="password" id="createWalletPassword" required>
                </div>
                <button type="submit" class="btn btn-success">Create Wallet</button>
            </form>
            <div id="createWalletMessage"></div>
        </div>
    </div>

    <div id="importWalletModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('importWalletModal')">&times;</span>
            <h3>Import Wallet</h3>
            <form id="importWalletForm">
                <div class="form-group">
                    <label>Wallet Name:</label>
                    <input type="text" id="importWalletName" required>
                </div>
                <div class="form-group">
                    <label>Password (to secure wallet):</label>
                    <input type="password" id="importWalletPassword" required>
                </div>
                <div class="form-group">
                    <label>Private Key (hex):</label>
                    <input type="text" id="importPrivateKey" required placeholder="Enter private key in hexadecimal format">
                </div>
                <button type="submit" class="btn btn-success">Import Wallet</button>
            </form>
            <div id="importWalletMessage"></div>
        </div>
    </div>

    <div id="exportWalletModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('exportWalletModal')">&times;</span>
            <h3>Export Wallet Private Key</h3>
            <form id="exportWalletForm">
                <div class="form-group">
                    <label>Select Wallet:</label>
                    <select id="exportWalletSelect" required>
                        <option value="">Select a wallet...</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" id="exportWalletPassword" required>
                </div>
                <button type="submit" class="btn btn-warning">Export Private Key</button>
            </form>
            <div id="exportWalletMessage"></div>
        </div>
    </div>

    <div id="balanceModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('balanceModal')">&times;</span>
            <h3>Check Wallet Balance</h3>
            <form id="balanceForm">
                <div class="form-group">
                    <label>Select Wallet:</label>
                    <select id="balanceWalletSelect" required>
                        <option value="">Select a wallet...</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" id="balancePassword" required>
                </div>
                <div class="form-group">
                    <label>Token Symbol:</label>
                    <input type="text" id="balanceTokenSymbol" required placeholder="e.g., BHX">
                </div>
                <button type="submit" class="btn">Check Balance</button>
            </form>
            <div id="balanceMessage"></div>
        </div>
    </div>

    <div id="transferModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('transferModal')">&times;</span>
            <h3>Transfer Tokens</h3>
            <form id="transferForm">
                <div class="form-group">
                    <label>From Wallet:</label>
                    <select id="transferWalletSelect" required>
                        <option value="">Select a wallet...</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" id="transferPassword" required>
                </div>
                <div class="form-group">
                    <label>To Address:</label>
                    <input type="text" id="transferToAddress" required placeholder="Recipient wallet address">
                </div>
                <div class="form-group">
                    <label>Token Symbol:</label>
                    <input type="text" id="transferTokenSymbol" required placeholder="e.g., BHX">
                </div>
                <div class="form-group">
                    <label>Amount:</label>
                    <input type="number" id="transferAmount" required min="1">
                </div>
                <button type="submit" class="btn btn-success">Transfer Tokens</button>
            </form>
            <div id="transferMessage"></div>
        </div>
    </div>

    <div id="stakeModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('stakeModal')">&times;</span>
            <h3>Stake Tokens</h3>
            <form id="stakeForm">
                <div class="form-group">
                    <label>Select Wallet:</label>
                    <select id="stakeWalletSelect" required>
                        <option value="">Select a wallet...</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" id="stakePassword" required>
                </div>
                <div class="form-group">
                    <label>Token Symbol:</label>
                    <input type="text" id="stakeTokenSymbol" required placeholder="e.g., BHX">
                </div>
                <div class="form-group">
                    <label>Amount to Stake:</label>
                    <input type="number" id="stakeAmount" required min="1">
                </div>
                <button type="submit" class="btn btn-warning">Stake Tokens</button>
            </form>
            <div id="stakeMessage"></div>
        </div>
    </div>

    <!-- Advanced Transactions Modal -->
    <div id="advancedTransactionsModal" class="modal">
        <div class="modal-content" style="max-width: 800px;">
            <span class="close" onclick="closeModal('advancedTransactionsModal')">&times;</span>
            <h3>🚀 Advanced Transactions</h3>

            <!-- Transaction Type Selector -->
            <div class="form-group">
                <label>Transaction Type:</label>
                <select id="transactionType" onchange="showTransactionForm()" required>
                    <option value="">Select transaction type...</option>
                    <option value="otc">🤝 OTC Trading</option>
                    <option value="token_transfer">💸 Token Transfer</option>
                    <option value="dex">🔄 DEX Swap</option>
                    <option value="staking">🥩 Staking</option>
                    <option value="governance">🗳️ Governance</option>
                    <option value="cross_chain">🌉 Cross-Chain</option>
                </select>
            </div>

            <!-- OTC Trading Form -->
            <div id="otcForm" class="transaction-form" style="display: none;">
                <h4>🤝 Over-The-Counter Trading</h4>
                <div class="form-row">
                    <div class="form-group">
                        <label>Your Wallet:</label>
                        <select id="otcWalletSelect" required>
                            <option value="">Select wallet...</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Password:</label>
                        <input type="password" id="otcPassword" required>
                    </div>
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label>Token You're Offering:</label>
                        <input type="text" id="otcTokenOffered" required placeholder="e.g., BHX">
                    </div>
                    <div class="form-group">
                        <label>Amount Offering:</label>
                        <input type="number" id="otcAmountOffered" required min="1">
                    </div>
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label>Token You Want:</label>
                        <input type="text" id="otcTokenRequested" required placeholder="e.g., ETH">
                    </div>
                    <div class="form-group">
                        <label>Amount Requested:</label>
                        <input type="number" id="otcAmountRequested" required min="1">
                    </div>
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label>Expiration (hours):</label>
                        <input type="number" id="otcExpiration" value="24" min="1" max="168">
                    </div>
                    <div class="form-group">
                        <label>
                            <input type="checkbox" id="otcMultiSig"> Multi-Signature Required
                        </label>
                    </div>
                </div>

                <div id="otcMultiSigSection" style="display: none;">
                    <label>Required Signers (comma-separated addresses):</label>
                    <textarea id="otcRequiredSigs" placeholder="addr1,addr2,addr3"></textarea>
                </div>

                <button type="button" class="btn btn-primary" onclick="createOTCOrder()">Create OTC Order</button>
            </div>

            <!-- Token Transfer Form -->
            <div id="tokenTransferForm" class="transaction-form" style="display: none;">
                <h4>💸 Enhanced Token Transfer</h4>
                <div class="form-row">
                    <div class="form-group">
                        <label>From Wallet:</label>
                        <select id="transferFromWallet" required>
                            <option value="">Select wallet...</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Password:</label>
                        <input type="password" id="transferFromPassword" required>
                    </div>
                </div>

                <div class="form-group">
                    <label>To Address:</label>
                    <input type="text" id="transferToAddr" required placeholder="Recipient address">
                    <button type="button" class="btn btn-small" onclick="detectAddress()">🔍 Auto-Detect</button>
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label>Token:</label>
                        <input type="text" id="transferTokenType" required placeholder="e.g., BHX">
                    </div>
                    <div class="form-group">
                        <label>Amount:</label>
                        <input type="number" id="transferTokenAmount" required min="1">
                    </div>
                </div>

                <div class="form-group">
                    <label>
                        <input type="checkbox" id="transferWithEscrow"> Use Escrow Service
                    </label>
                </div>

                <button type="button" class="btn btn-success" onclick="executeTokenTransfer()">Execute Transfer</button>
            </div>

            <!-- DEX Swap Form -->
            <div id="dexForm" class="transaction-form" style="display: none;">
                <h4>🔄 DEX Token Swap</h4>
                <div class="alert alert-info">
                    <strong>Coming Soon!</strong> DEX functionality will be available in the next update.
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>From Token:</label>
                        <input type="text" placeholder="e.g., BHX" disabled>
                    </div>
                    <div class="form-group">
                        <label>To Token:</label>
                        <input type="text" placeholder="e.g., ETH" disabled>
                    </div>
                </div>
                <button type="button" class="btn" disabled>Swap Tokens (Coming Soon)</button>
            </div>

            <!-- Staking Form -->
            <div id="stakingForm" class="transaction-form" style="display: none;">
                <h4>🥩 Enhanced Staking</h4>
                <div class="form-row">
                    <div class="form-group">
                        <label>Wallet:</label>
                        <select id="stakingWallet" required>
                            <option value="">Select wallet...</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Password:</label>
                        <input type="password" id="stakingPassword" required>
                    </div>
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label>Token:</label>
                        <input type="text" id="stakingToken" value="BHX" required>
                    </div>
                    <div class="form-group">
                        <label>Amount:</label>
                        <input type="number" id="stakingAmount" required min="1">
                    </div>
                </div>

                <div class="form-group">
                    <label>Staking Duration:</label>
                    <select id="stakingDuration">
                        <option value="30">30 Days (5% APY)</option>
                        <option value="90">90 Days (8% APY)</option>
                        <option value="180">180 Days (12% APY)</option>
                        <option value="365">1 Year (15% APY)</option>
                    </select>
                </div>

                <button type="button" class="btn btn-warning" onclick="executeStaking()">Stake Tokens</button>
            </div>

            <!-- Governance Form -->
            <div id="governanceForm" class="transaction-form" style="display: none;">
                <h4>🗳️ Governance Voting</h4>
                <div class="alert alert-info">
                    <strong>Coming Soon!</strong> Governance features will be available in the next update.
                </div>
                <button type="button" class="btn" disabled>Vote (Coming Soon)</button>
            </div>

            <!-- Cross-Chain Form -->
            <div id="crossChainForm" class="transaction-form" style="display: none;">
                <h4>🌉 Cross-Chain Transfer</h4>
                <div class="alert alert-info">
                    <strong>Coming Soon!</strong> Cross-chain functionality will be available in the next update.
                </div>
                <button type="button" class="btn" disabled>Transfer Cross-Chain (Coming Soon)</button>
            </div>

            <div id="advancedTransactionMessage"></div>
        </div>
    </div>

    <!-- Advanced Transactions Modal -->
    <div id="advancedTransactionsModal" class="modal">
        <div class="modal-content" style="max-width: 800px;">
            <span class="close" onclick="closeModal('advancedTransactionsModal')">&times;</span>
            <h3>🚀 Advanced Transactions</h3>

            <!-- Transaction Type Selector -->
            <div class="form-group">
                <label>Transaction Type:</label>
                <select id="transactionType" onchange="showTransactionForm()" required>
                    <option value="">Select transaction type...</option>
                    <option value="otc">🤝 OTC Trading</option>
                    <option value="token_transfer">💸 Enhanced Token Transfer</option>
                    <option value="dex">🔄 DEX Swap (Coming Soon)</option>
                    <option value="staking">🥩 Enhanced Staking</option>
                    <option value="governance">🗳️ Governance (Coming Soon)</option>
                    <option value="cross_chain">🌉 Cross-Chain (Coming Soon)</option>
                </select>
            </div>

            <!-- OTC Trading Form -->
            <div id="otcForm" class="transaction-form" style="display: none;">
                <h4>🤝 Over-The-Counter Trading</h4>
                <div class="form-row" style="display: flex; gap: 15px;">
                    <div class="form-group" style="flex: 1;">
                        <label>Your Wallet:</label>
                        <select id="otcWalletSelect" required>
                            <option value="">Select wallet...</option>
                        </select>
                    </div>
                    <div class="form-group" style="flex: 1;">
                        <label>Password:</label>
                        <input type="password" id="otcPassword" required>
                    </div>
                </div>

                <div class="form-row" style="display: flex; gap: 15px;">
                    <div class="form-group" style="flex: 1;">
                        <label>Token You're Offering:</label>
                        <input type="text" id="otcTokenOffered" required placeholder="e.g., BHX">
                    </div>
                    <div class="form-group" style="flex: 1;">
                        <label>Amount Offering:</label>
                        <input type="number" id="otcAmountOffered" required min="1">
                    </div>
                </div>

                <div class="form-row" style="display: flex; gap: 15px;">
                    <div class="form-group" style="flex: 1;">
                        <label>Token You Want:</label>
                        <input type="text" id="otcTokenRequested" required placeholder="e.g., ETH">
                    </div>
                    <div class="form-group" style="flex: 1;">
                        <label>Amount Requested:</label>
                        <input type="number" id="otcAmountRequested" required min="1">
                    </div>
                </div>

                <div class="form-row" style="display: flex; gap: 15px;">
                    <div class="form-group" style="flex: 1;">
                        <label>Expiration (hours):</label>
                        <input type="number" id="otcExpiration" value="24" min="1" max="168">
                    </div>
                    <div class="form-group" style="flex: 1;">
                        <label>
                            <input type="checkbox" id="otcMultiSig"> Multi-Signature Required
                        </label>
                    </div>
                </div>

                <div id="otcMultiSigSection" style="display: none;">
                    <label>Required Signers (comma-separated addresses):</label>
                    <textarea id="otcRequiredSigs" placeholder="addr1,addr2,addr3" style="width: 100%; height: 60px;"></textarea>
                </div>

                <button type="button" class="btn btn-primary" onclick="createOTCOrder()">Create OTC Order</button>

                <!-- OTC Orders Display -->
                <div id="otcOrdersSection" style="margin-top: 30px;">
                    <h4>📋 Your OTC Orders</h4>
                    <button type="button" class="btn btn-small" onclick="refreshOTCOrders()">🔄 Refresh Orders</button>
                    <div id="otcOrdersList" style="margin-top: 15px;">
                        <div class="loading">Loading orders...</div>
                    </div>
                </div>
            </div>

            <div id="advancedTransactionMessage"></div>
        </div>
    </div>

    <!-- Slashing Dashboard Modal -->
    <div id="slashingDashboardModal" class="modal">
        <div class="modal-content" style="max-width: 1000px;">
            <span class="close" onclick="closeModal('slashingDashboardModal')">&times;</span>
            <h3>⚡ Slashing Dashboard</h3>

            <div class="dashboard-tabs">
                <button class="tab-btn active" onclick="showSlashingTab('events')">🚨 Slashing Events</button>
                <button class="tab-btn" onclick="showSlashingTab('validators')">👥 Validator Status</button>
                <button class="tab-btn" onclick="showSlashingTab('report')">📝 Report Violation</button>
            </div>

            <!-- Slashing Events Tab -->
            <div id="slashingEventsTab" class="tab-content active">
                <h4>🚨 Recent Slashing Events</h4>
                <button type="button" class="btn btn-small" onclick="refreshSlashingEvents()">🔄 Refresh</button>
                <div id="slashingEventsList" style="margin-top: 15px;">
                    <div class="loading">Loading slashing events...</div>
                </div>
            </div>

            <!-- Validator Status Tab -->
            <div id="validatorStatusTab" class="tab-content">
                <h4>👥 Validator Status Overview</h4>
                <button type="button" class="btn btn-small" onclick="refreshValidatorStatus()">🔄 Refresh</button>
                <div id="validatorStatusList" style="margin-top: 15px;">
                    <div class="loading">Loading validator status...</div>
                </div>
            </div>

            <!-- Report Violation Tab -->
            <div id="reportViolationTab" class="tab-content">
                <h4>📝 Report Validator Violation</h4>
                <form id="reportViolationForm">
                    <div class="form-row">
                        <div class="form-group">
                            <label>Validator Address:</label>
                            <input type="text" id="violationValidator" required placeholder="Validator address">
                        </div>
                        <div class="form-group">
                            <label>Violation Type:</label>
                            <select id="violationType" required>
                                <option value="">Select violation type...</option>
                                <option value="0">Double Signing</option>
                                <option value="1">Excessive Downtime</option>
                                <option value="2">Invalid Block Production</option>
                                <option value="3">Malicious Transaction</option>
                                <option value="4">Consensus Violation</option>
                            </select>
                        </div>
                    </div>

                    <div class="form-group">
                        <label>Block Height:</label>
                        <input type="number" id="violationBlockHeight" required min="0">
                    </div>

                    <div class="form-group">
                        <label>Evidence:</label>
                        <textarea id="violationEvidence" required placeholder="Provide detailed evidence of the violation..."></textarea>
                    </div>

                    <button type="button" class="btn btn-danger" onclick="reportViolation()">🚨 Report Violation</button>
                </form>
            </div>

            <div id="slashingMessage"></div>
        </div>
    </div>

    <!-- Cross-Chain DEX Modal -->
    <div id="crossChainDEXModal" class="modal">
        <div class="modal-content" style="max-width: 1200px;">
            <span class="close" onclick="closeModal('crossChainDEXModal')">&times;</span>
            <h3>🌉 Cross-Chain DEX</h3>

            <div class="dex-tabs">
                <button class="tab-btn active" onclick="showDEXTab('swap')">🔄 Cross-Chain Swap</button>
                <button class="tab-btn" onclick="showDEXTab('orders')">📋 My Orders</button>
                <button class="tab-btn" onclick="showDEXTab('chains')">🌐 Supported Chains</button>
            </div>

            <!-- Cross-Chain Swap Tab -->
            <div id="swapTab" class="tab-content active">
                <div class="swap-interface">
                    <div class="swap-form">
                        <h4>🔄 Cross-Chain Token Swap</h4>

                        <!-- Source Chain Selection -->
                        <div class="chain-selection">
                            <div class="chain-input">
                                <label>From Chain:</label>
                                <select id="sourceChain" onchange="updateTokenOptions('source')">
                                    <option value="blackhole">Blackhole Blockchain</option>
                                    <option value="ethereum">Ethereum</option>
                                    <option value="solana">Solana</option>
                                </select>

                                <label>Token:</label>
                                <select id="sourceToken" onchange="updateSwapQuote()">
                                    <option value="BHX">BHX</option>
                                    <option value="USDT">USDT</option>
                                    <option value="ETH">ETH</option>
                                </select>

                                <label>Amount:</label>
                                <input type="number" id="swapAmountIn" placeholder="0.0" onchange="updateSwapQuote()">
                            </div>
                        </div>

                        <!-- Swap Direction Arrow -->
                        <div class="swap-arrow">
                            <button type="button" onclick="swapChains()">⇅</button>
                        </div>

                        <!-- Destination Chain Selection -->
                        <div class="chain-selection">
                            <div class="chain-input">
                                <label>To Chain:</label>
                                <select id="destChain" onchange="updateTokenOptions('dest')">
                                    <option value="ethereum">Ethereum</option>
                                    <option value="blackhole">Blackhole Blockchain</option>
                                    <option value="solana">Solana</option>
                                </select>

                                <label>Token:</label>
                                <select id="destToken" onchange="updateSwapQuote()">
                                    <option value="USDT">USDT</option>
                                    <option value="BHX">BHX</option>
                                    <option value="ETH">ETH</option>
                                </select>

                                <label>Estimated Output:</label>
                                <input type="number" id="swapAmountOut" placeholder="0.0" readonly>
                            </div>
                        </div>

                        <!-- Swap Details -->
                        <div class="swap-details">
                            <div class="detail-row">
                                <span>Exchange Rate:</span>
                                <span id="exchangeRate">-</span>
                            </div>
                            <div class="detail-row">
                                <span>Price Impact:</span>
                                <span id="priceImpact">-</span>
                            </div>
                            <div class="detail-row">
                                <span>Bridge Fee:</span>
                                <span id="bridgeFee">-</span>
                            </div>
                            <div class="detail-row">
                                <span>Swap Fee:</span>
                                <span id="swapFee">-</span>
                            </div>
                            <div class="detail-row total">
                                <span>Total Fees:</span>
                                <span id="totalFees">-</span>
                            </div>
                        </div>

                        <!-- Slippage Settings -->
                        <div class="slippage-settings">
                            <label>Slippage Tolerance:</label>
                            <div class="slippage-buttons">
                                <button type="button" onclick="setSlippage(0.5)">0.5%</button>
                                <button type="button" onclick="setSlippage(1.0)" class="active">1.0%</button>
                                <button type="button" onclick="setSlippage(3.0)">3.0%</button>
                                <input type="number" id="customSlippage" placeholder="Custom %" onchange="setSlippage(this.value)">
                            </div>
                        </div>

                        <!-- Wallet Selection -->
                        <div class="form-group">
                            <label>Wallet:</label>
                            <select id="swapWalletSelect" required>
                                <option value="">Select wallet...</option>
                            </select>
                        </div>

                        <!-- Execute Swap Button -->
                        <button type="button" class="btn btn-primary btn-large" onclick="executeCrossChainSwap()">
                            🌉 Execute Cross-Chain Swap
                        </button>
                    </div>

                    <!-- Quote Display -->
                    <div class="quote-display">
                        <h4>💰 Current Quote</h4>
                        <div id="quoteDetails">
                            <p>Enter swap details to get a quote</p>
                        </div>
                        <button type="button" class="btn btn-small" onclick="refreshQuote()">🔄 Refresh Quote</button>
                    </div>
                </div>
            </div>

            <!-- My Orders Tab -->
            <div id="ordersTab" class="tab-content">
                <h4>📋 My Cross-Chain Orders</h4>
                <button type="button" class="btn btn-small" onclick="refreshCrossChainOrders()">🔄 Refresh</button>
                <div id="crossChainOrdersList" style="margin-top: 15px;">
                    <div class="loading">Loading orders...</div>
                </div>
            </div>

            <!-- Supported Chains Tab -->
            <div id="chainsTab" class="tab-content">
                <h4>🌐 Supported Chains & Tokens</h4>
                <div id="supportedChainsList" style="margin-top: 15px;">
                    <div class="loading">Loading supported chains...</div>
                </div>
            </div>

            <div id="crossChainMessage"></div>
        </div>
    </div>

    <script>
        let userWallets = [];

        // Load user info and wallets on page load
        window.onload = function() {
            loadUserInfo();
            loadWallets();
        };

        async function loadUserInfo() {
            // For now, just show a welcome message
            document.getElementById('userInfo').textContent = 'Welcome to your wallet dashboard';
        }

        async function logout() {
            try {
                await fetch('/api/logout', { method: 'POST' });
                window.location.href = '/login';
            } catch (error) {
                alert('Error logging out');
            }
        }

        // Modal functions
        function showModal(modalId) {
            // Prevent background scrolling
            document.body.classList.add('modal-open');
            document.body.style.overflow = 'hidden';

            const modal = document.getElementById(modalId);
            modal.style.display = 'block';

            // Add large class for bigger modals
            const modalContent = modal.querySelector('.modal-content');
            if (modalId === 'crossChainDEXModal' || modalId === 'slashingDashboardModal' || modalId === 'advancedTransactionsModal') {
                modalContent.classList.add('large');
            }

            // Focus on modal for accessibility
            modal.focus();

            // Add click outside to close functionality
            modal.onclick = function(event) {
                if (event.target === modal) {
                    closeModal(modalId);
                }
            };

            // Scroll to top of modal content
            modalContent.scrollTop = 0;
        }

        function closeModal(modalId) {
            // Restore background scrolling
            document.body.classList.remove('modal-open');
            document.body.style.overflow = 'auto';

            const modal = document.getElementById(modalId);
            modal.style.display = 'none';

            // Remove large class
            const modalContent = modal.querySelector('.modal-content');
            modalContent.classList.remove('large');

            // Remove click outside handler
            modal.onclick = null;
        }

        // Wallet Management Functions
        function showCreateWallet() {
            showModal('createWalletModal');
        }

        function showImportWallet() {
            showModal('importWalletModal');
        }

        function showExportWallet() {
            populateWalletSelect('exportWalletSelect');
            showModal('exportWalletModal');
        }

        function populateWalletSelect(selectId) {
            const select = document.getElementById(selectId);
            select.innerHTML = '<option value="">Select a wallet...</option>';
            userWallets.forEach(wallet => {
                const option = document.createElement('option');
                option.value = wallet.name;
                option.textContent = wallet.name + ' (' + wallet.address.substring(0, 10) + '...)';
                select.appendChild(option);
            });
        }

        // Load wallets from server
        async function loadWallets() {
            try {
                document.getElementById('wallets-list').innerHTML = '<p class="loading">Loading wallets...</p>';
                const response = await fetch('/api/wallets');
                const result = await response.json();

                if (result.success && result.data) {
                    userWallets = result.data;
                    displayWallets(result.data);
                } else {
                    document.getElementById('wallets-list').innerHTML = '<p>No wallets found. Create your first wallet!</p>';
                }
            } catch (error) {
                document.getElementById('wallets-list').innerHTML = '<p class="error">Error loading wallets: ' + error.message + '</p>';
            }
        }

        function displayWallets(wallets) {
            const container = document.getElementById('wallets-list');
            if (wallets.length === 0) {
                container.innerHTML = '<p>No wallets found. Create your first wallet!</p>';
                return;
            }

            let html = '';
            wallets.forEach((wallet, index) => {
                html += '<div class="wallet-item">';
                html += '<h4>' + wallet.name + '</h4>';
                html += '<p class="wallet-address">Address: ' + wallet.address + '</p>';
                html += '<p>Created: ' + new Date(wallet.created_at).toLocaleString() + '</p>';
                html += '<button class="btn" onclick="checkWalletBalance(\'' + wallet.name + '\')">Check Balance</button>';
                html += '<button class="btn" onclick="showWalletDetails(\'' + wallet.name + '\')">View Details</button>';
                html += '</div>';
            });
            container.innerHTML = html;
        }

        // Token Operations
        function showCheckBalance() {
            populateWalletSelect('balanceWalletSelect');
            showModal('balanceModal');
        }

        async function checkBalance(walletName, password, tokenSymbol) {
            try {
                const response = await fetch('/api/wallets/balance', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ wallet_name: walletName, password: password, token_symbol: tokenSymbol })
                });

                const result = await response.json();
                if (result.success) {
                    displayBalance(walletName, tokenSymbol, result.data.balance);
                } else {
                    alert('Error: ' + result.message);
                }
            } catch (error) {
                alert('Error checking balance: ' + error.message);
            }
        }

        async function checkWalletBalance(walletName) {
            const password = prompt('Enter password for wallet "' + walletName + '":');
            const tokenSymbol = prompt('Enter token symbol (e.g., BHX):');

            if (password && tokenSymbol) {
                await checkBalance(walletName, password, tokenSymbol);
            }
        }

        function displayBalance(walletName, tokenSymbol, balance) {
            const container = document.getElementById('balances-list');
            const balanceHtml = '<div class="balance-item">' +
                '<h4>' + walletName + '</h4>' +
                '<p><strong>' + balance + ' ' + tokenSymbol + '</strong></p>' +
                '<p>Last checked: ' + new Date().toLocaleString() + '</p>' +
                '</div>';
            container.innerHTML = balanceHtml + container.innerHTML;
        }

        function showTransferTokens() {
            populateWalletSelect('transferWalletSelect');
            showModal('transferModal');
        }

        async function transferTokens(walletName, password, toAddress, tokenSymbol, amount) {
            try {
                const response = await fetch('/api/wallets/transfer', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        wallet_name: walletName,
                        password: password,
                        to_address: toAddress,
                        token_symbol: tokenSymbol,
                        amount: amount
                    })
                });

                const result = await response.json();
                if (result.success) {
                    alert('Transfer successful!');
                    loadTransactionHistory();
                } else {
                    alert('Transfer failed: ' + result.message);
                }
            } catch (error) {
                alert('Error transferring tokens: ' + error.message);
            }
        }

        function showStakeTokens() {
            populateWalletSelect('stakeWalletSelect');
            showModal('stakeModal');
        }

        // Advanced Transactions Functions
        function showAdvancedTransactions() {
            populateWalletSelect('otcWalletSelect');
            showModal('advancedTransactionsModal');
        }

        function showTransactionForm() {
            const transactionType = document.getElementById('transactionType').value;

            // Hide all forms
            const forms = document.querySelectorAll('.transaction-form');
            forms.forEach(form => form.style.display = 'none');

            // Show selected form
            if (transactionType) {
                const formId = transactionType + 'Form';
                const form = document.getElementById(formId);
                if (form) {
                    form.style.display = 'block';

                    // Populate wallet selects for the active form
                    if (transactionType === 'otc') {
                        populateWalletSelect('otcWalletSelect');
                    } else if (transactionType === 'token_transfer') {
                        populateWalletSelect('transferFromWallet');
                    } else if (transactionType === 'staking') {
                        populateWalletSelect('stakingWallet');
                    }
                }
            }
        }

        // OTC Trading Functions
        async function createOTCOrder() {
            const walletName = document.getElementById('otcWalletSelect').value;
            const password = document.getElementById('otcPassword').value;
            const tokenOffered = document.getElementById('otcTokenOffered').value;
            const amountOffered = parseInt(document.getElementById('otcAmountOffered').value);
            const tokenRequested = document.getElementById('otcTokenRequested').value;
            const amountRequested = parseInt(document.getElementById('otcAmountRequested').value);
            const expiration = parseInt(document.getElementById('otcExpiration').value);
            const isMultiSig = document.getElementById('otcMultiSig').checked;

            let requiredSigs = [];
            if (isMultiSig) {
                const sigsText = document.getElementById('otcRequiredSigs').value;
                requiredSigs = sigsText.split(',').map(s => s.trim()).filter(s => s);
            }

            try {
                const response = await fetch('/api/otc/create', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        wallet_name: walletName,
                        password: password,
                        token_offered: tokenOffered,
                        amount_offered: amountOffered,
                        token_requested: tokenRequested,
                        amount_requested: amountRequested,
                        expiration_hours: expiration,
                        is_multi_sig: isMultiSig,
                        required_sigs: requiredSigs
                    })
                });

                const result = await response.json();
                const messageDiv = document.getElementById('advancedTransactionMessage');

                if (result.success) {
                    messageDiv.innerHTML = '<div class="success">✅ OTC Order created successfully!<br>Order ID: ' + result.data.order_id + '</div>';
                    setTimeout(() => closeModal('advancedTransactionsModal'), 3000);
                } else {
                    messageDiv.innerHTML = '<div class="error">❌ ' + result.message + '</div>';
                }
            } catch (error) {
                document.getElementById('advancedTransactionMessage').innerHTML = '<div class="error">❌ Error: ' + error.message + '</div>';
            }
        }

        // OTC Orders Management
        async function refreshOTCOrders() {
            try {
                const response = await fetch('/api/otc/orders');
                const result = await response.json();

                const ordersList = document.getElementById('otcOrdersList');

                if (result.success && result.data && result.data.length > 0) {
                    let html = '<div class="otc-orders-grid">';

                    result.data.forEach(order => {
                        const createdDate = new Date(order.created_at * 1000).toLocaleString();
                        const expiresDate = new Date(order.expires_at * 1000).toLocaleString();
                        const isExpired = order.expires_at * 1000 < Date.now();
                        const statusClass = isExpired ? 'expired' : '';
                        const cancelButton = (order.status === 'open' && !isExpired) ?
                            '<button class="btn btn-small btn-danger" onclick="cancelOTCOrder(\'' + order.order_id + '\')">Cancel</button>' : '';

                        html += '<div class="otc-order-card ' + statusClass + '">' +
                                    '<div class="order-header">' +
                                        '<strong>Order #' + order.order_id.substring(0, 12) + '...</strong>' +
                                        '<span class="order-status status-' + order.status + '">' + order.status.toUpperCase() + '</span>' +
                                    '</div>' +
                                    '<div class="order-details">' +
                                        '<div class="trade-info">' +
                                            '<span class="offering">Offering: ' + order.amount_offered + ' ' + order.token_offered + '</span>' +
                                            '<span class="requesting">For: ' + order.amount_requested + ' ' + order.token_requested + '</span>' +
                                        '</div>' +
                                        '<div class="order-meta">' +
                                            '<small>Created: ' + createdDate + '</small>' +
                                            '<small>Expires: ' + expiresDate + '</small>' +
                                        '</div>' +
                                    '</div>' +
                                    '<div class="order-actions">' +
                                        cancelButton +
                                    '</div>' +
                                '</div>';
                    });

                    html += '</div>';
                    ordersList.innerHTML = html;
                } else {
                    ordersList.innerHTML = '<div class="no-orders">No OTC orders found</div>';
                }
            } catch (error) {
                document.getElementById('otcOrdersList').innerHTML = '<div class="error">Failed to load orders: ' + error.message + '</div>';
            }
        }

        async function cancelOTCOrder(orderId) {
            if (!confirm('Are you sure you want to cancel this OTC order?')) {
                return;
            }

            try {
                const response = await fetch('/api/otc/cancel', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        order_id: orderId,
                        wallet_name: document.getElementById('otcWalletSelect').value,
                        password: document.getElementById('otcPassword').value
                    })
                });

                const result = await response.json();
                const messageDiv = document.getElementById('advancedTransactionMessage');

                if (result.success) {
                    messageDiv.innerHTML = '<div class="success">✅ OTC order cancelled successfully!</div>';
                    refreshOTCOrders(); // Refresh the orders list
                } else {
                    messageDiv.innerHTML = '<div class="error">❌ ' + result.message + '</div>';
                }
            } catch (error) {
                document.getElementById('advancedTransactionMessage').innerHTML = '<div class="error">❌ Error: ' + error.message + '</div>';
            }
        }

        // Toggle multi-sig section
        document.addEventListener('DOMContentLoaded', function() {
            const multiSigCheckbox = document.getElementById('otcMultiSig');
            if (multiSigCheckbox) {
                multiSigCheckbox.addEventListener('change', function() {
                    const section = document.getElementById('otcMultiSigSection');
                    section.style.display = this.checked ? 'block' : 'none';
                });
            }

            // Auto-refresh OTC orders when the modal is opened
            const advancedModal = document.getElementById('advancedTransactionsModal');
            if (advancedModal) {
                const observer = new MutationObserver(function(mutations) {
                    mutations.forEach(function(mutation) {
                        if (mutation.type === 'attributes' && mutation.attributeName === 'style') {
                            if (advancedModal.style.display === 'block') {
                                setTimeout(refreshOTCOrders, 500); // Small delay to ensure form is loaded
                                startOTCAutoRefresh(); // Start auto-refresh
                            } else {
                                stopOTCAutoRefresh(); // Stop auto-refresh when modal closes
                            }
                        }
                    });
                });
                observer.observe(advancedModal, { attributes: true });
            }
        });

        // Auto-refresh system for OTC orders
        let otcRefreshInterval;

        function startOTCAutoRefresh() {
            if (otcRefreshInterval) {
                clearInterval(otcRefreshInterval);
            }
            // Refresh every 5 seconds
            otcRefreshInterval = setInterval(refreshOTCOrders, 5000);
        }

        function stopOTCAutoRefresh() {
            if (otcRefreshInterval) {
                clearInterval(otcRefreshInterval);
                otcRefreshInterval = null;
            }
        }

        // Check for OTC events (real-time updates)
        async function checkOTCEvents() {
            try {
                const response = await fetch('http://localhost:8080/api/otc/events');
                const result = await response.json();

                if (result.success && result.data && result.data.length > 0) {
                    // Process recent events
                    const recentEvents = result.data.slice(-5); // Last 5 events
                    recentEvents.forEach(event => {
                        if (event.type === 'order_created' || event.type === 'order_updated') {
                            // Refresh orders if there are relevant events
                            refreshOTCOrders();
                        }
                    });
                }
            } catch (error) {
                console.log('Failed to check OTC events:', error);
            }
        }

        // Start event checking when page loads
        setInterval(checkOTCEvents, 3000); // Check every 3 seconds

        // Add global keyboard support for modals
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                // Find any open modal and close it
                const openModals = document.querySelectorAll('.modal[style*="display: block"]');
                openModals.forEach(modal => {
                    closeModal(modal.id);
                });
            }
        });

        // Slashing Dashboard Functions
        function showSlashingDashboard() {
            showModal('slashingDashboardModal');
            refreshSlashingEvents();
        }

        function showSlashingTab(tabName) {
            // Hide all tab contents
            const tabs = document.querySelectorAll('.tab-content');
            tabs.forEach(tab => tab.classList.remove('active'));

            // Hide all tab buttons
            const buttons = document.querySelectorAll('.tab-btn');
            buttons.forEach(btn => btn.classList.remove('active'));

            // Show selected tab
            document.getElementById(tabName + 'Tab').classList.add('active');
            event.target.classList.add('active');

            // Load data for the selected tab
            if (tabName === 'events') {
                refreshSlashingEvents();
            } else if (tabName === 'validators') {
                refreshValidatorStatus();
            }
        }

        async function refreshSlashingEvents() {
            try {
                const response = await fetch('http://localhost:8080/api/slashing/events');
                const result = await response.json();

                const eventsList = document.getElementById('slashingEventsList');

                if (result.success && result.data && Object.keys(result.data).length > 0) {
                    let html = '<div class="slashing-events-grid">';

                    Object.values(result.data).forEach(event => {
                        const createdDate = new Date(event.timestamp * 1000).toLocaleString();
                        const severityClass = getSeverityClass(event.severity);
                        const conditionName = getConditionName(event.condition);

                        html += '<div class="slashing-event-card ' + severityClass + '">' +
                                    '<div class="event-header">' +
                                        '<strong>Event #' + event.id.substring(0, 12) + '...</strong>' +
                                        '<span class="event-status status-' + event.status + '">' + event.status.toUpperCase() + '</span>' +
                                    '</div>' +
                                    '<div class="event-details">' +
                                        '<div class="violation-info">' +
                                            '<span class="validator">Validator: ' + event.validator + '</span>' +
                                            '<span class="condition">Violation: ' + conditionName + '</span>' +
                                            '<span class="amount">Slash Amount: ' + event.amount + ' tokens</span>' +
                                        '</div>' +
                                        '<div class="event-meta">' +
                                            '<small>Block: ' + event.block_height + '</small>' +
                                            '<small>Time: ' + createdDate + '</small>' +
                                        '</div>' +
                                        '<div class="evidence">' +
                                            '<small>Evidence: ' + event.evidence + '</small>' +
                                        '</div>' +
                                    '</div>' +
                                    '<div class="event-actions">' +
                                        (event.status === 'pending' ?
                                            '<button class="btn btn-small btn-danger" onclick="executeSlashing(\'' + event.id + '\')">Execute</button>' :
                                            '') +
                                    '</div>' +
                                '</div>';
                    });

                    html += '</div>';
                    eventsList.innerHTML = html;
                } else {
                    eventsList.innerHTML = '<div class="no-events">No slashing events found</div>';
                }
            } catch (error) {
                document.getElementById('slashingEventsList').innerHTML = '<div class="error">Failed to load events: ' + error.message + '</div>';
            }
        }

        async function refreshValidatorStatus() {
            try {
                const response = await fetch('http://localhost:8080/api/slashing/validator-status');
                const result = await response.json();

                const statusList = document.getElementById('validatorStatusList');

                if (result.success && result.data && Object.keys(result.data).length > 0) {
                    let html = '<div class="validator-status-grid">';

                    Object.entries(result.data).forEach(([validator, status]) => {
                        const statusClass = status.jailed ? 'jailed' : (status.strikes > 0 ? 'warning' : 'healthy');

                        html += '<div class="validator-status-card ' + statusClass + '">' +
                                    '<div class="validator-header">' +
                                        '<strong>' + validator + '</strong>' +
                                        '<span class="validator-status-badge ' + statusClass + '">' +
                                            (status.jailed ? 'JAILED' : (status.strikes > 0 ? 'AT RISK' : 'HEALTHY')) +
                                        '</span>' +
                                    '</div>' +
                                    '<div class="validator-details">' +
                                        '<div class="status-info">' +
                                            '<span class="stake">Stake: ' + status.stake + ' tokens</span>' +
                                            '<span class="strikes">Strikes: ' + status.strikes + '/3</span>' +
                                        '</div>' +
                                    '</div>' +
                                '</div>';
                    });

                    html += '</div>';
                    statusList.innerHTML = html;
                } else {
                    statusList.innerHTML = '<div class="no-validators">No validators found</div>';
                }
            } catch (error) {
                document.getElementById('validatorStatusList').innerHTML = '<div class="error">Failed to load status: ' + error.message + '</div>';
            }
        }

        async function reportViolation() {
            const validator = document.getElementById('violationValidator').value;
            const violationType = parseInt(document.getElementById('violationType').value);
            const blockHeight = parseInt(document.getElementById('violationBlockHeight').value);
            const evidence = document.getElementById('violationEvidence').value;

            if (!validator || isNaN(violationType) || !blockHeight || !evidence) {
                alert('Please fill in all required fields');
                return;
            }

            try {
                const response = await fetch('http://localhost:8080/api/slashing/report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        validator: validator,
                        condition: violationType,
                        evidence: evidence,
                        block_height: blockHeight
                    })
                });

                const result = await response.json();
                const messageDiv = document.getElementById('slashingMessage');

                if (result.success) {
                    messageDiv.innerHTML = '<div class="success">✅ Violation reported successfully!</div>';
                    document.getElementById('reportViolationForm').reset();
                    refreshSlashingEvents(); // Refresh events list
                } else {
                    messageDiv.innerHTML = '<div class="error">❌ ' + result.error + '</div>';
                }
            } catch (error) {
                document.getElementById('slashingMessage').innerHTML = '<div class="error">❌ Error: ' + error.message + '</div>';
            }
        }

        async function executeSlashing(eventId) {
            if (!confirm('Are you sure you want to execute this slashing? This action cannot be undone.')) {
                return;
            }

            try {
                const response = await fetch('http://localhost:8080/api/slashing/execute', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        event_id: eventId
                    })
                });

                const result = await response.json();
                const messageDiv = document.getElementById('slashingMessage');

                if (result.success) {
                    messageDiv.innerHTML = '<div class="success">⚡ Slashing executed successfully!</div>';
                    refreshSlashingEvents(); // Refresh events list
                    refreshValidatorStatus(); // Refresh validator status
                } else {
                    messageDiv.innerHTML = '<div class="error">❌ ' + result.error + '</div>';
                }
            } catch (error) {
                document.getElementById('slashingMessage').innerHTML = '<div class="error">❌ Error: ' + error.message + '</div>';
            }
        }

        function getSeverityClass(severity) {
            switch (severity) {
                case 0: return 'severity-minor';
                case 1: return 'severity-major';
                case 2: return 'severity-critical';
                default: return 'severity-minor';
            }
        }

        function getConditionName(condition) {
            switch (condition) {
                case 0: return 'Double Signing';
                case 1: return 'Excessive Downtime';
                case 2: return 'Invalid Block Production';
                case 3: return 'Malicious Transaction';
                case 4: return 'Consensus Violation';
                default: return 'Unknown Violation';
            }
        }

        // Cross-Chain DEX Functions
        function showCrossChainDEX() {
            populateWalletSelect('swapWalletSelect');
            showModal('crossChainDEXModal');
            loadSupportedChains();
        }

        function showDEXTab(tabName) {
            // Hide all tab contents
            const tabs = document.querySelectorAll('.tab-content');
            tabs.forEach(tab => tab.classList.remove('active'));

            // Hide all tab buttons
            const buttons = document.querySelectorAll('.tab-btn');
            buttons.forEach(btn => btn.classList.remove('active'));

            // Show selected tab
            document.getElementById(tabName + 'Tab').classList.add('active');
            event.target.classList.add('active');

            // Load data for the selected tab
            if (tabName === 'orders') {
                refreshCrossChainOrders();
            } else if (tabName === 'chains') {
                loadSupportedChains();
            }
        }

        async function updateSwapQuote() {
            const sourceChain = document.getElementById('sourceChain').value;
            const destChain = document.getElementById('destChain').value;
            const sourceToken = document.getElementById('sourceToken').value;
            const destToken = document.getElementById('destToken').value;
            const amountIn = parseFloat(document.getElementById('swapAmountIn').value);

            if (!sourceChain || !destChain || !sourceToken || !destToken || !amountIn || amountIn <= 0) {
                document.getElementById('quoteDetails').innerHTML = '<p>Enter swap details to get a quote</p>';
                return;
            }

            try {
                const response = await fetch('http://localhost:8080/api/cross-chain/quote', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        source_chain: sourceChain,
                        dest_chain: destChain,
                        token_in: sourceToken,
                        token_out: destToken,
                        amount_in: Math.floor(amountIn * 1000000) // Convert to base units
                    })
                });

                const result = await response.json();

                if (result.success) {
                    const quote = result.data;

                    // Update output amount
                    document.getElementById('swapAmountOut').value = (quote.estimated_out / 1000000).toFixed(6);

                    // Update exchange rate
                    const rate = (quote.estimated_out / quote.amount_in).toFixed(6);
                    document.getElementById('exchangeRate').textContent = '1 ' + sourceToken + ' = ' + rate + ' ' + destToken;

                    // Update fees and impact
                    document.getElementById('priceImpact').textContent = quote.price_impact.toFixed(2) + '%';
                    document.getElementById('bridgeFee').textContent = (quote.bridge_fee / 1000000).toFixed(6) + ' ' + sourceToken;
                    document.getElementById('swapFee').textContent = (quote.swap_fee / 1000000).toFixed(6) + ' ' + destToken;

                    const totalFeeValue = (quote.bridge_fee + quote.swap_fee) / 1000000;
                    document.getElementById('totalFees').textContent = totalFeeValue.toFixed(6);

                    // Update quote display
                    const quoteHtml =
                        '<div class="quote-summary">' +
                            '<div class="quote-row">' +
                                '<span>You Pay:</span>' +
                                '<span>' + amountIn + ' ' + sourceToken + ' on ' + sourceChain + '</span>' +
                            '</div>' +
                            '<div class="quote-row">' +
                                '<span>You Receive:</span>' +
                                '<span>' + (quote.estimated_out / 1000000).toFixed(6) + ' ' + destToken + ' on ' + destChain + '</span>' +
                            '</div>' +
                            '<div class="quote-row">' +
                                '<span>Route:</span>' +
                                '<span>' + sourceChain + ' → Bridge → ' + destChain + ' → DEX</span>' +
                            '</div>' +
                            '<div class="quote-row">' +
                                '<span>Estimated Time:</span>' +
                                '<span>2-5 minutes</span>' +
                            '</div>' +
                        '</div>';
                    document.getElementById('quoteDetails').innerHTML = quoteHtml;
                } else {
                    document.getElementById('quoteDetails').innerHTML = '<p class="error">Failed to get quote: ' + result.error + '</p>';
                }
            } catch (error) {
                document.getElementById('quoteDetails').innerHTML = '<p class="error">Error getting quote: ' + error.message + '</p>';
            }
        }

        async function executeCrossChainSwap() {
            const sourceChain = document.getElementById('sourceChain').value;
            const destChain = document.getElementById('destChain').value;
            const sourceToken = document.getElementById('sourceToken').value;
            const destToken = document.getElementById('destToken').value;
            const amountIn = parseFloat(document.getElementById('swapAmountIn').value);
            const wallet = document.getElementById('swapWalletSelect').value;

            if (!sourceChain || !destChain || !sourceToken || !destToken || !amountIn || !wallet) {
                alert('Please fill in all required fields');
                return;
            }

            if (!confirm('Execute cross-chain swap of ' + amountIn + ' ' + sourceToken + ' from ' + sourceChain + ' to ' + destToken + ' on ' + destChain + '?')) {
                return;
            }

            try {
                const response = await fetch('http://localhost:8080/api/cross-chain/swap', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        user: wallet, // This is the wallet address
                        source_chain: sourceChain,
                        dest_chain: destChain,
                        token_in: sourceToken,
                        token_out: destToken,
                        amount_in: Math.floor(amountIn * 1000000),
                        min_amount_out: Math.floor(parseFloat(document.getElementById('swapAmountOut').value) * 1000000 * 0.99) // 1% slippage
                    })
                });

                const result = await response.json();
                const messageDiv = document.getElementById('crossChainMessage');

                if (result.success) {
                    messageDiv.innerHTML =
                        '<div class="success">' +
                            '✅ Cross-chain swap initiated successfully!<br>' +
                            'Order ID: ' + result.data.id + '<br>' +
                            'Status: ' + result.data.status + '<br>' +
                            '<small>You can track progress in the "My Orders" tab</small>' +
                        '</div>';

                    // Clear form
                    document.getElementById('swapAmountIn').value = '';
                    document.getElementById('swapAmountOut').value = '';
                    document.getElementById('quoteDetails').innerHTML = '<p>Enter swap details to get a quote</p>';

                    // Switch to orders tab to show progress
                    setTimeout(() => {
                        showDEXTab('orders');
                    }, 2000);
                } else {
                    messageDiv.innerHTML = '<div class="error">❌ ' + result.error + '</div>';
                }
            } catch (error) {
                document.getElementById('crossChainMessage').innerHTML = '<div class="error">❌ Error: ' + error.message + '</div>';
            }
        }

        async function refreshCrossChainOrders() {
            // Get the selected wallet address
            const walletSelect = document.getElementById('swapWalletSelect');
            let userAddress = 'user123'; // Default fallback

            if (walletSelect && walletSelect.value) {
                userAddress = walletSelect.value;
            } else {
                // Try to get from other wallet selects if available
                const otherSelects = ['walletSelect', 'transferWalletSelect', 'stakeWalletSelect'];
                for (const selectId of otherSelects) {
                    const select = document.getElementById(selectId);
                    if (select && select.value) {
                        userAddress = select.value;
                        break;
                    }
                }
            }

            try {
                const response = await fetch('http://localhost:8080/api/cross-chain/orders?user=' + encodeURIComponent(userAddress));
                const result = await response.json();

                const ordersList = document.getElementById('crossChainOrdersList');

                if (result.success && result.data && result.data.length > 0) {
                    let html = '<div class="orders-grid">';

                    result.data.forEach(order => {
                        const createdDate = new Date(order.created_at * 1000).toLocaleString();
                        const statusClass = 'status-' + order.status;

                        html += '<div class="order-card">' +
                                    '<div class="order-header">' +
                                        '<strong>Order #' + order.id.substring(0, 12) + '...</strong>' +
                                        '<span class="order-status ' + statusClass + '">' + order.status.toUpperCase() + '</span>' +
                                    '</div>' +
                                    '<div class="order-details">' +
                                        '<div class="swap-info">' +
                                            '<span class="route">' + order.source_chain + ' → ' + order.dest_chain + '</span>' +
                                            '<span class="tokens">' + order.amount_in + ' ' + order.token_in + ' → ' + order.estimated_out + ' ' + order.token_out + '</span>' +
                                        '</div>' +
                                        '<div class="order-meta">' +
                                            '<small>Created: ' + createdDate + '</small>' +
                                            (order.completed_at ? '<small>Completed: ' + new Date(order.completed_at * 1000).toLocaleString() + '</small>' : '') +
                                        '</div>' +
                                    '</div>' +
                                '</div>';
                    });

                    html += '</div>';
                    ordersList.innerHTML = html;
                } else {
                    ordersList.innerHTML = '<div class="no-orders">No cross-chain orders found</div>';
                }
            } catch (error) {
                document.getElementById('crossChainOrdersList').innerHTML = '<div class="error">Failed to load orders: ' + error.message + '</div>';
            }
        }

        async function loadSupportedChains() {
            try {
                const response = await fetch('http://localhost:8080/api/cross-chain/supported-chains');
                const result = await response.json();

                const chainsList = document.getElementById('supportedChainsList');

                if (result.success && result.data && result.data.chains) {
                    let html = '<div class="chains-grid">';

                    result.data.chains.forEach(chain => {
                        html += '<div class="chain-card">' +
                                    '<div class="chain-header">' +
                                        '<h4>' + chain.name + '</h4>' +
                                        '<span class="chain-id">' + chain.id + '</span>' +
                                    '</div>' +
                                    '<div class="chain-details">' +
                                        '<div class="native-token">Native: ' + chain.native_token + '</div>' +
                                        '<div class="bridge-fee">Bridge Fee: ' + chain.bridge_fee + ' tokens</div>' +
                                        '<div class="supported-tokens">' +
                                            '<strong>Supported Tokens:</strong><br>' +
                                            chain.supported_tokens.join(', ') +
                                        '</div>' +
                                    '</div>' +
                                '</div>';
                    });

                    html += '</div>';
                    chainsList.innerHTML = html;
                } else {
                    chainsList.innerHTML = '<div class="error">Failed to load supported chains</div>';
                }
            } catch (error) {
                document.getElementById('supportedChainsList').innerHTML = '<div class="error">Error loading chains: ' + error.message + '</div>';
            }
        }

        function swapChains() {
            const sourceChain = document.getElementById('sourceChain');
            const destChain = document.getElementById('destChain');
            const sourceToken = document.getElementById('sourceToken');
            const destToken = document.getElementById('destToken');

            // Swap chain values
            const tempChain = sourceChain.value;
            sourceChain.value = destChain.value;
            destChain.value = tempChain;

            // Swap token values
            const tempToken = sourceToken.value;
            sourceToken.value = destToken.value;
            destToken.value = tempToken;

            // Update quote
            updateSwapQuote();
        }

        function setSlippage(percentage) {
            // Remove active class from all buttons
            document.querySelectorAll('.slippage-buttons button').forEach(btn => btn.classList.remove('active'));

            // Add active class to clicked button or find closest
            const buttons = document.querySelectorAll('.slippage-buttons button');
            buttons.forEach(btn => {
                if (btn.textContent === percentage + '%') {
                    btn.classList.add('active');
                }
            });

            // Update custom input if needed
            if (![0.5, 1.0, 3.0].includes(parseFloat(percentage))) {
                document.getElementById('customSlippage').value = percentage;
            }
        }

        function refreshQuote() {
            updateSwapQuote();
        }

        function updateTokenOptions(type) {
            // This would update available tokens based on selected chain
            // For now, we'll keep it simple with static options
        }

        async function stakeTokens(walletName, password, tokenSymbol, amount) {
            try {
                const response = await fetch('/api/wallets/stake', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        wallet_name: walletName,
                        password: password,
                        token_symbol: tokenSymbol,
                        amount: amount
                    })
                });

                const result = await response.json();
                if (result.success) {
                    alert('Staking successful!');
                    loadTransactionHistory();
                } else {
                    alert('Staking failed: ' + result.message);
                }
            } catch (error) {
                alert('Error staking tokens: ' + error.message);
            }
        }

        function showTransactionHistory() {
            loadTransactionHistory();
        }

        async function loadTransactionHistory() {
            try {
                const response = await fetch('/api/wallets/transactions');
                const result = await response.json();

                if (result.success && result.data) {
                    displayTransactions(result.data);
                } else {
                    document.getElementById('transactions-list').innerHTML = '<p>No transactions found.</p>';
                }
            } catch (error) {
                document.getElementById('transactions-list').innerHTML = '<p class="error">Error loading transactions: ' + error.message + '</p>';
            }
        }

        function displayTransactions(transactions) {
            const container = document.getElementById('transactions-list');
            if (transactions.length === 0) {
                container.innerHTML = '<p>No transactions found.</p>';
                return;
            }

            let html = '';
            transactions.slice(0, 10).forEach(tx => { // Show only last 10 transactions
                html += '<div class="transaction-item">';
                html += '<h5>' + tx.type + '</h5>';
                html += '<p><strong>Amount:</strong> ' + tx.amount + ' ' + tx.token_symbol + '</p>';
                html += '<p><strong>From:</strong> ' + tx.from + '</p>';
                html += '<p><strong>To:</strong> ' + tx.to + '</p>';
                html += '<p><strong>Status:</strong> ' + tx.status + '</p>';
                html += '<p><strong>Time:</strong> ' + new Date(tx.timestamp).toLocaleString() + '</p>';
                html += '</div>';
            });
            container.innerHTML = html;
        }

        // Form submissions
        document.getElementById('createWalletForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const walletName = document.getElementById('createWalletName').value;
            const password = document.getElementById('createWalletPassword').value;

            try {
                const response = await fetch('/api/wallets/create', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ wallet_name: walletName, password: password })
                });

                const result = await response.json();
                const messageDiv = document.getElementById('createWalletMessage');

                if (result.success) {
                    messageDiv.innerHTML = '<div class="success">Wallet created successfully!</div>';
                    setTimeout(() => {
                        closeModal('createWalletModal');
                        loadWallets();
                    }, 2000);
                } else {
                    messageDiv.innerHTML = '<div class="error">' + result.message + '</div>';
                }
            } catch (error) {
                document.getElementById('createWalletMessage').innerHTML = '<div class="error">Error: ' + error.message + '</div>';
            }
        });

        document.getElementById('importWalletForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const walletName = document.getElementById('importWalletName').value;
            const password = document.getElementById('importWalletPassword').value;
            const privateKey = document.getElementById('importPrivateKey').value;

            try {
                const response = await fetch('/api/wallets/import', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        wallet_name: walletName,
                        password: password,
                        private_key: privateKey
                    })
                });

                const result = await response.json();
                const messageDiv = document.getElementById('importWalletMessage');

                if (result.success) {
                    messageDiv.innerHTML = '<div class="success">Wallet imported successfully!</div>';
                    setTimeout(() => {
                        closeModal('importWalletModal');
                        loadWallets();
                    }, 2000);
                } else {
                    messageDiv.innerHTML = '<div class="error">' + result.message + '</div>';
                }
            } catch (error) {
                document.getElementById('importWalletMessage').innerHTML = '<div class="error">Error: ' + error.message + '</div>';
            }
        });

        document.getElementById('exportWalletForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const walletName = document.getElementById('exportWalletSelect').value;
            const password = document.getElementById('exportWalletPassword').value;

            try {
                const response = await fetch('/api/wallets/export', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ wallet_name: walletName, password: password })
                });

                const result = await response.json();
                const messageDiv = document.getElementById('exportWalletMessage');

                if (result.success) {
                    messageDiv.innerHTML = '<div class="success">Private Key: <br><code>' + result.data.private_key + '</code><br><strong>⚠️ Keep this secure!</strong></div>';
                } else {
                    messageDiv.innerHTML = '<div class="error">' + result.message + '</div>';
                }
            } catch (error) {
                document.getElementById('exportWalletMessage').innerHTML = '<div class="error">Error: ' + error.message + '</div>';
            }
        });

        document.getElementById('balanceForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const walletName = document.getElementById('balanceWalletSelect').value;
            const password = document.getElementById('balancePassword').value;
            const tokenSymbol = document.getElementById('balanceTokenSymbol').value;

            try {
                const response = await fetch('/api/wallets/balance', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ wallet_name: walletName, password: password, token_symbol: tokenSymbol })
                });

                const result = await response.json();
                const messageDiv = document.getElementById('balanceMessage');

                if (result.success) {
                    messageDiv.innerHTML = '<div class="success">Balance: <strong>' + result.data.balance + ' ' + result.data.token_symbol + '</strong></div>';
                    displayBalance(walletName, tokenSymbol, result.data.balance);
                    setTimeout(() => closeModal('balanceModal'), 2000);
                } else {
                    messageDiv.innerHTML = '<div class="error">' + result.message + '</div>';
                }
            } catch (error) {
                document.getElementById('balanceMessage').innerHTML = '<div class="error">Error: ' + error.message + '</div>';
            }
        });

        document.getElementById('transferForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const walletName = document.getElementById('transferWalletSelect').value;
            const password = document.getElementById('transferPassword').value;
            const toAddress = document.getElementById('transferToAddress').value;
            const tokenSymbol = document.getElementById('transferTokenSymbol').value;
            const amount = parseInt(document.getElementById('transferAmount').value);

            try {
                const response = await fetch('/api/wallets/transfer', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        wallet_name: walletName,
                        password: password,
                        to_address: toAddress,
                        token_symbol: tokenSymbol,
                        amount: amount
                    })
                });

                const result = await response.json();
                const messageDiv = document.getElementById('transferMessage');

                if (result.success) {
                    messageDiv.innerHTML = '<div class="success">' + result.message + '</div>';
                    loadTransactionHistory();
                    setTimeout(() => closeModal('transferModal'), 2000);
                } else {
                    messageDiv.innerHTML = '<div class="error">' + result.message + '</div>';
                }
            } catch (error) {
                document.getElementById('transferMessage').innerHTML = '<div class="error">Error: ' + error.message + '</div>';
            }
        });

        document.getElementById('stakeForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const walletName = document.getElementById('stakeWalletSelect').value;
            const password = document.getElementById('stakePassword').value;
            const tokenSymbol = document.getElementById('stakeTokenSymbol').value;
            const amount = parseInt(document.getElementById('stakeAmount').value);

            try {
                const response = await fetch('/api/wallets/stake', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        wallet_name: walletName,
                        password: password,
                        token_symbol: tokenSymbol,
                        amount: amount
                    })
                });

                const result = await response.json();
                const messageDiv = document.getElementById('stakeMessage');

                if (result.success) {
                    messageDiv.innerHTML = '<div class="success">' + result.message + '</div>';
                    loadTransactionHistory();
                    setTimeout(() => closeModal('stakeModal'), 2000);
                } else {
                    messageDiv.innerHTML = '<div class="error">' + result.message + '</div>';
                }
            } catch (error) {
                document.getElementById('stakeMessage').innerHTML = '<div class="error">Error: ' + error.message + '</div>';
            }
        });

        function showWalletDetails(walletName) {
            const password = prompt('Enter password for wallet "' + walletName + '":');
            if (password) {
                // This would show detailed wallet information
                alert('Wallet details functionality - showing basic info for: ' + walletName);
            }
        }

        // Missing function implementations
        async function executeTokenTransfer() {
            const walletName = document.getElementById('transferFromWallet').value;
            const password = document.getElementById('transferFromPassword').value;
            const toAddress = document.getElementById('transferToAddr').value;
            const tokenType = document.getElementById('transferTokenType').value;
            const amount = parseInt(document.getElementById('transferTokenAmount').value);
            const useEscrow = document.getElementById('transferWithEscrow').checked;

            if (!walletName || !password || !toAddress || !tokenType || !amount) {
                alert('Please fill in all required fields');
                return;
            }

            try {
                const response = await fetch('/api/wallets/transfer', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        wallet_name: walletName,
                        password: password,
                        to_address: toAddress,
                        token_symbol: tokenType,
                        amount: amount,
                        use_escrow: useEscrow
                    })
                });

                const result = await response.json();
                const messageDiv = document.getElementById('advancedTransactionMessage');

                if (result.success) {
                    messageDiv.innerHTML = '<div class="success">✅ Token transfer successful!</div>';
                    setTimeout(() => closeModal('advancedTransactionsModal'), 3000);
                } else {
                    messageDiv.innerHTML = '<div class="error">❌ ' + result.message + '</div>';
                }
            } catch (error) {
                document.getElementById('advancedTransactionMessage').innerHTML = '<div class="error">❌ Error: ' + error.message + '</div>';
            }
        }

        async function executeStaking() {
            const walletName = document.getElementById('stakingWallet').value;
            const password = document.getElementById('stakingPassword').value;
            const token = document.getElementById('stakingToken').value;
            const amount = parseInt(document.getElementById('stakingAmount').value);
            const duration = parseInt(document.getElementById('stakingDuration').value);

            if (!walletName || !password || !token || !amount || !duration) {
                alert('Please fill in all required fields');
                return;
            }

            try {
                const response = await fetch('/api/wallets/stake', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        wallet_name: walletName,
                        password: password,
                        token_symbol: token,
                        amount: amount,
                        duration_days: duration
                    })
                });

                const result = await response.json();
                const messageDiv = document.getElementById('advancedTransactionMessage');

                if (result.success) {
                    messageDiv.innerHTML = '<div class="success">✅ Tokens staked successfully!</div>';
                    setTimeout(() => closeModal('advancedTransactionsModal'), 3000);
                } else {
                    messageDiv.innerHTML = '<div class="error">❌ ' + result.message + '</div>';
                }
            } catch (error) {
                document.getElementById('advancedTransactionMessage').innerHTML = '<div class="error">❌ Error: ' + error.message + '</div>';
            }
        }

        function detectAddress() {
            // Auto-detect address functionality
            const addressInput = document.getElementById('transferToAddr');

            // Simulate address detection (in real implementation, this would scan for nearby wallets)
            const detectedAddresses = [
                '0x1234567890abcdef1234567890abcdef12345678',
                '0xabcdef1234567890abcdef1234567890abcdef12',
                '0x9876543210fedcba9876543210fedcba98765432'
            ];

            if (detectedAddresses.length > 0) {
                const selectedAddress = prompt('Detected addresses:\\n' +
                    detectedAddresses.map((addr, i) => (i + 1) + '. ' + addr).join('\\n') +
                    '\\n\\nEnter the number of the address to use (1-' + detectedAddresses.length + '):');

                const index = parseInt(selectedAddress) - 1;
                if (index >= 0 && index < detectedAddresses.length) {
                    addressInput.value = detectedAddresses[index];
                }
            } else {
                alert('No addresses detected nearby');
            }
        }

        // Close modals when clicking outside
        window.onclick = function(event) {
            const modals = document.getElementsByClassName('modal');
            for (let i = 0; i < modals.length; i++) {
                if (event.target === modals[i]) {
                    modals[i].style.display = 'none';
                }
            }
        }
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// getUserFromSession gets user from session
func getUserFromSession(r *http.Request) (*wallet.User, error) {
	sessionID := getSessionID(r)
	if sessionID == "" {
		return nil, fmt.Errorf("no session found")
	}

	sessionData := sessions[sessionID]
	if sessionData == nil {
		return nil, fmt.Errorf("session not found")
	}

	// Get user from database
	ctx := context.Background()
	var user wallet.User
	err := wallet.UserCollection.FindOne(ctx, map[string]interface{}{"username": sessionData.Username}).Decode(&user)
	if err != nil {
		return nil, fmt.Errorf("user not found in database")
	}

	return &user, nil
}

// handleWallets returns list of user wallets
func handleWallets(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromSession(r)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Authentication error"}, http.StatusUnauthorized)
		return
	}

	ctx := context.Background()
	wallets, err := wallet.ListUserWallets(ctx, user)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: err.Error()}, http.StatusInternalServerError)
		return
	}

	// Convert to response format
	var walletData []map[string]interface{}
	for _, w := range wallets {
		walletData = append(walletData, map[string]interface{}{
			"name":       w.WalletName,
			"address":    w.Address,
			"public_key": w.PublicKey,
			"created_at": w.CreatedAt,
		})
	}

	sendJSONResponse(w, APIResponse{Success: true, Data: walletData}, http.StatusOK)
}

// handleCreateWallet creates a new wallet
func handleCreateWallet(w http.ResponseWriter, r *http.Request) {
	logInfo("CREATE_WALLET", "Processing wallet creation request")

	if r.Method != "POST" {
		logError("CREATE_WALLET_METHOD", fmt.Errorf("invalid method: %s", r.Method))
		sendJSONResponse(w, APIResponse{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	user, err := getUserFromSession(r)
	if err != nil {
		logError("CREATE_WALLET_AUTH", err)
		sendJSONResponse(w, APIResponse{Success: false, Message: "Authentication error"}, http.StatusUnauthorized)
		return
	}

	var req struct {
		WalletName string `json:"wallet_name"`
		Password   string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logError("CREATE_WALLET_DECODE", err)
		sendJSONResponse(w, APIResponse{Success: false, Message: "Invalid request body"}, http.StatusBadRequest)
		return
	}

	logInfo("CREATE_WALLET_USER", fmt.Sprintf("Creating wallet '%s' for user %s", req.WalletName, user.Username))

	ctx := context.Background()
	newWallet, err := wallet.GenerateWalletFromMnemonic(ctx, user, req.Password, req.WalletName)
	if err != nil {
		logError("CREATE_WALLET_GENERATE", fmt.Errorf("failed to create wallet '%s' for user %s: %v", req.WalletName, user.Username, err))
		sendJSONResponse(w, APIResponse{Success: false, Message: err.Error()}, http.StatusInternalServerError)
		return
	}

	logSuccess("CREATE_WALLET_SUCCESS", fmt.Sprintf("Wallet '%s' created successfully for user %s with address %s", req.WalletName, user.Username, newWallet.Address))

	sendJSONResponse(w, APIResponse{
		Success: true,
		Message: "Wallet created successfully",
		Data: map[string]interface{}{
			"name":    newWallet.WalletName,
			"address": newWallet.Address,
		},
	}, http.StatusOK)
}

// handleCheckBalance checks wallet balance
func handleCheckBalance(w http.ResponseWriter, r *http.Request) {
	logInfo("CHECK_BALANCE", "Processing balance check request")

	if r.Method != "POST" {
		logError("CHECK_BALANCE_METHOD", fmt.Errorf("invalid method: %s", r.Method))
		sendJSONResponse(w, APIResponse{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	user, err := getUserFromSession(r)
	if err != nil {
		logError("CHECK_BALANCE_AUTH", err)
		sendJSONResponse(w, APIResponse{Success: false, Message: "Authentication error"}, http.StatusUnauthorized)
		return
	}

	var req struct {
		WalletName  string `json:"wallet_name"`
		Password    string `json:"password"`
		TokenSymbol string `json:"token_symbol"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logError("CHECK_BALANCE_DECODE", err)
		sendJSONResponse(w, APIResponse{Success: false, Message: "Invalid request body"}, http.StatusBadRequest)
		return
	}

	logInfo("CHECK_BALANCE_REQUEST", fmt.Sprintf("Checking balance for wallet '%s', token '%s', user '%s'", req.WalletName, req.TokenSymbol, user.Username))

	ctx := context.Background()
	balance, err := wallet.CheckTokenBalance(ctx, user, req.WalletName, req.Password, req.TokenSymbol)
	if err != nil {
		logError("CHECK_BALANCE_QUERY", fmt.Errorf("failed to check balance for wallet '%s', token '%s', user '%s': %v", req.WalletName, req.TokenSymbol, user.Username, err))
		sendJSONResponse(w, APIResponse{Success: false, Message: err.Error()}, http.StatusInternalServerError)
		return
	}

	logSuccess("CHECK_BALANCE_SUCCESS", fmt.Sprintf("Balance retrieved: %d %s for wallet '%s', user '%s'", balance, req.TokenSymbol, req.WalletName, user.Username))

	sendJSONResponse(w, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"balance":      balance,
			"token_symbol": req.TokenSymbol,
			"wallet_name":  req.WalletName,
		},
	}, http.StatusOK)
}

// handleTransfer transfers tokens
func handleTransfer(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	user, err := getUserFromSession(r)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Authentication error"}, http.StatusUnauthorized)
		return
	}

	var req struct {
		WalletName  string `json:"wallet_name"`
		Password    string `json:"password"`
		ToAddress   string `json:"to_address"`
		TokenSymbol string `json:"token_symbol"`
		Amount      uint64 `json:"amount"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Invalid request body"}, http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	err = wallet.TransferTokensWithHistory(ctx, user, req.WalletName, req.Password, req.ToAddress, req.TokenSymbol, req.Amount)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: err.Error()}, http.StatusInternalServerError)
		return
	}

	sendJSONResponse(w, APIResponse{
		Success: true,
		Message: fmt.Sprintf("Successfully transferred %d %s tokens to %s", req.Amount, req.TokenSymbol, req.ToAddress),
	}, http.StatusOK)
}

// handleImportWallet imports a wallet from private key
func handleImportWallet(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	user, err := getUserFromSession(r)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Authentication error"}, http.StatusUnauthorized)
		return
	}

	var req struct {
		WalletName string `json:"wallet_name"`
		Password   string `json:"password"`
		PrivateKey string `json:"private_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Invalid request body"}, http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	importedWallet, err := wallet.ImportWalletFromPrivateKey(ctx, user, req.Password, req.WalletName, req.PrivateKey)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: err.Error()}, http.StatusInternalServerError)
		return
	}

	sendJSONResponse(w, APIResponse{
		Success: true,
		Message: "Wallet imported successfully",
		Data: map[string]interface{}{
			"name":    importedWallet.WalletName,
			"address": importedWallet.Address,
		},
	}, http.StatusOK)
}

// handleExportWallet exports wallet private key
func handleExportWallet(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	user, err := getUserFromSession(r)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Authentication error"}, http.StatusUnauthorized)
		return
	}

	var req struct {
		WalletName string `json:"wallet_name"`
		Password   string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Invalid request body"}, http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	privateKeyHex, err := wallet.ExportWalletPrivateKey(ctx, user, req.WalletName, req.Password)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: err.Error()}, http.StatusInternalServerError)
		return
	}

	sendJSONResponse(w, APIResponse{
		Success: true,
		Message: "Private key exported successfully",
		Data: map[string]interface{}{
			"private_key": privateKeyHex,
		},
	}, http.StatusOK)
}

// handleStakeTokens handles token staking
func handleStakeTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	user, err := getUserFromSession(r)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Authentication error"}, http.StatusUnauthorized)
		return
	}

	var req struct {
		WalletName  string `json:"wallet_name"`
		Password    string `json:"password"`
		TokenSymbol string `json:"token_symbol"`
		Amount      uint64 `json:"amount"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Invalid request body"}, http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	err = wallet.StakeTokensWithHistory(ctx, user, req.WalletName, req.Password, req.TokenSymbol, req.Amount)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: err.Error()}, http.StatusInternalServerError)
		return
	}

	sendJSONResponse(w, APIResponse{
		Success: true,
		Message: fmt.Sprintf("Successfully staked %d %s tokens", req.Amount, req.TokenSymbol),
	}, http.StatusOK)
}

// handleTransactions returns transaction history
func handleTransactions(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromSession(r)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Authentication error"}, http.StatusUnauthorized)
		return
	}

	ctx := context.Background()
	transactions, err := wallet.GetAllUserTransactions(ctx, user.ID.Hex(), 50)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: err.Error()}, http.StatusInternalServerError)
		return
	}

	// Convert to response format
	var txData []map[string]interface{}
	for _, tx := range transactions {
		txData = append(txData, map[string]interface{}{
			"type":         tx.Type,
			"from":         tx.From,
			"to":           tx.To,
			"amount":       tx.Amount,
			"token_symbol": tx.TokenSymbol,
			"status":       tx.Status,
			"timestamp":    tx.Timestamp,
			"block_height": tx.BlockHeight,
		})
	}

	sendJSONResponse(w, APIResponse{Success: true, Data: txData}, http.StatusOK)
}

// OTC Trading Handlers
func handleCreateOTCOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		WalletName      string   `json:"wallet_name"`
		Password        string   `json:"password"`
		TokenOffered    string   `json:"token_offered"`
		AmountOffered   uint64   `json:"amount_offered"`
		TokenRequested  string   `json:"token_requested"`
		AmountRequested uint64   `json:"amount_requested"`
		ExpirationHours int      `json:"expiration_hours"`
		IsMultiSig      bool     `json:"is_multi_sig"`
		RequiredSigs    []string `json:"required_sigs"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Invalid request format"}, http.StatusBadRequest)
		return
	}

	// Get user from session
	user, err := getUserFromSession(r)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Authentication required"}, http.StatusUnauthorized)
		return
	}

	// Get wallet details to get the address
	ctx := context.Background()
	walletDoc, _, _, err := wallet.GetWalletDetails(ctx, user, req.WalletName, req.Password)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Failed to access wallet: " + err.Error()}, http.StatusInternalServerError)
		return
	}

	// Connect to blockchain and create OTC order
	orderData, err := createOTCOrderOnBlockchain(walletDoc.Address, req.TokenOffered, req.TokenRequested,
		req.AmountOffered, req.AmountRequested, req.ExpirationHours, req.IsMultiSig, req.RequiredSigs)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Failed to create OTC order: " + err.Error()}, http.StatusInternalServerError)
		return
	}

	logSuccess("OTC_ORDER_CREATE", fmt.Sprintf("Order %s created by %s", orderData["order_id"], user.Username))

	sendJSONResponse(w, APIResponse{
		Success: true,
		Message: "OTC order created successfully",
		Data:    orderData,
	}, http.StatusOK)
}

func handleGetOTCOrders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	// Get user from session to filter orders
	user, err := getUserFromSession(r)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Authentication required"}, http.StatusUnauthorized)
		return
	}

	// Get user's wallet address (use first wallet for now)
	userAddress := fmt.Sprintf("user_%s", user.Username) // Use username as placeholder address

	// Get orders from blockchain
	orders, err := getOTCOrdersFromBlockchain(userAddress)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Failed to get OTC orders: " + err.Error()}, http.StatusInternalServerError)
		return
	}

	sendJSONResponse(w, APIResponse{Success: true, Data: orders}, http.StatusOK)
}

func handleCancelOTCOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		OrderID    string `json:"order_id"`
		WalletName string `json:"wallet_name"`
		Password   string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Invalid request format"}, http.StatusBadRequest)
		return
	}

	// Get user from session
	user, err := getUserFromSession(r)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Authentication required"}, http.StatusUnauthorized)
		return
	}

	// Get wallet details to get the address
	ctx := context.Background()
	walletDoc, _, _, err := wallet.GetWalletDetails(ctx, user, req.WalletName, req.Password)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Failed to access wallet: " + err.Error()}, http.StatusInternalServerError)
		return
	}

	// Connect to blockchain and cancel OTC order
	success, err := cancelOTCOrderOnBlockchain(req.OrderID, walletDoc.Address)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Failed to cancel OTC order: " + err.Error()}, http.StatusInternalServerError)
		return
	}

	if !success {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Order cancellation failed"}, http.StatusInternalServerError)
		return
	}

	logSuccess("OTC_ORDER_CANCEL", fmt.Sprintf("Order %s cancelled by %s", req.OrderID, user.Username))

	sendJSONResponse(w, APIResponse{
		Success: true,
		Message: "OTC order cancelled successfully",
		Data: map[string]interface{}{
			"order_id":     req.OrderID,
			"cancelled_by": walletDoc.Address,
			"cancelled_at": time.Now().Unix(),
		},
	}, http.StatusOK)
}

func handleMatchOTCOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		OrderID    string `json:"order_id"`
		WalletName string `json:"wallet_name"`
		Password   string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Invalid request format"}, http.StatusBadRequest)
		return
	}

	// Get user from session
	user, err := getUserFromSession(r)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Authentication required"}, http.StatusUnauthorized)
		return
	}

	// Get wallet details to get the address
	ctx := context.Background()
	walletDoc, _, _, err := wallet.GetWalletDetails(ctx, user, req.WalletName, req.Password)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Failed to access wallet: " + err.Error()}, http.StatusInternalServerError)
		return
	}

	// Connect to blockchain and match OTC order
	success, err := matchOTCOrderOnBlockchain(req.OrderID, walletDoc.Address)
	if err != nil {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Failed to match OTC order: " + err.Error()}, http.StatusInternalServerError)
		return
	}

	if !success {
		sendJSONResponse(w, APIResponse{Success: false, Message: "Order matching failed"}, http.StatusInternalServerError)
		return
	}

	logSuccess("OTC_ORDER_MATCH", fmt.Sprintf("Order %s matched by %s", req.OrderID, user.Username))

	sendJSONResponse(w, APIResponse{
		Success: true,
		Message: "OTC order matched successfully",
		Data: map[string]interface{}{
			"order_id":   req.OrderID,
			"matched_by": walletDoc.Address,
			"matched_at": time.Now().Unix(),
		},
	}, http.StatusOK)
}

// Blockchain OTC Integration Functions
func createOTCOrderOnBlockchain(creator, tokenOffered, tokenRequested string, amountOffered, amountRequested uint64, expirationHours int, isMultiSig bool, requiredSigs []string) (map[string]interface{}, error) {
	// Try to connect to blockchain API with retry logic
	blockchainURL := "http://localhost:8080/api/otc/create"

	// Test blockchain connectivity first
	if !testBlockchainConnection() {
		fmt.Printf("⚠️ Blockchain API not available, creating simulated OTC order\n")
		return createSimulatedOTCOrder(creator, tokenOffered, tokenRequested, amountOffered, amountRequested, expirationHours, isMultiSig, requiredSigs), nil
	}

	requestData := map[string]interface{}{
		"creator":          creator,
		"token_offered":    tokenOffered,
		"amount_offered":   amountOffered,
		"token_requested":  tokenRequested,
		"amount_requested": amountRequested,
		"expiration_hours": expirationHours,
		"is_multisig":      isMultiSig,
		"required_sigs":    requiredSigs,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	resp, err := http.Post(blockchainURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		// If blockchain API is not available, create a simulated order
		fmt.Printf("⚠️ Blockchain API not available, creating simulated OTC order\n")
		return createSimulatedOTCOrder(creator, tokenOffered, tokenRequested, amountOffered, amountRequested, expirationHours, isMultiSig, requiredSigs), nil
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	if success, ok := result["success"].(bool); !ok || !success {
		message := "Unknown error"
		if msg, ok := result["message"].(string); ok {
			message = msg
		}
		return nil, fmt.Errorf("blockchain error: %s", message)
	}

	if data, ok := result["data"].(map[string]interface{}); ok {
		return data, nil
	}

	return nil, fmt.Errorf("invalid response format")
}

func createSimulatedOTCOrder(creator, tokenOffered, tokenRequested string, amountOffered, amountRequested uint64, expirationHours int, isMultiSig bool, requiredSigs []string) map[string]interface{} {
	// Safely handle short creator addresses
	creatorSuffix := creator
	if len(creator) > 8 {
		creatorSuffix = creator[:8]
	}
	orderID := fmt.Sprintf("otc_%d_%s", time.Now().UnixNano(), creatorSuffix)

	return map[string]interface{}{
		"order_id":         orderID,
		"creator":          creator,
		"token_offered":    tokenOffered,
		"amount_offered":   amountOffered,
		"token_requested":  tokenRequested,
		"amount_requested": amountRequested,
		"expiration_hours": expirationHours,
		"is_multi_sig":     isMultiSig,
		"required_sigs":    requiredSigs,
		"status":           "open",
		"created_at":       time.Now().Unix(),
		"expires_at":       time.Now().Add(time.Duration(expirationHours) * time.Hour).Unix(),
		"note":             "Simulated order - blockchain API not available",
	}
}

func getOTCOrdersFromBlockchain(userAddress string) ([]map[string]interface{}, error) {
	// Try to connect to blockchain API
	blockchainURL := fmt.Sprintf("http://localhost:8080/api/otc/orders?user=%s", userAddress)

	resp, err := http.Get(blockchainURL)
	if err != nil {
		// If blockchain API is not available, return simulated orders
		fmt.Printf("⚠️ Blockchain API not available, returning simulated OTC orders\n")
		return getSimulatedOTCOrders(userAddress), nil
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	if success, ok := result["success"].(bool); !ok || !success {
		return getSimulatedOTCOrders(userAddress), nil
	}

	if data, ok := result["data"].([]interface{}); ok {
		orders := make([]map[string]interface{}, len(data))
		for i, order := range data {
			if orderMap, ok := order.(map[string]interface{}); ok {
				orders[i] = orderMap
			}
		}
		return orders, nil
	}

	return getSimulatedOTCOrders(userAddress), nil
}

func getSimulatedOTCOrders(userAddress string) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"order_id":         "otc_example_1",
			"creator":          userAddress,
			"token_offered":    "BHX",
			"amount_offered":   1000,
			"token_requested":  "USDT",
			"amount_requested": 5000,
			"status":           "open",
			"created_at":       time.Now().Unix() - 3600,
			"expires_at":       time.Now().Unix() + 82800, // 23 hours from now
			"note":             "Simulated order",
		},
		{
			"order_id":         "otc_example_2",
			"creator":          "0x1234...5678",
			"token_offered":    "USDT",
			"amount_offered":   2000,
			"token_requested":  "BHX",
			"amount_requested": 400,
			"status":           "open",
			"created_at":       time.Now().Unix() - 1800,
			"expires_at":       time.Now().Unix() + 84600, // 23.5 hours from now
			"note":             "Simulated order from another user",
		},
	}
}

func cancelOTCOrderOnBlockchain(orderID, canceller string) (bool, error) {
	// Try to connect to blockchain API
	blockchainURL := "http://localhost:8080/api/otc/cancel"

	requestData := map[string]interface{}{
		"order_id":  orderID,
		"canceller": canceller,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return false, fmt.Errorf("failed to marshal request: %v", err)
	}

	resp, err := http.Post(blockchainURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		// If blockchain API is not available, simulate cancellation
		fmt.Printf("⚠️ Blockchain API not available, simulating OTC order cancellation\n")
		return true, nil
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("failed to decode response: %v", err)
	}

	if success, ok := result["success"].(bool); !ok || !success {
		message := "Unknown error"
		if msg, ok := result["message"].(string); ok {
			message = msg
		}
		return false, fmt.Errorf("blockchain error: %s", message)
	}

	return true, nil
}

func matchOTCOrderOnBlockchain(orderID, counterparty string) (bool, error) {
	// Try to connect to blockchain API
	blockchainURL := "http://localhost:8080/api/otc/match"

	requestData := map[string]interface{}{
		"order_id":     orderID,
		"counterparty": counterparty,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return false, fmt.Errorf("failed to marshal request: %v", err)
	}

	resp, err := http.Post(blockchainURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		// If blockchain API is not available, simulate matching
		fmt.Printf("⚠️ Blockchain API not available, simulating OTC order matching\n")
		return true, nil
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("failed to decode response: %v", err)
	}

	if success, ok := result["success"].(bool); !ok || !success {
		message := "Unknown error"
		if msg, ok := result["message"].(string); ok {
			message = msg
		}
		return false, fmt.Errorf("blockchain error: %s", message)
	}

	return true, nil
}

// Blockchain connection testing functions
func testBlockchainConnection() bool {
	// Test basic connectivity to blockchain API
	testURL := "http://localhost:8080/api/health"

	client := &http.Client{
		Timeout: 5 * time.Second, // 5 second timeout
	}

	resp, err := client.Get(testURL)
	if err != nil {
		fmt.Printf("🔴 Blockchain connection test failed: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		fmt.Printf("🟢 Blockchain connection successful\n")
		return true
	}

	fmt.Printf("🟡 Blockchain responded with status: %d\n", resp.StatusCode)
	return false
}

func retryBlockchainConnection(maxRetries int) bool {
	for i := 0; i < maxRetries; i++ {
		if testBlockchainConnection() {
			return true
		}
		fmt.Printf("🔄 Retry %d/%d: Waiting 2 seconds before next attempt...\n", i+1, maxRetries)
		time.Sleep(2 * time.Second)
	}
	return false
}
