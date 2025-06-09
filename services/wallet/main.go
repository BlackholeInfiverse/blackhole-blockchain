package main

import (
	"bufio"
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
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); }
        .modal-content { background-color: white; margin: 5% auto; padding: 20px; border-radius: 8px; width: 80%; max-width: 600px; }
        .close { color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer; }
        .close:hover { color: black; }
        .error { color: #dc3545; margin-top: 10px; }
        .success { color: #28a745; margin-top: 10px; }
        .loading { color: #666; font-style: italic; }
        .hidden { display: none; }
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
            document.getElementById(modalId).style.display = 'block';
        }

        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
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
