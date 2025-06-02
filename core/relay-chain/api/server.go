package api

// import (
// 	"encoding/json"
// 	"net/http"

// 	"github.com/BlackholeInfiverse/blackhole-blockchain/core/relay-chain/consensus"
// 	"github.com/gorilla/mux"
// )

// func StartServer() {
// 	r := mux.NewRouter()
// 	r.HandleFunc("/stake", handleStake).Methods("POST", "OPTIONS")
// 	r.HandleFunc("/unstake", handleUnstake).Methods("POST", "OPTIONS")
// 	r.HandleFunc("/claim-rewards", handleClaimRewards).Methods("GET", "OPTIONS")
// 	http.ListenAndServe(":8080", r)
// }

// func handleStake(w http.ResponseWriter, r *http.Request) {
// 	// Set CORS headers
// 	w.Header().Set("Access-Control-Allow-Origin", "*")
// 	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
// 	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

// 	// Handle preflight OPTIONS request
// 	if r.Method == http.MethodOptions {
// 		w.WriteHeader(http.StatusOK)
// 		return
// 	}

// 	var req struct {
// 		Address   string `json:"address"`
// 		Target    string `json:"target"`
// 		Amount    uint64 `json:"amount"`
// 		StakeType string `json:"stakeType"`
// 	}
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, "Invalid request body", http.StatusBadRequest)
// 		return
// 	}
// 	err := consensus.StakeTokens(req.Address, req.Target, req.Amount, req.StakeType)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}
// 	w.Write([]byte("Stake successful"))
// }

// func handleUnstake(w http.ResponseWriter, r *http.Request) {
// 	// Set CORS headers
// 	w.Header().Set("Access-Control-Allow-Origin", "*")
// 	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
// 	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

// 	// Handle preflight OPTIONS request
// 	if r.Method == http.MethodOptions {
// 		w.WriteHeader(http.StatusOK)
// 		return
// 	}

// 	var req struct {
// 		Address string `json:"address"`
// 		Amount  uint64 `json:"amount"`
// 	}
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, "Invalid request body", http.StatusBadRequest)
// 		return
// 	}
// 	err := consensus.UnstakeTokens(req.Address, req.Amount)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}
// 	w.Write([]byte("Unstake successful"))
// }

// func handleClaimRewards(w http.ResponseWriter, r *http.Request) {
// 	// Set CORS headers
// 	w.Header().Set("Access-Control-Allow-Origin", "*")
// 	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
// 	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

// 	// Handle preflight OPTIONS request
// 	if r.Method == http.MethodOptions {
// 		w.WriteHeader(http.StatusOK)
// 		return
// 	}

// 	address := r.URL.Query().Get("address")
// 	if address == "" {
// 		http.Error(w, "Address is required", http.StatusBadRequest)
// 		return
// 	}
// 	rewards, err := consensus.ClaimRewards(address)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(rewards)
// }
