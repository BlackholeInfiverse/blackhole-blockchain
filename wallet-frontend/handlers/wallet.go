package handlers

import (
	"log"
	"net/http"
	"strconv"
	"text/template"

	wallet "github.com/Shivam-Patel-G/blackhole-blockchain/wallet-backend/wallet_common"
)

var (
	indexTmpl       *template.Template
	walletTmpl      *template.Template
	transactionTmpl *template.Template
)

func init() {
	var err error

	indexTmpl, err = template.ParseFiles("templates/index.html")
	if err != nil {
		log.Fatalf("Failed to load index template: %v", err)
	}

	walletTmpl, err = template.ParseFiles("templates/wallet.html")
	if err != nil {
		log.Fatalf("Failed to load wallet template: %v", err)
	}

	transactionTmpl, err = template.ParseFiles("templates/transaction.html")
	if err != nil {
		log.Fatalf("Failed to load transaction template: %v", err)
	}

}

func Index(w http.ResponseWriter, r *http.Request) {
	err := indexTmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func CreateWallet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	password := r.FormValue("password")
	if password == "" {
		http.Error(w, "Password is required", http.StatusBadRequest)
		return
	}

	wlt, err := wallet.NewWallet(password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = walletTmpl.Execute(w, wlt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func RestoreWallet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	mnemonic := r.FormValue("mnemonic")
	password := r.FormValue("password")
	if mnemonic == "" || password == "" {
		http.Error(w, "Mnemonic and password are required", http.StatusBadRequest)
		return
	}

	wlt, err := wallet.RestoreWallet(mnemonic, password)
	if err != nil {
		http.Error(w, "Invalid mnemonic or password", http.StatusBadRequest)
		return
	}

	err = walletTmpl.Execute(w, wlt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func SendTransaction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	mnemonic := r.FormValue("mnemonic")
	password := r.FormValue("password")
	toAddress := r.FormValue("to_address")
	amountStr := r.FormValue("amount")

	if mnemonic == "" || password == "" || toAddress == "" || amountStr == "" {
		http.Error(w, "All fields are required", http.StatusBadRequest)
		return
	}

	// Optional: validate amount
	_, err := strconv.ParseFloat(amountStr, 64)
	if err != nil {
		http.Error(w, "Invalid amount", http.StatusBadRequest)
		return
	}

	// Create and sign transaction
	tx, err := wallet.CreateAndSignTransaction(mnemonic, password, toAddress, amountStr, "transfer")
	if err != nil {
		http.Error(w, "Transaction signing failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// TODO: Broadcast tx to your blockchain (not shown here)

	// Send transaction info back to frontend
	err = transactionTmpl.Execute(w, struct {
	Message     string
	Transaction *wallet.Transaction
}{
	Message:     "Transaction created and signed successfully!",
	Transaction: tx,
})

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
