package main

import (
	"log"
	"net/http"

	"github.com/Shivam-Patel-G/blackhole-blockchain/wallet-frontend/handlers"
)

func main() {
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	http.HandleFunc("/", handlers.Index)
	http.HandleFunc("/create", handlers.CreateWallet)
	http.HandleFunc("/restore", handlers.RestoreWallet)
	http.HandleFunc("/send", handlers.SendTransaction) // ✅ Added for transaction

	log.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
