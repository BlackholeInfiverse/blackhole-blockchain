package main

import (
	"fmt"

	"github.com/Shivam-Patel-G/blackhole-blockchain/relay-chain/token"
)

func main() {
	tk := token.NewToken("BlackHole", "BLH", 18, 0)
	
	fmt.Println("=== Token Demo ===")
	fmt.Printf("Initial Supply: %d\n", tk.TotalSupply())

	// Mint tokens
	tk.Mint("0xAlice", 1000)
	fmt.Printf("After Mint(Alice,1000): Supply=%d, Alice=%d\n", 
		tk.TotalSupply(), getBalance(tk, "0xAlice"))

	// Transfer
	tk.Transfer("0xAlice", "0xBob", 300)
	fmt.Printf("After Transfer(Alice→Bob,300): Alice=%d, Bob=%d\n", 
		getBalance(tk, "0xAlice"), getBalance(tk, "0xBob"))

	// Burn
	tk.Burn("0xAlice", 200)
	fmt.Printf("After Burn(Alice,200): Supply=%d, Alice=%d\n", 
		tk.TotalSupply(), getBalance(tk, "0xAlice"))
}

func getBalance(tk *token.Token, addr string) uint64 {
	bal, _ := tk.BalanceOf(addr)
	return bal
}