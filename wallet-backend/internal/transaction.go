// package internal

// import (
// 	"encoding/json"
// 	"time"
// )

// type Transaction struct {
// 	From   string  `json:"from"`
// 	To     string  `json:"to"`
// 	Amount float64 `json:"amount"`
// 	Nonce  int64   `json:"nonce"`
// }

// func NewTransaction(from, to string, amount float64) *Transaction {
// 	return &Transaction{
// 		From:   from,
// 		To:     to,
// 		Amount: amount,
// 		Nonce:  time.Now().UnixNano(),
// 	}
// }

// func (t *Transaction) Sign(wallet *Wallet) (string, error) {
// 	data, err := json.Marshal(t)
// 	if err != nil {
// 		return "", err
// 	}
// 	return wallet.KeyManager.Sign(data)
// }
package internal