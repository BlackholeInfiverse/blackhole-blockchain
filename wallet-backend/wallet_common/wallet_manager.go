// wallet_common/wallet_manager.go
package wallet_common

// import (
// 	"os"
// 	"path/filepath"
// )

// const WalletDir = "wallets"

// func init() {
// 	// Create wallets directory if it doesn't exist
// 	os.MkdirAll(WalletDir, 0700)
// }

// func GetWalletPath(address string) string {
// 	return filepath.Join(WalletDir, address+".json")
// }

// func WalletExists(address string) bool {
// 	_, err := os.Stat(GetWalletPath(address))
// 	return !os.IsNotExist(err)
// }

// func ListWallets() ([]string, error) {
// 	files, err := os.ReadDir(WalletDir)
// 	if err != nil {
// 		return nil, err
// 	}

// 	var wallets []string
// 	for _, file := range files {
// 		if filepath.Ext(file.Name()) == ".json" {
// 			wallets = append(wallets, file.Name())
// 		}
// 	}
// 	return wallets, nil
// }
