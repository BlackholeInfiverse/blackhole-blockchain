module github.com/Shivam-Patel-G/blackhole-blockchain/bridge-sdk

go 1.24.3

require (
	github.com/Shivam-Patel-G/blackhole-blockchain/bridge/core v0.0.0-00010101000000-000000000000
	github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain v0.0.0-20250614104919-d0656764ebf1
	github.com/ethereum/go-ethereum v1.15.11
	github.com/fatih/color v1.16.0
	github.com/gorilla/websocket v1.5.3
	go.etcd.io/bbolt v1.4.1
	go.uber.org/zap v1.27.0
)

replace github.com/Shivam-Patel-G/blackhole-blockchain/core => ../core
replace github.com/Shivam-Patel-G/blackhole-blockchain/bridge/core => ../bridge/core

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/StackExchange/wmi v1.2.1 // indirect
	github.com/benbjohnson/clock v1.3.5 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bits-and-blooms/bitset v1.20.0 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.3.4 // indirect
	github.com/consensys/bavard v0.1.27 // indirect
	github.com/consensys/gnark-crypto v0.16.0 // indirect
	github.com/crate-crypto/go-eth-kzg v1.3.0 // indirect
	github.com/crate-crypto/go-kzg-4844 v0.7.0 // indirect
	github.com/deckarep/golang-set/v2 v2.6.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/ethereum/c-kzg-4844 v0.4.0 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/shirou/gopsutil v3.21.4-0.20210419000835-c7a38de76ee5+incompatible // indirect
	github.com/supranational/blst v0.3.14 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	golang.org/x/crypto v0.35.0 // indirect
	golang.org/x/exp v0.0.0-20250218142911-aa4b98e5adaa // indirect
	golang.org/x/mod v0.23.0 // indirect
	golang.org/x/sync v0.11.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/tools v0.30.0 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)
