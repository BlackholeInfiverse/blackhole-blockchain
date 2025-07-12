module github.com/Shivam-Patel-G/blackhole-blockchain

go 1.24.3

require (
	github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain v0.0.0-20250614104919-d0656764ebf1
	github.com/ethereum/go-ethereum v1.15.11
	github.com/fatih/color v1.16.0
	github.com/gorilla/websocket v1.5.3
	github.com/sirupsen/logrus v1.9.3
	go.etcd.io/bbolt v1.4.1
	go.uber.org/zap v1.27.0
)

replace github.com/Shivam-Patel-G/blackhole-blockchain/core => ../core
