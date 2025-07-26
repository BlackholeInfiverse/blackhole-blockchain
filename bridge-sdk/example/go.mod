module bridge-example

go 1.24.3

require (
	github.com/Shivam-Patel-G/blackhole-blockchain/bridge-sdk v0.0.0-00010101000000-000000000000
)

replace github.com/Shivam-Patel-G/blackhole-blockchain/bridge-sdk => ../

replace github.com/Shivam-Patel-G/blackhole-blockchain/core => ../../core

replace github.com/Shivam-Patel-G/blackhole-blockchain/bridge/core => ../../bridge/core
