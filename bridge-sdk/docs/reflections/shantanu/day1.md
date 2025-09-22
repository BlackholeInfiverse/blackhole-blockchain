# Day 1 Values Reflection

One thing I wasn't sure about was the choice of database for idempotency and storage. I handled it by using BoltDB as it's lightweight, embedded, and suitable for the key-value operations needed for eventHash dedupe and transaction persistence, avoiding external dependencies for the MVP.

Credit to the gRPC ecosystem (proto3, grpc-gateway) for enabling seamless REST/gRPC dual surface, and to the Go standard library for crypto/sha256 in hash generation.

One limitation left explicit is the use of in-process mocks for listeners—real Ethereum/Solana RPC integration is deferred to future sprints, documented in API.md as "mocks only". Follow-up: Add real RPC in Day 2+.