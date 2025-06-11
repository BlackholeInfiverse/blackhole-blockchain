# Go Bridge Relay

## Overview
The Go Bridge Relay project is designed to capture transaction events from Ethereum and Solana networks, convert them into a standardized Go blockchain format, and push them into a blockchain. The project also provides a web server to display these events and their metadata.

## Project Structure
```
go-bridge-relay
├── cmd
│   └── main.go          # Entry point of the application
├── internal
│   ├── bridgeRelay.go   # Relay handler for transaction events
│   ├── ethListener.go    # ETH transaction listener
│   ├── solanaListener.go  # Solana transaction listener
│   ├── blockchain.go      # Blockchain interaction logic
│   └── types.go          # Data structures and types
├── web
│   └── server.go        # Web server for displaying events
├── go.mod               # Module definition
└── README.md            # Project documentation
```

## Setup Instructions
1. **Clone the repository:**
   ```
   git clone <repository-url>
   cd go-bridge-relay
   ```

2. **Install dependencies:**
   ```
   go mod tidy
   ```

3. **Run the application:**
   ```
   go run cmd/main.go
   ```

4. **Access the web server:**
   Open your browser and navigate to `http://localhost:8080` to view the captured transaction events.

## Usage
- The application listens for transaction events from both Ethereum and Solana networks.
- Captured events are processed and pushed into the blockchain with metadata including:
  - `sourceChain`: The blockchain from which the transaction originated (ETH or Solana).
  - `txHash`: The transaction hash.
  - `amount`: The amount involved in the transaction.

## Relay Module Functionality
The relay module is responsible for:
- Capturing transaction events from the ETH and Solana listeners.
- Converting these events into a Go blockchain format.
- Pushing the formatted events into the blockchain.
- Displaying the events on the console and through the web server.

## Contributing
Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.