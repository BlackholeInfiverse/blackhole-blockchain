package bridgesdk

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	core "github.com/Shivam-Patel-G/blackhole-blockchain/bridge-sdk/core"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

// BridgeConfig holds the configuration for the bridge service
type BridgeConfig struct {
	EthereumRPC      string `mapstructure:"ETHEREUM_RPC"`
	SolanaRPC        string `mapstructure:"SOLANA_RPC"`
	BlackHoleRPC     string `mapstructure:"BLACKHOLE_RPC"`
	DatabasePath     string `mapstructure:"DATABASE_PATH"`
	HTTPPort         string `mapstructure:"HTTP_PORT"`
	GRPCPort         string `mapstructure:"GRPC_PORT"`
	MaxRetries       int    `mapstructure:"MAX_RETRIES"`
	RetryDelayMs     int    `mapstructure:"RETRY_DELAY_MS"`
	CircuitBreaker   bool   `mapstructure:"CIRCUIT_BREAKER_ENABLED"`
	ReplayProtection bool   `mapstructure:"REPLAY_PROTECTION_ENABLED"`
	InjectDrop       float64 `mapstructure:"INJECT_DROP"`
	InjectDelayMs    int    `mapstructure:"INJECT_DELAY_MS"`
	LogLevel         string `mapstructure:"LOG_LEVEL"`
}

func main() {
	// Parse command line flags
	configPath := flag.String("config", "./deploy/bridge/.env", "Path to config file")
	flag.Parse()

	// Load configuration
	config := loadConfig(*configPath)
	if config == nil {
		log.Fatal("Failed to load config")
	}

	// Initialize logger
	// Assuming structured logger from core, for now use log
	log.Printf("Starting BlackHole Bridge v0.3-rc1 with config: %+v", config)

	// Initialize database and SDK
	dbPath := config.DatabasePath
	if dbPath == "" {
		dbPath = "bridge.db"
	}
	sdk := core.NewBridgeSDK(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start mock listeners
	go func() {
		if err := sdk.StartEthereumListener(ctx); err != nil {
			log.Printf("Ethereum listener error: %v", err)
		}
	}()
	go func() {
		if err := sdk.StartSolanaListener(ctx); err != nil {
			log.Printf("Solana listener error: %v", err)
		}
	}()

	// Start retry processor
	go sdk.RetryQueue.ProcessRetries(ctx, sdk.RelayToChain)

	// Start metrics snapshot (every 30s)
	go startMetricsSnapshot(sdk, "./deploy/bridge/metrics.json")

	// gRPC server
	go startGRPCServer(config.GRPCPort, sdk)

	// HTTP/REST server with gateway
	go startHTTPServer(config.HTTPPort, sdk)

	// Graceful shutdown
	waitForShutdown(cancel)

	log.Println("Bridge service stopped")
}

func loadConfig(configPath string) *BridgeConfig {
	viper.SetConfigFile(configPath)
	viper.AutomaticEnv()
	viper.WatchConfig()
	viper.OnConfigFileChange(func(e fsnotify.Event) {
		log.Println("Config file changed:", e.Name)
	})

	if err := viper.ReadInConfig(); err != nil {
		log.Printf("Warning: Could not read config file %s: %v", configPath, err)
		// Use defaults
	}

	config := &BridgeConfig{
		EthereumRPC:      viper.GetString("ETHEREUM_RPC"),
		SolanaRPC:        viper.GetString("SOLANA_RPC"),
		BlackHoleRPC:     viper.GetString("BLACKHOLE_RPC"),
		DatabasePath:     viper.GetString("DATABASE_PATH"),
		HTTPPort:         viper.GetString("HTTP_PORT"),
		GRPCPort:         viper.GetString("GRPC_PORT"),
		MaxRetries:       viper.GetInt("MAX_RETRIES"),
		RetryDelayMs:     viper.GetInt("RETRY_DELAY_MS"),
		CircuitBreaker:   viper.GetBool("CIRCUIT_BREAKER_ENABLED"),
		ReplayProtection: viper.GetBool("REPLAY_PROTECTION_ENABLED"),
		InjectDrop:       viper.GetFloat64("INJECT_DROP"),
		InjectDelayMs:    viper.GetInt("INJECT_DELAY_MS"),
		LogLevel:         viper.GetString("LOG_LEVEL"),
	}

	if config.EthereumRPC == "" {
		config.EthereumRPC = "http://localhost:8545" // default mock
	}
	// Set other defaults...

	return config
}

func startGRPCServer(port string, sdk *core.BridgeSDK) {
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Failed to listen on gRPC port %s: %v", port, err)
	}
	s := grpc.NewServer()
	pb.RegisterBridgeServiceServer(s, sdk) // Assuming proto generated pb
	reflection.Register(s)
	log.Printf("gRPC server listening on :%s", port)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("gRPC server failed: %v", err)
	}
}

func startHTTPServer(port string, sdk *core.BridgeSDK) {
	mux := http.NewServeMux()
	// Register REST handlers from core (e.g., /relay, /stats)
	mux.HandleFunc("/relay/eth", sdk.HandleRelayEth)
	mux.HandleFunc("/relay/sol", sdk.HandleRelaySol)
	mux.HandleFunc("/bridge/status", sdk.HandleStatus)
	mux.HandleFunc("/log/retry", sdk.HandleRetryLog)
	mux.HandleFunc("/log/events", sdk.HandleEventLog)
	// Add more...

	// Gateway for gRPC-REST
	ctx := context.Background()
	dopts := []grpc.DialOption{grpc.WithInsecure()}
	mux, cleanup, err := gateway.NewGateway(ctx, gatewayOptions, opts...)
	if err != nil {
		log.Fatalf("Failed to start gateway: %v", err)
	}
	defer cleanup()

	log.Printf("HTTP server listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("HTTP server failed: %v", err)
	}
}

func startMetricsSnapshot(sdk *core.BridgeSDK, path string) {
	ticker := time.NewTicker(30 * time.Second)
	for {
		<-ticker.C
		stats := sdk.GetBridgeStats()
		data, _ := json.MarshalIndent(stats, "", "  ")
		os.WriteFile(path, data, 0644)
	}
}

func waitForShutdown(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("Shutdown signal received")
	cancel()
	time.Sleep(5 * time.Second) // Drain
}