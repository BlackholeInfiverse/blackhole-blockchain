package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/api"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/bridge"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/consensus"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/governance"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/monitoring"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/validation"
)

func main() {
	chain.RegisterGobTypes()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	port := 3000
	if len(os.Args) > 1 {
		fmt.Sscanf(os.Args[1], "%d", &port)
	}

	// Check if running in Docker mode
	dockerMode := os.Getenv("DOCKER_MODE") == "true" || os.Getenv("BLOCKCHAIN_DOCKER") == "true"
	if dockerMode {
		fmt.Println("🐳 BlackHole Blockchain - Docker Mode")
		fmt.Println("=====================================")
	}

	bc, err := chain.NewBlockchain(port)
	if err != nil {
		log.Fatal("Failed to create blockchain:", err)
	}

	// Create a node ID based on port for logging
	nodeID := fmt.Sprintf("node_%d", port)

	fmt.Println("🚀 Your peer multiaddr:")
	fmt.Printf("   /ip4/127.0.0.1/tcp/%d/p2p/%s\n", port, bc.P2PNode.Host.ID())

	if len(os.Args) > 2 {
		for _, addr := range os.Args[2:] {
			if strings.Contains(addr, "12D3KooWKzQh2siF6pAidubw16GrZDhRZqFSeEJFA7BCcKvpopmG") {
				fmt.Println("🚫 Skipping problematic peer:", addr)
				continue
			}
			fmt.Println("🌐 Connecting to:", addr)
			if err := bc.P2PNode.Connect(ctx, addr); err != nil {
				log.Println("❌ Connection failed:", err)
			}
		}
	}

	bc.P2PNode.SetChain(bc)

	// Initialize enhanced monitoring system
	fmt.Println("🔍 Initializing advanced monitoring system...")
	if err := monitoring.InitializeGlobalMonitor(); err != nil {
		log.Printf("⚠️ Warning: Failed to initialize monitoring: %v", err)
	} else {
		fmt.Println("✅ Advanced monitoring system initialized")

		// Record initial metrics
		monitoring.GlobalMonitor.RecordMetric("blockchain_height", monitoring.MetricGauge, float64(len(bc.Blocks)), nil)
		monitoring.GlobalMonitor.RecordMetric("pending_transactions", monitoring.MetricGauge, float64(len(bc.PendingTxs)), nil)
		monitoring.GlobalMonitor.RecordMetric("total_supply", monitoring.MetricGauge, float64(bc.TotalSupply), nil)
	}

	// Initialize E2E validation system
	fmt.Println("🧪 Initializing E2E validation system...")
	if err := validation.InitializeGlobalValidator(); err != nil {
		log.Printf("⚠️ Warning: Failed to initialize E2E validator: %v", err)
	} else {
		fmt.Println("✅ E2E validation system initialized")
	}

	// Initialize governance simulation
	fmt.Println("🏛️ Initializing governance simulation...")
	if err := governance.InitializeGlobalGovernanceSimulator(); err != nil {
		log.Printf("⚠️ Warning: Failed to initialize governance simulator: %v", err)
	} else {
		fmt.Println("✅ Governance simulation initialized")

		// Create a sample governance proposal
		go func() {
			time.Sleep(5 * time.Second) // Wait for system to stabilize
			proposal, err := governance.GlobalGovernanceSimulator.SubmitProposal(
				governance.ProposalParameterChange,
				"Increase Block Reward",
				"Proposal to increase block reward from 10 BHX to 15 BHX to incentivize validators",
				"genesis-validator",
				map[string]interface{}{
					"current_reward":  10,
					"proposed_reward": 15,
					"impact":          "positive",
				},
			)
			if err != nil {
				log.Printf("⚠️ Failed to create sample proposal: %v", err)
			} else {
				fmt.Printf("📝 Sample governance proposal created: %s\n", proposal.Title)

				// Simulate voting after a short delay
				time.Sleep(2 * time.Second)
				governance.GlobalGovernanceSimulator.SimulateVoting(proposal.ID)
			}
		}()
	}

	// Log initial blockchain state
	if err := bc.LogBlockchainState(nodeID); err != nil {
		log.Printf("❌ Failed to log blockchain state: %v", err)
	}

	go bc.SyncChain()

	validator := consensus.NewValidator(bc.StakeLedger)

	// Set up periodic blockchain state logging
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := bc.LogBlockchainState(nodeID); err != nil {
					log.Printf("❌ Failed to log blockchain state: %v", err)
				}
			}
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		// Log final state before exiting
		if err := bc.LogBlockchainState(nodeID); err != nil {
			log.Printf("❌ Failed to log final blockchain state: %v", err)
		}
		cancel()
	}()

	go miningLoop(ctx, bc, validator, nodeID)

	// Create bridge instance
	bridgeInstance := bridge.NewBridge(bc)

	// Start API server for UI
	apiServer := api.NewAPIServer(bc, bridgeInstance, 8080)
	go apiServer.Start()

	// Start CLI only if not in Docker mode
	if !dockerMode {
		startCLI(ctx, bc, nodeID)
	} else {
		fmt.Println("🔄 Running in Docker daemon mode - use Docker logs to monitor")
		fmt.Printf("   P2P Port: %d\n", port)
		fmt.Printf("   HTTP API Port: %d\n", 8080)
		fmt.Println("🌐 Access dashboard at http://localhost:8080")

		// Keep the container running
		<-ctx.Done()
	}
}
func miningLoop(ctx context.Context, bc *chain.Blockchain, validator *consensus.Validator, nodeID string) {
	ticker := time.NewTicker(6 * time.Second) // Optional minimal interval
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if len(bc.GetPendingTransactions()) == 0 {
				fmt.Println("🚫 No pending transactions, skipping block mining")
				continue // 🚫 No transaction, don't mine
			}

			validatorAddr := validator.SelectValidator()
			if validatorAddr == "" {
				log.Println("⚠️ No validator selected")
				continue
			}

			block := bc.MineBlock(validatorAddr)
			if validator.ValidateBlock(block, bc) {
				bc.BroadcastBlock(block)
				time.Sleep(500 * time.Millisecond)

				if bc.AddBlock(block) {
					// Get token system for rewards
					tokenSystem := bc.TokenRegistry["BHX"]
					if tokenSystem == nil {
						log.Printf("❌ BHX token not found in registry")
						return
					}

					// Try to mint block reward (respects max supply)
					err := tokenSystem.Mint(block.Header.Validator, bc.BlockReward)
					if err != nil {
						log.Printf("⚠️ Failed to mint block reward: %v", err)
						// Continue without reward if supply limit reached
					} else {
						log.Printf("💰 Block reward of %d BHX minted to %s", bc.BlockReward, block.Header.Validator)
					}

					// Update stake ledger
					bc.StakeLedger.AddStake(block.Header.Validator, bc.BlockReward)

					log.Printf("✅ Block %d added with %d transactions", block.Header.Index, len(block.Transactions))

					// Record metrics if monitoring is available
					if monitoring.GlobalMonitor != nil {
						monitoring.GlobalMonitor.RecordMetric("blocks_mined", monitoring.MetricCounter, 1, map[string]string{
							"validator": block.Header.Validator,
							"node_id":   nodeID,
						})
						monitoring.GlobalMonitor.RecordMetric("blockchain_height", monitoring.MetricGauge, float64(len(bc.Blocks)), nil)
						monitoring.GlobalMonitor.RecordMetric("pending_transactions", monitoring.MetricGauge, float64(len(bc.PendingTxs)), nil)
						monitoring.GlobalMonitor.RecordMetric("total_supply", monitoring.MetricGauge, float64(bc.TotalSupply), nil)
						monitoring.GlobalMonitor.RecordMetric("transactions_per_block", monitoring.MetricGauge, float64(len(block.Transactions)), nil)

						// Trigger alert for high transaction volume
						if len(block.Transactions) > 50 {
							monitoring.GlobalMonitor.TriggerAlert(
								monitoring.AlertWarning,
								"High Transaction Volume",
								fmt.Sprintf("Block %d contains %d transactions", block.Header.Index, len(block.Transactions)),
								"mining_system",
								map[string]interface{}{
									"block_index": block.Header.Index,
									"tx_count":    len(block.Transactions),
								},
							)
						}
					}
				}
			}
		}
	}
}

func startCLI(ctx context.Context, bc *chain.Blockchain, nodeID string) {
	fmt.Println("🖥️ BlackHole Blockchain CLI - Enhanced Edition")
	fmt.Println("Available commands:")
	fmt.Println("  status     - Show blockchain status")
	fmt.Println("  log        - Log blockchain state to file")
	fmt.Println("  list       - List all blockchain state files")
	fmt.Println("  compare    - Compare blockchain states from two files")
	fmt.Println("  monitor    - Show monitoring metrics and alerts")
	fmt.Println("  validate   - Run E2E validation tests")
	fmt.Println("  governance - Show governance proposals and voting")
	fmt.Println("  proposal   - Create a new governance proposal")
	fmt.Println("  vote       - Vote on a governance proposal")
	fmt.Println("  exit       - Shutdown node")

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			return
		}

		switch scanner.Text() {
		case "status":
			fmt.Println("📊 Blockchain Status")
			fmt.Printf("  Block height       : %d\n", len(bc.Blocks))
			fmt.Printf("  Pending Tx count   : %d\n", len(bc.PendingTxs))
			fmt.Printf("  Total Supply       : %d BHX\n", bc.TotalSupply)
			fmt.Printf("  Latest Block Hash  : %s\n", bc.Blocks[len(bc.Blocks)-1].CalculateHash())
		case "log":
			fmt.Println("📝 Logging blockchain state...")
			if err := bc.LogBlockchainState(nodeID); err != nil {
				fmt.Printf("❌ Error: %v\n", err)
			} else {
				fmt.Println("✅ Blockchain state logged successfully")
			}
		case "list":
			fmt.Println("📋 Listing blockchain state files:")
			files, err := chain.ListBlockchainStateFiles()
			if err != nil {
				fmt.Printf("❌ Error: %v\n", err)
			} else if len(files) == 0 {
				fmt.Println("No blockchain state files found")
			} else {
				for i, file := range files {
					fmt.Printf("%d. %s\n", i+1, file)
				}
			}
		case "compare":
			// First list all available files
			files, err := chain.ListBlockchainStateFiles()
			if err != nil {
				fmt.Printf("❌ Error listing blockchain state files: %v\n", err)
				continue
			}
			if len(files) < 2 {
				fmt.Println("❌ Need at least 2 blockchain state files to compare")
				continue
			}

			fmt.Println("� Available blockchain state files:")
			for i, file := range files {
				fmt.Printf("%d. %s\n", i+1, file)
			}

			// Get first file selection
			fmt.Println("🔍 Enter number of first blockchain state file:")
			scanner.Scan()
			fileNum1 := scanner.Text()
			idx1, err := strconv.Atoi(fileNum1)
			if err != nil || idx1 < 1 || idx1 > len(files) {
				fmt.Println("❌ Invalid file number")
				continue
			}

			// Get second file selection
			fmt.Println("🔍 Enter number of second blockchain state file:")
			scanner.Scan()
			fileNum2 := scanner.Text()
			idx2, err := strconv.Atoi(fileNum2)
			if err != nil || idx2 < 1 || idx2 > len(files) {
				fmt.Println("❌ Invalid file number")
				continue
			}

			// Compare the selected files
			result, err := chain.CompareBlockchainStates(files[idx1-1], files[idx2-1])
			if err != nil {
				fmt.Printf("❌ Error comparing blockchain states: %v\n", err)
			} else {
				fmt.Println(result)
			}
		case "monitor":
			fmt.Println("📊 Monitoring Dashboard")
			if monitoring.GlobalMonitor != nil {
				// Show recent metrics
				metrics := monitoring.GlobalMonitor.GetMetrics()
				fmt.Printf("📈 Current Metrics (%d total):\n", len(metrics))
				for name, metric := range metrics {
					fmt.Printf("  %s: %.2f (%s)\n", name, metric.Value, metric.Type)
				}

				// Show recent alerts
				alerts := monitoring.GlobalMonitor.GetAlerts()
				activeAlerts := 0
				for _, alert := range alerts {
					if !alert.Resolved {
						activeAlerts++
					}
				}
				fmt.Printf("🚨 Active Alerts: %d\n", activeAlerts)

				// Show performance stats
				perfStats := monitoring.GlobalMonitor.GetPerformanceStats(5)
				if len(perfStats) > 0 {
					latest := perfStats[len(perfStats)-1]
					fmt.Printf("⚡ Performance (latest):\n")
					fmt.Printf("  CPU Usage: %.1f%%\n", latest.CPUUsage)
					fmt.Printf("  Memory Usage: %.1f%%\n", latest.MemoryUsage)
					fmt.Printf("  Transaction TPS: %.1f\n", latest.TransactionTPS)
					fmt.Printf("  Block Time: %v\n", latest.BlockTime)
				}
			} else {
				fmt.Println("❌ Monitoring system not available")
			}

		case "validate":
			fmt.Println("🧪 Running E2E Validation Tests...")
			if validation.GlobalValidator != nil {
				results, err := validation.GlobalValidator.RunAllTests(ctx)
				if err != nil {
					fmt.Printf("❌ Validation failed: %v\n", err)
				} else {
					fmt.Printf("✅ Validation completed: %d tests run\n", len(results))
				}
			} else {
				fmt.Println("❌ E2E validation system not available")
			}

		case "governance":
			fmt.Println("🏛️ Governance Dashboard")
			if governance.GlobalGovernanceSimulator != nil {
				proposals := governance.GlobalGovernanceSimulator.GetProposals()
				fmt.Printf("📝 Active Proposals (%d total):\n", len(proposals))
				for _, proposal := range proposals {
					fmt.Printf("  %s: %s (%s)\n", proposal.ID, proposal.Title, proposal.Status)
					fmt.Printf("    Type: %s | Proposer: %s\n", proposal.Type, proposal.Proposer)
					if len(proposal.Votes) > 0 {
						fmt.Printf("    Votes: %d\n", len(proposal.Votes))
					}
				}

				validators := governance.GlobalGovernanceSimulator.GetValidators()
				fmt.Printf("👥 Validators (%d total):\n", len(validators))
				for _, validator := range validators {
					status := "🔴 Inactive"
					if validator.Active {
						status = "🟢 Active"
					}
					fmt.Printf("  %s: %s (Power: %d, Rep: %.2f)\n",
						validator.Name, status, validator.VotingPower, validator.Reputation)
				}
			} else {
				fmt.Println("❌ Governance system not available")
			}

		case "proposal":
			fmt.Println("📝 Create New Governance Proposal")
			if governance.GlobalGovernanceSimulator != nil {
				fmt.Print("Enter proposal title: ")
				scanner.Scan()
				title := scanner.Text()

				fmt.Print("Enter proposal description: ")
				scanner.Scan()
				description := scanner.Text()

				fmt.Println("Select proposal type:")
				fmt.Println("1. Parameter Change")
				fmt.Println("2. Upgrade")
				fmt.Println("3. Treasury")
				fmt.Println("4. Validator")
				fmt.Println("5. Emergency")
				fmt.Print("Enter choice (1-5): ")
				scanner.Scan()
				choice := scanner.Text()

				var proposalType governance.ProposalType
				switch choice {
				case "1":
					proposalType = governance.ProposalParameterChange
				case "2":
					proposalType = governance.ProposalUpgrade
				case "3":
					proposalType = governance.ProposalTreasury
				case "4":
					proposalType = governance.ProposalValidator
				case "5":
					proposalType = governance.ProposalEmergency
				default:
					fmt.Println("❌ Invalid choice")
					continue
				}

				proposal, err := governance.GlobalGovernanceSimulator.SubmitProposal(
					proposalType, title, description, "cli-user", nil)
				if err != nil {
					fmt.Printf("❌ Failed to create proposal: %v\n", err)
				} else {
					fmt.Printf("✅ Proposal created: %s\n", proposal.ID)
				}
			} else {
				fmt.Println("❌ Governance system not available")
			}

		case "vote":
			fmt.Println("🗳️ Vote on Governance Proposal")
			if governance.GlobalGovernanceSimulator != nil {
				proposals := governance.GlobalGovernanceSimulator.GetProposals()
				if len(proposals) == 0 {
					fmt.Println("❌ No proposals available")
					continue
				}

				fmt.Println("Available proposals:")
				i := 1
				proposalIDs := make([]string, 0)
				for id, proposal := range proposals {
					if proposal.Status == governance.StatusActive {
						fmt.Printf("%d. %s: %s\n", i, id, proposal.Title)
						proposalIDs = append(proposalIDs, id)
						i++
					}
				}

				if len(proposalIDs) == 0 {
					fmt.Println("❌ No active proposals available for voting")
					continue
				}

				fmt.Print("Enter proposal number: ")
				scanner.Scan()
				choice := scanner.Text()
				idx, err := strconv.Atoi(choice)
				if err != nil || idx < 1 || idx > len(proposalIDs) {
					fmt.Println("❌ Invalid proposal number")
					continue
				}

				fmt.Println("Vote options:")
				fmt.Println("1. Yes")
				fmt.Println("2. No")
				fmt.Println("3. Abstain")
				fmt.Println("4. No with Veto")
				fmt.Print("Enter vote (1-4): ")
				scanner.Scan()
				voteChoice := scanner.Text()

				var voteOption governance.VoteOption
				switch voteChoice {
				case "1":
					voteOption = governance.VoteYes
				case "2":
					voteOption = governance.VoteNo
				case "3":
					voteOption = governance.VoteAbstain
				case "4":
					voteOption = governance.VoteNoWithVeto
				default:
					fmt.Println("❌ Invalid vote option")
					continue
				}

				err = governance.GlobalGovernanceSimulator.CastVote(
					proposalIDs[idx-1], "cli-validator", voteOption)
				if err != nil {
					fmt.Printf("❌ Failed to cast vote: %v\n", err)
				} else {
					fmt.Printf("✅ Vote cast: %s\n", voteOption)
				}
			} else {
				fmt.Println("❌ Governance system not available")
			}

		case "exit":
			fmt.Println("👋 Shutting down enhanced systems...")

			// Gracefully shutdown enhanced systems
			if monitoring.GlobalMonitor != nil {
				monitoring.GlobalMonitor.Stop()
			}
			if governance.GlobalGovernanceSimulator != nil {
				governance.GlobalGovernanceSimulator.Stop()
			}

			fmt.Println("👋 Shutting down...")
			os.Exit(0)
		default:
			fmt.Println("❓ Unknown command")
		}
	}
}
func MineOnce(ctx context.Context, bc *chain.Blockchain, validator *consensus.Validator, nodeID string) {
	validatorAddr := validator.SelectValidator()
	if validatorAddr == "" {
		log.Println("⚠️ No validator selected")
		return
	}

	block := bc.MineBlock(validatorAddr)
	if validator.ValidateBlock(block, bc) {
		// First broadcast the block
		bc.BroadcastBlock(block)

		// Wait longer to allow network propagation and processing by other nodes
		// This reduces the chance of forks by giving other nodes time to receive
		// and process our block before we add it to our own chain
		fmt.Printf("⏳ Waiting for block propagation...\n")
		time.Sleep(500 * time.Millisecond)

		// Then try to add it to our chain
		if bc.AddBlock(block) {
			// Try to mint block reward (respects max supply)
			tokenSystem := bc.TokenRegistry["BHX"]
			if tokenSystem != nil {
				err := tokenSystem.Mint(block.Header.Validator, bc.BlockReward)
				if err != nil {
					log.Printf("⚠️ Failed to mint block reward: %v", err)
				} else {
					log.Printf("💰 Block reward of %d BHX minted to %s", bc.BlockReward, block.Header.Validator)
				}
			}

			// Update stake ledger
			bc.StakeLedger.AddStake(block.Header.Validator, bc.BlockReward)

			log.Println("=====================================")
			log.Printf("✅ Block %d added successfully", block.Header.Index)
			log.Printf("🕒 Timestamp     : %s", block.Header.Timestamp.Format(time.RFC3339))
			log.Printf("🔗 PreviousHash  : %s", block.Header.PreviousHash)
			log.Printf("🔐 Current Hash  : %s", block.CalculateHash())
			// Display transaction details...
			log.Println("=====================================")

			// Log blockchain state after mining a block
			if err := bc.LogBlockchainState(nodeID); err != nil {
				log.Printf("❌ Failed to log blockchain state after mining: %v", err)
			}
		} else {
			log.Printf("⚠️ Failed to add our own mined block %d to chain", block.Header.Index)
		}
	} else {
		log.Printf("❌ Failed to validate block %d", block.Header.Index)
	}
}
func startCLI1(ctx context.Context, bc *chain.Blockchain, validator *consensus.Validator, nodeID string) {
	fmt.Println("🖥️ BlackHole Blockchain CLI")
	fmt.Println("Available commands:")
	fmt.Println("  status  - Show blockchain status")
	fmt.Println("  mine    - Manually mine a block")
	fmt.Println("  log     - Log blockchain state to file")
	fmt.Println("  list    - List all blockchain state files")
	fmt.Println("  compare - Compare blockchain states from two files")
	fmt.Println("  exit    - Shutdown node")

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			return
		}

		switch scanner.Text() {
		case "status":
			fmt.Println("📊 Blockchain Status")
			fmt.Printf("  Block height       : %d\n", len(bc.Blocks))
			fmt.Printf("  Pending Tx count   : %d\n", len(bc.PendingTxs))
			fmt.Printf("  Total Supply       : %d BHX\n", bc.TotalSupply)
			fmt.Printf("  Latest Block Hash  : %s\n", bc.Blocks[len(bc.Blocks)-1].CalculateHash())
		case "mine":
			fmt.Println("⛏️ Mining new block...")
			MineOnce(ctx, bc, validator, nodeID)
		case "log":
			fmt.Println("📝 Logging blockchain state...")
			if err := bc.LogBlockchainState(nodeID); err != nil {
				fmt.Printf("❌ Error: %v\n", err)
			} else {
				fmt.Println("✅ Blockchain state logged successfully")
			}
		case "list":
			fmt.Println("📋 Listing blockchain state files:")
			files, err := chain.ListBlockchainStateFiles()
			if err != nil {
				fmt.Printf("❌ Error: %v\n", err)
			} else if len(files) == 0 {
				fmt.Println("No blockchain state files found")
			} else {
				for i, file := range files {
					fmt.Printf("%d. %s\n", i+1, file)
				}
			}
		case "compare":
			// First list all available files
			files, err := chain.ListBlockchainStateFiles()
			if err != nil {
				fmt.Printf("❌ Error listing blockchain state files: %v\n", err)
				continue
			}
			if len(files) < 2 {
				fmt.Println("❌ Need at least 2 blockchain state files to compare")
				continue
			}

			fmt.Println("� Available blockchain state files:")
			for i, file := range files {
				fmt.Printf("%d. %s\n", i+1, file)
			}

			// Get first file selection
			fmt.Println("🔍 Enter number of first blockchain state file:")
			scanner.Scan()
			fileNum1 := scanner.Text()
			idx1, err := strconv.Atoi(fileNum1)
			if err != nil || idx1 < 1 || idx1 > len(files) {
				fmt.Println("❌ Invalid file number")
				continue
			}

			// Get second file selection
			fmt.Println("🔍 Enter number of second blockchain state file:")
			scanner.Scan()
			fileNum2 := scanner.Text()
			idx2, err := strconv.Atoi(fileNum2)
			if err != nil || idx2 < 1 || idx2 > len(files) {
				fmt.Println("❌ Invalid file number")
				continue
			}

			// Compare the selected files
			result, err := chain.CompareBlockchainStates(files[idx1-1], files[idx2-1])
			if err != nil {
				fmt.Printf("❌ Error comparing blockchain states: %v\n", err)
			} else {
				fmt.Println(result)
			}
		case "exit":
			fmt.Println("👋 Shutting down...")
			os.Exit(0)
		default:
			fmt.Println("❓ Unknown command")
		}
	}
}
