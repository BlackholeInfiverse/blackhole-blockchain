package chain

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// BlockchainState represents the state of the blockchain for logging
type BlockchainState struct {
	NodeID        string    `json:"node_id"`
	BlockHeight   int       `json:"block_height"`
	LatestBlock   *Block    `json:"latest_block"`
	PendingBlocks int       `json:"pending_blocks"`
	TotalSupply   uint64    `json:"total_supply"`
	Timestamp     time.Time `json:"timestamp"`
	ForkInfo      *ForkInfo `json:"fork_info,omitempty"`
	BlockHashes   []string  `json:"block_hashes"`
}

// ForkInfo contains information about potential forks
type ForkInfo struct {
	HasFork            bool     `json:"has_fork"`
	ForkHeight         uint64   `json:"fork_height,omitempty"`
	CompetingBlockHash string   `json:"competing_block_hash,omitempty"`
	MainChainBlockHash string   `json:"main_chain_block_hash,omitempty"`
	Reason             string   `json:"reason,omitempty"`
	ForkPoints         []uint64 `json:"fork_points,omitempty"`
	ForkBlocks         []string `json:"fork_blocks,omitempty"`
}

func (bc *Blockchain) LogBlockchainState(nodeID string) error {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	// Create logs directory if it doesn't exist
	logsDir := "blockchain_logs"
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return fmt.Errorf("failed to create logs directory: %v", err)
	}

	state := BlockchainState{
		NodeID:        nodeID,
		PendingBlocks: len(bc.pendingBlocks),
		TotalSupply:   bc.TotalSupply,
		Timestamp:     time.Now(),
		BlockHashes:   make([]string, 0, len(bc.Blocks)),
	}

	if len(bc.Blocks) > 0 {
		latest := bc.Blocks[len(bc.Blocks)-1]
		state.LatestBlock = latest
		state.BlockHeight = int(latest.Header.Index + 1)
	}

	for _, block := range bc.Blocks {
		state.BlockHashes = append(state.BlockHashes, block.Hash)
	}

	state.ForkInfo = bc.detectForks()

	filename := filepath.Join(logsDir, fmt.Sprintf("blockchain_state_%s.json", nodeID))

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal blockchain state: %v", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write blockchain state: %v", err)
	}

	fmt.Printf("📝 Blockchain state updated at %s\n", filename)
	return nil
}

// detectForks checks if there are any potential forks in the blockchain
func (bc *Blockchain) detectForks() *ForkInfo {
	forkInfo := &ForkInfo{
		HasFork:    false,
		ForkPoints: []uint64{},
		ForkBlocks: []string{},
	}

	// Check for pending blocks (potential forks)
	if len(bc.pendingBlocks) > 0 {
		forkInfo.Reason = "Pending blocks exist"

		// Check for blocks at the same height as existing blocks
		for _, pendingBlock := range bc.pendingBlocks {
			for _, block := range bc.Blocks {
				if block.Header.Index == pendingBlock.Header.Index {
					forkInfo.HasFork = true
					forkInfo.ForkHeight = block.Header.Index
					forkInfo.CompetingBlockHash = pendingBlock.Hash
					forkInfo.MainChainBlockHash = block.Hash
					forkInfo.Reason = "Competing blocks at same height"
					forkInfo.ForkPoints = append(forkInfo.ForkPoints, block.Header.Index)
					forkInfo.ForkBlocks = append(forkInfo.ForkBlocks,
						fmt.Sprintf("Main: %s, Competing: %s", block.Hash, pendingBlock.Hash))
				}
			}
		}
	}

	// Check for gaps in the blockchain
	for i := 1; i < len(bc.Blocks); i++ {
		if bc.Blocks[i].Header.Index != bc.Blocks[i-1].Header.Index+1 {
			forkInfo.HasFork = true
			if forkInfo.ForkHeight == 0 { // Only set if not already set
				forkInfo.ForkHeight = bc.Blocks[i-1].Header.Index
			}
			forkInfo.Reason = fmt.Sprintf("%s; Gap in blockchain between blocks %d and %d",
				forkInfo.Reason, bc.Blocks[i-1].Header.Index, bc.Blocks[i].Header.Index)
			forkInfo.ForkPoints = append(forkInfo.ForkPoints, bc.Blocks[i-1].Header.Index)
		}
	}

	// Check for inconsistent previous hashes
	for i := 1; i < len(bc.Blocks); i++ {
		if bc.Blocks[i].Header.PreviousHash != bc.Blocks[i-1].Hash {
			forkInfo.HasFork = true
			if forkInfo.ForkHeight == 0 { // Only set if not already set
				forkInfo.ForkHeight = bc.Blocks[i].Header.Index
			}
			if forkInfo.MainChainBlockHash == "" { // Only set if not already set
				forkInfo.MainChainBlockHash = bc.Blocks[i].Hash
			}
			forkInfo.Reason = fmt.Sprintf("%s; Inconsistent previous hash at block %d",
				forkInfo.Reason, bc.Blocks[i].Header.Index)
			forkInfo.ForkPoints = append(forkInfo.ForkPoints, bc.Blocks[i].Header.Index)
			forkInfo.ForkBlocks = append(forkInfo.ForkBlocks,
				fmt.Sprintf("Block %d hash: %s, Previous block hash: %s, Expected previous hash: %s",
					bc.Blocks[i].Header.Index, bc.Blocks[i].Hash,
					bc.Blocks[i].Header.PreviousHash, bc.Blocks[i-1].Hash))
		}
	}

	// Check for blocks with same index but different hashes in the main chain
	// This is a more subtle form of fork that might not be detected by other checks
	indexMap := make(map[uint64][]string)
	for _, block := range bc.Blocks {
		indexMap[block.Header.Index] = append(indexMap[block.Header.Index], block.Hash)
	}

	for idx, hashes := range indexMap {
		if len(hashes) > 1 {
			forkInfo.HasFork = true
			if forkInfo.ForkHeight == 0 { // Only set if not already set
				forkInfo.ForkHeight = idx
			}
			forkInfo.Reason = fmt.Sprintf("%s; Multiple blocks at index %d",
				forkInfo.Reason, idx)
			forkInfo.ForkPoints = append(forkInfo.ForkPoints, idx)
			forkInfo.ForkBlocks = append(forkInfo.ForkBlocks,
				fmt.Sprintf("Multiple blocks at index %d: %v", idx, hashes))
		}
	}

	if !forkInfo.HasFork {
		forkInfo.Reason = "No forks detected"
	}

	return forkInfo
}

// CompareBlockchainStates compares two blockchain state files and returns differences
func CompareBlockchainStates(file1, file2 string) (string, error) {
	// Read the first file
	data1, err := os.ReadFile(file1)
	if err != nil {
		return "", fmt.Errorf("failed to read file1: %v", err)
	}

	// Read the second file
	data2, err := os.ReadFile(file2)
	if err != nil {
		return "", fmt.Errorf("failed to read file2: %v", err)
	}

	// Unmarshal the first file
	var state1 BlockchainState
	if err := json.Unmarshal(data1, &state1); err != nil {
		return "", fmt.Errorf("failed to unmarshal file1: %v", err)
	}

	// Unmarshal the second file
	var state2 BlockchainState
	if err := json.Unmarshal(data2, &state2); err != nil {
		return "", fmt.Errorf("failed to unmarshal file2: %v", err)
	}

	// Compare the states
	var result strings.Builder
	result.WriteString(fmt.Sprintf("Comparing blockchain states:\n"))
	result.WriteString(fmt.Sprintf("Node 1: %s (Height: %d)\n", state1.NodeID, state1.BlockHeight))
	result.WriteString(fmt.Sprintf("Node 2: %s (Height: %d)\n", state2.NodeID, state2.BlockHeight))
	result.WriteString("\n")

	// Compare block heights
	if state1.BlockHeight != state2.BlockHeight {
		result.WriteString(fmt.Sprintf("❌ Block heights differ: %d vs %d\n", state1.BlockHeight, state2.BlockHeight))
	} else {
		result.WriteString(fmt.Sprintf("✅ Block heights match: %d\n", state1.BlockHeight))
	}

	// Compare block hashes
	minHeight := state1.BlockHeight
	if state2.BlockHeight < minHeight {
		minHeight = state2.BlockHeight
	}

	for i := 0; i < minHeight; i++ {
		if i < len(state1.BlockHashes) && i < len(state2.BlockHashes) {
			if state1.BlockHashes[i] != state2.BlockHashes[i] {
				result.WriteString(fmt.Sprintf("❌ Block %d hashes differ:\n", i))
				result.WriteString(fmt.Sprintf("   Node 1: %s\n", state1.BlockHashes[i]))
				result.WriteString(fmt.Sprintf("   Node 2: %s\n", state2.BlockHashes[i]))
			}
		}
	}

	// Check for forks
	if (state1.ForkInfo != nil && state1.ForkInfo.HasFork) || (state2.ForkInfo != nil && state2.ForkInfo.HasFork) {
		result.WriteString("\n🔍 Fork information:\n")

		if state1.ForkInfo != nil && state1.ForkInfo.HasFork {
			result.WriteString(fmt.Sprintf("Node 1 (%s) reports fork at height %d: %s\n",
				state1.NodeID, state1.ForkInfo.ForkHeight, state1.ForkInfo.Reason))

			if len(state1.ForkInfo.ForkPoints) > 0 {
				result.WriteString("  Fork points: ")
				for i, point := range state1.ForkInfo.ForkPoints {
					if i > 0 {
						result.WriteString(", ")
					}
					result.WriteString(fmt.Sprintf("%d", point))
				}
				result.WriteString("\n")
			}

			if len(state1.ForkInfo.ForkBlocks) > 0 {
				result.WriteString("  Fork details:\n")
				for _, detail := range state1.ForkInfo.ForkBlocks {
					result.WriteString(fmt.Sprintf("    - %s\n", detail))
				}
			}
		}

		if state2.ForkInfo != nil && state2.ForkInfo.HasFork {
			result.WriteString(fmt.Sprintf("Node 2 (%s) reports fork at height %d: %s\n",
				state2.NodeID, state2.ForkInfo.ForkHeight, state2.ForkInfo.Reason))

			if len(state2.ForkInfo.ForkPoints) > 0 {
				result.WriteString("  Fork points: ")
				for i, point := range state2.ForkInfo.ForkPoints {
					if i > 0 {
						result.WriteString(", ")
					}
					result.WriteString(fmt.Sprintf("%d", point))
				}
				result.WriteString("\n")
			}

			if len(state2.ForkInfo.ForkBlocks) > 0 {
				result.WriteString("  Fork details:\n")
				for _, detail := range state2.ForkInfo.ForkBlocks {
					result.WriteString(fmt.Sprintf("    - %s\n", detail))
				}
			}
		}

		// Analyze fork points between the two nodes
		if state1.BlockHeight > 0 && state2.BlockHeight > 0 {
			result.WriteString("\n🔍 Fork analysis between nodes:\n")

			// Find the first divergence point
			minHeight := state1.BlockHeight
			if state2.BlockHeight < minHeight {
				minHeight = state2.BlockHeight
			}

			divergencePoint := -1
			for i := 0; i < minHeight; i++ {
				if i < len(state1.BlockHashes) && i < len(state2.BlockHashes) {
					if state1.BlockHashes[i] != state2.BlockHashes[i] {
						divergencePoint = i
						break
					}
				}
			}

			if divergencePoint >= 0 {
				result.WriteString(fmt.Sprintf("  ❌ Chains diverge at block %d\n", divergencePoint))
				if divergencePoint > 0 {
					result.WriteString(fmt.Sprintf("  ✅ Chains are identical up to block %d\n", divergencePoint-1))
				}
			} else {
				result.WriteString(fmt.Sprintf("  ✅ Chains are identical up to block %d\n", minHeight-1))
				if state1.BlockHeight != state2.BlockHeight {
					result.WriteString(fmt.Sprintf("  ⚠️ One chain is longer than the other\n"))
				}
			}
		}
	} else {
		result.WriteString("\n✅ No forks detected in either node\n")
	}

	return result.String(), nil
}

// ListBlockchainStateFiles lists all available blockchain state files
func ListBlockchainStateFiles() ([]string, error) {
	logsDir := "blockchain_logs"
	if _, err := os.Stat(logsDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("blockchain_logs directory does not exist")
	}

	files, err := os.ReadDir(logsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read blockchain_logs directory: %v", err)
	}

	var stateFiles []string
	for _, file := range files {
		if !file.IsDir() && strings.HasPrefix(file.Name(), "blockchain_state_") && strings.HasSuffix(file.Name(), ".json") {
			stateFiles = append(stateFiles, filepath.Join(logsDir, file.Name()))
		}
	}

	return stateFiles, nil
}
