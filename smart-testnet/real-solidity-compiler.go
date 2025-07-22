package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Import types from main file to avoid redeclaration
// SmartContract, ContractFunction, ContractEvent, Parameter are defined in real-wallet-smart-testnet.go

// RealSolidityCompiler integrates with the actual Solidity compiler
type RealSolidityCompiler struct {
	SolcPath  string
	TempDir   string
	OutputDir string
}

// SolcOutput represents the output from the Solidity compiler
type SolcOutput struct {
	Contracts map[string]map[string]SolcContract `json:"contracts"`
	Errors    []SolcError                        `json:"errors"`
	Sources   map[string]SolcSource              `json:"sources"`
}

// SolcContract represents a compiled contract
type SolcContract struct {
	ABI      []interface{} `json:"abi"`
	Bytecode struct {
		Object string `json:"object"`
	} `json:"evm"`
	Metadata string `json:"metadata"`
}

// SolcError represents a compiler error
type SolcError struct {
	Type           string `json:"type"`
	Component      string `json:"component"`
	Severity       string `json:"severity"`
	Message        string `json:"message"`
	SourceLocation struct {
		File  string `json:"file"`
		Start int    `json:"start"`
		End   int    `json:"end"`
	} `json:"sourceLocation"`
	FormattedMessage string `json:"formattedMessage"`
}

// SolcSource represents source information
type SolcSource struct {
	ID  int         `json:"id"`
	AST interface{} `json:"ast"`
}

// NewRealSolidityCompiler creates a new real Solidity compiler
func NewRealSolidityCompiler() (*RealSolidityCompiler, error) {
	// Try to find solc in common locations
	solcPaths := []string{
		"solc",
		"/usr/bin/solc",
		"/usr/local/bin/solc",
		"C:\\Program Files\\solc\\solc.exe",
		"C:\\solc\\solc.exe",
		"./solc.exe",
		"./solc",
	}

	var solcPath string
	for _, path := range solcPaths {
		if _, err := exec.LookPath(path); err == nil {
			solcPath = path
			break
		}
		if _, err := os.Stat(path); err == nil {
			solcPath = path
			break
		}
	}

	if solcPath == "" {
		return nil, fmt.Errorf("solidity compiler (solc) not found. Please install Solidity compiler")
	}

	// Create temp directory
	tempDir, err := ioutil.TempDir("", "solidity_compile_")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %v", err)
	}

	compiler := &RealSolidityCompiler{
		SolcPath:  solcPath,
		TempDir:   tempDir,
		OutputDir: "./compiled-contracts",
	}

	// Test compiler
	if err := compiler.testCompiler(); err != nil {
		return nil, fmt.Errorf("solidity compiler test failed: %v", err)
	}

	log.Printf("✅ Real Solidity compiler initialized: %s", solcPath)
	return compiler, nil
}

// testCompiler tests if the Solidity compiler is working
func (rsc *RealSolidityCompiler) testCompiler() error {
	cmd := exec.Command(rsc.SolcPath, "--version")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to run solc --version: %v", err)
	}

	version := strings.TrimSpace(string(output))
	log.Printf("🔧 Solidity compiler version: %s", version)
	return nil
}

// CompileContract compiles a Solidity contract using the real compiler
func (rsc *RealSolidityCompiler) CompileContract(sourceCode, contractName string) (*SmartContract, error) {
	// Create temporary source file
	sourceFile := filepath.Join(rsc.TempDir, contractName+".sol")
	if err := ioutil.WriteFile(sourceFile, []byte(sourceCode), 0644); err != nil {
		return nil, fmt.Errorf("failed to write source file: %v", err)
	}

	// Compile with solc
	cmd := exec.Command(rsc.SolcPath,
		"--combined-json", "abi,bin,metadata",
		"--optimize",
		sourceFile,
	)

	output, err := cmd.Output()
	if err != nil {
		// Try to get error details
		if exitError, ok := err.(*exec.ExitError); ok {
			errorOutput := string(exitError.Stderr)
			return nil, fmt.Errorf("compilation failed:\n%s", errorOutput)
		}
		return nil, fmt.Errorf("compilation failed: %v", err)
	}

	// Parse compiler output
	var solcOutput SolcOutput
	if err := json.Unmarshal(output, &solcOutput); err != nil {
		return nil, fmt.Errorf("failed to parse compiler output: %v", err)
	}

	// Check for errors
	var errors []string
	var warnings []string

	for _, solcErr := range solcOutput.Errors {
		if solcErr.Severity == "error" {
			errors = append(errors, solcErr.FormattedMessage)
		} else if solcErr.Severity == "warning" {
			warnings = append(warnings, solcErr.FormattedMessage)
		}
	}

	if len(errors) > 0 {
		return nil, fmt.Errorf("compilation errors:\n%s", strings.Join(errors, "\n"))
	}

	// Find the contract in the output
	var contract SolcContract
	var found bool

	for fileName, contracts := range solcOutput.Contracts {
		for contractNameInFile, contractData := range contracts {
			if contractNameInFile == contractName || strings.Contains(fileName, contractName) {
				contract = contractData
				found = true
				break
			}
		}
		if found {
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("contract '%s' not found in compilation output", contractName)
	}

	// Convert ABI to string
	abiBytes, err := json.Marshal(contract.ABI)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ABI: %v", err)
	}

	// Parse functions and events from ABI
	functions, events := rsc.parseABI(contract.ABI)

	// Create smart contract object
	smartContract := &SmartContract{
		Address:   rsc.generateContractAddress(contractName),
		Code:      "0x" + contract.Bytecode.Object,
		ABI:       string(abiBytes),
		Creator:   "",
		CreatedAt: time.Now(),
		State:     make(map[string]interface{}),
		Functions: functions,
		Events:    events,
		TxHistory: make([]string, 0),
	}

	// Log warnings if any
	if len(warnings) > 0 {
		log.Printf("⚠️ Compilation warnings for %s:\n%s", contractName, strings.Join(warnings, "\n"))
	}

	log.Printf("✅ Real Solidity compilation successful: %s", contractName)
	return smartContract, nil
}

// parseABI parses the ABI to extract functions and events
func (rsc *RealSolidityCompiler) parseABI(abi []interface{}) ([]ContractFunction, []ContractEvent) {
	var functions []ContractFunction
	var events []ContractEvent

	for _, item := range abi {
		if abiItem, ok := item.(map[string]interface{}); ok {
			itemType, _ := abiItem["type"].(string)
			name, _ := abiItem["name"].(string)

			switch itemType {
			case "function", "constructor":
				function := ContractFunction{
					Name:       name,
					Type:       itemType,
					Inputs:     rsc.parseABIParameters(abiItem["inputs"]),
					Outputs:    rsc.parseABIParameters(abiItem["outputs"]),
					Visibility: "public", // Default, real visibility parsing would be more complex
					Mutability: rsc.getStateMutability(abiItem),
				}
				functions = append(functions, function)

			case "event":
				event := ContractEvent{
					Name:   name,
					Inputs: rsc.parseABIParameters(abiItem["inputs"]),
				}
				events = append(events, event)
			}
		}
	}

	return functions, events
}

// parseABIParameters parses ABI parameters
func (rsc *RealSolidityCompiler) parseABIParameters(params interface{}) []Parameter {
	var parameters []Parameter

	if paramList, ok := params.([]interface{}); ok {
		for _, param := range paramList {
			if paramMap, ok := param.(map[string]interface{}); ok {
				name, _ := paramMap["name"].(string)
				paramType, _ := paramMap["type"].(string)

				parameters = append(parameters, Parameter{
					Name: name,
					Type: paramType,
				})
			}
		}
	}

	return parameters
}

// getStateMutability gets the state mutability from ABI
func (rsc *RealSolidityCompiler) getStateMutability(abiItem map[string]interface{}) string {
	if mutability, ok := abiItem["stateMutability"].(string); ok {
		return mutability
	}

	// Fallback for older ABI format
	if constant, ok := abiItem["constant"].(bool); ok && constant {
		return "view"
	}

	if payable, ok := abiItem["payable"].(bool); ok && payable {
		return "payable"
	}

	return "nonpayable"
}

// generateContractAddress generates a contract address
func (rsc *RealSolidityCompiler) generateContractAddress(contractName string) string {
	timestamp := time.Now().UnixNano()
	return fmt.Sprintf("0x%x", timestamp)[:42] // Simulate contract address
}

// Cleanup cleans up temporary files
func (rsc *RealSolidityCompiler) Cleanup() {
	if rsc.TempDir != "" {
		os.RemoveAll(rsc.TempDir)
	}
}

// InstallSolidity provides instructions for installing Solidity
func InstallSolidity() string {
	return `
To use the real Solidity compiler, please install it:

Windows:
1. Download from: https://github.com/ethereum/solidity/releases
2. Extract solc.exe to your PATH or current directory

Linux/macOS:
1. npm install -g solc
   OR
2. brew install solidity (macOS)
   OR  
3. sudo apt-get install solidity (Ubuntu)

Docker:
docker run -v $(pwd):/contracts ethereum/solc:stable --combined-json abi,bin /contracts/Contract.sol
`
}
