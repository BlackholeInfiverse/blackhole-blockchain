package governance

// import (
// 	"testing"
// 	"time"

// 	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
// )

// func setupTestGovernance() (*Governance, *chain.Blockchain) {
// 	blockchain := chain.NewBlockchain()
// 	return NewGovernance(blockchain), blockchain
// }

// func TestValidatorRegistration(t *testing.T) {
// 	gov, blockchain := setupTestGovernance()

// 	// Test successful validator registration
// 	validator := "validator1"
// 	stake := uint64(100000)
// 	err := gov.RegisterValidator(validator, stake)
// 	if err != nil {
// 		t.Errorf("Failed to register validator: %v", err)
// 	}

// 	// Verify validator is registered
// 	validators := gov.GetValidators()
// 	if len(validators) != 1 {
// 		t.Errorf("Expected 1 validator, got %d", len(validators))
// 	}
// 	if validators[0].Address != validator {
// 		t.Errorf("Expected validator %s, got %s", validator, validators[0].Address)
// 	}

// 	// Test insufficient stake
// 	err = gov.RegisterValidator("validator2", gov.MinValidatorStake-1)
// 	if err == nil {
// 		t.Error("Expected error for insufficient stake")
// 	}
// }

// func TestProposalCreation(t *testing.T) {
// 	gov, blockchain := setupTestGovernance()

// 	// Register validator
// 	validator := "validator1"
// 	stake := uint64(100000)
// 	gov.RegisterValidator(validator, stake)

// 	// Test successful proposal creation
// 	proposal := &Proposal{
// 		Type:        ProposalTypeParameterChange,
// 		Title:       "Test Proposal",
// 		Description: "This is a test proposal",
// 		Proposer:    validator,
// 		Params: map[string]interface{}{
// 			"param1": "value1",
// 		},
// 	}

// 	proposalID, err := gov.CreateProposal(proposal)
// 	if err != nil {
// 		t.Errorf("Failed to create proposal: %v", err)
// 	}

// 	// Verify proposal exists
// 	savedProposal, err := gov.GetProposal(proposalID)
// 	if err != nil {
// 		t.Fatalf("Failed to get proposal: %v", err)
// 	}
// 	if savedProposal.Title != proposal.Title {
// 		t.Errorf("Expected proposal title %s, got %s", proposal.Title, savedProposal.Title)
// 	}
// }

// func TestVoting(t *testing.T) {
// 	gov, blockchain := setupTestGovernance()

// 	// Setup test accounts
// 	validator1 := "validator1"
// 	validator2 := "validator2"
// 	stake := uint64(100000)

// 	gov.RegisterValidator(validator1, stake)
// 	gov.RegisterValidator(validator2, stake)

// 	// Create proposal
// 	proposal := &Proposal{
// 		Type:        ProposalTypeParameterChange,
// 		Title:       "Test Proposal",
// 		Description: "This is a test proposal",
// 		Proposer:    validator1,
// 		Params: map[string]interface{}{
// 			"param1": "value1",
// 		},
// 	}

// 	proposalID, _ := gov.CreateProposal(proposal)

// 	// Test voting
// 	err := gov.Vote(proposalID, validator1, VoteYes)
// 	if err != nil {
// 		t.Errorf("Failed to vote: %v", err)
// 	}

// 	err = gov.Vote(proposalID, validator2, VoteNo)
// 	if err != nil {
// 		t.Errorf("Failed to vote: %v", err)
// 	}

// 	// Verify vote count
// 	proposal, _ = gov.GetProposal(proposalID)
// 	if proposal.YesVotes != stake {
// 		t.Errorf("Expected yes votes %d, got %d", stake, proposal.YesVotes)
// 	}
// 	if proposal.NoVotes != stake {
// 		t.Errorf("Expected no votes %d, got %d", stake, proposal.NoVotes)
// 	}
// }

// func TestProposalExecution(t *testing.T) {
// 	gov, blockchain := setupTestGovernance()

// 	// Setup test accounts
// 	validator1 := "validator1"
// 	validator2 := "validator2"
// 	validator3 := "validator3"
// 	stake := uint64(100000)

// 	gov.RegisterValidator(validator1, stake)
// 	gov.RegisterValidator(validator2, stake)
// 	gov.RegisterValidator(validator3, stake)

// 	// Create proposal
// 	proposal := &Proposal{
// 		Type:        ProposalTypeParameterChange,
// 		Title:       "Test Proposal",
// 		Description: "This is a test proposal",
// 		Proposer:    validator1,
// 		Params: map[string]interface{}{
// 			"MinValidatorStake": uint64(200000),
// 		},
// 	}

// 	proposalID, _ := gov.CreateProposal(proposal)

// 	// Vote
// 	gov.Vote(proposalID, validator1, VoteYes)
// 	gov.Vote(proposalID, validator2, VoteYes)
// 	gov.Vote(proposalID, validator3, VoteYes)

// 	// Wait for voting period
// 	time.Sleep(gov.VotingPeriod)

// 	// Process proposal
// 	err := gov.ProcessProposal(proposalID)
// 	if err != nil {
// 		t.Errorf("Failed to process proposal: %v", err)
// 	}

// 	// Verify parameter change
// 	if gov.MinValidatorStake != 200000 {
// 		t.Errorf("Expected MinValidatorStake 200000, got %d", gov.MinValidatorStake)
// 	}
// }

// func TestSlashing(t *testing.T) {
// 	gov, blockchain := setupTestGovernance()

// 	// Register validator
// 	validator := "validator1"
// 	initialStake := uint64(100000)
// 	gov.RegisterValidator(validator, initialStake)

// 	// Test slashing
// 	slashAmount := uint64(10000)
// 	err := gov.SlashValidator(validator, slashAmount)
// 	if err != nil {
// 		t.Errorf("Failed to slash validator: %v", err)
// 	}

// 	// Verify stake reduction
// 	validators := gov.GetValidators()
// 	for _, v := range validators {
// 		if v.Address == validator {
// 			expectedStake := initialStake - slashAmount
// 			if v.Stake != expectedStake {
// 				t.Errorf("Expected stake %d, got %d", expectedStake, v.Stake)
// 			}
// 			break
// 		}
// 	}
// }

// func TestDelegation(t *testing.T) {
// 	gov, blockchain := setupTestGovernance()

// 	// Setup accounts
// 	validator := "validator1"
// 	delegator := "delegator1"
// 	validatorStake := uint64(100000)
// 	delegationAmount := uint64(50000)

// 	// Register validator
// 	gov.RegisterValidator(validator, validatorStake)

// 	// Test delegation
// 	err := gov.Delegate(delegator, validator, delegationAmount)
// 	if err != nil {
// 		t.Errorf("Failed to delegate: %v", err)
// 	}

// 	// Verify delegation
// 	delegation, err := gov.GetDelegation(delegator, validator)
// 	if err != nil {
// 		t.Fatalf("Failed to get delegation: %v", err)
// 	}
// 	if delegation.Amount != delegationAmount {
// 		t.Errorf("Expected delegation amount %d, got %d", delegationAmount, delegation.Amount)
// 	}
// }
