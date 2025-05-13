package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type StakeRequest struct {
	Address   string `json:"address"`
	Target    string `json:"target"`
	Amount    uint64 `json:"amount"`
	StakeType string `json:"stakeType"`
}

type UnstakeRequest struct {
	Address string `json:"address"`
	Amount  uint64 `json:"amount"`
}

type Reward struct {
	Address string `json:"Address"`
	Amount  uint64 `json:"Amount"`
	Epoch   int64  `json:"Epoch"`
}

func main() {
	// Test Stake
	stakeReq := StakeRequest{
		Address:   "user1",
		Target:    "",
		Amount:    1000,
		StakeType: "validator",
	}
	stakeBody, _ := json.Marshal(stakeReq)
	resp, err := http.Post("http://localhost:8080/stake", "application/json", bytes.NewBuffer(stakeBody))
	if err != nil {
		fmt.Printf("Stake error: %v\n", err)
		return
	}
	defer resp.Body.Close()
	stakeResponse, _ := io.ReadAll(resp.Body)
	fmt.Printf("Stake response: %s\n", stakeResponse)

	// Test Claim Rewards
	resp, err = http.Get("http://localhost:8080/claim-rewards?address=user1")
	if err != nil {
		fmt.Printf("Claim Rewards error: %v\n", err)
		return
	}
	defer resp.Body.Close()
	var rewards []Reward
	json.NewDecoder(resp.Body).Decode(&rewards)
	fmt.Printf("Claim Rewards response: %+v\n", rewards)

	// Test Unstake
	unstakeReq := UnstakeRequest{
		Address: "user1",
		Amount:  500,
	}
	unstakeBody, _ := json.Marshal(unstakeReq)
	resp, err = http.Post("http://localhost:8080/unstake", "application/json", bytes.NewBuffer(unstakeBody))
	if err != nil {
		fmt.Printf("Unstake error: %v\n", err)
		return
	}
	defer resp.Body.Close()
	unstakeResponse, _ := io.ReadAll(resp.Body)
	fmt.Printf("Unstake response: %s\n", unstakeResponse)
}
