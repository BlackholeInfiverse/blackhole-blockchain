package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
)

func Stake(address, target string, amount uint64, stakeType string) error {
	req := struct {
		Address   string `json:"address"`
		Target    string `json:"target"`
		Amount    uint64 `json:"amount"`
		StakeType string `json:"stakeType"`
	}{address, target, amount, stakeType}
	body, _ := json.Marshal(req)
	resp, err := http.Post("http://relay-chain:8080/stake", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("stake failed")
	}
	return nil
}