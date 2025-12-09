package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)


func testEndpoint(url string, data map[string]interface{}, testName string) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("❌ Failed to marshal JSON for %s: %v\n", testName, err)
		return
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("❌ Failed to make request to %s: %v\n", testName, err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("❌ Failed to read response for %s: %v\n", testName, err)
		return
	}

	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		fmt.Printf("❌ Failed to parse response for %s: %v\n", testName, err)
		fmt.Printf("Raw response: %s\n", string(body))
		return
	}

	if success, ok := response["success"].(bool); ok && success {
		fmt.Printf("✅ %s endpoint test PASSED\n", testName)
		if data, ok := response["data"].(map[string]interface{}); ok {
			if eventHash, ok := data["event_hash"].(string); ok {
				fmt.Printf("   Event Hash: %s\n", eventHash)
			}
			if status, ok := data["status"].(string); ok {
				fmt.Printf("   Status: %s\n", status)
			}
		}
	} else {
		fmt.Printf("❌ %s endpoint test FAILED\n", testName)
		if errorMsg, ok := response["error"].(string); ok {
			fmt.Printf("   Error: %s\n", errorMsg)
		}
	}
}