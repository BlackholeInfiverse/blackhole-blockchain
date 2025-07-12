package main

import (
	"encoding/json"
	"fmt"
)

// KVStore represents the contract state
type KVStore struct {
	Data    map[string]string
	Version uint32 // For contract upgrades
}

//export init
func init() {
	// Initialize contract state
	store := KVStore{
		Data:    make(map[string]string),
		Version: 1,
	}
	saveStore(store)
}

//export set
func set(key, value string) *string {
	store := loadStore()
	store.Data[key] = value
	saveStore(store)
	result := fmt.Sprintf("Set %s: %s", key, value)
	return &result
}

//export get
func get(key string) *string {
	store := loadStore()
	value, exists := store.Data[key]
	if !exists {
		result := "Key not found"
		return &result
	}
	return &value
}

//export getVersion
func getVersion() uint32 {
	store := loadStore()
	return store.Version
}

// loadStore retrieves state (placeholder for NEAR storage)
func loadStore() KVStore {
	var store KVStore
	// Simulate blockchain storage (replace with NEAR syscalls in production)
	data := getStorage("state")
	if len(data) == 0 {
		store.Data = make(map[string]string)
		store.Version = 1
		return store
	}
	json.Unmarshal([]byte(data), &store)
	return store
}

// saveStore persists state (placeholder for NEAR storage)
func saveStore(store KVStore) {
	data, _ := json.Marshal(store)
	setStorage("state", string(data))
}

// getStorage simulates blockchain storage read
func getStorage(key string) string {
	// In NEAR, use syscalls (e.g., storage_read)
	return ""
}

// setStorage simulates blockchain storage write
func setStorage(key, value string) {
	// In NEAR, use syscalls (e.g., storage_write)
	fmt.Println("Storing:", key, value)
}

// main is required for TinyGo Wasm compilation
func main() {}
