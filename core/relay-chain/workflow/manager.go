package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
)

// WorkflowManager manages the entire workflow system
type WorkflowManager struct {
	registry   *ServiceRegistry
	blockchain *chain.Blockchain
	config     *WorkflowConfig
	mutex      sync.RWMutex
	started    bool
	httpServer *http.Server
}

// WorkflowConfig holds configuration for the workflow manager
type WorkflowConfig struct {
	EnabledWorkflows    []string               `json:"enabled_workflows"`
	WorkflowConfigs     map[string]interface{} `json:"workflow_configs"`
	MonitoringPort      int                    `json:"monitoring_port"`
	AutoStart           bool                   `json:"auto_start"`
	HealthCheckInterval time.Duration          `json:"health_check_interval"`
}

// NewWorkflowManager creates a new workflow manager
func NewWorkflowManager(blockchain *chain.Blockchain, config *WorkflowConfig) *WorkflowManager {
	if config == nil {
		config = &WorkflowConfig{
			EnabledWorkflows: []string{"bridge"},
			WorkflowConfigs:  make(map[string]interface{}),
			MonitoringPort:   8085,
			AutoStart:        true,
			HealthCheckInterval: 30 * time.Second,
		}
	}

	// Create registry config
	registryConfig := &RegistryConfig{
		EnabledComponents:   config.EnabledWorkflows,
		ComponentConfigs:    config.WorkflowConfigs,
		EventBufferSize:     1000,
		HealthCheckInterval: config.HealthCheckInterval,
		AutoRestart:         true,
		MaxRestartAttempts:  3,
	}

	registry := NewServiceRegistry(registryConfig)

	return &WorkflowManager{
		registry:   registry,
		blockchain: blockchain,
		config:     config,
	}
}

// Initialize sets up the workflow manager
func (wm *WorkflowManager) Initialize() error {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	// Register default components
	if err := wm.registerDefaultComponents(); err != nil {
		return fmt.Errorf("failed to register default components: %v", err)
	}

	// Set up monitoring HTTP server
	if err := wm.setupMonitoringServer(); err != nil {
		return fmt.Errorf("failed to setup monitoring server: %v", err)
	}

	return nil
}

// Start starts the workflow manager and all enabled components
func (wm *WorkflowManager) Start(ctx context.Context) error {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	if wm.started {
		return fmt.Errorf("workflow manager is already started")
	}

	// Start the monitoring server
	go func() {
		if err := wm.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Workflow monitoring server error: %v", err)
		}
	}()

	// Start the service registry
	if err := wm.registry.StartAll(); err != nil {
		return fmt.Errorf("failed to start service registry: %v", err)
	}

	wm.started = true
	log.Printf("Workflow manager started on port %d", wm.config.MonitoringPort)

	return nil
}

// Stop stops the workflow manager and all components
func (wm *WorkflowManager) Stop(ctx context.Context) error {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	if !wm.started {
		return nil
	}

	// Stop the service registry
	if err := wm.registry.StopAll(); err != nil {
		log.Printf("Error stopping service registry: %v", err)
	}

	// Stop the monitoring server
	if wm.httpServer != nil {
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := wm.httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("Error shutting down monitoring server: %v", err)
		}
	}

	wm.started = false
	log.Println("Workflow manager stopped")

	return nil
}

// GetRegistry returns the service registry
func (wm *WorkflowManager) GetRegistry() *ServiceRegistry {
	return wm.registry
}

// GetBridgeComponent returns the bridge component if available
func (wm *WorkflowManager) GetBridgeComponent() (*BridgeComponentImpl, error) {
	component, err := wm.registry.GetComponent("bridge")
	if err != nil {
		return nil, err
	}

	bridgeComponent, ok := component.(*BridgeComponentImpl)
	if !ok {
		return nil, fmt.Errorf("bridge component is not of expected type")
	}

	return bridgeComponent, nil
}

// IsHealthy returns true if the workflow manager and all components are healthy
func (wm *WorkflowManager) IsHealthy() bool {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()

	if !wm.started {
		return false
	}

	return wm.registry.IsHealthy()
}

// GetStatus returns the status of all workflow components
func (wm *WorkflowManager) GetStatus() map[string]ComponentStatus {
	return wm.registry.GetStatus()
}

// GetAllComponents returns all registered components
func (wm *WorkflowManager) GetAllComponents() map[string]WorkflowComponent {
	return wm.registry.GetAllComponents()
}

// registerDefaultComponents registers the default workflow components
func (wm *WorkflowManager) registerDefaultComponents() error {
	// Register bridge component
	bridgeComponent := NewBridgeComponent(wm.blockchain)
	if err := wm.registry.RegisterComponent(bridgeComponent); err != nil {
		return fmt.Errorf("failed to register bridge component: %v", err)
	}

	// Future components will be registered here:
	// - Mint component
	// - Approve component
	// - Stake component
	// - Swap component
	// - Cybercrime component

	return nil
}

// setupMonitoringServer sets up the HTTP server for monitoring
func (wm *WorkflowManager) setupMonitoringServer() error {
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", wm.handleHealth)

	// Status endpoint
	mux.HandleFunc("/status", wm.handleStatus)

	// Component status endpoint
	mux.HandleFunc("/components", wm.handleComponents)

	// Bridge-specific endpoints
	mux.HandleFunc("/bridge/status", wm.handleBridgeStatus)
	mux.HandleFunc("/bridge/port", wm.handleBridgePort)

	// Metrics endpoint
	mux.HandleFunc("/metrics", wm.handleMetrics)

	wm.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", wm.config.MonitoringPort),
		Handler: mux,
	}

	return nil
}

// HTTP handlers for monitoring endpoints

func (wm *WorkflowManager) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	healthy := wm.IsHealthy()
	status := "unhealthy"
	if healthy {
		status = "healthy"
	}

	response := map[string]interface{}{
		"status":  status,
		"healthy": healthy,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	if healthy {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	json.NewEncoder(w).Encode(response)
}

func (wm *WorkflowManager) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	wm.mutex.RLock()
	started := wm.started
	wm.mutex.RUnlock()

	response := map[string]interface{}{
		"started":           started,
		"healthy":           wm.IsHealthy(),
		"enabled_workflows": wm.config.EnabledWorkflows,
		"monitoring_port":   wm.config.MonitoringPort,
		"timestamp":         time.Now().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(response)
}

func (wm *WorkflowManager) handleComponents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	components := wm.GetStatus()
	response := map[string]interface{}{
		"components": components,
		"count":      len(components),
		"timestamp":  time.Now().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(response)
}

func (wm *WorkflowManager) handleBridgeStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	bridgeComponent, err := wm.GetBridgeComponent()
	if err != nil {
		http.Error(w, fmt.Sprintf("Bridge component not available: %v", err), http.StatusNotFound)
		return
	}

	status := bridgeComponent.GetStatus()
	response := map[string]interface{}{
		"bridge_status":     status,
		"sdk_running":       bridgeComponent.IsBridgeSDKRunning(),
		"sdk_port":          bridgeComponent.GetBridgeSDKPort(),
		"timestamp":         time.Now().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(response)
}

func (wm *WorkflowManager) handleBridgePort(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	bridgeComponent, err := wm.GetBridgeComponent()
	if err != nil {
		http.Error(w, fmt.Sprintf("Bridge component not available: %v", err), http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"port":      bridgeComponent.GetBridgeSDKPort(),
		"running":   bridgeComponent.IsBridgeSDKRunning(),
		"timestamp": time.Now().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(response)
}

func (wm *WorkflowManager) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	components := wm.registry.GetAllComponents()
	metrics := make(map[string]interface{})

	for name, component := range components {
		metrics[name] = component.GetMetrics()
	}

	response := map[string]interface{}{
		"metrics":   metrics,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(response)
}
