package workflow

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ServiceRegistry manages all workflow components and their lifecycle
type ServiceRegistry struct {
	components    map[string]WorkflowComponent
	eventHandlers []EventHandler
	config        *RegistryConfig
	mutex         sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	started       bool
	events        chan WorkflowEvent
}

// RegistryConfig holds configuration for the service registry
type RegistryConfig struct {
	EnabledComponents []string               `json:"enabled_components"`
	ComponentConfigs  map[string]interface{} `json:"component_configs"`
	EventBufferSize   int                    `json:"event_buffer_size"`
	HealthCheckInterval time.Duration        `json:"health_check_interval"`
	AutoRestart       bool                   `json:"auto_restart"`
	MaxRestartAttempts int                   `json:"max_restart_attempts"`
}

// NewServiceRegistry creates a new service registry
func NewServiceRegistry(config *RegistryConfig) *ServiceRegistry {
	if config == nil {
		config = &RegistryConfig{
			EnabledComponents:   []string{"bridge"}, // Only bridge enabled by default
			ComponentConfigs:    make(map[string]interface{}),
			EventBufferSize:     1000,
			HealthCheckInterval: 30 * time.Second,
			AutoRestart:         true,
			MaxRestartAttempts:  3,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	
	return &ServiceRegistry{
		components:    make(map[string]WorkflowComponent),
		eventHandlers: make([]EventHandler, 0),
		config:        config,
		ctx:           ctx,
		cancel:        cancel,
		events:        make(chan WorkflowEvent, config.EventBufferSize),
	}
}

// RegisterComponent registers a workflow component with the registry
func (r *ServiceRegistry) RegisterComponent(component WorkflowComponent) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	name := component.GetName()
	if _, exists := r.components[name]; exists {
		return fmt.Errorf("component %s is already registered", name)
	}

	r.components[name] = component
	r.emitEvent(WorkflowEvent{
		ID:        generateEventID(),
		Component: name,
		Type:      "component_registered",
		Data: map[string]interface{}{
			"version": component.GetVersion(),
		},
		Timestamp: time.Now(),
		Severity:  "info",
	})

	return nil
}

// UnregisterComponent removes a workflow component from the registry
func (r *ServiceRegistry) UnregisterComponent(name string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	component, exists := r.components[name]
	if !exists {
		return fmt.Errorf("component %s is not registered", name)
	}

	// Stop the component if it's running
	if component.GetStatus().Status == "running" {
		if err := component.Stop(r.ctx); err != nil {
			return fmt.Errorf("failed to stop component %s: %v", name, err)
		}
	}

	delete(r.components, name)
	r.emitEvent(WorkflowEvent{
		ID:        generateEventID(),
		Component: name,
		Type:      "component_unregistered",
		Data:      map[string]interface{}{},
		Timestamp: time.Now(),
		Severity:  "info",
	})

	return nil
}

// GetComponent returns a registered component by name
func (r *ServiceRegistry) GetComponent(name string) (WorkflowComponent, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	component, exists := r.components[name]
	if !exists {
		return nil, fmt.Errorf("component %s is not registered", name)
	}

	return component, nil
}

// GetAllComponents returns all registered components
func (r *ServiceRegistry) GetAllComponents() map[string]WorkflowComponent {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	result := make(map[string]WorkflowComponent)
	for name, component := range r.components {
		result[name] = component
	}

	return result
}

// StartAll starts all enabled workflow components
func (r *ServiceRegistry) StartAll() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.started {
		return fmt.Errorf("service registry is already started")
	}

	// Start event processing
	go r.processEvents()

	// Start health monitoring
	go r.healthMonitor()

	// Initialize and start enabled components
	for _, componentName := range r.config.EnabledComponents {
		component, exists := r.components[componentName]
		if !exists {
			continue // Skip if component is not registered
		}

		// Initialize component
		config := r.config.ComponentConfigs[componentName]
		if config == nil {
			config = make(map[string]interface{})
		}

		if err := component.Initialize(r.ctx, config.(map[string]interface{})); err != nil {
			return fmt.Errorf("failed to initialize component %s: %v", componentName, err)
		}

		// Start component
		if err := component.Start(r.ctx); err != nil {
			return fmt.Errorf("failed to start component %s: %v", componentName, err)
		}

		r.emitEvent(WorkflowEvent{
			ID:        generateEventID(),
			Component: componentName,
			Type:      "component_started",
			Data:      map[string]interface{}{},
			Timestamp: time.Now(),
			Severity:  "info",
		})
	}

	r.started = true
	return nil
}

// StopAll stops all running workflow components
func (r *ServiceRegistry) StopAll() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if !r.started {
		return nil
	}

	// Stop all components
	for name, component := range r.components {
		if component.GetStatus().Status == "running" {
			if err := component.Stop(r.ctx); err != nil {
				// Log error but continue stopping other components
				r.emitEvent(WorkflowEvent{
					ID:        generateEventID(),
					Component: name,
					Type:      "component_stop_error",
					Data: map[string]interface{}{
						"error": err.Error(),
					},
					Timestamp: time.Now(),
					Severity:  "error",
				})
			} else {
				r.emitEvent(WorkflowEvent{
					ID:        generateEventID(),
					Component: name,
					Type:      "component_stopped",
					Data:      map[string]interface{}{},
					Timestamp: time.Now(),
					Severity:  "info",
				})
			}
		}
	}

	// Cancel context to stop background processes
	r.cancel()
	r.started = false

	return nil
}

// GetStatus returns the status of all components
func (r *ServiceRegistry) GetStatus() map[string]ComponentStatus {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	status := make(map[string]ComponentStatus)
	for name, component := range r.components {
		status[name] = component.GetStatus()
	}

	return status
}

// IsHealthy returns true if all enabled components are healthy
func (r *ServiceRegistry) IsHealthy() bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, componentName := range r.config.EnabledComponents {
		component, exists := r.components[componentName]
		if !exists {
			continue
		}

		if !component.IsHealthy() {
			return false
		}
	}

	return true
}

// AddEventHandler adds an event handler to the registry
func (r *ServiceRegistry) AddEventHandler(handler EventHandler) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.eventHandlers = append(r.eventHandlers, handler)
}

// emitEvent emits an event to all registered handlers
func (r *ServiceRegistry) emitEvent(event WorkflowEvent) {
	select {
	case r.events <- event:
	default:
		// Event buffer is full, drop the event
	}
}

// processEvents processes events in the background
func (r *ServiceRegistry) processEvents() {
	for {
		select {
		case <-r.ctx.Done():
			return
		case event := <-r.events:
			r.mutex.RLock()
			handlers := make([]EventHandler, len(r.eventHandlers))
			copy(handlers, r.eventHandlers)
			r.mutex.RUnlock()

			for _, handler := range handlers {
				go func(h EventHandler) {
					if err := h.HandleEvent(r.ctx, event); err != nil {
						// Log error handling event
					}
				}(handler)
			}
		}
	}
}

// healthMonitor monitors the health of all components
func (r *ServiceRegistry) healthMonitor() {
	ticker := time.NewTicker(r.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.checkComponentHealth()
		}
	}
}

// checkComponentHealth checks the health of all components and restarts unhealthy ones if configured
func (r *ServiceRegistry) checkComponentHealth() {
	r.mutex.RLock()
	components := make(map[string]WorkflowComponent)
	for name, component := range r.components {
		components[name] = component
	}
	r.mutex.RUnlock()

	for name, component := range components {
		if !component.IsHealthy() {
			r.emitEvent(WorkflowEvent{
				ID:        generateEventID(),
				Component: name,
				Type:      "component_unhealthy",
				Data:      map[string]interface{}{},
				Timestamp: time.Now(),
				Severity:  "warning",
			})

			// Auto-restart if configured
			if r.config.AutoRestart {
				go r.restartComponent(name, component)
			}
		}
	}
}

// restartComponent attempts to restart an unhealthy component
func (r *ServiceRegistry) restartComponent(name string, component WorkflowComponent) {
	r.emitEvent(WorkflowEvent{
		ID:        generateEventID(),
		Component: name,
		Type:      "component_restart_attempt",
		Data:      map[string]interface{}{},
		Timestamp: time.Now(),
		Severity:  "info",
	})

	// Stop the component
	if err := component.Stop(r.ctx); err != nil {
		r.emitEvent(WorkflowEvent{
			ID:        generateEventID(),
			Component: name,
			Type:      "component_restart_failed",
			Data: map[string]interface{}{
				"error": err.Error(),
				"phase": "stop",
			},
			Timestamp: time.Now(),
			Severity:  "error",
		})
		return
	}

	// Wait a moment before restarting
	time.Sleep(5 * time.Second)

	// Start the component
	if err := component.Start(r.ctx); err != nil {
		r.emitEvent(WorkflowEvent{
			ID:        generateEventID(),
			Component: name,
			Type:      "component_restart_failed",
			Data: map[string]interface{}{
				"error": err.Error(),
				"phase": "start",
			},
			Timestamp: time.Now(),
			Severity:  "error",
		})
		return
	}

	r.emitEvent(WorkflowEvent{
		ID:        generateEventID(),
		Component: name,
		Type:      "component_restarted",
		Data:      map[string]interface{}{},
		Timestamp: time.Now(),
		Severity:  "info",
	})
}

// generateEventID generates a unique event ID
func generateEventID() string {
	return fmt.Sprintf("evt_%d", time.Now().UnixNano())
}
