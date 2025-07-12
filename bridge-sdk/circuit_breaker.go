package bridgesdk

import (
	"sync"
	"time"
)

// Circuit Breaker
type CircuitBreaker struct {
	name             string
	state            string
	failureCount     int
	failureThreshold int
	lastFailure      *time.Time
	nextAttempt      *time.Time
	mutex            sync.RWMutex
	timeout          time.Duration
	resetTimeout     time.Duration
}

func (cb *CircuitBreaker) recordFailure() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	
	cb.failureCount++
	now := time.Now()
	cb.lastFailure = &now
	
	if cb.failureCount >= cb.failureThreshold {
		cb.state = "open"
		nextAttempt := now.Add(cb.resetTimeout)
		cb.nextAttempt = &nextAttempt
	}
}

func (cb *CircuitBreaker) recordSuccess() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	
	cb.failureCount = 0
	cb.state = "closed"
	cb.lastFailure = nil
	cb.nextAttempt = nil
}

func (cb *CircuitBreaker) canExecute() bool {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	
	if cb.state == "closed" {
		return true
	}
	
	if cb.state == "open" && cb.nextAttempt != nil && time.Now().After(*cb.nextAttempt) {
		return true
	}
	
	return false
}

func (cb *CircuitBreaker) getState() string {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.state
}

// GetCircuitBreakerStatus returns circuit breaker status
func (sdk *BridgeSDK) GetCircuitBreakerStatus() map[string]*CircuitBreaker {
	result := make(map[string]*CircuitBreaker)
	for name, cb := range sdk.circuitBreakers {
		result[name] = cb
	}
	return result
}
