package chain

import (
	"sync"
)

type StakeLedger struct {
	Stakes map[string]uint64
	mu     sync.RWMutex
}

func (sl *StakeLedger) ToMap() map[string]uint64 {
	panic("unimplemented")
}

func NewStakeLedger() *StakeLedger {
	return &StakeLedger{
		Stakes: make(map[string]uint64),
	}
}

func (sl *StakeLedger) GetStake(address string) uint64 {
	sl.mu.RLock()
	defer sl.mu.RUnlock()
	return sl.Stakes[address]
}

func (sl *StakeLedger) SetStake(address string, stake uint64) {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	sl.Stakes[address] = stake
}

func (sl *StakeLedger) AddStake(address string, amount uint64) {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	sl.Stakes[address] += amount
}

func (sl *StakeLedger) GetAllStakes() map[string]uint64 {
	sl.mu.RLock()
	defer sl.mu.RUnlock()
	stakes := make(map[string]uint64)
	for addr, stake := range sl.Stakes {
		stakes[addr] = stake
	}
	return stakes
}