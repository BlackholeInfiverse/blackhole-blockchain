package chain

import "encoding/gob"

func RegisterGobTypes() {
	//log.Println("✅ Registering gob types")
	gob.Register(&Transaction{})
	gob.Register(&Block{})
	gob.Register(&StakeLedger{})
	// Removed CommonType registration to fix gob deserialization error
	// Add anything else you transmit over P2P here
}
