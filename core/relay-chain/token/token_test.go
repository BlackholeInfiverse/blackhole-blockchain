package token

import (
	"sync"
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestNewToken(t *testing.T) {
	t.Run("Valid Initialization", func(t *testing.T) {
		tk := NewToken("BlackHole", "BLH", 18, 1000)
		assert.Equal(t, "BlackHole", tk.Name)
		assert.Equal(t, uint8(18), tk.Decimals)
		assert.Equal(t, uint64(1000), tk.TotalSupply())
	})
}

func TestMint(t *testing.T) {
	tk := NewToken("Test", "TST", 18, 0)

	t.Run("Mint to valid address", func(t *testing.T) {
		err := tk.Mint("0xAlice", 500)
		assert.Nil(t, err)
		assert.Equal(t, uint64(500), tk.TotalSupply())
		
		balance, _ := tk.BalanceOf("0xAlice")
		assert.Equal(t, uint64(500), balance)
	})

	t.Run("Mint zero amount", func(t *testing.T) {
		err := tk.Mint("0xBob", 0)
		assert.ErrorContains(t, err, "amount must be > 0")
	})
}

func TestBurn(t *testing.T) {
	// Initialize with 1000 total supply
	tk := NewToken("Test", "TST", 18, 1000)
	
	// Mint 500 to Alice (total supply = 1000 + 500 = 1500)
	tk.Mint("0xAlice", 500)

	t.Run("Burn valid amount", func(t *testing.T) {
		// Burn 300 from Alice
		err := tk.Burn("0xAlice", 300)
		assert.Nil(t, err)

		// Verify total supply (1500 - 300 = 1200)
		assert.Equal(t, uint64(1200), tk.TotalSupply())

		// Verify Alice's balance (500 - 300 = 200)
		balance, _ := tk.BalanceOf("0xAlice")
		assert.Equal(t, uint64(200), balance)
	})
}

func TestTransfer(t *testing.T) {
	tk := NewToken("Test", "TST", 18, 1000)
	tk.Mint("0xAlice", 1000)

	t.Run("Valid transfer", func(t *testing.T) {
		err := tk.Transfer("0xAlice", "0xBob", 200)
		assert.Nil(t, err)
		
		aliceBal, _ := tk.BalanceOf("0xAlice")
		bobBal, _ := tk.BalanceOf("0xBob")
		assert.Equal(t, uint64(800), aliceBal)
		assert.Equal(t, uint64(200), bobBal)
	})

	t.Run("Insufficient balance", func(t *testing.T) {
		err := tk.Transfer("0xAlice", "0xBob", 1000)
		assert.ErrorContains(t, err, "insufficient balance")
	})
}

func TestAllowances(t *testing.T) {
	tk := NewToken("Test", "TST", 18, 1000)
	tk.Mint("0xOwner", 1000)

	t.Run("Approve and TransferFrom", func(t *testing.T) {
		_ = tk.Approve("0xOwner", "0xSpender", 300)
		
		allowance, _ := tk.Allowance("0xOwner", "0xSpender")
		assert.Equal(t, uint64(300), allowance)

		err := tk.TransferFrom("0xOwner", "0xSpender", "0xRecipient", 200)
		assert.Nil(t, err)
		
		recipientBal, _ := tk.BalanceOf("0xRecipient")
		assert.Equal(t, uint64(200), recipientBal)
	})
}

func TestConcurrentMints(t *testing.T) {
	tk := NewToken("Test", "TST", 18, 0)
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = tk.Mint("0xConcurrent", 10)
		}()
	}

	wg.Wait()
	assert.Equal(t, uint64(1000), tk.TotalSupply()) // 100 goroutines * 10 tokens
}

func TestEdgeCases(t *testing.T) {
	tk := NewToken("Test", "TST", 18, 0)

	t.Run("Overflow protection", func(t *testing.T) {
			// Mint max uint64 to Alice
			err := tk.Mint("0xAlice", ^uint64(0))
			assert.Nil(t, err)

			// Attempt to mint 1 more (should overflow)
			err = tk.Mint("0xAlice", 1)
			assert.ErrorContains(t, err, "overflow")

			// Verify balance didn't change
			balance, _ := tk.BalanceOf("0xAlice")
			assert.Equal(t, ^uint64(0), balance)
	})
}