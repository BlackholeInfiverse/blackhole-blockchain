package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

type Block struct {
	Header       BlockHeader
	Transactions []*Transaction
	Hash         string `json:"hash"`
}

func (b *Block) Serialize() []byte {
	data, err := json.Marshal(b)
	if err != nil {
		panic("failed to serialize block: " + err.Error())
	}
	return data
}

type BlockHeader struct {
	Index          uint64    `json:"index"`
	Timestamp      time.Time `json:"timestamp"`
	PreviousHash   string    `json:"previousHash"`
	Validator      string    `json:"validator"`
	StakeSnapshot  uint64    `json:"stakeSnapshot"`
	MerkleRoot     string    `json:"merkleRoot"`
	StateRoot      string    `json:"stateRoot"`
	ReceiptsRoot   string    `json:"receiptsRoot"`
	ConsensusRound uint64    `json:"consensusRound"`
}

func NewBlock(index uint64, txs []*Transaction, prevHash string, validator string, stake uint64) *Block {
	block := &Block{
		Header: BlockHeader{
			Index:         index,
			Timestamp:     time.Now().UTC(),
			PreviousHash:  prevHash,
			Validator:     validator,
			StakeSnapshot: stake,
		},
		Transactions: txs,
	}

	block.Header.MerkleRoot = block.CalculateMerkleRoot()
	block.Header.StateRoot = "0x0"
	block.Header.ReceiptsRoot = "0x0"
	block.Hash = block.CalculateHash()

	return block
}

func (b *Block) CalculateHash() string {
	headerData := fmt.Sprintf("%d%s%s%s%d%s",
		b.Header.Index,
		b.Header.Timestamp.UTC().Format(time.RFC3339Nano),
		b.Header.PreviousHash,
		b.Header.Validator,
		b.Header.StakeSnapshot,
		b.Header.MerkleRoot,
	)
	hash := sha256.Sum256([]byte(headerData))
	return hex.EncodeToString(hash[:])
}

func (b *Block) CalculateMerkleRoot() string {
	if len(b.Transactions) == 0 {
		return ""
	}

	var hashes []string
	for _, tx := range b.Transactions {
		hashes = append(hashes, tx.ID)
	}

	for len(hashes) > 1 {
		var newHashes []string
		for i := 0; i < len(hashes); i += 2 {
			if i+1 == len(hashes) {
				newHashes = append(newHashes, hashPair(hashes[i], hashes[i]))
			} else {
				newHashes = append(newHashes, hashPair(hashes[i], hashes[i+1]))
			}
		}
		hashes = newHashes
	}

	return hashes[0]
}

func hashPair(a, b string) string {
	h := sha256.New()
	h.Write([]byte(a + b))
	return hex.EncodeToString(h.Sum(nil))
}