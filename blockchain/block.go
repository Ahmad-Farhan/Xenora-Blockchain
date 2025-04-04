package blockchain

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Block represents a basic block in the Xenora blockchain
type Block struct {
	BlockHeader  BlockHeader   `json:"header"`
	Transactions []Transaction `json:"transactions"`
	Signature    []byte        `json:"signature"`
}

// BlockHeader contains metadata about the block
type BlockHeader struct {
	Version       uint32    `json:"version"`       // Version of the block structure
	Height        uint64    `json:"height"`        // Block height in the chain
	PreviousHash  string    `json:"previousHash"`  // Hash of the previous block
	MerkleRoot    string    `json:"merkleRoot"`    // Root hash of transaction Merkle tree
	StateRoot     string    `json:"stateRoot"`     // Root hash of the state tree (for account balances, etc.)
	Timestamp     time.Time `json:"timestamp"`     // Block creation timestamp
	Difficulty    uint32    `json:"difficulty"`    // Mining difficulty (will be relevant for consensus)
	Nonce         uint64    `json:"nonce"`         // Nonce used for consensus algorithm
	ShardID       uint32    `json:"shardID"`       // ID of the shard this block belongs to (for future sharding)
	ProposerID    string    `json:"proposerID"`    // ID of the node that proposed this block
	ConsensusData []byte    `json:"consensusData"` // Additional data required by consensus algorithm
}

const nullhash = "0000000000000000000000000000000000000000000000000000000000000000" // 64 zeros

// Hash calculates the hash of the block header
func (h *BlockHeader) Hash() string {
	// Convert header to bytes - maybe replace with a proper serialization method later
	headerbytes := []byte(
		string(h.Version) +
			string(h.Height) +
			h.PreviousHash +
			h.MerkleRoot +
			h.StateRoot +
			h.Timestamp.String() +
			string(h.Difficulty) +
			string(h.Nonce) +
			string(h.ShardID) +
			h.ProposerID +
			string(h.ConsensusData),
	)
	hash := sha256.Sum256(headerbytes)
	return hex.EncodeToString(hash[:])
}

// GenesisBlock creates the first block in the blockchain
func GenesisBlock() *Block {
	header := BlockHeader{
		Version:      1,
		Height:       0,
		PreviousHash: nullhash,
		MerkleRoot:   nullhash,
		StateRoot:    nullhash,
		Timestamp:    time.Now(),
		Difficulty:   1,
		Nonce:        0,
		ShardID:      0,
		ProposerID:   "genesis",
	}

	return &Block{
		BlockHeader:  header,
		Transactions: []Transaction{},
		Signature:    []byte{},
	}
}
