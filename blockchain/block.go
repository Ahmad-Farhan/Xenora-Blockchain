package blockchain

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"log"
	"time"

	"xenora/xtx"
)

// Block represents a basic block in the Xenora blockchain
type Block struct {
	Header       BlockHeader       `json:"header"`
	Transactions []xtx.Transaction `json:"transactions"`
	Signature    []byte            `json:"signature"`
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
	data, err := h.Serialize()
	if err != nil {
		log.Printf("Error Serializing Block Header: %v", err)
		return nullhash
	}
	hash := sha256.Sum256(data)
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
		Header:       header,
		Transactions: []xtx.Transaction{},
		Signature:    []byte{},
	}
}

// Serialize converts the block header to bytes for hashing
func (h *BlockHeader) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(h); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SerializeBlock converts an entire block to bytes
func SerializeBlock(block *Block) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(block); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DeserializeBlock converts bytes back to a Block
func DeserializeBlock(data []byte) (*Block, error) {
	var block Block
	buf := bytes.NewReader(data)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(&block)
	if err != nil {
		return nil, err
	}
	return &block, nil
}
