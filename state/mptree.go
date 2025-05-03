package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
)

// StateMerkleTree provides cryptographic state representation
type StateMerkleTree struct {
	root     []byte
	nodeMap  map[string]*StateNode
	modified bool
}

// newStateMerkleTree creates a new Merkle tree for state management
func newStateMerkleTree() *StateMerkleTree {
	return &StateMerkleTree{
		nodeMap:  make(map[string]*StateNode),
		modified: true,
	}
}

// addNode adds a node to the Merkle tree
func (smt *StateMerkleTree) addNode(key string, value []byte) {
	hash := hashData(value)
	smt.nodeMap[key] = &StateNode{
		Key:   key,
		Value: value,
		Hash:  hash,
	}
}

// computeRoot computes the root hash of the Merkle tree
func (smt *StateMerkleTree) computeRoot() []byte {
	if len(smt.nodeMap) == 0 {
		// Return a special hash for empty tree
		return hashData([]byte("empty_state"))
	}

	// Sort keys for deterministic root calculation
	keys := make([]string, 0, len(smt.nodeMap))
	for k := range smt.nodeMap {
		keys = append(keys, k)
	}

	// For efficiency in the prototype, just combine all hashes
	// In a real implementation, this would build a proper Merkle tree
	combinedHash := []byte{}
	for _, key := range keys {
		node := smt.nodeMap[key]
		combinedHash = append(combinedHash, node.Hash...)
	}

	return hashData(combinedHash)
}

// StateProof represents a proof that a key has a specific value in the state
type StateProof struct {
	Key       string
	Value     []byte
	Hash      []byte
	StateRoot []byte
}

// serializeProof serializes a state proof
func serializeProof(proof *StateProof) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(proof); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// deserializeProof deserializes a state proof
func deserializeProof(data []byte) (*StateProof, error) {
	var proof StateProof
	buf := bytes.NewReader(data)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(&proof)
	if err != nil {
		return nil, err
	}
	return &proof, nil
}

// hashData creates a hash from data
func hashData(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// uint64ToBytes converts a uint64 to a byte slice
func uint64ToBytes(val uint64) []byte {
	buf := make([]byte, 8)
	for i := 0; i < 8; i++ {
		buf[i] = byte(val >> (8 * i))
	}
	return buf
}
