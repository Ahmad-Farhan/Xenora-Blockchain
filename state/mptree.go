package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"math/big"
	"sort"
)

// StateNode represents a node in the state merkle tree
type StateNode struct {
	Key   string
	Value []byte
	Hash  []byte
	Left  *StateNode
	Right *StateNode
}

// StateMerkleTree provides cryptographic state representation
type StateMerkleTree struct {
	root  *StateNode
	nodes map[string]*StateNode
}

// newStateMerkleTree creates a new Merkle tree for state management
func newStateMerkleTree() *StateMerkleTree {
	return &StateMerkleTree{
		nodes: make(map[string]*StateNode),
	}
}

// addNode adds a node to the Merkle tree
func (smt *StateMerkleTree) addNode(key string, value []byte) {
	hash := hashData(value)
	smt.nodes[key] = &StateNode{
		Key:   key,
		Value: value,
		Hash:  hash,
	}
}

// computeRoot computes the root hash of the Merkle tree
func (smt *StateMerkleTree) computeRoot() []byte {
	if len(smt.nodes) == 0 {
		return hashData([]byte("empty_state"))
	}

	// Get all leaf nodes
	leaves := make([]*StateNode, 0, len(smt.nodes))
	for _, node := range smt.nodes {
		leaves = append(leaves, node)
	}
	sort.Slice(leaves, func(i, j int) bool {
		return leaves[i].Key < leaves[j].Key
	})

	// Build the tree bottom-up
	for len(leaves) > 1 {
		var nextLevel []*StateNode
		for i := 0; i < len(leaves); i += 2 {
			if i+1 < len(leaves) {
				// Pair two nodes
				combined := append(leaves[i].Hash, leaves[i+1].Hash...)
				parentHash := hashData(combined)
				parent := &StateNode{
					Hash:  parentHash,
					Left:  leaves[i],
					Right: leaves[i+1],
				}
				nextLevel = append(nextLevel, parent)
			} else {
				// Odd node out, promote it
				nextLevel = append(nextLevel, leaves[i])
			}
		}
		leaves = nextLevel
	}

	smt.root = leaves[0]
	return smt.root.Hash
}

// StateProof represents a proof that a key has a specific value in the state
type StateProof struct {
	Key       string
	Value     []byte
	Hash      []byte
	StateRoot []byte
	Path      [][]byte
	Positions []bool
	// ZKProof   *ZKStateProof
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

func hashToPrime(data string) *big.Int {
	hash := sha256.Sum256([]byte(data))
	num := new(big.Int).SetBytes(hash[:])

	// Find next prime using Miller-Rabin test
	if num.Bit(0) == 0 {
		num.Add(num, big.NewInt(1))
	}
	for !num.ProbablyPrime(20) {
		num.Add(num, big.NewInt(2))
	}
	return num
}
