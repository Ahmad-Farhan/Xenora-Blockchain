package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"xenora/xtx"
)

// Enhance existing MerkleTree to store transactions
type MerkleTree struct {
	RootNode *MerkleNode
	leaves   []xtx.Transaction
}

type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Data  []byte
}

func NewMerkleNode(left, right *MerkleNode, data []byte) *MerkleNode {
	node := MerkleNode{}

	if left == nil && right == nil {
		hash := sha256.Sum256(data)
		node.Data = hash[:]
	} else {
		prevHashes := append(left.Data, right.Data...)
		hash := sha256.Sum256(prevHashes)
		node.Data = hash[:]
	}

	node.Left = left
	node.Right = right
	return &node
}

// NewMerkleTree creates a new Merkle tree from transactions
func NewMerkleTree(transactions []xtx.Transaction) *MerkleTree {
	var nodes []*MerkleNode

	for _, tx := range transactions {
		txHash, _ := hex.DecodeString(tx.TxID)
		nodes = append(nodes, NewMerkleNode(nil, nil, txHash))
	}

	if len(nodes) == 0 {
		root := NewMerkleNode(nil, nil, []byte{})
		return &MerkleTree{root, transactions}
	}
	if len(nodes)%2 != 0 && len(nodes) > 1 {
		nodes = append(nodes, nodes[len(nodes)-1])
	}

	for len(nodes) > 1 {
		var level []*MerkleNode
		for i := 0; i < len(nodes); i += 2 {
			if i+1 < len(nodes) {
				node := NewMerkleNode(nodes[i], nodes[i+1], nil)
				level = append(level, node)
			} else {
				node := NewMerkleNode(nodes[i], nodes[i], nil)
				level = append(level, node)
			}
		}

		if len(level)%2 != 0 && len(level) > 1 {
			level = append(level, level[len(level)-1])
		}
		nodes = level
	}

	tree := MerkleTree{nodes[0], transactions}
	return &tree
}

// GetRootHash returns the hex-encoded root hash
func (m *MerkleTree) GetRootHash() string {
	if m.RootNode == nil {
		return nullhash
	}
	return hex.EncodeToString(m.RootNode.Data)
}
