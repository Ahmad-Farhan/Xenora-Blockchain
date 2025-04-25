package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"xenora/xtx"
)

// TestNewMerkleNode validates the creation of Merkle nodes.
func TestNewMerkleNode(t *testing.T) {
	// Test leaf node
	data := []byte("test transaction")
	hash := sha256.Sum256(data)
	node := NewMerkleNode(nil, nil, data)
	if !bytes.Equal(node.Data, hash[:]) {
		t.Errorf("Leaf node hash mismatch: expected %x, got %x", hash[:], node.Data)
	}

	// Test internal node
	left := NewMerkleNode(nil, nil, []byte("left"))
	right := NewMerkleNode(nil, nil, []byte("right"))
	combined := append(left.Data, right.Data...)
	expectedHash := sha256.Sum256(combined)
	parent := NewMerkleNode(left, right, nil)
	if !bytes.Equal(parent.Data, expectedHash[:]) {
		t.Errorf("Parent node hash mismatch: expected %x, got %x", expectedHash[:], parent.Data)
	}
}

// TestNewMerkleTreeEmpty checks the root hash of an empty Merkle tree.
func TestNewMerkleTreeEmpty(t *testing.T) {
	tree := NewMerkleTree([]xtx.Transaction{})
	emptyHash := sha256.Sum256([]byte{})
	expectedRoot := hex.EncodeToString(emptyHash[:])
	if tree.GetRootHash() != expectedRoot {
		t.Errorf("Empty tree root hash mismatch: expected %s, got %s", expectedRoot, tree.GetRootHash())
	}
}

// TestNewMerkleTreeSingleTransaction verifies a tree with one transaction.
func TestNewMerkleTreeSingleTransaction(t *testing.T) {
	tx := xtx.NewTransaction(xtx.TransferTx, "sender", "receiver", 50, 1, 5, nil)
	txs := []xtx.Transaction{*tx}
	tree := NewMerkleTree(txs)
	txHash, _ := hex.DecodeString(tx.TxID)
	expectedHash := sha256.Sum256(txHash)
	expectedRoot := hex.EncodeToString(expectedHash[:])
	if tree.GetRootHash() != expectedRoot {
		t.Errorf("Single transaction root hash mismatch: expected %s, got %s", expectedRoot, tree.GetRootHash())
	}
}

// TestNewMerkleTreeMultipleTransactions tests a tree with an even number of transactions.
func TestNewMerkleTreeMultipleTransactions(t *testing.T) {
	tx1 := xtx.NewTransaction(xtx.TransferTx, "alice", "bob", 100, 1, 10, nil)
	tx2 := xtx.NewTransaction(xtx.TransferTx, "charlie", "dave", 200, 1, 20, nil)
	txs := []xtx.Transaction{*tx1, *tx2}
	tree := NewMerkleTree(txs)
	tx1Hash, _ := hex.DecodeString(tx1.TxID)
	tx2Hash, _ := hex.DecodeString(tx2.TxID)
	leftHash := sha256.Sum256(tx1Hash)
	rightHash := sha256.Sum256(tx2Hash)
	combined := append(leftHash[:], rightHash[:]...)
	expectedRootHash := sha256.Sum256(combined)
	expectedRoot := hex.EncodeToString(expectedRootHash[:])
	if tree.GetRootHash() != expectedRoot {
		t.Errorf("Multiple transactions root hash mismatch: expected %s, got %s", expectedRoot, tree.GetRootHash())
	}
}

// TestNewMerkleTreeOddNumberOfTransactions ensures proper handling of odd transaction counts.
func TestNewMerkleTreeOddNumberOfTransactions(t *testing.T) {
	tx1 := xtx.NewTransaction(xtx.TransferTx, "alice", "bob", 100, 1, 10, nil)
	tx2 := xtx.NewTransaction(xtx.TransferTx, "charlie", "dave", 200, 1, 20, nil)
	tx3 := xtx.NewTransaction(xtx.TransferTx, "eve", "frank", 300, 1, 30, nil)
	txs := []xtx.Transaction{*tx1, *tx2, *tx3}
	tree := NewMerkleTree(txs)
	tx1Hash, _ := hex.DecodeString(tx1.TxID)
	tx2Hash, _ := hex.DecodeString(tx2.TxID)
	tx3Hash, _ := hex.DecodeString(tx3.TxID)
	left := sha256.Sum256(tx1Hash)
	right := sha256.Sum256(tx2Hash)
	combined1 := append(left[:], right[:]...)
	hash1 := sha256.Sum256(combined1)
	duplicate := sha256.Sum256(tx3Hash)
	combined2 := append(duplicate[:], duplicate[:]...)
	hash2 := sha256.Sum256(combined2)
	combinedRoot := append(hash1[:], hash2[:]...)
	expectedRootHash := sha256.Sum256(combinedRoot)
	expectedRoot := hex.EncodeToString(expectedRootHash[:])
	if tree.GetRootHash() != expectedRoot {
		t.Errorf("Odd number transactions root hash mismatch: expected %s, got %s", expectedRoot, tree.GetRootHash())
	}
}
