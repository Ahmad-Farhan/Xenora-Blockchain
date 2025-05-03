package merkle

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"testing"
	"xenora/crypto"
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

// createTx creates a transaction with a specified TxID for testing purposes.
func createTx(txID string) xtx.Transaction {
	return xtx.Transaction{TxID: txID}
}

// TestMerkleTree validates the MerkleTree functionality.
func TestMerkleTree1(t *testing.T) {
	t.Run("EmptyTree", func(t *testing.T) {
		tree := NewMerkleTree([]xtx.Transaction{})
		if tree.GetRootHash() != defaultHash {
			t.Errorf("Expected root hash %s for empty tree, got %s", nullhash, tree.GetRootHash())
		}
	})

	t.Run("SingleTransaction", func(t *testing.T) {
		tx := createTx("tx1")
		tree := NewMerkleTree([]xtx.Transaction{tx})
		txHash, _ := hex.DecodeString(tx.TxID)
		expectedHash := sha256.Sum256(txHash)
		expectedRoot := hex.EncodeToString(expectedHash[:])
		if got := tree.GetRootHash(); got != expectedRoot {
			t.Errorf("Expected root hash %s, got %s", expectedRoot, got)
		}
	})

	t.Run("MultipleTransactions", func(t *testing.T) {
		txs := []xtx.Transaction{createTx("tx1"), createTx("tx2"), createTx("tx3")}
		tree := NewMerkleTree(txs)
		hash1, _ := hex.DecodeString("tx1")
		hash2, _ := hex.DecodeString("tx2")
		hash3, _ := hex.DecodeString("tx3")
		leaf1 := sha256.Sum256(hash1)
		leaf2 := sha256.Sum256(hash2)
		leaf3 := sha256.Sum256(hash3)
		leaf4 := leaf3 // Duplicate last leaf for odd number
		parent1 := sha256.Sum256(append(leaf1[:], leaf2[:]...))
		parent2 := sha256.Sum256(append(leaf3[:], leaf4[:]...))
		root := sha256.Sum256(append(parent1[:], parent2[:]...))
		expectedRoot := hex.EncodeToString(root[:])
		if got := tree.GetRootHash(); got != expectedRoot {
			t.Errorf("Expected root hash %s, got %s", expectedRoot, got)
		}
	})

	// t.Run("ProofGenerationAndVerification", func(t *testing.T) {
	// 	txs := []xtx.Transaction{createTx("tx1"), createTx("tx2"), createTx("tx3")}
	// 	tree := NewMerkleTree(txs)
	// 	proof, err := tree.GenerateProof("tx2")
	// 	if err != nil {
	// 		t.Errorf("Failed to generate proof: %v", err)
	// 	}
	// 	if !VerifyProof(proof) {
	// 		t.Errorf("Proof verification failed for valid transaction tx2")
	// 	}
	// })

	// t.Run("InvalidProof", func(t *testing.T) {
	// 	txs := []xtx.Transaction{createTx("tx1"), createTx("tx2"), createTx("tx3")}
	// 	tree := NewMerkleTree(txs)
	// 	proof, _ := tree.GenerateProof("tx2")
	// 	if len(proof.Path) > 0 {
	// 		proof.Path[0] = "invalidhash" // Tamper with proof
	// 	}
	// 	if VerifyProof(proof) {
	// 		t.Errorf("Proof verification should fail for tampered proof")
	// 	}
	// })
}

// TestMerkleForest validates the MerkleForest functionality.
func TestMerkleForest1(t *testing.T) {
	forest := NewMerkleForest(2)

	t.Run("Initialization", func(t *testing.T) {
		if got := len(forest.Trees); got != 2 {
			t.Errorf("Expected 2 shards, got %d", got)
		}
	})

	t.Run("TransactionAddition", func(t *testing.T) {
		tx1 := createTx("00000000deadbeef") // Shard 0
		tx2 := createTx("00000001cafebeef") // Shard 1
		forest.AddTransaction(tx1)
		forest.AddTransaction(tx2)
		if got := len(forest.Trees[0].leaves); got != 1 {
			t.Errorf("Expected 1 transaction in shard 0, got %d", got)
		}
		if got := len(forest.Trees[1].leaves); got != 1 {
			t.Errorf("Expected 1 transaction in shard 1, got %d", got)
		}
	})

	t.Run("RootHashForShard", func(t *testing.T) {
		if got := forest.GetRootHashForShard(0); got == nullhash {
			t.Errorf("Expected non-null root hash for shard 0, got %s", got)
		}
	})

	t.Run("ForestHash", func(t *testing.T) {
		if got := forest.GetForestHash(); got == nullhash {
			t.Errorf("Expected non-null forest hash, got %s", got)
		}
	})

	t.Run("Rebalancing", func(t *testing.T) {
		for i := 0; i < 1001; i++ {
			txID := fmt.Sprintf("%08x", i)
			forest.AddTransaction(createTx(txID))
		}
		log.Print(forest.TotalShards)
		if got := forest.TotalShards; got <= 2 {
			t.Errorf("Expected more than 2 shards after rebalancing, got %d", got)
		}
	})
}

// TestBloomFilter validates the BloomFilter functionality.
func TestBloomFilter(t *testing.T) {
	bf := NewBloomFilter(1000, 0.01)

	t.Run("AddAndTest", func(t *testing.T) {
		bf.Add([]byte("testitem"))
		if !bf.Test([]byte("testitem")) {
			t.Errorf("Expected true for added item 'testitem'")
		}
	})

	t.Run("TestNonExistent", func(t *testing.T) {
		randomItem := make([]byte, 10)
		rand.Read(randomItem)
		if bf.Test(randomItem) {
			t.Logf("False positive detected for item: %x (this is statistically possible)", randomItem)
		}
	})
}

// TestCrossShardSynchronizer validates the CrossShardSynchronizer functionality.
func TestCrossShardSynchronizer1(t *testing.T) {
	forest := NewMerkleForest(2)
	css := NewCrossShardSynchronizer(forest)

	t.Run("ProcessCrossShardTransaction", func(t *testing.T) {
		mainTx := createTx("crossshardtx")
		mainTx.Type = xtx.CrossShardTx
		ctx := &CrossShardTransaction{
			MainTx:       &mainTx,
			SourceShard:  0,
			TargetShards: []uint32{1},
			AtomicID:     "atomic1",
		}
		if err := css.ProcessCrossShardTransaction(ctx); err != nil {
			t.Errorf("Failed to process cross-shard transaction: %v", err)
		}
		if ctx.Status != Committed {
			t.Errorf("Expected status Committed, got %v", ctx.Status)
		}
	})

	t.Run("VerifyCrossShardTransaction", func(t *testing.T) {
		valid, err := css.VerifyCrossShardTransaction("atomic1")
		if err != nil || !valid {
			t.Errorf("Failed to verify valid cross-shard transaction: %v", err)
		}
	})

	t.Run("InvalidAtomicID", func(t *testing.T) {
		valid, err := css.VerifyCrossShardTransaction("invalidatomic")
		if valid || err == nil {
			t.Errorf("Expected error for invalid atomic ID, got valid=%v, err=%v", valid, err)
		}
	})
}

// createSignedTx creates a signed transaction using the xtx package.
func createSignedTx(t *testing.T, priv *ecdsa.PrivateKey, from, to string, value, nonce, fee uint64) *xtx.Transaction {
	tx := xtx.NewTransaction(xtx.TransferTx, from, to, value, nonce, fee, []byte("test data"))
	if err := tx.Sign(priv); err != nil {
		t.Fatalf("Failed to sign transaction: %v", err)
	}
	return tx
}

// TestMerkleTree validates MerkleTree functionality with xtx transactions.
func TestMerkleTree(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()

	t.Run("EmptyTree", func(t *testing.T) {
		tree := NewMerkleTree([]xtx.Transaction{})
		if tree.GetRootHash() != defaultHash {
			t.Errorf("Expected root hash %s, got %s", nullhash, tree.GetRootHash())
		}
	})

	t.Run("SingleSignedTransaction", func(t *testing.T) {
		tx := createSignedTx(t, kp.PrivateKey, kp.GetAddress(), "toAddr", 100, 0, 10)
		tree := NewMerkleTree([]xtx.Transaction{*tx})
		txHash, _ := hex.DecodeString(tx.TxID)
		expectedHash := sha256.Sum256(txHash)
		expectedRoot := hex.EncodeToString(expectedHash[:])
		if got := tree.GetRootHash(); got != expectedRoot {
			t.Errorf("Expected root hash %s, got %s", expectedRoot, got)
		}
	})

	// t.Run("MultipleSignedTransactions", func(t *testing.T) {
	// 	txs := []*xtx.Transaction{
	// 		createSignedTx(t, kp.PrivateKey, kp.GetAddress(), "to1", 100, 0, 10),
	// 		createSignedTx(t, kp.PrivateKey, kp.GetAddress(), "to2", 200, 1, 20),
	// 		createSignedTx(t, kp.PrivateKey, kp.GetAddress(), "to3", 300, 2, 30),
	// 	}
	// 	tree := NewMerkleTree([]xtx.Transaction{*txs[0], *txs[1], *txs[2]})
	// 	proof, err := tree.GenerateProof(txs[1].TxID)
	// 	if err != nil {
	// 		t.Errorf("Failed to generate proof: %v", err)
	// 	}
	// 	if !VerifyProof(proof) {
	// 		t.Errorf("Proof verification failed")
	// 	}
	// })
}

// TestMerkleForest validates MerkleForest with xtx transactions.
func TestMerkleForest(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	forest := NewMerkleForest(2)

	t.Run("Initialization", func(t *testing.T) {
		if forest.TotalShards != 2 {
			t.Errorf("Expected 2 shards, got %d", forest.TotalShards)
		}
	})

	t.Run("AddSignedTransaction", func(t *testing.T) {
		tx1 := createSignedTx(t, kp.PrivateKey, kp.GetAddress(), "to1", 100, 0, 10) // Shard based on TxID
		forest.AddTransaction(*tx1)
		shardID := forest.GetShardForTransaction(tx1)
		if len(forest.Trees[shardID].leaves) != 1 {
			t.Errorf("Expected 1 transaction in shard %d", shardID)
		}
	})

	t.Run("Rebalancing", func(t *testing.T) {
		forest := NewMerkleForest(1)
		forest.ShardThreshold = 2
		forest.MaxShardsLimit = 3
		for i := 0; i < 4; i++ {
			tx := createSignedTx(t, kp.PrivateKey, kp.GetAddress(), fmt.Sprintf("to%d", i), 100, uint64(i), 10)
			// Adjust TxID to target shard 0 by setting prefix
			txBytes, _ := tx.Serialize()
			hash := sha256.Sum256(txBytes)
			tx.TxID = "00000000" + hex.EncodeToString(hash[4:])
			forest.AddTransaction(*tx)
		}
		if forest.TotalShards <= 1 {
			t.Errorf("Expected rebalancing, got %d shards", forest.TotalShards)
		}
	})

	t.Run("ProofForSignedTx", func(t *testing.T) {
		tx := createSignedTx(t, kp.PrivateKey, kp.GetAddress(), "toAddr", 100, 0, 10)
		forest.AddTransaction(*tx)
		proof, err := forest.GenerateProof(tx.TxID)
		if err != nil {
			t.Errorf("Failed to generate proof: %v", err)
		}
		if !VerifyProof(proof) {
			t.Errorf("Proof verification failed")
		}
	})
}

// TestCrossShardSynchronizer validates cross-shard transactions.
func TestCrossShardSynchronizer(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	forest := NewMerkleForest(2)
	css := NewCrossShardSynchronizer(forest)

	t.Run("ProcessCrossShardTx", func(t *testing.T) {
		tx := createSignedTx(t, kp.PrivateKey, kp.GetAddress(), "toAddr", 100, 0, 10)
		tx.Type = xtx.CrossShardTx
		tx.ExtraFields["atomicID"] = "atomic1"
		ctx := &CrossShardTransaction{
			MainTx:       tx,
			SourceShard:  0,
			TargetShards: []uint32{1},
			AtomicID:     "atomic1",
		}
		if err := css.ProcessCrossShardTransaction(ctx); err != nil {
			t.Errorf("Failed to process: %v", err)
		}
		if ctx.Status != Committed {
			t.Errorf("Expected Committed, got %v", ctx.Status)
		}
	})

	t.Run("VerifyCrossShardTx", func(t *testing.T) {
		valid, err := css.VerifyCrossShardTransaction("atomic1")
		if err != nil || !valid {
			t.Errorf("Verification failed: %v", err)
		}
	})
}

// TestConcurrency validates thread safety with xtx transactions.
func TestConcurrency(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	forest := NewMerkleForest(2)
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(nonce uint64) {
			defer wg.Done()
			tx := createSignedTx(t, kp.PrivateKey, kp.GetAddress(), fmt.Sprintf("to%d", nonce), 100, nonce, 10)
			forest.AddTransaction(*tx)
		}(uint64(i))
	}
	wg.Wait()

	totalTxs := 0
	for _, tree := range forest.Trees {
		totalTxs += len(tree.leaves)
	}
	if totalTxs != 50 {
		t.Errorf("Expected 50 transactions, got %d", totalTxs)
	}
}
