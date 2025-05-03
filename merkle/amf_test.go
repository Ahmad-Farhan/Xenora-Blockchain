package merkle

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
	"xenora/xtx"
)

// const nullhash = "0000000000000000000000000000000000000000000000000000000000000000"
const defaultHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestNewMerkleForest(t *testing.T) {
	f := NewMerkleForest(3)
	if len(f.Trees) != 3 {
		t.Errorf("expected 3 trees, got %d", len(f.Trees))
	}
	for i := uint32(0); i < 3; i++ {
		root := f.GetRootHashForShard(i)
		if root != defaultHash {
			t.Errorf("shard %d: expected root %s, got %s", i, nullhash, root)
		}
	}
}

func TestGetShardForTransaction(t *testing.T) {
	f := NewMerkleForest(4)
	tx := xtx.Transaction{TxID: "0000000a", Type: 0}
	shard := f.GetShardForTransaction(&tx)
	expected := binary.BigEndian.Uint32([]byte{0x00, 0x00, 0x00, 0x0a}) % 4
	if shard != expected {
		t.Errorf("expected shard %d, got %d", expected, shard)
	}

	// cross-shard always maps to 0
	c := xtx.Transaction{TxID: "deadbeef", Type: xtx.CrossShardTx}
	if f.GetShardForTransaction(&c) != 0 {
		t.Error("CrossShardTx should map to shard 0")
	}
}

func TestAddTransactionAndRoot(t *testing.T) {
	f := NewMerkleForest(1)
	txid := "abcdef01"
	tx := xtx.Transaction{TxID: txid, Type: 0}
	f.AddTransaction(tx)

	if f.ShardInfo[0].TransactionCount != 1 {
		t.Errorf("expected TransactionCount 1, got %d", f.ShardInfo[0].TransactionCount)
	}

	// Compute expected leaf hash
	data, _ := hex.DecodeString(txid)
	leaf := sha256.Sum256(data)
	want := hex.EncodeToString(leaf[:])

	if root := f.GetRootHashForShard(0); root != want {
		t.Errorf("expected root %s, got %s", want, root)
	}
}

func TestForestHash(t *testing.T) {
	f := NewMerkleForest(2)
	tx1 := xtx.Transaction{TxID: "aa", Type: 0}
	tx2 := xtx.Transaction{TxID: "bb", Type: 0}
	f.AddTransaction(tx1)
	f.AddTransaction(tx2)

	// Manually compute combined forest hash
	root0Bytes, _ := hex.DecodeString(f.GetRootHashForShard(0))
	root1Bytes, _ := hex.DecodeString(f.GetRootHashForShard(1))
	combined := append(root0Bytes, root1Bytes...)
	sum := sha256.Sum256(combined)
	want := hex.EncodeToString(sum[:])

	if forest := f.GetForestHash(); forest != want {
		t.Errorf("expected forest hash %s, got %s", want, forest)
	}
}

func TestAutoSharding(t *testing.T) {
	f := NewMerkleForest(1)
	f.ShardThreshold = 2

	// Add one more than threshold to trigger rebalance
	for i := 0; i < 4; i++ {
		tx := xtx.Transaction{TxID: fmt.Sprintf("%08x", i+1), Type: 0}
		f.AddTransaction(tx)
	}

	if f.TotalShards != 2 {
		t.Errorf("expected TotalShards 2, got %d", f.TotalShards)
	}

	// Ensure new shard got some transactions
	if f.ShardInfo[1].TransactionCount == 0 {
		t.Error("expected new shard to receive transactions")
	}
}

func TestGenerateAndVerifyProof(t *testing.T) {
	f := NewMerkleForest(2)
	f.ShardThreshold = 10

	targetTx := xtx.Transaction{TxID: "deadbeef", Type: 0}
	f.AddTransaction(targetTx)

	for i := 0; i < 50; i++ {
		txid := fmt.Sprintf("%08x", i+1)
		f.AddTransaction(xtx.Transaction{TxID: txid, Type: 0})
	}

	proof, err := f.GenerateProof(targetTx.TxID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !VerifyProof(proof) {
		t.Error("proof verification failed for target transaction")
	}

	if _, err := f.GenerateProof("nope"); err == nil {
		t.Error("expected error for nonexistent tx")
	}

	// Check proof for a few random transactions
	for i := 10; i < 20; i++ {
		txid := fmt.Sprintf("%08x", i+1)
		proof, err := f.GenerateProof(txid)
		if err != nil {
			t.Errorf("failed to generate proof for tx %s: %v", txid, err)
			continue
		}
		if !VerifyProof(proof) {
			t.Errorf("proof verification failed for tx %s", txid)
		}
	}
}
