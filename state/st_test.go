package state

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"xenora/xtx"

	"github.com/syndtr/goleveldb/leveldb"
)

const testDBPath = "./state/data"

// cleanupDB removes test databases
func cleanupDB(t *testing.T) {
	os.RemoveAll(testDBPath)
	os.RemoveAll(filepath.Join(testDBPath, "state"))
	os.RemoveAll(filepath.Join(testDBPath, "archive"))
}

// TestNewEnhancedState tests initialization of EnhancedState
func TestNewEnhancedState(t *testing.T) {
	defer cleanupDB(t)
	s := NewEnhancedState()
	if s == nil {
		t.Fatal("NewEnhancedState returned nil")
	}
	if len(s.accounts) != 0 || len(s.data) != 0 || len(s.nonces) != 0 {
		t.Error("New state should have empty maps")
	}
	if s.archive == nil || s.merkleTree == nil || s.accumulator == nil {
		t.Error("State components not initialized")
	}
}

// TestApplyTransaction tests transaction application
func TestApplyTransaction(t *testing.T) {
	defer cleanupDB(t)
	s := NewEnhancedState()
	// Setup initial state
	s.accounts["alice"] = 1000
	s.nonces["alice"] = 0

	tx := xtx.NewTransaction(xtx.TransferTx, "alice", "bob", 200, 1, 10, nil)

	// Test valid transaction
	err := s.ApplyTransaction(tx)
	if err != nil {
		t.Errorf("ApplyTransaction failed: %v", err)
	}
	if s.accounts["alice"] != 790 {
		t.Errorf("Expected alice balance 790, got %d", s.accounts["alice"])
	}
	if s.accounts["bob"] != 200 {
		t.Errorf("Expected bob balance 200, got %d", s.accounts["bob"])
	}
	if s.nonces["alice"] != 1 {
		t.Errorf("Expected alice nonce 1, got %d", s.nonces["alice"])
	}

	// Test insufficient balance
	tx.Value = 1000
	tx.Nonce += 1
	err = s.ApplyTransaction(tx)
	if err == nil || err.Error() != "insufficient balance" {
		t.Errorf("Expected insufficient balance error, got %v", err)
	}

	// Test invalid nonce
	tx.Value = 100
	tx.Nonce = 1
	err = s.ApplyTransaction(tx)
	if err == nil || err.Error() != "invalid nonce" {
		t.Errorf("Expected invalid nonce error, got %v", err)
	}
}

// TestStateRootComputation tests state root consistency
func TestStateRootComputation(t *testing.T) {
	defer cleanupDB(t)
	s := NewEnhancedState()

	s.accounts["alice"] = 1000
	s.nonces["alice"] = 1
	s.data["key1"] = []byte("value1")

	root1 := s.GetStateRootString()
	s.computeStateRoot()
	root2 := s.GetStateRootString()

	if root1 != root2 {
		t.Errorf("State root inconsistent: %s != %s", root1, root2)
	}
	if root1 == "" {
		t.Error("State root should not be empty")
	}
}

// TestSnapshotAndPruning tests snapshot creation and pruning
func TestSnapshotAndPruning(t *testing.T) {
	defer cleanupDB(t)
	s := NewEnhancedState()

	// Create initial state
	s.accounts["alice"] = 1000
	s.nonces["alice"] = 1

	// Create snapshots
	for h := uint64(0); h <= SnapshotInterval*2; h += SnapshotInterval {
		err := s.CreateSnapshot(h)
		if err != nil {
			t.Errorf("CreateSnapshot failed at height %d: %v", h, err)
		}
	}

	// Prune old snapshots
	err := s.PruneState(SnapshotInterval * 3)
	if err != nil {
		t.Errorf("PruneState failed: %v", err)
	}

	// Verify pruning
	for h := uint64(0); h < SnapshotInterval; h += SnapshotInterval {
		key := fmt.Sprintf("snapshot:%d", h)
		_, err := s.archive.stateDB.Get([]byte(key), nil)
		if err != leveldb.ErrNotFound {
			t.Errorf("Snapshot at height %d not pruned", h)
		}
		_, err = s.archive.archiveDB.Get([]byte(key), nil)
		if err != nil {
			t.Errorf("Snapshot at height %d not archived: %v", h, err)
		}
	}
}

// TestStateProof tests state proof generation and verification
func TestStateProof(t *testing.T) {
	defer cleanupDB(t)
	s := NewEnhancedState()

	// Setup state
	s.accounts["alice"] = 1000
	s.computeStateRoot()

	// Generate proof
	proofBytes, err := s.GenerateStateProof("acct:alice")
	if err != nil {
		t.Errorf("GenerateStateProof failed: %v", err)
	}

	// Verify proof
	valid, err := s.VerifyStateProof(proofBytes)
	if err != nil || !valid {
		t.Errorf("VerifyStateProof failed: valid=%v, err=%v", valid, err)
	}

	// Test invalid key
	_, err = s.GenerateStateProof("invalid")
	if err == nil || err.Error() != "key not found" {
		t.Errorf("Expected key not found error, got %v", err)
	}
}

// TestArchiveAndLoad tests state archival and loading
func TestArchiveAndLoad(t *testing.T) {
	defer cleanupDB(t)
	s := NewEnhancedState()
	// Setup state and snapshot
	s.accounts["alice"] = 1000
	s.nonces["alice"] = 1
	err := s.CreateSnapshot(SnapshotInterval)
	if err != nil {
		t.Errorf("CreateSnapshot failed: %v", err)
	}

	// Load and verify state
	err = s.LoadLatestState()
	if err != nil {
		t.Errorf("LoadLatestState failed: %v", err)
	}
	if s.accounts["alice"] != 1000 || s.nonces["alice"] != 1 {
		t.Error("Loaded state incorrect")
	}
	// Archive snapshot
	err = s.Archive(SnapshotInterval)
	if err != nil {
		t.Errorf("Archive failed: %v", err)
	}

	// Verify archived snapshot
	key := fmt.Sprintf("snapshot:%d", SnapshotInterval)
	_, err = s.archive.stateDB.Get([]byte(key), nil)
	if err != leveldb.ErrNotFound {
		t.Error("Snapshot not removed from stateDB")
	}
	if _, err := s.archive.archiveDB.Get([]byte(key), nil); err != nil {
		t.Errorf("Snapshot not found in archiveDB: %v", err)
	}
	// Load and verify state
	err = s.LoadLatestState()
	if err == nil {
		t.Errorf("LoadLatestState failed: %v", err)
	}
}
