package state

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
	"xenora/xtx"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

const (
	stateDBPath      = "./data/state"
	archiveDBPath    = "./data/archive"
	SnapshotInterval = 1000 // Take a snapshot every 1000 blocks
)

// StateNode represents a node in the state merkle tree
type StateNode struct {
	Key   string
	Value []byte
	Hash  []byte
}

// EnhancedState extends the existing State with compression and archival capabilities
type EnhancedState struct {
	accounts   map[string]uint64 // address -> balance
	data       map[string][]byte // key -> value store for data
	nonces     map[string]uint64 // address -> nonce
	stateRoot  []byte            // Merkle root of the entire state
	archive    *StateArchive     // Archive for state persistence
	merkleTree *StateMerkleTree  // Merkle tree for state verification
	prune      *StatePruner      // Pruner for state management
	lock       sync.RWMutex
}

type BaseState struct {
	Accounts  map[string]uint64
	Data      map[string][]byte
	Nonces    map[string]uint64
	StateRoot []byte
	Timestamp time.Time
}

// StateArchive handles persistence and retrieval of state data
type StateArchive struct {
	db        *leveldb.DB
	archiveDB *leveldb.DB
}

// StatePruner handles state pruning operations
type StatePruner struct {
	state          *EnhancedState
	snapshotHeight uint64
	snapshots      map[uint64][]byte // height -> stateRoot
}

// NewEnhancedState creates a new EnhancedState
func NewEnhancedState() *EnhancedState {
	archive, err := newStateArchive()
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize state archive: %v", err))
	}

	state := &EnhancedState{
		accounts:   make(map[string]uint64),
		data:       make(map[string][]byte),
		nonces:     make(map[string]uint64),
		archive:    archive,
		merkleTree: newStateMerkleTree(),
	}

	state.prune = newStatePruner(state)

	// Try to load the latest state from the archive
	err = state.LoadLatestState()
	if err != nil {
		// If we can't load a state, we're starting fresh
		fmt.Printf("Starting with fresh state: %v\n", err)
	}

	return state
}

// GetBalance returns the balance for an address
func (s *EnhancedState) GetBalance(address string) uint64 {
	s.lock.RLock()
	defer s.lock.RUnlock()
	balance, exists := s.accounts[address]
	if !exists {
		return 0
	}
	return balance
}

// GetNonce returns the nonce for an address
func (s *EnhancedState) GetNonce(address string) uint64 {
	s.lock.RLock()
	defer s.lock.RUnlock()
	nonce, exists := s.nonces[address]
	if !exists {
		return 0
	}
	return nonce
}

// GetData retrieves stored data by key
func (s *EnhancedState) GetData(key string) []byte {
	s.lock.RLock()
	defer s.lock.RUnlock()
	data, exists := s.data[key]
	if !exists {
		return nil
	}
	return data
}

// GetStateRootString returns the current state root as a hex string
func (s *EnhancedState) GetStateRootString() string {
	return hex.EncodeToString(s.GetStateRoot())
}

// GetStateRoot returns the current state root
func (s *EnhancedState) GetStateRoot() []byte {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if s.merkleTree.modified {
		s.computeStateRoot()
		s.merkleTree.modified = false
	}

	return s.stateRoot
}

// computeStateRoot calculates the Merkle root of the current state
func (s *EnhancedState) computeStateRoot() {
	// Clear the existing tree
	s.merkleTree.nodeMap = make(map[string]*StateNode)

	// Add all accounts to the tree
	for addr, balance := range s.accounts {
		key := "acct:" + addr
		value := uint64ToBytes(balance)
		s.merkleTree.addNode(key, value)
	}

	// Add all nonces to the tree
	for addr, nonce := range s.nonces {
		key := "nonce:" + addr
		value := uint64ToBytes(nonce)
		s.merkleTree.addNode(key, value)
	}

	// Add all data entries to the tree
	for key, value := range s.data {
		treeKey := "data:" + key
		s.merkleTree.addNode(treeKey, value)
	}

	// Compute the root hash
	s.stateRoot = s.merkleTree.computeRoot()
}

// ApplyTransaction applies a transaction to the state
func (s *EnhancedState) ApplyTransaction(tx *xtx.Transaction) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if tx.Type != xtx.RewardTx {
		currentNonce := s.nonces[tx.From]
		if currentNonce >= tx.Nonce {
			return errors.New("invalid nonce")
		}
		if s.accounts[tx.From] < tx.Value+tx.Fee {
			return errors.New("insufficient balance")
		}
	}

	// Apply transaction based on type
	switch tx.Type {
	case xtx.TransferTx:
		s.accounts[tx.From] -= (tx.Value + tx.Fee)
		s.accounts[tx.To] += tx.Value

	case xtx.RewardTx:
		s.accounts[tx.To] += tx.Value

	case xtx.DataTx:
		if len(tx.Data) > 0 {
			dataKey := tx.From + "-" + tx.TxID
			s.data[dataKey] = tx.Data
			if tx.From != "" {
				s.accounts[tx.From] -= tx.Fee
			}
		}

	case xtx.CrossShardTx:
		// Handle cross-shard transaction logic
		s.accounts[tx.From] -= (tx.Value + tx.Fee)
		// The receiving account will be updated when the transaction is finalized
	}

	if tx.Type != xtx.RewardTx {
		s.nonces[tx.From] = tx.Nonce
	}

	// Mark the Merkle tree as modified
	s.merkleTree.modified = true

	return nil
}

// newStatePruner creates a new state pruner
func newStatePruner(state *EnhancedState) *StatePruner {
	return &StatePruner{
		state:     state,
		snapshots: make(map[uint64][]byte),
	}
}

// pruneOldSnapshots removes old snapshots based on a retention policy
func (sp *StatePruner) pruneOldSnapshots(currentHeight uint64) error {
	// Keep all snapshots from the last 10 intervals
	minHeightToKeep := currentHeight - 10*SnapshotInterval
	if minHeightToKeep <= 0 {
		return nil
	}

	// Find snapshots to prune
	toArchive := []uint64{}
	for height := range sp.snapshots {
		if height < minHeightToKeep {
			if err := sp.state.Archive(height); err != nil {
				return err
			}
			toArchive = append(toArchive, height)
		}
	}

	// Remove the archived snapshots from the pruner
	for _, height := range toArchive {
		delete(sp.snapshots, height)
	}

	return nil
}

// newStateArchive creates a new state archive
func newStateArchive() (*StateArchive, error) {
	// Ensure directories exist
	if err := os.MkdirAll(stateDBPath, 0755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(archiveDBPath, 0755); err != nil {
		return nil, err
	}

	// Open the main state database
	opts := &opt.Options{
		CompactionTableSize: 2 * 1024 * 1024,
		WriteBuffer:         16 * 1024 * 1024,
	}
	db, err := leveldb.OpenFile(stateDBPath, opts)
	if err != nil {
		return nil, err
	}

	// Open the archive database
	archiveDB, err := leveldb.OpenFile(archiveDBPath, opts)
	if err != nil {
		db.Close()
		return nil, err
	}

	return &StateArchive{
		db:        db,
		archiveDB: archiveDB,
	}, nil
}

// LoadLatestState loads the most recent state snapshot
func (s *EnhancedState) LoadLatestState() error {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Get the latest snapshot height
	heightBytes, err := s.archive.db.Get([]byte("latest_snapshot"), nil)
	if err != nil {
		return err
	}

	var height uint64
	fmt.Sscanf(string(heightBytes), "%d", &height)

	// Load the snapshot
	key := fmt.Sprintf("snapshot:%d", height)
	data, err := s.archive.db.Get([]byte(key), nil)
	if err != nil {
		return err
	}

	err = s.deserialize(data)
	if err != nil {
		return err
	}

	s.prune.snapshotHeight = height
	return nil
}

// serialize serializes the entire state
func (s *EnhancedState) serialize() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	state := BaseState{
		Accounts:  s.accounts,
		Data:      s.data,
		Nonces:    s.nonces,
		StateRoot: s.stateRoot,
		Timestamp: time.Now(),
	}

	if err := enc.Encode(state); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// deserialize deserializes the state from bytes
func (s *EnhancedState) deserialize(data []byte) error {
	var state BaseState

	buf := bytes.NewReader(data)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(&state)
	if err != nil {
		return err
	}

	s.accounts = state.Accounts
	s.data = state.Data
	s.nonces = state.Nonces
	s.stateRoot = state.StateRoot
	s.merkleTree.modified = true

	return nil
}

// PruneState prunes the state based on the specified strategy
func (s *EnhancedState) PruneState(currentHeight uint64) error {
	// If we've passed the snapshot interval, create a new snapshot
	if currentHeight%SnapshotInterval == 0 {
		err := s.CreateSnapshot(currentHeight)
		if err != nil {
			return err
		}
	}

	// Let the pruner decide what to prune
	return s.prune.pruneOldSnapshots(currentHeight)
}

// Archive moves older state snapshots to archival storage
func (s *EnhancedState) Archive(height uint64) error {
	// Only archive if it's far enough in the past
	if height > s.prune.snapshotHeight-2*SnapshotInterval {
		return nil
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	key := fmt.Sprintf("snapshot:%d", height)
	data, err := s.archive.db.Get([]byte(key), nil)
	if err != nil {
		return err
	}

	// Store in archive DB
	err = s.archive.archiveDB.Put([]byte(key), data, nil)
	if err != nil {
		return err
	}

	// Delete from main DB
	return s.archive.db.Delete([]byte(key), nil)
}

// CreateSnapshot creates a snapshot of the current state at a specific height
func (s *EnhancedState) CreateSnapshot(height uint64) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Compute state root if needed
	if s.merkleTree.modified {
		s.computeStateRoot()
		s.merkleTree.modified = false
	}

	// Serialize the state
	stateData, err := s.serialize()
	if err != nil {
		return err
	}

	// Store the snapshot in the archive
	key := fmt.Sprintf("snapshot:%d", height)
	err = s.archive.db.Put([]byte(key), stateData, nil)
	if err != nil {
		return err
	}

	// Store the state root in the pruner
	s.prune.snapshots[height] = s.stateRoot
	s.prune.snapshotHeight = height

	// Store a reference to this snapshot as latest
	err = s.archive.db.Put([]byte("latest_snapshot"), []byte(fmt.Sprintf("%d", height)), nil)
	if err != nil {
		return err
	}

	return nil
}

// VerifyStateProof verifies a proof against the current state root
func (s *EnhancedState) VerifyStateProof(proofData []byte) (bool, error) {
	proof, err := deserializeProof(proofData)
	if err != nil {
		return false, err
	}

	s.lock.RLock()
	defer s.lock.RUnlock()

	// Ensure we have the latest state root
	if s.merkleTree.modified {
		s.computeStateRoot()
		s.merkleTree.modified = false
	}

	// In a real implementation, this would verify the Merkle path
	// For our prototype, we'll verify the key exists in our current state
	valueHash := hashData(proof.Value)
	if !bytes.Equal(valueHash, proof.Hash) {
		return false, errors.New("hash mismatch")
	}

	// Simple verification - check if the state root matches our current state
	return bytes.Equal(s.stateRoot, proof.StateRoot), nil
}

// GenerateStateProof generates a proof for a specific key in the state
func (s *EnhancedState) GenerateStateProof(key string) ([]byte, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if s.merkleTree.modified {
		s.computeStateRoot()
		s.merkleTree.modified = false
	}

	// Generate a simple inclusion proof
	// In a production system, this would be more sophisticated
	proof := &StateProof{
		Key:       key,
		StateRoot: s.stateRoot,
	}

	// Figure out what type of key this is and get the value
	var value []byte
	if len(key) >= 5 && key[:5] == "acct:" {
		addr := key[5:]
		balance, exists := s.accounts[addr]
		if !exists {
			return nil, errors.New("account not found")
		}
		value = uint64ToBytes(balance)
	} else if len(key) >= 6 && key[:6] == "nonce:" {
		addr := key[6:]
		nonce, exists := s.nonces[addr]
		if !exists {
			return nil, errors.New("nonce not found")
		}
		value = uint64ToBytes(nonce)
	} else if len(key) >= 5 && key[:5] == "data:" {
		dataKey := key[5:]
		var exists bool
		value, exists = s.data[dataKey]
		if !exists {
			return nil, errors.New("data not found")
		}
	} else {
		return nil, errors.New("invalid key format")
	}

	proof.Value = value
	proof.Hash = hashData(value)

	// Serialize the proof
	return serializeProof(proof)
}

// Close closes the state databases
func (s *EnhancedState) Close() error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.archive != nil {
		if s.archive.db != nil {
			if err := s.archive.db.Close(); err != nil {
				return err
			}
		}
		if s.archive.archiveDB != nil {
			if err := s.archive.archiveDB.Close(); err != nil {
				return err
			}
		}
	}

	return nil
}
