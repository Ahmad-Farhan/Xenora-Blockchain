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
	s.merkleTree.nodes = make(map[string]*StateNode)

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
		s.accounts[tx.From] -= (tx.Value + tx.Fee)
	}

	if tx.Type != xtx.RewardTx {
		s.nonces[tx.From] = tx.Nonce
	}

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
	if err := os.MkdirAll(stateDBPath, 0755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(archiveDBPath, 0755); err != nil {
		return nil, err
	}

	opts := &opt.Options{
		CompactionTableSize: 2 * 1024 * 1024,
		WriteBuffer:         16 * 1024 * 1024,
	}
	db, err := leveldb.OpenFile(stateDBPath, opts)
	if err != nil {
		return nil, err
	}

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

	heightBytes, err := s.archive.db.Get([]byte("latest_snapshot"), nil)
	if err != nil {
		return err
	}

	var height uint64
	fmt.Sscanf(string(heightBytes), "%d", &height)

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
	if currentHeight%SnapshotInterval == 0 {
		err := s.CreateSnapshot(currentHeight)
		if err != nil {
			return err
		}
	}
	return s.prune.pruneOldSnapshots(currentHeight)
}

// Archive moves older state snapshots to archival storage
func (s *EnhancedState) Archive(height uint64) error {
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

	err = s.archive.archiveDB.Put([]byte(key), data, nil)
	if err != nil {
		return err
	}

	return s.archive.db.Delete([]byte(key), nil)
}

// CreateSnapshot creates a snapshot of the current state at a specific height
func (s *EnhancedState) CreateSnapshot(height uint64) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.merkleTree.modified {
		s.computeStateRoot()
		s.merkleTree.modified = false
	}

	stateData, err := s.serialize()
	if err != nil {
		return err
	}

	key := fmt.Sprintf("snapshot:%d", height)
	err = s.archive.db.Put([]byte(key), stateData, nil)
	if err != nil {
		return err
	}

	// Store the state root in the pruner
	s.prune.snapshots[height] = s.stateRoot
	s.prune.snapshotHeight = height

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

	if s.merkleTree.modified {
		s.computeStateRoot()
		s.merkleTree.modified = false
	}

	currentHash := proof.Hash
	for i, sibling := range proof.Path {
		var combined []byte
		if proof.Positions[i] {
			combined = append(currentHash, sibling...)
		} else {
			combined = append(sibling, currentHash...)
		}
		currentHash = hashData(combined)
	}
	return bytes.Equal(currentHash, s.stateRoot), nil
}

// GenerateStateProof generates a proof for a specific key in the state
func (s *EnhancedState) GenerateStateProof(key string) ([]byte, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if s.merkleTree.modified {
		s.computeStateRoot()
		s.merkleTree.modified = false
	}

	node, exists := s.merkleTree.nodes[key]
	if !exists {
		return nil, errors.New("key not found")
	}

	proof := &StateProof{
		Key:       key,
		Value:     node.Value,
		Hash:      node.Hash,
		StateRoot: s.stateRoot,
		Path:      [][]byte{},
		Positions: []bool{},
	}

	current := node
	parent := s.findParent(current)
	for parent != nil {
		if parent.Left == current {
			proof.Path = append(proof.Path, parent.Right.Hash)
			proof.Positions = append(proof.Positions, true)
		} else {
			proof.Path = append(proof.Path, parent.Left.Hash)
			proof.Positions = append(proof.Positions, false)
		}
		current = parent
		parent = s.findParent(current)
	}

	return serializeProof(proof)
}

// findParent finds the parent of a node in the Merkle tree
func (s *EnhancedState) findParent(node *StateNode) *StateNode {
	for _, n := range s.merkleTree.nodes {
		if n.Left == node || n.Right == node {
			return n
		}
	}
	return nil
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
