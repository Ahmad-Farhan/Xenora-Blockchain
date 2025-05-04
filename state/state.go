package state

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
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
	SnapshotInterval = 100 // Take a snapshot every 1000 blocks
)

// EnhancedState extends the existing State with compression and archival capabilities
type EnhancedState struct {
	accounts    map[string]uint64 // address -> balance
	data        map[string][]byte // key -> value store for data
	nonces      map[string]uint64 // address -> nonce
	stateRoot   []byte            // Merkle root of the entire state
	archive     *StateArchive     // Archive for state persistence
	merkleTree  *StateMerkleTree  // Merkle tree for state verification
	prune       *StatePruner      // Pruner for state management
	accumulator *CryptoAccumulator
	zkSystem    *ZKProofSystem
	lock        sync.RWMutex
}

type BaseState struct {
	Accounts   map[string]uint64
	Data       map[string][]byte
	Nonces     map[string]uint64
	StateRoot  []byte
	AccumValue *big.Int
	Timestamp  time.Time
}

// StateArchive handles persistence and retrieval of state data
type StateArchive struct {
	stateDB   *leveldb.DB
	archiveDB *leveldb.DB
}

// StatePruner handles state pruning operations
type StatePruner struct {
	state     *EnhancedState
	ssHeight  uint64
	snapshots map[uint64][]byte // height -> stateRoot
}

// NewEnhancedState creates a new EnhancedState
func NewEnhancedState() *EnhancedState {
	archive, err := newStateArchive()
	if err != nil {
		panic(fmt.Sprintf("Archive init failed: %v", err))
	}

	s := &EnhancedState{
		accounts:    make(map[string]uint64),
		data:        make(map[string][]byte),
		nonces:      make(map[string]uint64),
		archive:     archive,
		merkleTree:  newStateMerkleTree(),
		accumulator: newCryptoAccumulator(),
		zkSystem:    newZKProofSystem(),
	}

	s.prune = newStatePruner(s)

	if err := s.LoadLatestState(); err != nil {
		fmt.Printf("Fresh state: %v\n", err)
	}

	return s
}

// GetBalance returns the balance for an address
func (s *EnhancedState) GetBalance(address string) uint64 {
	s.lock.RLock()
	defer s.lock.RUnlock()
	if balance, exists := s.accounts[address]; exists {
		return balance
	}
	return 0
}

// GetNonce returns the nonce for an address
func (s *EnhancedState) GetNonce(address string) uint64 {
	s.lock.RLock()
	defer s.lock.RUnlock()
	if nonce, exists := s.nonces[address]; exists {
		return nonce
	}
	return 0
}

// GetData retrieves stored data by key
func (s *EnhancedState) GetData(key string) []byte {
	s.lock.RLock()
	defer s.lock.RUnlock()
	if data, exists := s.data[key]; exists {
		return data
	}
	return nil
}

// GetStateRootString returns the current state root as a hex string
func (s *EnhancedState) GetStateRootString() string {
	return hex.EncodeToString(s.GetStateRoot())
}

// GetStateRoot returns the current state root
func (s *EnhancedState) GetStateRoot() []byte {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if len(s.stateRoot) == 0 {
		s.computeStateRoot()
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
	s.updateAccumulator()
}

// ApplyTransaction applies a transaction to the state
func (s *EnhancedState) ApplyTransaction(tx *xtx.Transaction) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if tx.Type != xtx.RewardTx {
		if s.nonces[tx.From] >= tx.Nonce {
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

	s.stateRoot = nil
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
	stateDB, err := leveldb.OpenFile(stateDBPath, opts)
	if err != nil {
		return nil, err
	}

	archiveDB, err := leveldb.OpenFile(archiveDBPath, opts)
	if err != nil {
		stateDB.Close()
		return nil, err
	}

	return &StateArchive{
		stateDB:   stateDB,
		archiveDB: archiveDB,
	}, nil
}

// LoadLatestState loads the most recent state snapshot
func (s *EnhancedState) LoadLatestState() error {
	s.lock.Lock()
	defer s.lock.Unlock()

	heightBytes, err := s.archive.stateDB.Get([]byte("latest_snapshot"), nil)
	if err != nil {
		return err
	}

	var height uint64
	fmt.Sscanf(string(heightBytes), "%d", &height)

	key := fmt.Sprintf("snapshot:%d", height)
	compressedData, err := s.archive.stateDB.Get([]byte(key), nil)
	if err != nil {
		return err
	}

	data, err := decompress(compressedData)
	if err != nil {
		return err
	}

	if err = s.deserialize(data); err != nil {
		return err
	}

	s.prune.ssHeight = height
	s.stateRoot = nil
	return nil
}

// serialize serializes the entire state
func (s *EnhancedState) serialize() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if len(s.stateRoot) == 0 {
		s.computeStateRoot()
	}

	state := BaseState{
		Accounts:   s.accounts,
		Data:       s.data,
		Nonces:     s.nonces,
		StateRoot:  s.stateRoot,
		AccumValue: s.accumulator.value,
		Timestamp:  time.Now(),
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

	if err := dec.Decode(&state); err != nil {
		return err
	}

	s.accounts = state.Accounts
	s.data = state.Data
	s.nonces = state.Nonces
	s.stateRoot = state.StateRoot

	if state.AccumValue != nil {
		s.accumulator.value = state.AccumValue
	}

	return nil
}

// PruneState prunes the state based on the specified strategy
func (s *EnhancedState) PruneState(currentHeight uint64) error {
	if currentHeight%SnapshotInterval == 0 {
		if err := s.CreateSnapshot(currentHeight); err != nil {
			return err
		}
	}
	return s.prune.pruneOldSnapshots(currentHeight)
}

// Archive moves older state snapshots to archival storage
func (s *EnhancedState) Archive(height uint64) error {
	if height > s.prune.ssHeight-2*SnapshotInterval {
		return nil
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	key := fmt.Sprintf("snapshot:%d", height)
	data, err := s.archive.stateDB.Get([]byte(key), nil)
	if err != nil {
		return err
	}

	err = s.archive.archiveDB.Put([]byte(key), data, nil)
	if err != nil {
		return err
	}

	return s.archive.stateDB.Delete([]byte(key), nil)
}

// CreateSnapshot creates a snapshot of the current state at a specific height
func (s *EnhancedState) CreateSnapshot(height uint64) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if len(s.stateRoot) == 0 {
		s.computeStateRoot()
	}

	stateData, err := s.serialize()
	if err != nil {
		return err
	}

	compressedData, err := compress(stateData)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("snapshot:%d", height)
	err = s.archive.stateDB.Put([]byte(key), compressedData, nil)
	if err != nil {
		return err
	}

	// Store the state root in the pruner
	s.prune.snapshots[height] = s.stateRoot
	s.prune.ssHeight = height

	value := []byte(fmt.Sprintf("%d", height))
	err = s.archive.stateDB.Put([]byte("latest_snapshot"), value, nil)
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

	if len(s.stateRoot) == 0 {
		s.computeStateRoot()
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

	merkleValid := bytes.Equal(currentHash, s.stateRoot)
	zkValid := true
	if proof.ZKProof != nil {
		zkValid = s.zkSystem.verifyProof(proof.ZKProof)
	}
	return merkleValid && zkValid, nil
}

// GenerateStateProof generates a proof for a specific key in the state
func (s *EnhancedState) GenerateStateProof(key string) ([]byte, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if len(s.stateRoot) == 0 {
		s.computeStateRoot()
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
	zkProof, err := s.zkSystem.generateProof(key, node.Value, s.stateRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ZK proof: %v", err)
	}
	proof.ZKProof = zkProof
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
		if s.archive.stateDB != nil {
			if err := s.archive.stateDB.Close(); err != nil {
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
