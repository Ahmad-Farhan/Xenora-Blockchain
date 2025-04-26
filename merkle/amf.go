package merkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"xenora/xtx"
)

// ShardInfo represents metadata about a shard
type ShardInfo struct {
	ShardID          uint32
	TransactionCount uint64
	StateSize        uint64
	LoadFactor       float64
}

// MerkleForest represents a collection of Merkle trees organized by shard
type MerkleForest struct {
	Trees          map[uint32]*MerkleTree
	ShardInfo      map[uint32]*ShardInfo
	TotalShards    uint32
	MaxShardsLimit uint32
	ShardThreshold uint64
	lock           sync.RWMutex
	bloomFilters   map[uint32]*BloomFilter
}

const nullhash = "0000000000000000000000000000000000000000000000000000000000000000" // 64 zeros

// NewMerkleForest creates a new Merkle Forest with initial sharding configuration
func NewMerkleForest(initialShardCount uint32) *MerkleForest {
	if initialShardCount < 1 {
		initialShardCount = 1
	}

	forest := &MerkleForest{
		Trees:          make(map[uint32]*MerkleTree),
		ShardInfo:      make(map[uint32]*ShardInfo),
		TotalShards:    initialShardCount,
		MaxShardsLimit: 16,
		ShardThreshold: 1000,
		bloomFilters:   make(map[uint32]*BloomFilter),
	}

	for i := uint32(0); i < initialShardCount; i++ {
		forest.ShardInfo[i] = &ShardInfo{
			ShardID:    i,
			LoadFactor: 0.0,
			StateSize:  0,
		}
		forest.Trees[i] = NewMerkleTree([]xtx.Transaction{})
		forest.bloomFilters[i] = NewBloomFilter(10000, 0.01) // 10k items, 1% error rate
	}

	return forest
}

// GetShardForTransaction determines which shard a transaction belongs to
func (f *MerkleForest) GetShardForTransaction(tx *xtx.Transaction) uint32 {
	if tx.Type == xtx.CrossShardTx {
		return 0
	}
	txid, _ := hex.DecodeString(tx.TxID)
	if len(txid) < 4 {
		return 0
	}
	// Use first 4 bytes of txid as shard number
	shardNum := binary.BigEndian.Uint32(txid[:4]) % f.TotalShards
	return shardNum
}

// AddTransaction adds a transaction to the appropriate shard
func (f *MerkleForest) AddTransaction(tx xtx.Transaction) {
	f.lock.Lock()
	defer f.lock.Unlock()

	shardID := f.GetShardForTransaction(&tx)
	if _, exists := f.Trees[shardID]; !exists {
		f.Trees[shardID] = NewMerkleTree([]xtx.Transaction{})
		f.ShardInfo[shardID] = &ShardInfo{
			ShardID:    shardID,
			LoadFactor: 0.0,
			StateSize:  0,
		}
		f.bloomFilters[shardID] = NewBloomFilter(10000, 0.01)
	}

	// Add transaction to the tree
	var txs []xtx.Transaction
	if f.Trees[shardID].RootNode != nil {
		txs = f.Trees[shardID].leaves
	}
	txs = append(txs, tx)
	f.Trees[shardID] = NewMerkleTree(txs)
	f.Trees[shardID].leaves = txs

	info := f.ShardInfo[shardID]
	info.TransactionCount++
	info.LoadFactor = float64(info.TransactionCount) / float64(f.ShardThreshold)

	f.bloomFilters[shardID].Add([]byte(tx.TxID))
	if info.TransactionCount > f.ShardThreshold && f.TotalShards < f.MaxShardsLimit {
		f.rebalanceShards()
	}
}

// GetRootHashForShard returns the Merkle root for a specific shard
func (f *MerkleForest) GetRootHashForShard(shardID uint32) string {
	f.lock.RLock()
	defer f.lock.RUnlock()

	tree, exists := f.Trees[shardID]
	if !exists || tree.RootNode == nil {
		return nullhash
	}

	return tree.GetRootHash()
}

// GetForestHash returns a combined hash of all shard root hashes
func (f *MerkleForest) GetForestHash() string {
	f.lock.RLock()
	defer f.lock.RUnlock()

	// Get all shard IDs and sort them
	shardIDs := make([]uint32, 0, len(f.Trees))
	for shardID := range f.Trees {
		shardIDs = append(shardIDs, shardID)
	}
	sort.Slice(shardIDs, func(i, j int) bool { return shardIDs[i] < shardIDs[j] })

	// Combine all root hashes
	var combined []byte
	for _, shardID := range shardIDs {
		if f.Trees[shardID].RootNode != nil {
			rootHash, _ := hex.DecodeString(f.Trees[shardID].GetRootHash())
			combined = append(combined, rootHash...)
		}
	}

	if len(combined) == 0 {
		return nullhash
	}
	hash := sha256.Sum256(combined)
	return hex.EncodeToString(hash[:])
}

// rebalanceShards adjusts sharding based on current load
func (f *MerkleForest) rebalanceShards() {
	overloadedShards := make([]uint32, 0)
	for id, info := range f.ShardInfo {
		if info.LoadFactor > 1.5 {
			overloadedShards = append(overloadedShards, id)
		}
	}
	if len(overloadedShards) == 0 {
		return
	}

	// Add shards if needed and under the limit
	newShardID := f.TotalShards
	if newShardID < f.MaxShardsLimit {
		f.TotalShards++
		f.Trees[newShardID] = NewMerkleTree([]xtx.Transaction{})
		f.ShardInfo[newShardID] = &ShardInfo{
			ShardID:    newShardID,
			LoadFactor: 0.0,
			StateSize:  0,
		}
		f.bloomFilters[newShardID] = NewBloomFilter(10000, 0.01)
		f.redistributeTransactions()
	}
}

// redistributeTransactions moves transactions between shards based on updated shard count
func (f *MerkleForest) redistributeTransactions() {
	allTransactions := make([]xtx.Transaction, 0)
	for _, tree := range f.Trees {
		if tree.leaves != nil {
			allTransactions = append(allTransactions, tree.leaves...)
		}
	}

	// Reset and redistribute
	for shardID := range f.Trees {
		f.Trees[shardID] = NewMerkleTree([]xtx.Transaction{})
		f.Trees[shardID].leaves = []xtx.Transaction{}
		f.ShardInfo[shardID].TransactionCount = 0
		f.ShardInfo[shardID].LoadFactor = 0.0
		f.bloomFilters[shardID] = NewBloomFilter(10000, 0.01)
	}
	for _, tx := range allTransactions {
		shardID := f.GetShardForTransaction(&tx)

		if _, exists := f.Trees[shardID]; !exists {
			f.Trees[shardID] = NewMerkleTree([]xtx.Transaction{})
			f.ShardInfo[shardID] = &ShardInfo{
				ShardID:    shardID,
				LoadFactor: 0.0,
				StateSize:  0,
			}
			f.bloomFilters[shardID] = NewBloomFilter(10000, 0.01)
		}

		txs := f.Trees[shardID].leaves
		if txs == nil {
			txs = []xtx.Transaction{}
		}

		txs = append(txs, tx)
		f.Trees[shardID].leaves = txs
		f.Trees[shardID] = NewMerkleTree(txs)
		f.ShardInfo[shardID].TransactionCount++
		f.ShardInfo[shardID].LoadFactor = float64(f.ShardInfo[shardID].TransactionCount) / float64(f.ShardThreshold)
		f.bloomFilters[shardID].Add([]byte(tx.TxID))
	}
}

// MerkleProof represents a compact proof of inclusion
func (f *MerkleForest) GenerateProof(txID string) (*MerkleProof, error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	// Find which shard contains the transaction
	var foundShardID uint32
	var foundTx *xtx.Transaction
	var foundTree *MerkleTree
	var txIndex int

	// First use bloom filters for quick elimination
	for shardID, filter := range f.bloomFilters {
		if filter.Test([]byte(txID)) {
			for i, tx := range f.Trees[shardID].leaves {
				if tx.TxID == txID {
					foundShardID = shardID
					foundTx = &tx
					foundTree = f.Trees[shardID]
					txIndex = i
					break
				}
			}
		}
	}

	if foundTx == nil {
		return nil, errors.New("transaction not found in any shard")
	}

	// Generate proof path
	proofPath := make([]string, 0)
	isLeft := make([]bool, 0)
	var nodes []*MerkleNode
	for _, tx := range foundTree.leaves {
		hash, _ := hex.DecodeString(tx.TxID)
		nodes = append(nodes, NewMerkleNode(nil, nil, hash))
	}

	currentLevel := nodes
	currentIndex := txIndex
	for len(currentLevel) > 1 {
		if currentIndex%2 == 0 { // Left node
			if currentIndex+1 < len(currentLevel) {
				proofPath = append(proofPath, hex.EncodeToString(currentLevel[currentIndex+1].Data))
				isLeft = append(isLeft, false)
			} else {
				proofPath = append(proofPath, hex.EncodeToString(currentLevel[currentIndex].Data))
				isLeft = append(isLeft, false)
			}
		} else { // Right node
			proofPath = append(proofPath, hex.EncodeToString(currentLevel[currentIndex-1].Data))
			isLeft = append(isLeft, true)
		}

		// Move to next level
		var nextLevel []*MerkleNode
		for i := 0; i < len(currentLevel); i += 2 {
			var left, right *MerkleNode

			left = currentLevel[i]
			if i+1 < len(currentLevel) {
				right = currentLevel[i+1]
			} else {
				right = left
			}

			nextLevel = append(nextLevel, NewMerkleNode(left, right, nil))
		}
		currentIndex = currentIndex / 2
		currentLevel = nextLevel
	}

	proof := &MerkleProof{
		TxID:       txID,
		ShardID:    foundShardID,
		MerkleRoot: foundTree.GetRootHash(),
		Path:       proofPath,
		IsLeft:     isLeft,
		ForestRoot: f.GetForestHash(),
	}

	return proof, nil
}

// MerkleProof represents a proof that a transaction is in the Merkle tree
type MerkleProof struct {
	TxID       string   // Transaction ID being proven
	ShardID    uint32   // Shard containing the transaction
	MerkleRoot string   // Root hash of the tree
	Path       []string // Hashes forming the proof path
	IsLeft     []bool   // Whether each proof node is a left child
	ForestRoot string   // Combined root hash of the forest
}

// VerifyProof verifies a transaction is in the tree using the provided proof
func VerifyProof(proof *MerkleProof) bool {
	if len(proof.Path) == 0 {
		return proof.MerkleRoot == nullhash
	}

	// Start with transaction hash
	hash, _ := hex.DecodeString(proof.TxID)
	currentHash := sha256.Sum256(hash)
	for i, proofElement := range proof.Path {
		proofHash, _ := hex.DecodeString(proofElement)

		var combinedHash []byte
		if proof.IsLeft[i] { // Sibling on left
			combinedHash = append(proofHash, currentHash[:]...)
		} else { // Sibling on right
			combinedHash = append(currentHash[:], proofHash...)
		}

		hash := sha256.Sum256(combinedHash)
		currentHash = hash
	}
	return hex.EncodeToString(currentHash[:]) == proof.MerkleRoot
}

// SerializeProof serializes a MerkleProof to bytes
func SerializeProof(proof *MerkleProof) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	err := encoder.Encode(proof)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// DeserializeProof deserializes bytes to a MerkleProof
func DeserializeProof(data []byte) (*MerkleProof, error) {
	var proof MerkleProof
	buffer := bytes.NewReader(data)
	decoder := gob.NewDecoder(buffer)
	err := decoder.Decode(&proof)
	if err != nil {
		return nil, err
	}
	return &proof, nil
}

// hash generates a hash for the Bloom filter using double hashing
func hash(data []byte, seed uint32) uint64 {
	h1 := sha256.Sum256(data)

	// Create a seeded hash using the first hash
	h := sha256.New()
	h.Write(h1[:])
	binary.Write(h, binary.LittleEndian, seed)

	h2 := h.Sum(nil)
	return binary.BigEndian.Uint64(h2[:8])
}
