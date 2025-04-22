package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

type NodeType uint8

const (
	LeafNode NodeType = iota
	BranchNode
	ShardRootNode
	ForestRootNode
)

type MerkleNode struct {
	Type      NodeType
	Hash      string
	Data      []byte
	Parent    *MerkleNode
	Left      *MerkleNode
	Right     *MerkleNode
	Children  []*MerkleNode
	ShardID   uint32
	Timestamp time.Time
	Metadata  map[string]interface{}
	lock      sync.RWMutex
}

type AdaptiveMerkleForest struct {
	shards        map[uint32]*MerkleShard
	forestRoot    *MerkleNode
	totalNodes    int
	shardCount    int
	balanceThresh float64
	maxShardSize  int
	lock          sync.RWMutex
}

type MerkleShard struct {
	ID          uint32
	Root        *MerkleNode
	NodeCount   int
	LastUpdated time.Time
	Parent      *AdaptiveMerkleForest
	LoadFactor  float64
	lock        sync.RWMutex
}

func NewAdaptiveMerkleForest(initShardCount int, maxShardSize int) *AdaptiveMerkleForest {
	amf := &AdaptiveMerkleForest{
		shards:        make(map[uint32]*MerkleShard),
		totalNodes:    0,
		shardCount:    0,
		balanceThresh: 0.3,
		maxShardSize:  maxShardSize,
	}

	amf.forestRoot = &MerkleNode{
		Type:      ForestRootNode,
		Timestamp: time.Now(),
		Children:  make([]*MerkleNode, 0),
		Metadata:  make(map[string]interface{}),
	}

	for i := 0; i < initShardCount; i++ {
		amf.createShard(uint32(i))
	}
	amf.updateForestRoot()
	return amf
}

func (amf *AdaptiveMerkleForest) createShard(id uint32) *MerkleShard {
	amf.lock.Lock()
	defer amf.lock.Unlock()

	rootNode := &MerkleNode{
		Type:      ShardRootNode,
		ShardID:   id,
		Timestamp: time.Now(),
		Children:  make([]*MerkleNode, 0),
		Metadata:  make(map[string]interface{}),
	}

	hashData := []byte(
		string(rootNode.Type) +
			string(rootNode.ShardID) +
			rootNode.Timestamp.String(),
	)
	hash := sha256.Sum256(hashData)
	rootNode.Hash = hex.EncodeToString(hash[:])

	shard := &MerkleShard{
		ID:          id,
		Root:        rootNode,
		NodeCount:   0,
		LastUpdated: time.Now(),
		Parent:      amf,
		LoadFactor:  0.0,
	}
	amf.shards[id] = shard
	amf.shardCount++

	rootNode.Parent = amf.forestRoot
	amf.forestRoot.Children = append(amf.forestRoot.Children, rootNode)
	return shard
}

func (amf *AdaptiveMerkleForest) insertData(data []byte, shardHint uint32) (string, error) {
	amf.lock.RLock()

	shard, exists := amf.shards[shardHint]

	if !exists || shard.NodeCount >= amf.maxShardSize {
		var bestShard *MerkleShard
		lowestLoad := float64(1000000)

		for _, s := range amf.shards {
			if s.LoadFactor < lowestLoad && s.NodeCount < amf.maxShardSize {
				bestShard = s
				lowestLoad = s.LoadFactor
			}
		}

		if bestShard == nil {
			amf.lock.RUnlock()
			amf.lock.Lock()
			newShardID := uint32(len(amf.shards))
			bestShard = amf.createShard(newShardID)
			amf.lock.Lock()
		} else {
			amf.lock.RUnlock()
		}
		shard = bestShard
	} else {
		amf.lock.RUnlock()
	}

	dataHash, err := shard.InsertData(data)
	if err != nil {
		return "", err
	}

	amf.lock.Lock()
	amf.totalNodes++
	amf.lock.Unlock()

	if amf.shouldRebalance() {
		go amf.rebalanceShards()
	}
	return dataHash, nil
}

func (s *MerkleShard) InsertData(data []byte) (string, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	leafNode := &MerkleNode{
		Type:      LeafNode,
		Data:      data,
		ShardID:   s.ID,
		Timestamp: time.Now(),
		Children:  nil,
		Metadata:  make(map[string]interface{}),
	}

	hash := sha256.Sum256(data)
	leafNode.Hash = hex.EncodeToString(hash[:])

	if s.Root.Children == nil {
		s.Root.Children = make([]*MerkleNode, 0)
	}
	leafNode.Parent = s.Root

	s.Root.Children = append(s.Root.Children, leafNode)
	s.NodeCount++
	s.LastUpdated = time.Now()
	s.updateLoadFactor()
	s.updateRootHash()

	s.Parent.updateForestRoot()
	return leafNode.Hash, nil
}

func (s *MerkleShard) updateRootHash() {
	hashData := []byte{}
	for _, child := range s.Root.Children {
		childHashBytes, _ := hex.DecodeString(child.Hash)
		hashData = append(hashData, childHashBytes...)
	}
	hash := sha256.Sum256(hashData)
	s.Root.Hash = hex.EncodeToString(hash[:])
}

func (amf *AdaptiveMerkleForest) updateForestRoot() {
	amf.lock.Lock()
	defer amf.lock.Unlock()

	hashData := []byte{}
	for _, shard := range amf.shards {
		shardHashBytes, _ := hex.DecodeString(shard.Root.Hash)
		hashData = append(hashData, shardHashBytes...)
	}

	hash := sha256.Sum256(hashData)
	amf.forestRoot.Hash = hex.EncodeToString(hash[:])
}

func (s *MerkleShard) updateLoadFactor() {
	s.LoadFactor = float64(s.NodeCount) / float64(s.Parent.maxShardSize)
}

func (amf *AdaptiveMerkleForest) shouldRebalance() bool {
	amf.lock.RLock()
	defer amf.lock.RUnlock()

	if len(amf.shards) < 2 {
		return false
	}

	minLoad := float64(1000000)
	maxLoad := float64(0)

	for _, shard := range amf.shards {
		if shard.LoadFactor < minLoad {
			minLoad = shard.LoadFactor
		}
		if shard.LoadFactor > maxLoad {
			maxLoad = shard.LoadFactor
		}
	}
	return (maxLoad - minLoad) > amf.balanceThresh
}

func (amf *AdaptiveMerkleForest) rebalanceShards() {
	amf.lock.Lock()
	defer amf.lock.Unlock()

	var mostLoaded, leastLoaded *MerkleShard
	highestLoad := float64(0)
	lowestLoad := float64(1000000)

	for _, shard := range amf.shards {
		if shard.LoadFactor > highestLoad {
			mostLoaded = shard
			highestLoad = shard.LoadFactor
		}
		if shard.LoadFactor < lowestLoad {
			leastLoaded = shard
			lowestLoad = shard.LoadFactor
		}
	}

	if (highestLoad - lowestLoad) <= amf.balanceThresh {
		return
	}
	nodesToMove := mostLoaded.NodeCount / 4
	if nodesToMove < 1 {
		nodesToMove = 1
	}

	mostLoaded.lock.Lock()
	leastLoaded.lock.Lock()

	for i := 0; i < nodesToMove && len(mostLoaded.Root.Children) > 0; i++ {
		nodeToMove := mostLoaded.Root.Children[0]

		mostLoaded.Root.Children = mostLoaded.Root.Children[1:]
		mostLoaded.NodeCount--

		nodeToMove.Parent = leastLoaded.Root
		nodeToMove.ShardID = leastLoaded.ID
		leastLoaded.Root.Children = append(leastLoaded.Root.Children, nodeToMove)
		leastLoaded.NodeCount++
	}
	now := time.Now()
	mostLoaded.LastUpdated = now
	leastLoaded.LastUpdated = now
	mostLoaded.updateLoadFactor()
	leastLoaded.updateLoadFactor()

	mostLoaded.updateRootHash()
	leastLoaded.updateRootHash()

	leastLoaded.lock.Unlock()
	mostLoaded.lock.Unlock()

	amf.updateForestRoot()
}

func (amf *AdaptiveMerkleForest) verifyData(datahash string) (bool, *MerkleProof, error) {
	amf.lock.Lock()
	defer amf.lock.Unlock()

	for shardID, shard := range amf.shards {
		exists, proof, err := shard.VerifyData(datahash)
		if err != nil {
			return false, nil, err
		}
		if exists {
			proof.ForestRoot = amf.forestRoot.Hash
			proof.ShardID = shardID
			return true, proof, nil
		}
	}
	return false, nil, nil
}

type MerkleProof struct {
	DataHash   string
	Path       []string
	ShardRoot  string
	ForestRoot string
	ShardID    uint32
	Timestamp  time.Time
}

func (s *MerkleShard) VerifyData(dataHash string) (bool, *MerkleProof, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	for _, node := range s.Root.Children {
		if node.Hash == dataHash {
			proof := &MerkleProof{
				DataHash:  dataHash,
				Path:      []string{},
				ShardRoot: s.Root.Hash,
				Timestamp: time.Now(),
			}
			return true, proof, nil
		}
	}
	return false, nil, nil
}

// GetShardByID returns a shard by its ID
func (amf *AdaptiveMerkleForest) GetShardByID(id uint32) (*MerkleShard, error) {
	amf.lock.RLock()
	defer amf.lock.RUnlock()

	shard, exists := amf.shards[id]
	if !exists {
		return nil, errors.New("shard not found")
	}

	return shard, nil
}

// GetForestRoot returns the root hash of the entire forest
func (amf *AdaptiveMerkleForest) GetForestRoot() string {
	amf.lock.RLock()
	defer amf.lock.RUnlock()

	return amf.forestRoot.Hash
}

// SplitShard splits a shard into two when it gets too large
func (amf *AdaptiveMerkleForest) SplitShard(shardID uint32) error {
	amf.lock.Lock()
	defer amf.lock.Unlock()

	// Get source shard
	sourceShard, exists := amf.shards[shardID]
	if !exists {
		return errors.New("shard not found")
	}

	sourceShard.lock.Lock()
	defer sourceShard.lock.Unlock()

	// Check if split is needed
	if sourceShard.NodeCount < amf.maxShardSize {
		return nil // No need to split
	}

	// Create new shard
	newShardID := uint32(len(amf.shards))
	newShard := amf.createShard(newShardID)

	// Move half the nodes to new shard
	nodesToMove := sourceShard.NodeCount / 2

	for i := 0; i < nodesToMove && len(sourceShard.Root.Children) > 0; i++ {
		// Get node to move
		nodeToMove := sourceShard.Root.Children[len(sourceShard.Root.Children)-1]

		// Remove from source
		sourceShard.Root.Children = sourceShard.Root.Children[:len(sourceShard.Root.Children)-1]
		sourceShard.NodeCount--

		// Add to new shard
		newShard.lock.Lock()
		nodeToMove.Parent = newShard.Root
		nodeToMove.ShardID = newShardID
		newShard.Root.Children = append(newShard.Root.Children, nodeToMove)
		newShard.NodeCount++
		newShard.lock.Unlock()
	}

	// Update timestamps and load factors
	now := time.Now()
	sourceShard.LastUpdated = now
	newShard.LastUpdated = now
	sourceShard.updateLoadFactor()
	newShard.updateLoadFactor()

	// Update hashes
	sourceShard.updateRootHash()
	newShard.lock.Lock()
	newShard.updateRootHash()
	newShard.lock.Unlock()

	// Update forest root
	amf.updateForestRoot()

	return nil
}

// MergeShard merges two lightly-loaded shards
func (amf *AdaptiveMerkleForest) MergeShards(shardID1, shardID2 uint32) error {
	amf.lock.Lock()
	defer amf.lock.Unlock()

	// Get shards
	shard1, exists1 := amf.shards[shardID1]
	shard2, exists2 := amf.shards[shardID2]

	if !exists1 || !exists2 {
		return errors.New("one or both shards not found")
	}

	// Check if merge is possible
	totalNodes := shard1.NodeCount + shard2.NodeCount
	if totalNodes > amf.maxShardSize {
		return errors.New("shards too large to merge")
	}

	// Lock both shards
	shard1.lock.Lock()
	shard2.lock.Lock()

	// Move all nodes from shard2 to shard1
	for _, node := range shard2.Root.Children {
		node.Parent = shard1.Root
		node.ShardID = shard1.ID
		shard1.Root.Children = append(shard1.Root.Children, node)
	}

	// Update counts
	shard1.NodeCount += shard2.NodeCount
	shard2.NodeCount = 0
	shard2.Root.Children = []*MerkleNode{}

	// Update timestamps and load factors
	now := time.Now()
	shard1.LastUpdated = now
	shard1.updateLoadFactor()

	// Update hash
	shard1.updateRootHash()

	// Remove shard2 from forest
	delete(amf.shards, shardID2)
	amf.shardCount--

	// Remove shard2 root from forest root children
	for i, child := range amf.forestRoot.Children {
		if child == shard2.Root {
			amf.forestRoot.Children = append(
				amf.forestRoot.Children[:i],
				amf.forestRoot.Children[i+1:]...,
			)
			break
		}
	}

	// Unlock shards
	shard2.lock.Unlock()
	shard1.lock.Unlock()

	// Update forest root
	amf.updateForestRoot()

	return nil
}
