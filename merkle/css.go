package merkle

import (
	"errors"
	"fmt"
	"sync"
	"xenora/xtx"
)

// CrossShardSynchronizer manages and synchronizes state across shards
type CrossShardSynchronizer struct {
	forest     *MerkleForest
	stateLocks map[string]*sync.RWMutex
}

// NewCrossShardSynchronizer creates a new cross-shard synchronizer
func NewCrossShardSynchronizer(forest *MerkleForest) *CrossShardSynchronizer {
	return &CrossShardSynchronizer{
		forest:     forest,
		stateLocks: make(map[string]*sync.RWMutex),
	}
}

// CrossShardTransaction represents a transaction that spans multiple shards
type CrossShardTransaction struct {
	MainTx       *xtx.Transaction
	SourceShard  uint32
	TargetShards []uint32
	AtomicID     string
	Status       CrossShardStatus
}

// CrossShardStatus represents the status of a cross-shard transaction
type CrossShardStatus int

const (
	Pending CrossShardStatus = iota
	Prepared
	Committed
	Aborted
)

// ProcessCrossShardTransaction processes a transaction spanning multiple shards
func (css *CrossShardSynchronizer) ProcessCrossShardTransaction(ctx *CrossShardTransaction) error {
	// Phase 1: Prepare - verify transaction can be processed on all target shards
	for _, targetShard := range ctx.TargetShards {
		if _, exists := css.forest.Trees[targetShard]; !exists {
			return fmt.Errorf("target shard %d does not exist", targetShard)
		}
	}

	// Lock related state objects
	stateKey := fmt.Sprintf("xshard:%s", ctx.AtomicID)
	if _, exists := css.stateLocks[stateKey]; !exists {
		css.stateLocks[stateKey] = &sync.RWMutex{}
	}
	css.stateLocks[stateKey].Lock()
	defer css.stateLocks[stateKey].Unlock()
	ctx.Status = Prepared

	// Phase 2: Commit - actually apply the transaction to all shards
	css.forest.AddTransaction(*ctx.MainTx)
	for _, targetShard := range ctx.TargetShards {
		coordTx := *ctx.MainTx
		coordTx.ShardID = targetShard
		if coordTx.ExtraFields == nil {
			coordTx.ExtraFields = make(map[string]any)
		}
		coordTx.ExtraFields["atomicID"] = ctx.AtomicID
		coordTx.ExtraFields["sourceShardID"] = ctx.SourceShard
		css.forest.AddTransaction(coordTx)
	}

	ctx.Status = Committed
	return nil
}

// VerifyCrossShardTransaction verifies a cross-shard transaction across all involved shards
func (css *CrossShardSynchronizer) VerifyCrossShardTransaction(atomicID string) (bool, error) {
	transactionMap := make(map[uint32][]*xtx.Transaction)
	// Search for the transaction across all shards
	for shardID, tree := range css.forest.Trees {
		for _, tx := range tree.leaves {
			if txAtomicID, ok := tx.ExtraFields["atomicID"]; ok && txAtomicID == atomicID {
				if _, exists := transactionMap[shardID]; !exists {
					transactionMap[shardID] = make([]*xtx.Transaction, 0)
				}
				txCopy := tx
				transactionMap[shardID] = append(transactionMap[shardID], &txCopy)
			}
		}
	}
	if len(transactionMap) == 0 {
		return false, errors.New("no transactions found with the given atomic ID")
	}

	var sourceShardFound bool
	for _, txs := range transactionMap {
		for _, tx := range txs {
			if _, ok := tx.ExtraFields["sourceShardID"]; ok {
				sourceShardFound = true
				break
			}
		}
		if sourceShardFound {
			break
		}
	}

	if !sourceShardFound {
		return false, errors.New("source shard information not found")
	}

	// Generate and verify Merkle proofs for transactions in each shard
	for shardID, txs := range transactionMap {
		for _, tx := range txs {
			proof, err := css.forest.GenerateProof(tx.TxID)
			if err != nil || !VerifyProof(proof) {
				return false, fmt.Errorf("transaction verification failed for shard %d", shardID)
			}
		}
	}

	return true, nil
}
