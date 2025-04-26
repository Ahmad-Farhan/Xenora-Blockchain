// crossshard.go
package blockchain

import (
	"xenora/merkle"
	"xenora/xtx"
)

type CrossShardManager struct {
	blockchain   *Blockchain
	synchronizer *merkle.CrossShardSynchronizer
}

func NewCrossShardManager(bc *Blockchain) *CrossShardManager {
	return &CrossShardManager{
		blockchain:   bc,
		synchronizer: merkle.NewCrossShardSynchronizer(bc.forest),
	}
}

func (csm *CrossShardManager) InitiateCrossShardTransaction(mainTx *xtx.Transaction, targetShards []uint32) (*merkle.CrossShardTransaction, error) {
	if mainTx.Type != xtx.CrossShardTx {
		mainTx.Type = xtx.CrossShardTx
	}

	// Generate atomic ID for cross-shard transaction
	atomicID := mainTx.From + "-" + mainTx.TxID

	xsTx := &merkle.CrossShardTransaction{
		MainTx:       mainTx,
		SourceShard:  mainTx.ShardID,
		TargetShards: targetShards,
		AtomicID:     atomicID,
		Status:       merkle.Pending,
	}

	err := csm.synchronizer.ProcessCrossShardTransaction(xsTx)
	if err != nil {
		return nil, err
	}

	return xsTx, nil
}

func (csm *CrossShardManager) VerifyCrossShardTransaction(atomicID string) (bool, error) {
	return csm.synchronizer.VerifyCrossShardTransaction(atomicID)
}
