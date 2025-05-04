package blockchain

import (
	"errors"
	"sync"
	"time"

	"xenora/merkle"
	"xenora/state"
	"xenora/xtx"
)

const InitialShards = 2

// Blockchain represents the core blockchain structure
type Blockchain struct {
	blocks      []*Block
	latestBlock *Block
	lock        sync.RWMutex
	state       *state.EnhancedState
	txPool      *xtx.TransactionPool
	forest      *merkle.MerkleForest
}

// NewBlockchain creates a new blockchain with a genesis block
func NewBlockchain() *Blockchain {
	genesis := GenesisBlock()
	initialState := state.NewEnhancedState()
	merkleForest := merkle.NewMerkleForest(InitialShards)
	genesis.Header.StateRoot = initialState.GetStateRootString()
	blockchain := &Blockchain{
		blocks:      []*Block{genesis},
		latestBlock: genesis,
		state:       initialState,
		txPool:      xtx.NewTransactionPool(),
		forest:      merkleForest,
	}
	return blockchain
}

// AddBlock adds a new block to the blockchain
func (bc *Blockchain) AddBlock(block *Block) error {
	bc.lock.Lock()
	defer bc.lock.Unlock()

	if err := bc.ValidateBlock(block); err != nil {
		return err
	}

	bc.blocks = append(bc.blocks, block)
	bc.latestBlock = block

	// Update state with transactions in the block
	for _, tx := range block.Transactions {
		bc.state.ApplyTransaction(&tx)
		bc.forest.AddTransaction(tx)
		bc.txPool.Remove(tx.TxID)
	}
	// Update state root if using EnhancedState
	if enhancedState := bc.state; enhancedState != nil {
		block.Header.StateRoot = enhancedState.GetStateRootString()
		if block.Header.Height%state.SnapshotInterval == 0 {
			enhancedState.CreateSnapshot(block.Header.Height)
		}
		enhancedState.PruneState(block.Header.Height)
	}

	return nil
}

// GetLatestBlock returns the most recent block in the chain
func (bc *Blockchain) GetLatestBlock() *Block {
	bc.lock.Lock()
	defer bc.lock.Unlock()
	return bc.latestBlock
}

func (bc *Blockchain) GetMerkleForestHash() string {
	return bc.forest.GetForestHash()
}

// GetBlockByHeight returns a block at the specified height
func (bc *Blockchain) GetBlockByHeight(height uint64) (*Block, error) {
	bc.lock.Lock()
	defer bc.lock.Unlock()

	if height >= uint64(len(bc.blocks)) {
		return nil, errors.New("block height out of range")
	}
	return bc.blocks[height], nil
}

func (bc *Blockchain) ValidateBlock(block *Block) error {
	if err := bc.ValidateBlockHeader(&block.Header); err != nil {
		return err
	}

	merkleTree := merkle.NewMerkleTree(block.Transactions)
	calculatedRoot := merkleTree.GetRootHash()
	if calculatedRoot != block.Header.MerkleRoot {
		return errors.New("invalid merkle root")
	}

	seenTxs := make(map[string]bool)
	for _, tx := range block.Transactions {
		if seenTxs[tx.TxID] {
			return errors.New("duplicate transaction in block")
		}
		seenTxs[tx.TxID] = true

		if tx.Type == xtx.RewardTx {
			continue
		}

		if err := bc.ValidateTransaction(&tx); err != nil {
			return err
		}
	}

	return nil
}

func (bc *Blockchain) ValidateBlockHeader(header *BlockHeader) error {
	if header.Height != bc.latestBlock.Header.Height+1 {
		return errors.New("invalid block height")
	}
	if header.PreviousHash != bc.latestBlock.Header.Hash() {
		return errors.New("invalid previous hash")
	}
	if header.Timestamp.After(time.Now().Add(time.Minute * 15)) {
		return errors.New("block timestamp too far in the future")
	}
	if header.Timestamp.Before(bc.latestBlock.Header.Timestamp) {
		return errors.New("block timestamp before previous block")
	}
	// Validate state root if available
	if enhancedState := bc.state; header.Height > 0 {
		expectedStateRoot := enhancedState.GetStateRootString()
		if header.StateRoot != "" && header.StateRoot != expectedStateRoot {
			return errors.New("invalid state root")
		}
	}
	return nil
}

func (bc *Blockchain) ValidateTransaction(tx *xtx.Transaction) error {
	if tx.TxID != tx.Hash() {
		return errors.New("invalid transaction hash")
	}

	if tx.Type != xtx.RewardTx {
		valid, err := tx.Verify()
		if err != nil {
			return err
		}
		if !valid {
			return errors.New("invalid transaction signature")
		}
		if tx.Type != xtx.CrossShardTx || tx.ExtraFields == nil || tx.ExtraFields["atomicID"] == nil {
			senderBalance := bc.state.GetBalance(tx.From)
			if senderBalance < tx.Value+tx.Fee {
				return errors.New("insufficient balance")
			}
			expectedNonce := bc.state.GetNonce(tx.From) + 1
			if tx.Nonce != expectedNonce {
				return errors.New("invalid nonce")
			}
		}
	}
	return nil
}

func (bc *Blockchain) Close() error {
	if enhancedState := bc.state; enhancedState != nil {
		return enhancedState.Close()
	}
	return nil
}

func (bc *Blockchain) GetStateProof(key string) ([]byte, error) {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	return bc.state.GenerateStateProof(key)
}

func (bc *Blockchain) VerifyStateProof(proofData []byte) (bool, error) {
	bc.lock.RLock()
	defer bc.lock.RUnlock()
	return bc.state.VerifyStateProof(proofData)
}
