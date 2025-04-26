package blockchain

import (
	"errors"
	"log"
	"sync"
	"time"

	"xenora/merkle"
	"xenora/xtx"
)

// Blockchain represents the core blockchain structure
type Blockchain struct {
	blocks      []*Block
	latestBlock *Block
	lock        sync.RWMutex
	state       *State
	txPool      *xtx.TransactionPool
}

// NewBlockchain creates a new blockchain with a genesis block
func NewBlockchain() *Blockchain {
	genesis := GenesisBlock()
	initialState := NewState()

	blockchain := &Blockchain{
		blocks:      []*Block{genesis},
		latestBlock: genesis,
		state:       initialState,
		txPool:      xtx.NewTransactionPool(),
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
		bc.state.ApplyTransactions(&tx)
		bc.txPool.Remove(tx.TxID)
	}
	return nil
}

// GetLatestBlock returns the most recent block in the chain
func (bc *Blockchain) GetLatestBlock() *Block {
	bc.lock.Lock()
	defer bc.lock.Unlock()
	return bc.latestBlock
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
		senderBalance := bc.state.GetBalance(tx.From)
		if senderBalance < tx.Value+tx.Fee {
			return errors.New("insufficient balance")
		}
		expectedNonce := bc.state.GetNonce(tx.From) + 1
		if tx.Nonce != expectedNonce {
			return errors.New("invalid nonce")
		}
	}
	return nil
}

// State represents the current state of accounts and data
type State struct {
	accounts map[string]uint64 // address -> balance
	data     map[string][]byte // key -> value store for data
	nonces   map[string]uint64 // address -> nonce
	lock     sync.RWMutex
}

// NewState creates a new state
func NewState() *State {
	return &State{
		accounts: make(map[string]uint64),
		data:     make(map[string][]byte),
		nonces:   make(map[string]uint64),
	}
}

// ApplyTransaction applies a transaction to the state with proper validation
func (s *State) ApplyTransactions(tx *xtx.Transaction) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	// For non-reward transactions, validate nonce and balance
	if tx.Type != xtx.RewardTx {
		currentNonce := s.nonces[tx.From]
		if currentNonce >= tx.Nonce {
			return errors.New("invalid nonce")
		}

		// Check if sender has enough balance
		if s.accounts[tx.From] < tx.Value+tx.Fee {
			return errors.New("insufficient balance")
		}
	}

	// For transfer transactions
	if tx.Type == xtx.TransferTx {
		log.Printf("Transfer Transaction")
		s.accounts[tx.From] -= (tx.Value + tx.Fee)
		s.accounts[tx.To] += tx.Value
	} else if tx.Type == xtx.RewardTx {
		log.Printf("Reward Transaction")
		// For reward transactions
		s.accounts[tx.To] += tx.Value
	} else if tx.Type == xtx.DataTx && len(tx.Data) > 0 {
		// For data transactions
		dataKey := tx.From + "-" + tx.TxID
		s.data[dataKey] = tx.Data
		// Deduct fee
		if tx.From != "" {
			s.accounts[tx.From] -= tx.Fee
		}
	}

	// Update nonce if it's not a reward transaction
	if tx.Type != xtx.RewardTx {
		s.nonces[tx.From] = tx.Nonce
	}

	return nil
}

func (s *State) GetBalance(address string) uint64 {
	s.lock.RLock()
	defer s.lock.RUnlock()

	balance, exists := s.accounts[address]
	if !exists {
		return 0
	}
	return balance
}

func (s *State) GetNonce(address string) uint64 {
	s.lock.RLock()
	defer s.lock.RUnlock()

	nonce, exists := s.nonces[address]
	if !exists {
		return 0
	}
	return nonce
}
