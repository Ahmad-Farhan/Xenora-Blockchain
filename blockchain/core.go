package blockchain

import (
	"errors"
	"sync"
)

// Blockchain represents the core blockchain structure
type Blockchain struct {
	blocks      []*Block
	latestBlock *Block
	lock        sync.RWMutex
	state       *State
	txPool      *TransactionPool
}

// NewBlockchain creates a new blockchain with a genesis block
func NewBlockchain() *Blockchain {
	genesis := GenesisBlock()
	initialState := NewState()

	blockchain := &Blockchain{
		blocks:      []*Block{genesis},
		latestBlock: genesis,
		state:       initialState,
		txPool:      NewTransactionPool(),
	}
	return blockchain
}

// AddBlock adds a new block to the blockchain
func (bc *Blockchain) AddBlock(block *Block) error {
	bc.lock.Lock()
	defer bc.lock.Unlock()

	if err := bc.validateBlock(block); err != nil {
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

func (bc *Blockchain) validateBlock(block *Block) error {
	if block.Header.Height != bc.latestBlock.Header.Height+1 {
		return errors.New("invalid block height")
	}
	if block.Header.PreviousHash != bc.latestBlock.Header.Hash() {
		return errors.New("invalid previous hash")
	}

	// Updates needed here
	// - validate Merkle root
	// - validate consensus rules (POW)
	// - validate transaction signatures
	// - Check for double-spending

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

// ApplyTransaction applies a transaction to the state
func (s *State) ApplyTransactions(tx *Transaction) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.nonces[tx.From] >= tx.Nonce {
		return errors.New("invalid nonce")
	}

	// For transfer transactions
	if tx.Type == TransferTx {
		// Check if sender has enough balance
		if s.accounts[tx.From] < tx.Value+tx.Fee {
			return errors.New("insufficient balance")
		} // Update Balances
		s.accounts[tx.From] -= (tx.Value + tx.Fee)
		s.accounts[tx.To] += tx.Value
	}

	// For data transactions
	if tx.Type == DataTx && len(tx.Data) > 0 {
		dataKey := tx.From + "-" + tx.TxID
		s.data[dataKey] = tx.Data
	}
	s.nonces[tx.From] = tx.Nonce
	return nil
}
