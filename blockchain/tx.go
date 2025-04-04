package blockchain

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// TransactionType defines the different types of transactions
type TransactionType uint8

const (
	TransferTx      TransactionType = iota // Transfer value between accounts
	DataTx                                 // Store data on blockchain
	CrossShardTx                           // Cross-shard transaction (for future use)
	ConfigurationTx                        // System configuration transaction
)

// Transaction represents a transaction in the Xenora blockchain
type Transaction struct {
	TxID        string                 `json:"txID"`        // Transaction ID (hash)
	Type        TransactionType        `json:"type"`        // Type of transaction
	From        string                 `json:"from"`        // Sender address
	To          string                 `json:"to"`          // Recipient address
	Value       uint64                 `json:"value"`       // Amount to transfer
	Data        []byte                 `json:"data"`        // Additional data/payload
	Timestamp   time.Time              `json:"timestamp"`   // Transaction creation time
	Nonce       uint64                 `json:"nonce"`       // Sender's account nonce (for replay protection)
	Fee         uint64                 `json:"fee"`         // Transaction fee
	Signature   []byte                 `json:"signature"`   // Digital signature
	ShardID     uint32                 `json:"shardID"`     // Destination shard ID (for cross-shard)
	ExtraFields map[string]interface{} `json:"extraFields"` // Extensible fields for future use
}

// NewTransaction creates a new unsigned transaction
func NewTransaction(txType TransactionType, from, to string, value, nonce, fee uint64, data []byte) *Transaction {
	tx := Transaction{
		Type:        txType,
		From:        from,
		To:          to,
		Value:       value,
		Data:        data,
		Timestamp:   time.Now(),
		Nonce:       nonce,
		Fee:         fee,
		ExtraFields: make(map[string]interface{}),
	}
	// Compute transaction ID (hash)
	tx.TxID = tx.Hash()
	return &tx
}

// Hash computes the hash of the transaction (excluding the signature)
func (tx *Transaction) Hash() string {
	txBytes := []byte(
		string(tx.Type) +
			tx.From +
			tx.To +
			string(tx.Value) +
			string(tx.Data) +
			tx.Timestamp.String() +
			string(tx.Nonce) +
			string(tx.Fee) +
			string(tx.ShardID),
	)
	hash := sha256.Sum256(txBytes)
	return hex.EncodeToString(hash[:])
}

// TransactionPool maintains a pool of pending transactions
type TransactionPool struct {
	pending map[string]*Transaction // TxID -> Transaction
}

// NewTransactionPool creates a new transaction pool
func NewTransactionPool() *TransactionPool {
	return &TransactionPool{
		pending: make(map[string]*Transaction),
	}
}

// Add adds a transaction to the pool
func (pool *TransactionPool) Add(tx *Transaction) bool {
	// Potentially validate  before adding
	pool.pending[tx.TxID] = tx
	return true
}

// Remove removes a transaction from the pool
func (pool *TransactionPool) Remove(txID string) {
	delete(pool.pending, txID)
}

// GetPending returns all pending transactions
func (pool *TransactionPool) GetPending() []*Transaction {
	txs := make([]*Transaction, 0, len(pool.pending))
	for _, tx := range pool.pending {
		txs = append(txs, tx)
	}
	return txs
}
