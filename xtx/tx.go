package xtx

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"xenora/crypto"
)

// TransactionType defines the different types of transactions
type TransactionType uint8

const (
	TransferTx      TransactionType = iota // Transfer value between accounts
	DataTx                                 // Store data on blockchain
	CrossShardTx                           // Cross-shard transaction (for future use)
	ConfigurationTx                        // System configuration transaction
	RewardTx                               // Mining reward transaction
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

const nullhash = "0000000000000000000000000000000000000000000000000000000000000000" // 64 zeros

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
	return &tx
}

// CreateCoinbaseTx creates a new coinbase transaction (reward for mining a block)
func CreateCoinbaseTx(toAddress string, reward uint64, blockHeight uint64) *Transaction {
	cbTx := &Transaction{
		Type:        RewardTx,
		To:          toAddress,
		Value:       reward,
		Data:        []byte(fmt.Sprintf("Reward for block %d", blockHeight)),
		Timestamp:   time.Now(),
		Nonce:       0,
		Fee:         0,
		ExtraFields: make(map[string]interface{}),
	}
	cbTx.TxID = cbTx.Hash()
	return cbTx
}

// Serializes transaction for signing/verification (with Signature)
func (tx *Transaction) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(tx); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func DeserializeTransaction(data []byte) (*Transaction, error) {
	var tx Transaction
	buf := bytes.NewReader(data)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(&tx)
	if err != nil {
		return nil, err
	}
	return &tx, nil
}

// Serializes without Signature
func (tx *Transaction) serializeForSign() ([]byte, error) {
	txCopy := *tx
	txCopy.TxID = ""
	txCopy.Signature = nil
	return txCopy.Serialize()
}

// Serializes for Hash
func (tx *Transaction) serializeForHash() ([]byte, error) {
	txCopy := *tx
	txCopy.TxID = ""
	return txCopy.Serialize()
}

// Hash computes the hash of the transaction (excluding the signature) //Needs Update
func (tx *Transaction) Hash() string {
	txBytes, err := tx.serializeForHash()
	if err != nil {
		log.Printf("Error Serializing Block Header: %v", err)
		return nullhash
	}
	hash := sha256.Sum256(txBytes)
	return hex.EncodeToString(hash[:])
}

// Sign signs a transaction with the given private key
func (tx *Transaction) Sign(privateKey *ecdsa.PrivateKey) error {
	if tx.From == "" {
		return nil
	}

	txData, err := tx.serializeForSign()
	if err != nil {
		return err
	}

	signature, err := crypto.SignData(privateKey, txData)
	if err != nil {
		return err
	}

	tx.Signature = signature
	tx.TxID = tx.Hash()
	return nil
}

// Checks if the transaction already signed
func (tx *Transaction) isSigned() bool {
	return len(tx.Signature) > 0
}

// Verify checks if the transaction signature is valid
func (tx *Transaction) Verify() (bool, error) {
	if tx.From == "" || tx.Signature == nil {
		return false, nil
	}

	pubKey, err := crypto.PublicKeyFromAddress(tx.From)
	if err != nil {
		return false, err
	}

	txData, err := tx.serializeForSign()
	if err != nil {
		return false, err
	}
	verified := crypto.VerifySignature(pubKey, txData, tx.Signature)
	if !verified {
		log.Printf("Signature verification failed for tx %s", tx.TxID)
	}

	return verified, nil
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
	if _, exists := pool.pending[tx.TxID]; exists {
		return false
	}
	if tx.Type != RewardTx {
		valid, err := tx.Verify()
		if err != nil || !valid {
			return false
		}
	}
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
