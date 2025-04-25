package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"time"
	"xenora/blockchain"
	"xenora/xtx"
)

type SimpleConsensus struct {
	blockchain *blockchain.Blockchain
	difficulty uint32
	targetBits uint32
}

// NewSimpleConsensus creates a new consensus engine
func NewSimpleConsensus(bc *blockchain.Blockchain, diffculty uint32) *SimpleConsensus {
	return &SimpleConsensus{
		blockchain: bc,
		difficulty: diffculty,
		targetBits: 256 - diffculty,
	}
}

// CreateBlock creates a new block with transactions from the pool
func (sc *SimpleConsensus) CreateBlock(minerAddress string, coinbaseTx *xtx.Transaction, txPool *xtx.TransactionPool) (*blockchain.Block, error) {
	latestblock := sc.blockchain.GetLatestBlock()
	if latestblock == nil {
		return nil, errors.New("blockchain not initialized")
	}

	// Create new block header
	pendingTxs := txPool.GetPending()
	header := blockchain.BlockHeader{
		Version:      1,
		Height:       latestblock.Header.Height + 1,
		PreviousHash: latestblock.Header.Hash(),
		Timestamp:    time.Now(),
		Difficulty:   sc.difficulty,
		ProposerID:   minerAddress,
		ShardID:      0,
	}

	pendingTxs = prepend(pendingTxs, coinbaseTx)
	//Compute Merkle Root (simplified for now)
	merkleBuf := []byte{}
	for _, tx := range pendingTxs {
		txHashBytes, _ := hex.DecodeString(tx.Hash())
		merkleBuf = append(merkleBuf, txHashBytes...)
	}

	// Compute Merkle root (simplified) - Replace with proper merkle tree later
	merkleHash := sha256.Sum256(merkleBuf)
	header.MerkleRoot = hex.EncodeToString(merkleHash[:])
	txs := make([]xtx.Transaction, len(pendingTxs))
	for i, tx := range pendingTxs {
		txs[i] = *tx
	}

	// Create block and Find valid proof of work
	block := &blockchain.Block{
		Header:       header,
		Transactions: txs,
	}
	err := sc.findProof(block)
	if err != nil {
		return nil, err
	}
	return block, nil
}

// findProof implements Proof of Work to find a valid nonce
func (sc *SimpleConsensus) findProof(block *blockchain.Block) error {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-sc.targetBits))

	var hashInt big.Int
	var hash [32]byte
	nonce := uint64(0)

	maxNonce := uint64(math.MaxUint64)

	for nonce < maxNonce {
		block.Header.Nonce = nonce
		// Get block header as bytes and compute hash
		headerBytes := []byte(block.Header.Hash())
		hash = sha256.Sum256(headerBytes)
		hashInt.SetBytes(hash[:])

		if hashInt.Cmp(target) == -1 {
			return nil
		}
		nonce++
	}

	return errors.New("could not find valid proof")
}

// ValidateBlock validates a block according to consensus rules
func (sc *SimpleConsensus) ValidateBlock(block *blockchain.Block) error {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-block.Header.Difficulty))

	var hashInt big.Int

	// Get block header as bytes (excluding nonce)
	headerBytes := []byte(block.Header.Hash())
	hash := sha256.Sum256(headerBytes)
	hashInt.SetBytes(hash[:])
	if hashInt.Cmp(target) >= 0 {
		return errors.New("invalid proof of work")
	}
	return nil
}

// inserts the given transaction at the beginning of the slice.
func prepend(txs []*xtx.Transaction, coinbase *xtx.Transaction) []*xtx.Transaction {
	newTxs := make([]*xtx.Transaction, 0, len(txs)+1)
	newTxs = append(newTxs, coinbase)
	newTxs = append(newTxs, txs...)
	return newTxs
}
