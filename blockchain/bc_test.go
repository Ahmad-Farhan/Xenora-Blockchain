package blockchain

import (
	"log"
	"testing"
	"time"

	"xenora/core"
	"xenora/crypto"
	"xenora/xtx"
)

func TestNewBlockchain(t *testing.T) {
	bc := NewBlockchain()
	genesis := bc.GetLatestBlock()
	if genesis.Header.Height != 0 {
		t.Errorf("Expected genesis block height 0, got %d", genesis.Header.Height)
	}
	if genesis.Header.PreviousHash != nullhash {
		t.Errorf("Expected genesis block previous hash %s, got %s", nullhash, genesis.Header.PreviousHash)
	}
	if len(genesis.Transactions) != 0 {
		t.Errorf("Expected genesis block to have 0 transactions, got %d", len(genesis.Transactions))
	}
}

func TestAddBlockWithRewardTx(t *testing.T) {
	bc := NewBlockchain()
	rewardTx := xtx.CreateCoinbaseTx("miner", 50, 1)
	newBlock := &Block{
		Header: BlockHeader{
			Version:       1,
			Height:        1,
			PreviousHash:  bc.GetLatestBlock().Header.Hash(),
			MerkleRoot:    "",
			StateRoot:     "",
			Timestamp:     time.Now(),
			Difficulty:    1,
			Nonce:         0,
			ShardID:       0,
			ProposerID:    "miner",
			ConsensusData: []byte{},
		},
		Transactions: []xtx.Transaction{*rewardTx},
		Signature:    []byte{},
	}

	merkleTree := core.NewMerkleTree(newBlock.Transactions)
	newBlock.Header.MerkleRoot = merkleTree.GetRootHash()
	err := bc.AddBlock(newBlock)
	log.Printf("Balance before minied %d", bc.state.GetBalance("miner"))
	if err != nil {
		t.Errorf("Failed to add block: %v", err)
	}
	if bc.GetLatestBlock().Header.Height != 1 {
		t.Errorf("Expected latest block height 1, got %d", bc.GetLatestBlock().Header.Height)
	}
	// Current implementation does not update state for RewardTx
	balance := bc.state.GetBalance("miner")
	if balance != 50 {
		t.Errorf("Expected balance 0 due to unimplemented RewardTx, got %d", balance)
	}
}

func TestAddBlockWithTransferTx(t *testing.T) {
	bc := NewBlockchain()

	kp, _ := crypto.GenerateKeyPair()
	alice := kp.GetAddress()
	bc.state.accounts[alice] = 1000
	bc.state.nonces[alice] = 0

	tx := xtx.NewTransaction(xtx.TransferTx, alice, "bob", 100, 1, 10, nil)
	if err := tx.Sign(kp.PrivateKey); err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	newBlock := &Block{
		Header: BlockHeader{
			Version:       1,
			Height:        1,
			PreviousHash:  bc.GetLatestBlock().Header.Hash(),
			MerkleRoot:    "",
			StateRoot:     "",
			Timestamp:     time.Now(),
			Difficulty:    1,
			Nonce:         0,
			ShardID:       0,
			ProposerID:    "miner",
			ConsensusData: []byte{},
		},
		Transactions: []xtx.Transaction{*tx},
		Signature:    []byte{},
	}
	mt := core.NewMerkleTree(newBlock.Transactions)
	newBlock.Header.MerkleRoot = mt.GetRootHash()
	if err := bc.AddBlock(newBlock); err != nil {
		t.Fatalf("AddBlock failed: %v", err)
	}
	if got := bc.state.GetBalance(alice); got != 890 {
		t.Errorf("alice balance = %d; want 890", got)
	}
	if got := bc.state.GetBalance("bob"); got != 100 {
		t.Errorf("bob balance = %d; want 100", got)
	}
	if got := bc.state.GetNonce(alice); got != 1 {
		t.Errorf("alice nonce = %d; want 1", got)
	}
}

func TestAddBlockInvalidHeight(t *testing.T) {
	bc := NewBlockchain()
	invalidBlock := &Block{
		Header: BlockHeader{
			Version:       1,
			Height:        2,
			PreviousHash:  bc.GetLatestBlock().Header.Hash(),
			MerkleRoot:    "",
			StateRoot:     "",
			Timestamp:     time.Now(),
			Difficulty:    1,
			Nonce:         0,
			ShardID:       0,
			ProposerID:    "miner",
			ConsensusData: []byte{},
		},
		Transactions: []xtx.Transaction{},
		Signature:    []byte{},
	}
	err := bc.AddBlock(invalidBlock)
	if err == nil {
		t.Errorf("Expected error for invalid block height, got nil")
	}
}

func TestAddBlockInvalidPreviousHash(t *testing.T) {
	bc := NewBlockchain()
	invalidBlock := &Block{
		Header: BlockHeader{
			Version:       1,
			Height:        1,
			PreviousHash:  "invalid_hash",
			MerkleRoot:    "",
			StateRoot:     "",
			Timestamp:     time.Now(),
			Difficulty:    1,
			Nonce:         0,
			ShardID:       0,
			ProposerID:    "miner",
			ConsensusData: []byte{},
		},
		Transactions: []xtx.Transaction{},
		Signature:    []byte{},
	}
	err := bc.AddBlock(invalidBlock)
	if err == nil {
		t.Errorf("Expected error for invalid previous hash, got nil")
	}
}

func TestAddBlockInvalidMerkleRoot(t *testing.T) {
	bc := NewBlockchain()
	tx := xtx.NewTransaction(xtx.TransferTx, "alice", "bob", 100, 1, 10, nil)
	newBlock := &Block{
		Header: BlockHeader{
			Version:       1,
			Height:        1,
			PreviousHash:  bc.GetLatestBlock().Header.Hash(),
			MerkleRoot:    "invalid_root",
			StateRoot:     "",
			Timestamp:     time.Now(),
			Difficulty:    1,
			Nonce:         0,
			ShardID:       0,
			ProposerID:    "miner",
			ConsensusData: []byte{},
		},
		Transactions: []xtx.Transaction{*tx},
		Signature:    []byte{},
	}
	err := bc.AddBlock(newBlock)
	if err == nil {
		t.Errorf("Expected error for invalid merkle root, got nil")
	}
}

func TestAddBlockDuplicateTransactions(t *testing.T) {
	bc := NewBlockchain()
	tx := xtx.NewTransaction(xtx.TransferTx, "alice", "bob", 100, 1, 10, nil)
	newBlock := &Block{
		Header: BlockHeader{
			Version:       1,
			Height:        1,
			PreviousHash:  bc.GetLatestBlock().Header.Hash(),
			MerkleRoot:    "",
			StateRoot:     "",
			Timestamp:     time.Now(),
			Difficulty:    1,
			Nonce:         0,
			ShardID:       0,
			ProposerID:    "miner",
			ConsensusData: []byte{},
		},
		Transactions: []xtx.Transaction{*tx, *tx},
		Signature:    []byte{},
	}
	merkleTree := core.NewMerkleTree(newBlock.Transactions)
	newBlock.Header.MerkleRoot = merkleTree.GetRootHash()
	err := bc.AddBlock(newBlock)
	if err == nil {
		t.Errorf("Expected error for duplicate transactions, got nil")
	}
}

func TestAddBlockInvalidTransaction(t *testing.T) {
	bc := NewBlockchain()
	bc.state.accounts["alice"] = 50
	bc.state.nonces["alice"] = 0
	tx := xtx.NewTransaction(xtx.TransferTx, "alice", "bob", 100, 1, 10, nil)
	newBlock := &Block{
		Header: BlockHeader{
			Version:       1,
			Height:        1,
			PreviousHash:  bc.GetLatestBlock().Header.Hash(),
			MerkleRoot:    "",
			StateRoot:     "",
			Timestamp:     time.Now(),
			Difficulty:    1,
			Nonce:         0,
			ShardID:       0,
			ProposerID:    "miner",
			ConsensusData: []byte{},
		},
		Transactions: []xtx.Transaction{*tx},
		Signature:    []byte{},
	}
	merkleTree := core.NewMerkleTree(newBlock.Transactions)
	newBlock.Header.MerkleRoot = merkleTree.GetRootHash()
	err := bc.AddBlock(newBlock)
	if err == nil {
		t.Errorf("Expected error for invalid transaction, got nil")
	}
}

func TestGetBlockByHeight(t *testing.T) {
	bc := NewBlockchain()
	block, err := bc.GetBlockByHeight(0)
	if err != nil {
		t.Errorf("Failed to get genesis block: %v", err)
	}
	if block.Header.Height != 0 {
		t.Errorf("Expected height 0, got %d", block.Header.Height)
	}
	_, err = bc.GetBlockByHeight(1)
	if err == nil {
		t.Errorf("Expected error for out-of-range height, got nil")
	}
}

func TestStateApplyTransferTx(t *testing.T) {
	state := NewState()
	state.accounts["alice"] = 1000
	state.nonces["alice"] = 0
	tx := xtx.NewTransaction(xtx.TransferTx, "alice", "bob", 100, 1, 10, nil)
	err := state.ApplyTransactions(tx)
	if err != nil {
		t.Errorf("Failed to apply transaction: %v", err)
	}
	if state.accounts["alice"] != 890 {
		t.Errorf("Expected alice balance 890, got %d", state.accounts["alice"])
	}
	if state.accounts["bob"] != 100 {
		t.Errorf("Expected bob balance 100, got %d", state.accounts["bob"])
	}
	if state.nonces["alice"] != 1 {
		t.Errorf("Expected alice nonce 1, got %d", state.nonces["alice"])
	}
}

func TestStateApplyTransferTxInsufficientBalance(t *testing.T) {
	state := NewState()
	state.accounts["alice"] = 50
	state.nonces["alice"] = 0
	tx := xtx.NewTransaction(xtx.TransferTx, "alice", "bob", 100, 1, 10, nil)
	err := state.ApplyTransactions(tx)
	if err == nil {
		t.Errorf("Expected error for insufficient balance, got nil")
	}
}

func TestStateApplyTransferTxInvalidNonce(t *testing.T) {
	state := NewState()
	state.accounts["alice"] = 1000
	state.nonces["alice"] = 1
	tx := xtx.NewTransaction(xtx.TransferTx, "alice", "bob", 100, 1, 10, nil)
	err := state.ApplyTransactions(tx)
	if err == nil {
		t.Errorf("Expected error for invalid nonce, got nil")
	}
}

func TestStateApplyDataTx(t *testing.T) {
	state := NewState()
	state.nonces["alice"] = 0
	tx := xtx.NewTransaction(xtx.DataTx, "alice", "", 0, 1, 0, []byte("some data"))
	err := state.ApplyTransactions(tx)
	if err != nil {
		t.Errorf("Failed to apply data transaction: %v", err)
	}
	dataKey := "alice-" + tx.TxID
	if string(state.data[dataKey]) != "some data" {
		t.Errorf("Expected data 'some data', got '%s'", string(state.data[dataKey]))
	}
	if state.nonces["alice"] != 1 {
		t.Errorf("Expected alice nonce 1, got %d", state.nonces["alice"])
	}
}

func TestSerializeDeserializeBlock(t *testing.T) {
	block := GenesisBlock()
	data, err := SerializeBlock(block)
	if err != nil {
		t.Errorf("Failed to serialize block: %v", err)
	}
	deserializedBlock, err := DeserializeBlock(data)
	if err != nil {
		t.Errorf("Failed to deserialize block: %v", err)
	}
	if deserializedBlock.Header.Height != block.Header.Height {
		t.Errorf("Expected height %d, got %d", block.Header.Height, deserializedBlock.Header.Height)
	}
	if deserializedBlock.Header.PreviousHash != block.Header.PreviousHash {
		t.Errorf("Expected previous hash %s, got %s", block.Header.PreviousHash, deserializedBlock.Header.PreviousHash)
	}
}

func TestBlockHeaderHash(t *testing.T) {
	header := BlockHeader{
		Version:       1,
		Height:        0,
		PreviousHash:  nullhash,
		MerkleRoot:    nullhash,
		StateRoot:     nullhash,
		Timestamp:     time.Now(),
		Difficulty:    1,
		Nonce:         0,
		ShardID:       0,
		ProposerID:    "genesis",
		ConsensusData: []byte{},
	}
	hash1 := header.Hash()
	hash2 := header.Hash()
	if hash1 != hash2 {
		t.Errorf("Hash is not deterministic: %s != %s", hash1, hash2)
	}
	header.Height = 1
	hash3 := header.Hash()
	if hash1 == hash3 {
		t.Errorf("Expected different hash after changing height")
	}
}
