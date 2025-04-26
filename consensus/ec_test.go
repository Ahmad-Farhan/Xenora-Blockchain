package consensus

import (
	"testing"
	"time"
	"xenora/blockchain"
	"xenora/crypto"
	"xenora/xtx"
)

// TestNewEnhancedConsensus tests the initialization of the EnhancedConsensus engine.
func TestNewEnhancedConsensus(t *testing.T) {
	bc := blockchain.NewBlockchain()
	validators := []string{"v1", "v2", "v3"}
	cons := NewEnhancedConsensus(bc, 4, validators)

	if cons.blockchain != bc {
		t.Error("Blockchain not set correctly")
	}
	if cons.difficulty != 4 {
		t.Errorf("Expected difficulty 4, got %d", cons.difficulty)
	}
	if cons.targetBits != 252 {
		t.Errorf("Expected targetBits 252, got %d", cons.targetBits)
	}
	if cons.validatorThreshold != 2 {
		t.Errorf("Expected validatorThreshold 2, got %d", cons.validatorThreshold)
	}
	if len(cons.nodeScores) != 3 {
		t.Errorf("Expected 3 node scores, got %d", len(cons.nodeScores))
	}
	for _, v := range validators {
		if score := cons.nodeScores[v]; score != 100.0 {
			t.Errorf("Expected initial score 100 for %s, got %f", v, score)
		}
	}
	if len(cons.validatorWeights) != 3 {
		t.Errorf("Expected 3 validator weights, got %d", len(cons.validatorWeights))
	}
}

// TestCreateBlock tests block creation for both validators and non-validators.
func TestCreateBlock(t *testing.T) {
	bc := blockchain.NewBlockchain()
	txPool := xtx.NewTransactionPool()
	validators := []string{"v1"}
	cons := NewEnhancedConsensus(bc, 4, validators)

	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	validatorAddr := keyPair.GetAddress()
	nonValidatorAddr := "non-validator"

	// Add validator to consensus
	cons.validators = append(cons.validators, validatorAddr)
	cons.nodeScores[validatorAddr] = 100.0
	cons.validatorWeights[validatorAddr] = 100

	tx := xtx.NewTransaction(xtx.TransferTx, validatorAddr, "bob", 100, 1, 10, nil)
	tx.Sign(keyPair.PrivateKey)
	txPool.Add(tx)
	coinbaseTx := xtx.CreateCoinbaseTx(validatorAddr, blockReward, 1)

	// Test validator block creation
	block, err := cons.CreateBlock(validatorAddr, coinbaseTx, txPool)
	if err != nil {
		t.Fatalf("Failed to create validator block: %v", err)
	}
	if block.Header.Height != 1 {
		t.Errorf("Expected block height 1, got %d", block.Header.Height)
	}
	if block.Header.ConsensusData[0] != 1 {
		t.Error("Expected validator flag in consensus data")
	}
	if len(block.Transactions) != 2 {
		t.Errorf("Expected 2 transactions, got %d", len(block.Transactions))
	}

	// Test non-validator block creation
	block, err = cons.CreateBlock(nonValidatorAddr, coinbaseTx, txPool)
	if err != nil {
		t.Fatalf("Failed to create non-validator block: %v", err)
	}
	if block.Header.ConsensusData[0] != 0 {
		t.Error("Expected non-validator flag in consensus data")
	}
}

// TestFindEnhancedProof tests the hybrid proof mechanism for validators and non-validators.
func TestFindEnhancedProof(t *testing.T) {
	bc := blockchain.NewBlockchain()
	txPool := xtx.NewTransactionPool()

	cons := NewEnhancedConsensus(bc, 4, []string{"v1"})
	validatorAddr := "v1"
	nonValidatorAddr := "non-validator"

	coinbaseTx := xtx.CreateCoinbaseTx(validatorAddr, blockReward, 1)
	block, _ := cons.CreateBlock(nonValidatorAddr, coinbaseTx, txPool)

	// Test validator proof
	err := cons.findEnhancedProof(block, validatorAddr, true)
	if err != nil {
		t.Fatalf("Failed to find validator proof: %v", err)
	}
	if block.Header.ConsensusData[0] != 1 {
		t.Error("Expected validator flag")
	}
	if score := cons.getReputationScore(validatorAddr); score != 100.0 {
		t.Errorf("Expected reputation score 100, got %f", score)
	}

	// Test non-validator proof
	block.Header.ProposerID = nonValidatorAddr
	err = cons.findEnhancedProof(block, nonValidatorAddr, false)
	if err != nil {
		t.Fatalf("Failed to find non-validator proof: %v", err)
	}
	if block.Header.ConsensusData[0] != 0 {
		t.Error("Expected non-validator flag")
	}
}

// TestValidateBlock tests block validation for high-reputation, standard, and non-validator blocks.
func TestValidateBlock(t *testing.T) {
	bc := blockchain.NewBlockchain()
	txPool := xtx.NewTransactionPool()
	cons := NewEnhancedConsensus(bc, 4, []string{"v1"})
	validatorAddr := "v1"
	nonValidatorAddr := "non-validator"

	coinbaseTx := xtx.CreateCoinbaseTx(validatorAddr, blockReward, 1)
	block, _ := cons.CreateBlock(validatorAddr, coinbaseTx, txPool)

	// Test high-reputation validator block
	cons.nodeScores[validatorAddr] = 90.0 // High reputation
	cons.findEnhancedProof(block, validatorAddr, true)
	err := cons.ValidateBlock(block)
	if err != nil {
		t.Errorf("High-reputation block validation failed: %v", err)
	}
	if score := cons.getReputationScore(validatorAddr); score != 91.2 {
		t.Errorf("Expected reputation score 91.2, got %f", score)
	}

	// Test standard validator block
	cons.nodeScores[validatorAddr] = 60.0 // Standard reputation
	block.Header.Timestamp = time.Now()   // Reset timestamp
	cons.findEnhancedProof(block, validatorAddr, true)
	err = cons.ValidateBlock(block)
	if err != nil {
		t.Errorf("Standard block validation failed: %v", err)
	}
	if score := cons.getReputationScore(validatorAddr); score != 61.1 {
		t.Errorf("Expected reputation score 61.1, got %f", score)
	}

	// Test non-validator block
	block.Header.ProposerID = nonValidatorAddr
	cons.findEnhancedProof(block, nonValidatorAddr, false)
	err = cons.ValidateBlock(block)
	if err != nil {
		t.Errorf("Non-validator block validation failed: %v", err)
	}
	if score := cons.getReputationScore(nonValidatorAddr); score != 51.5 {
		t.Errorf("Expected reputation score 50.5, got %f", score)
	}
}

// TestValidateInvalidBlock tests validation failures for invalid blocks.
func TestValidateInvalidBlock(t *testing.T) {
	bc := blockchain.NewBlockchain()
	cons := NewEnhancedConsensus(bc, 4, []string{"v1"})
	validatorAddr := "v1"

	coinbaseTx := xtx.CreateCoinbaseTx(validatorAddr, blockReward, 1)
	block := &blockchain.Block{
		Header: blockchain.BlockHeader{
			Version:      1,
			Height:       2, // Invalid height
			PreviousHash: bc.GetLatestBlock().Header.Hash(),
			Timestamp:    time.Now(),
			Difficulty:   4,
			ProposerID:   validatorAddr,
		},
		Transactions: []xtx.Transaction{*coinbaseTx},
	}

	cons.findEnhancedProof(block, validatorAddr, true)
	err := cons.ValidateBlock(block)
	if err == nil {
		t.Error("Expected validation failure for invalid block height")
	}

	// Test invalid score tier
	cons.nodeScores[validatorAddr] = 50.0 // Low reputation
	cons.findEnhancedProof(block, validatorAddr, true)
	block.Header.ConsensusData[1] = 5 // High score tier
	if err := cons.ValidateBlock(block); err == nil {
		t.Error("Expected validation failure for invalid score tier")
	}
}

// TestReputationManagement tests reputation score updates and tier calculations.
func TestReputationManagement(t *testing.T) {
	bc := blockchain.NewBlockchain()
	cons := NewEnhancedConsensus(bc, 4, []string{"v1"})
	validatorAddr := "v1"

	// Test initial score
	if score := cons.GetNodeReputation(validatorAddr); score != 100.0 {
		t.Errorf("Expected initial score 100, got %f", score)
	}

	// Test reward and penalize
	cons.RewardNode(validatorAddr, 5.0)
	if score := cons.GetNodeReputation(validatorAddr); score != 100.0 {
		t.Errorf("Expected score 100 after reward (capped), got %f", score)
	}

	cons.PenalizeNode(validatorAddr, 30.0)
	if score := cons.GetNodeReputation(validatorAddr); score != 70.0 {
		t.Errorf("Expected score 70 after penalty, got %f", score)
	}

	// Test score tiers
	if tier := cons.getScoreTier(validatorAddr); tier != 3 {
		t.Errorf("Expected tier 3 for score 70, got %d", tier)
	}
	cons.nodeScores[validatorAddr] = 95.0
	if tier := cons.getScoreTier(validatorAddr); tier != 5 {
		t.Errorf("Expected tier 5 for score 95, got %d", tier)
	}
}

// TestVRFSeedGeneration tests the VRF seed generation for proposer selection.
func TestVRFSeedGeneration(t *testing.T) {
	bc := blockchain.NewBlockchain()
	cons := NewEnhancedConsensus(bc, 4, []string{"v1"})
	proposerAddr := "v1"

	seed1 := cons.generateVRFSeed(proposerAddr, 1)
	seed2 := cons.generateVRFSeed(proposerAddr, 1)
	if seed1 != seed2 {
		t.Error("Expected different VRF seeds for same input with time variation")
	}

	seed3 := cons.generateVRFSeed(proposerAddr, 2)
	if seed1 == seed3 {
		t.Error("Expected different VRF seeds for different heights")
	}
}

// TestSelectBlockProposer tests the weighted random proposer selection.
func TestSelectBlockProposer(t *testing.T) {
	bc := blockchain.NewBlockchain()
	cons := NewEnhancedConsensus(bc, 4, []string{"v1", "v2", "v3"})
	cons.nodeScores["v1"] = 70.0
	cons.nodeScores["v2"] = 50.0
	cons.nodeScores["v3"] = 10.0

	// Count selections over multiple rounds
	selections := make(map[string]int)
	for i := 0; i < 1000; i++ {
		proposer := cons.SelectBlockProposer(uint64(i))
		selections[proposer]++
	}

	// Higher reputation should lead to more selections
	if selections["v1"] < selections["v2"] || selections["v2"] < selections["v3"] {
		t.Errorf("Expected v1 > v2 > v3 in selections, got %v", selections)
	}
}

// TestBlockVoting tests the block voting and confirmation mechanism.
func TestBlockVoting(t *testing.T) {
	bc := blockchain.NewBlockchain()
	cons := NewEnhancedConsensus(bc, 4, []string{"v1", "v2", "v3"})
	blockHash := "test-block-hash"

	cons.recordBlockVote(blockHash, "v1")
	cons.recordBlockVote(blockHash, "v2")
	if !cons.IsBlockConfirmed(blockHash) {
		t.Error("Expected block to be confirmed with 2 votes (threshold 2)")
	}

	validators := cons.GetBlockValidators(blockHash)
	if len(validators) != 2 || validators[0] != "v1" || validators[1] != "v2" {
		t.Errorf("Expected validators [v1, v2], got %v", validators)
	}

	// Test duplicate vote
	cons.recordBlockVote(blockHash, "v1")
	if len(cons.GetBlockValidators(blockHash)) != 2 {
		t.Error("Expected no duplicate votes")
	}
}

// TestValidatorsByReputationRank tests sorting validators by reputation.
func TestValidatorsByReputationRank(t *testing.T) {
	bc := blockchain.NewBlockchain()
	cons := NewEnhancedConsensus(bc, 4, []string{"v1", "v2", "v3"})
	cons.nodeScores["v1"] = 90.0
	cons.nodeScores["v2"] = 100.0
	cons.nodeScores["v3"] = 50.0

	ranked := cons.GetValidatorsByReputationRank()
	expected := []string{"v2", "v1", "v3"}
	for i, v := range ranked {
		if v != expected[i] {
			t.Errorf("Expected ranked validators %v, got %v", expected, ranked)
			break
		}
	}
}

// TestNewEnhancedMiner tests the initialization of the EnhancedMiner.
func TestNewEnhancedMiner(t *testing.T) {
	bc := blockchain.NewBlockchain()
	txPool := xtx.NewTransactionPool()
	cons := NewEnhancedConsensus(bc, 4, []string{"v1"})
	minerAddr := "v1"

	miner := NewEnhancedMiner(bc, txPool, cons, minerAddr)
	if miner.blockchain != bc {
		t.Error("Blockchain not set correctly")
	}
	if miner.txPool != txPool {
		t.Error("Transaction pool not set correctly")
	}
	if miner.consensus != cons {
		t.Error("Consensus engine not set correctly")
	}
	if !miner.isValidator {
		t.Error("Expected validator status to be true")
	}
	if miner.currentRound != 0 {
		t.Errorf("Expected initial round 0, got %d", miner.currentRound)
	}
}

// TestEnhancedMinerStartStop tests starting and stopping the miner.
func TestEnhancedMinerStartStop(t *testing.T) {
	bc := blockchain.NewBlockchain()
	txPool := xtx.NewTransactionPool()
	cons := NewEnhancedConsensus(bc, 4, []string{"v1"})
	miner := NewEnhancedMiner(bc, txPool, cons, "v1")

	miner.Start()
	if !miner.isRunning {
		t.Error("Expected miner to be running after Start")
	}

	miner.Start() // Test idempotency
	if !miner.isRunning {
		t.Error("Expected miner to remain running after duplicate Start")
	}

	miner.Stop()
	if miner.isRunning {
		t.Error("Expected miner to be stopped after Stop")
	}

	miner.Stop() // Test idempotency
	if miner.isRunning {
		t.Error("Expected miner to remain stopped after duplicate Stop")
	}
}

// TestEnhancedMinerMiningLoop tests the mining loop with proposer selection.
func TestEnhancedMinerMiningLoop(t *testing.T) {
	bc := blockchain.NewBlockchain()
	txPool := xtx.NewTransactionPool()
	cons := NewEnhancedConsensus(bc, 4, []string{"v1"})
	minerAddr := "v1"
	miner := NewEnhancedMiner(bc, txPool, cons, minerAddr)

	tx := xtx.NewTransaction(xtx.TransferTx, minerAddr, "bob", 100, 1, 10, nil)
	txPool.Add(tx)

	// Mock proposer selection to ensure mining
	cons.ProposerSelector = func(height uint64) string { return minerAddr }

	miner.Start()
	time.Sleep(6 * time.Second) // Allow at least one block to be mined
	miner.Stop()

	if bc.GetLatestBlock().Header.Height < 1 {
		t.Error("No blocks were mined")
	}
	if len(txPool.GetPending()) != 0 {
		t.Error("Expected transaction to be removed from pool")
	}
	if miner.currentRound == 0 {
		t.Error("Expected round to increment after mining")
	}
}

// TestCalculateReward tests the reward calculation with reputation bonus.
func TestCalculateReward(t *testing.T) {
	bc := blockchain.NewBlockchain()
	txPool := xtx.NewTransactionPool()
	cons := NewEnhancedConsensus(bc, 4, []string{"v1"})
	miner := NewEnhancedMiner(bc, txPool, cons, "v1")

	// Test validator with high reputation
	cons.nodeScores["v1"] = 100.0
	reward := miner.calculateReward()
	if reward != blockReward+10 {
		t.Errorf("Expected reward %d, got %d", blockReward+10, reward)
	}

	// Test validator with low reputation
	cons.nodeScores["v1"] = 50.0
	reward = miner.calculateReward()
	if reward != blockReward+5 {
		t.Errorf("Expected reward %d, got %d", blockReward+5, reward)
	}

	// Test non-validator
	miner.isValidator = false
	reward = miner.calculateReward()
	if reward != blockReward {
		t.Errorf("Expected reward %d, got %d", blockReward, reward)
	}
}

// TestCalculateWaitTime tests the adaptive wait time calculation.
func TestCalculateWaitTime(t *testing.T) {
	bc := blockchain.NewBlockchain()
	txPool := xtx.NewTransactionPool()
	cons := NewEnhancedConsensus(bc, 4, []string{"v1"})
	miner := NewEnhancedMiner(bc, txPool, cons, "v1")

	// Test validator with high reputation
	cons.nodeScores["v1"] = 100.0
	waitTime := miner.calculateWaitTime()
	expected := time.Duration(5 * time.Second / 2) // 100/200 = 0.5 factor
	if waitTime != expected {
		t.Errorf("Expected wait time %v, got %v", expected, waitTime)
	}

	// Test with failed attempts
	miner.failedAttempts = 2
	waitTime = miner.calculateWaitTime()
	expected = time.Duration((7 * time.Second) / 2) // Backoff included
	if waitTime != expected {
		t.Errorf("Expected wait time %v, got %v", expected, waitTime)
	}
}
