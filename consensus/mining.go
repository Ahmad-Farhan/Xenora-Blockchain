package consensus

import (
	"context"
	"log"
	"time"
	"xenora/blockchain"
	"xenora/xtx"
)

const (
	blockReward         = 50
	minerTimeoutSeconds = 120
)

// EnhancedMiner implements a mining system with consensus awareness
type EnhancedMiner struct {
	blockchain     *blockchain.Blockchain
	txPool         *xtx.TransactionPool
	consensus      *EnhancedConsensus
	minerAddr      string
	isRunning      bool
	isValidator    bool
	ctx            context.Context
	cancelFunc     context.CancelFunc
	currentRound   int64
	lastBlockTime  time.Time
	failedAttempts int
}

// NewEnhancedMiner creates a new miner instance
func NewEnhancedMiner(bc *blockchain.Blockchain, txPool *xtx.TransactionPool,
	cons *EnhancedConsensus, minerAddr string) *EnhancedMiner {

	ctx, cancel := context.WithCancel(context.Background())
	isValidator := cons.isValidator(minerAddr)

	return &EnhancedMiner{
		blockchain:     bc,
		txPool:         txPool,
		consensus:      cons,
		minerAddr:      minerAddr,
		isValidator:    isValidator,
		ctx:            ctx,
		cancelFunc:     cancel,
		currentRound:   0,
		lastBlockTime:  time.Now(),
		failedAttempts: 0,
	}
}

// Start begins the mining process
func (m *EnhancedMiner) Start() {
	if m.isRunning {
		return
	}
	m.isRunning = true

	if m.isValidator {
		log.Printf("Starting mining as validator with address: %s (reputation: %.2f)",
			m.minerAddr, m.consensus.GetNodeReputation(m.minerAddr))
	} else {
		log.Printf("Starting mining as regular node with address: %s", m.minerAddr)
	}

	go m.miningLoop()
}

// Stop halts the mining process
func (m *EnhancedMiner) Stop() {
	if !m.isRunning {
		return
	}
	m.cancelFunc()
	m.isRunning = false
	log.Printf("Mining stopped for address: %s", m.minerAddr)
}

// miningLoop handles the continuous block creation process
func (m *EnhancedMiner) miningLoop() {
	backoffTime := time.Second * 5
	maxBackoff := time.Second * 30

	for {
		select {
		case <-m.ctx.Done():
			return
		default:
			// First, check if we should mine in this round
			shouldMine, waitTime := m.shouldMineNextBlock()
			if !shouldMine {
				log.Printf("Not selected to mine this round, waiting %v...", waitTime)
				select {
				case <-m.ctx.Done():
					return
				case <-time.After(waitTime):
					continue
				}
			}

			latestHeight := m.blockchain.GetLatestBlock().Header.Height
			coinbaseTx := xtx.CreateCoinbaseTx(m.minerAddr, m.calculateReward(), latestHeight+1)

			startTime := time.Now()
			log.Printf("Starting block creation at height %d", latestHeight+1)

			// Attempt to create a block
			block, err := m.consensus.CreateBlock(m.minerAddr, coinbaseTx, m.txPool)
			if err != nil {
				log.Printf("Failed to create block: %v", err)
				m.failedAttempts++

				// Apply exponential backoff for repeated failures
				if m.failedAttempts > 1 {
					backoffTime *= 2
					if backoffTime > maxBackoff {
						backoffTime = maxBackoff
					}
				}
				time.Sleep(backoffTime)
				continue
			}

			// Add block to blockchain
			m.failedAttempts = 0
			backoffTime = time.Second * 5
			elapsedTime := time.Since(startTime)
			err = m.blockchain.AddBlock(block)
			if err != nil {
				log.Printf("Failed to add block: %v", err)
				time.Sleep(time.Second * 5)
				continue
			}

			log.Printf("Successfully mined block at height %d with %d transactions in %v",
				block.Header.Height, len(block.Transactions), elapsedTime)
			m.lastBlockTime = time.Now()
			m.currentRound++

			// Remove block transactions from pool
			for _, tx := range block.Transactions {
				m.txPool.Remove(tx.TxID)
			}

			// Calculate adaptive wait time based on validator status and reputation
			waitTime = m.calculateWaitTime()
			select {
			case <-m.ctx.Done():
				return
			case <-time.After(waitTime):
				// Continue to next round
			}
		}
	}
}

// calculateReward computes the mining reward based on various factors
func (m *EnhancedMiner) calculateReward() uint64 {
	baseReward := blockReward

	// Apply reputation bonus for validators
	if m.isValidator {
		reputation := m.consensus.GetNodeReputation(m.minerAddr)
		reputationBonus := uint64((reputation / 100.0) * 10.0)
		return uint64(baseReward) + reputationBonus
	}

	return uint64(baseReward)
}

// shouldMineNextBlock determines if this miner is the selected proposer
func (m *EnhancedMiner) shouldMineNextBlock() (bool, time.Duration) {
	nextHeight := m.blockchain.GetLatestBlock().Header.Height + 1
	proposer := m.consensus.SelectBlockProposer(nextHeight)
	if proposer == m.minerAddr {
		return true, 0
	}
	// Not selected: retry after interval
	return false, m.calculateWaitTime()
}

func (m *EnhancedMiner) calculateWaitTime() time.Duration {
	baseTime := time.Second * 5
	repute := m.consensus.GetNodeReputation(m.minerAddr)
	reputationFactor := 1.0
	if m.isValidator { // Higher rep → lower wait
		reputationFactor = 1.0 - (repute / 200.0)
	}

	backoff := time.Duration(m.failedAttempts) * time.Second
	if backoff > baseTime {
		backoff = baseTime
	}
	adjusted := time.Duration(float64(baseTime+backoff) * reputationFactor)
	return adjusted
}
