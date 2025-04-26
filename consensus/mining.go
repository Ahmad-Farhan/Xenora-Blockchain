package consensus

import (
	"context"
	"log"
	"time"
	"xenora/blockchain"
	"xenora/xtx"
)

const blockReward = 50

type Miner struct {
	blockchain  *blockchain.Blockchain
	txPool      *xtx.TransactionPool
	consensus   *HybridConsensus
	minerAddr   string
	isRunning   bool
	isValidator bool
	ctx         context.Context
	cancelFunc  context.CancelFunc
}

func NewMiner(bc *blockchain.Blockchain, txPool *xtx.TransactionPool,
	cons *HybridConsensus, minerAddr string) *Miner {
	ctx, cancel := context.WithCancel(context.Background())
	isValidator := cons.isValidator(minerAddr)

	return &Miner{
		blockchain:  bc,
		txPool:      txPool,
		consensus:   cons,
		minerAddr:   minerAddr,
		isValidator: isValidator,
		ctx:         ctx,
		cancelFunc:  cancel,
	}
}

func (m *Miner) Start() {
	if m.isRunning {
		return
	}
	m.isRunning = true

	if m.isValidator {
		log.Printf("Starting mining as validator with address: %s", m.minerAddr)
	} else {
		log.Printf("Starting mining as regular node with address: %s", m.minerAddr)
	}

	go m.miningLoop()
}

func (m *Miner) Stop() {
	if !m.isRunning {
		return
	}
	m.cancelFunc()
	m.isRunning = false
	log.Printf("Mining stopped")
}

func (m *Miner) miningLoop() {
	for {
		select {
		case <-m.ctx.Done():
			return
		default:
			latestHeight := m.blockchain.GetLatestBlock().Header.Height
			coinbaseTx := xtx.CreateCoinbaseTx(m.minerAddr, blockReward, latestHeight+1)

			startTime := time.Now()
			log.Printf("Starting block creation at height %d", latestHeight+1)

			block, err := m.consensus.CreateBlock(m.minerAddr, coinbaseTx, m.txPool)
			if err != nil {
				log.Printf("Failed to create block: %v", err)
				time.Sleep(time.Second * 5)
				continue
			}

			elapsedTime := time.Since(startTime)
			err = m.blockchain.AddBlock(block)
			if err != nil {
				log.Printf("Failed to add block: %v", err)
				time.Sleep(time.Second * 5)
				continue
			}

			log.Printf("Successfully mined block at height %d with %d transactions in %v",
				block.Header.Height, len(block.Transactions), elapsedTime)

			for _, tx := range block.Transactions {
				m.txPool.Remove(tx.TxID)
			}
			if m.isValidator {
				time.Sleep(time.Millisecond * 100)
			} else {
				time.Sleep(time.Second * 1)
			}
		}
	}
}

// Helper function to check if a transaction exists in the blockchain
func (m *Miner) txExistsInBlockchain(txID string) bool {
	// This is a simplified implementation - in a real system, you would use a database index
	latestHeight := m.blockchain.GetLatestBlock().Header.Height

	for height := uint64(0); height <= latestHeight; height++ {
		block, err := m.blockchain.GetBlockByHeight(height)
		if err != nil {
			continue
		}

		for _, tx := range block.Transactions {
			if tx.TxID == txID {
				return true
			}
		}
	}

	return false
}
