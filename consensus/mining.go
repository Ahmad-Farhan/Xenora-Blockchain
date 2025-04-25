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
	blockchain *blockchain.Blockchain
	txPool     *xtx.TransactionPool
	consensus  *SimpleConsensus
	minerAddr  string
	isRunning  bool
	ctx        context.Context
	cancelFunc context.CancelFunc
}

func NewMiner(bc *blockchain.Blockchain, txPool *xtx.TransactionPool,
	cons *SimpleConsensus, minerAddr string) *Miner {
	ctx, cancel := context.WithCancel(context.Background())
	return &Miner{
		blockchain: bc,
		txPool:     txPool,
		consensus:  cons,
		minerAddr:  minerAddr,
		ctx:        ctx,
		cancelFunc: cancel,
	}
}

func (m *Miner) Start() {
	if m.isRunning {
		return
	}
	m.isRunning = true
	go m.miningLoop()
}

func (m *Miner) Stop() {
	if !m.isRunning {
		return
	}
	m.cancelFunc()
	m.isRunning = false
}

func (m *Miner) miningLoop() { // NEED TO INCLUDE COINBASE TX IN BLOCK
	for {
		select {
		case <-m.ctx.Done():
			return
		default:
			// pendingTxs := m.txPool.GetPending()

			// Add coinbase transaction (mining reward)
			// latestHeight := m.blockchain.GetLatestBlock().Header.Height
			// coinbaseTx := xtx.CreateCoinbaseTx(m.minerAddr, blockReward, latestHeight+1)

			// pendingTxs = append(pendingTxs, coinbase)
			// Create block with transactions
			block, err := m.consensus.CreateBlock(m.minerAddr, m.txPool)
			if err != nil {
				log.Printf("Failed to create block: %v", err)
				time.Sleep(time.Second * 5)
				continue
			}

			// Add block to blockchain
			err = m.blockchain.AddBlock(block)
			if err != nil {
				log.Printf("Failed to add block: %v", err)
				time.Sleep(time.Second * 5)
				continue
			}

			log.Printf("Successfully mined block at height %d with %d transactions",
				block.Header.Height, len(block.Transactions))

			// Short pause to prevent CPU overuse
			time.Sleep(time.Millisecond * 100)
		}
	}
}
