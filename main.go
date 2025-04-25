package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"xenora/blockchain"
	"xenora/consensus"
	"xenora/crypto"
	"xenora/network"
	"xenora/xtx"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:9000", "Address to listen on")
	peerAddr := flag.String("peer", "", "Address of peer to connect to")
	miningEnabled := flag.Bool("mine", true, "Enable mining")
	difficulty := flag.Uint("difficulty", 10, "Mining difficulty")
	flag.Parse()

	// Initialize blockchain components
	bc := blockchain.NewBlockchain()
	txPool := xtx.NewTransactionPool()
	cons := consensus.NewSimpleConsensus(bc, uint32(*difficulty))

	// Create or load keys
	keyPair, err := loadOrCreateKeys()
	if err != nil {
		log.Fatalf("Failed to initialize keys: %v", err)
	}
	minerAddress := keyPair.GetAddress()
	log.Printf("Miner address: %s", minerAddress)

	// Create network node
	node, err := network.NewNode(*listenAddr)
	if err != nil {
		log.Fatalf("Failed to create node: %v", err)
	}

	// Start node
	err = node.Start()
	if err != nil {
		log.Fatalf("Failed to start node: %v", err)
	}
	log.Printf("Node started with ID: %s", node.ID)
	log.Printf("Listening on: %s", *listenAddr)

	// Register message handlers
	node.RegisterHandler(network.BlockMsg, network.BlockHandler(bc))
	node.RegisterHandler(network.TransactionMsg, network.TransactionHandler(txPool))
	node.RegisterHandler(network.StatusMsg, network.StatusHandler(bc, node))

	// Connect to peer if specified
	if *peerAddr != "" {
		log.Printf("Connecting to peer: %s", *peerAddr)
		err = node.Connect(*peerAddr)
		if err != nil {
			log.Printf("Failed to connect to peer: %v", err)
		}
	}

	// Start miner if enabled
	var miner *consensus.Miner
	if *miningEnabled {
		miner = consensus.NewMiner(bc, txPool, cons, minerAddress)
		miner.Start()
		log.Println("Mining started")
	}

	// Periodically broadcast status
	go func() {
		for {
			network.BroadcastStatus(node, bc)
			time.Sleep(30 * time.Second)
		}
	}()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
	if miner != nil {
		miner.Stop()
	}
	node.Stop()
}

// loadOrCreateKeys loads or creates a keypair for the node
func loadOrCreateKeys() (*crypto.KeyPair, error) {
	// Try to load existing keys
	keyFile := "node_key.pem"

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		// Create new keys if file doesn't exist
		keyPair, err := crypto.GenerateKeyPair()
		if err != nil {
			return nil, err
		}

		// Save private key
		pemData, err := crypto.SavePrivateKey(keyPair.PrivateKey)
		if err != nil {
			return nil, err
		}

		err = os.WriteFile(keyFile, []byte(pemData), 0600)
		if err != nil {
			return nil, err
		}

		return keyPair, nil
	} else {
		// Load existing key
		keyData, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}

		privateKey, err := crypto.LoadPrivateKey(string(keyData))
		if err != nil {
			return nil, err
		}

		return &crypto.KeyPair{
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
		}, nil
	}
}
