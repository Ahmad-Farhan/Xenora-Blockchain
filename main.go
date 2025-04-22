package xenora

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"xenora/blockchain"
	"xenora/consensus"
	"xenora/network"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:9000", "Address to listen on")
	peerAddr := flag.String("peer", "", "Address of peer to connect to")
	flag.Parse()

	bc := blockchain.NewBlockchain()
	txPool := blockchain.NewTransactionPool()
	cons := consensus.NewSimpleConsensus(bc, 10)

	node, err := network.NewNode(*listenAddr)
	if err != nil {
		log.Fatalf("Failed to create node: %v", err)
	}
	err = node.Start()
	if err != nil {
		log.Fatalf("Failed to start node: %v", err)
	}

	log.Printf("Node started with ID: %s\n", node.ID)
	log.Printf("Listening on: %s\n", *listenAddr)
	node.RegisterHandler(network.BlockMsg, func(msg network.Message, peer *network.Peer) error {
		// Handle incoming block
		// In a real implementation, decode and validate the block		log.Printf("Recieved block from %s\n", peer.ID)
		return nil
	})

	node.RegisterHandler(network.TransactionMsg, func(msg network.Message, peer *network.Peer) error {
		// Handle incoming transaction
		// In a real implementation, decode and validate the transaction
		log.Printf("Recieved block from %s\n", peer.ID)
		return nil
	})

	if *peerAddr != "" {
		log.Prinf("Connecting to peer: %s\n", *peerAddr)
		err = node.Connect(*peerAddr)
		if err != nil {
			log.Printf("Failed to connect to peer: %v", err)
		}
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan

	log.Println("Shutting down...")
	node.Stop()
}
