package network

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"xenora/blockchain"
	"xenora/xtx"
)

type Node struct {
	ID       string
	Address  string
	peers    map[string]*Peer
	listener net.Listener
	msgChan  chan Message
	ctx      context.Context
	cancel   context.CancelFunc
	lock     sync.RWMutex
	handlers map[MessageType]MessageHandler
}

type Peer struct {
	ID       string
	Address  string
	conn     net.Conn
	lastSeen time.Time
	isActive bool
}

type MessageType uint8

const (
	BlockMsg MessageType = iota
	TransactionMsg
	PeerDiscoveryMsg
	StatusMsg
	RequestBlockMsg
	RequestStateMsg
)

type Message struct {
	Type    MessageType
	From    string
	To      string
	Payload []byte
}

type MessageHandler func(msg Message, peer *Peer) error

// Initialize gob encoder with known types
func init() {
	gob.Register(&blockchain.Block{})
	gob.Register(&xtx.Transaction{})
	gob.Register(&Status{})
	gob.Register(&BlockRequest{})
}

func NewNode(address string) (*Node, error) {
	idBytes := make([]byte, 16)
	_, err := rand.Read(idBytes)
	if err != nil {
		return nil, err
	}
	id := hex.EncodeToString(idBytes)
	ctx, cancel := context.WithCancel(context.Background())

	return &Node{
		ID:       id,
		Address:  address,
		peers:    make(map[string]*Peer),
		msgChan:  make(chan Message, 100),
		ctx:      ctx,
		cancel:   cancel,
		handlers: make(map[MessageType]MessageHandler),
	}, nil
}

func (n *Node) Start() error {
	listener, err := net.Listen("tcp", n.Address)
	if err != nil {
		return err
	}
	n.listener = listener

	go n.handleMessages()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-n.ctx.Done():
					return
				default:
					log.Printf("Error accepting connection: %v", err)
					continue
				}
			}
			go n.handleConnection(conn)
		}
	}()
	return nil
}

func (n *Node) Connect(address string) error {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return err
	}
	// Send our node ID (fixed 32 bytes)
	idBytes := []byte(n.ID)
	if len(idBytes) > 32 {
		idBytes = idBytes[:32]
	} else if len(idBytes) < 32 {
		padding := make([]byte, 32-len(idBytes))
		idBytes = append(idBytes, padding...)
	}

	_, err = conn.Write(idBytes)
	if err != nil {
		conn.Close()
		return err
	}

	// Read peer ID
	idBuf := make([]byte, 32)
	_, err = io.ReadFull(conn, idBuf)
	if err != nil {
		conn.Close()
		return err
	}

	var nullIndex int
	for nullIndex = 0; nullIndex < len(idBuf); nullIndex++ {
		if idBuf[nullIndex] == 0 {
			break
		}
	}
	peerID := string(idBuf[:nullIndex])
	if peerID == "" {
		peerID = hex.EncodeToString(idBuf)
	}

	n.lock.Lock()
	n.peers[peerID] = &Peer{
		ID:       peerID,
		Address:  address,
		conn:     conn,
		lastSeen: time.Now(),
		isActive: true,
	}
	n.lock.Unlock()
	go n.handlePeerMessages(peerID, conn)
	return nil
}

func (n *Node) handleConnection(conn net.Conn) {
	// Send our node ID (fixed 32 bytes)
	idBytes := []byte(n.ID)
	if len(idBytes) > 32 {
		idBytes = idBytes[:32]
	} else if len(idBytes) < 32 {
		padding := make([]byte, 32-len(idBytes))
		idBytes = append(idBytes, padding...)
	}

	_, err := conn.Write(idBytes)
	if err != nil {
		conn.Close()
		return
	}

	idBuf := make([]byte, 32)
	_, err = io.ReadFull(conn, idBuf)
	if err != nil {
		conn.Close()
		return
	}

	var nullIndex int
	for nullIndex = 0; nullIndex < len(idBuf); nullIndex++ {
		if idBuf[nullIndex] == 0 {
			break
		}
	}
	peerID := string(idBuf[:nullIndex])
	if peerID == "" {
		peerID = hex.EncodeToString(idBuf)
	}

	peerAddr := conn.RemoteAddr().String()

	n.lock.Lock()
	n.peers[peerID] = &Peer{
		ID:       peerID,
		Address:  peerAddr,
		conn:     conn,
		lastSeen: time.Now(),
		isActive: true,
	}
	n.lock.Unlock()

	go n.handlePeerMessages(peerID, conn)
}

func (n *Node) handlePeerMessages(peerID string, conn net.Conn) {
	defer conn.Close()

	for {
		typeBuf := make([]byte, 1)
		_, err := io.ReadFull(conn, typeBuf)
		if err != nil {
			n.disconnectPeer(peerID)
			return
		}

		lenBuf := make([]byte, 4)
		_, err = io.ReadFull(conn, lenBuf)
		if err != nil {
			n.disconnectPeer(peerID)
			return
		}

		msgLen := binary.BigEndian.Uint32(lenBuf)
		if msgLen > 10*1024*1024 { // 10MB max message size
			log.Printf("Message too large from peer %s: %d bytes", peerID, msgLen)
			n.disconnectPeer(peerID)
			return
		}

		payload := make([]byte, msgLen)
		_, err = io.ReadFull(conn, payload)
		if err != nil {
			n.disconnectPeer(peerID)
			return
		}
		n.lock.Lock()
		if peer, exists := n.peers[peerID]; exists {
			peer.lastSeen = time.Now()
		}
		n.lock.Unlock()

		msg := Message{
			Type:    MessageType(typeBuf[0]),
			From:    peerID,
			Payload: payload,
		}
		n.msgChan <- msg
	}
}

func (n *Node) handleMessages() {
	for {
		select {
		case <-n.ctx.Done():
			return
		case msg := <-n.msgChan:
			n.lock.RLock()
			handler, exists := n.handlers[msg.Type]
			peer, peerExists := n.peers[msg.From]
			n.lock.RUnlock()

			if exists && peerExists {
				err := handler(msg, peer)
				if err != nil {
					log.Printf("Error handling message: %v", err)
				}
			}
		}
	}
}

func (n *Node) Broadcast(msgType MessageType, payload []byte) {
	n.lock.RLock()
	defer n.lock.RUnlock()

	for _, peer := range n.peers {
		if peer.isActive {
			go n.sendToPeer(peer, msgType, payload)
		}
	}
}

func (n *Node) SendTo(peerId string, msgType MessageType, payload []byte) error {
	n.lock.RLock()
	peer, exists := n.peers[peerId]
	n.lock.RUnlock()

	if !exists || !peer.isActive {
		return fmt.Errorf("peer %s not connected", peerId)
	}
	return n.sendToPeer(peer, msgType, payload)
}

func (n *Node) sendToPeer(peer *Peer, msgType MessageType, payload []byte) error {
	msgLen := len(payload)
	header := make([]byte, 5) // 1 byte type + 4 bytes length

	header[0] = byte(msgType)
	binary.BigEndian.PutUint32(header[1:], uint32(msgLen))

	// Create full message
	msg := append(header, payload...)

	// Send message
	_, err := peer.conn.Write(msg)
	return err
}

func (n *Node) RegisterHandler(msgType MessageType, handler MessageHandler) {
	n.lock.Lock()
	defer n.lock.Unlock()

	n.handlers[msgType] = handler
}

func (n *Node) disconnectPeer(peerId string) {
	n.lock.Lock()
	defer n.lock.Unlock()

	if peer, exists := n.peers[peerId]; exists {
		peer.isActive = false
		peer.conn.Close()
		log.Printf("Disconnected from peer %s", peerId)
	}
}

func (n *Node) Stop() {
	n.cancel()
	if n.listener != nil {
		n.listener.Close()
	}

	n.lock.Lock()
	for _, peer := range n.peers {
		if peer.isActive {
			peer.conn.Close()
			peer.isActive = false
		}
	}
	n.lock.Unlock()
}

// BlockHandler processes incoming blocks
func BlockHandler(bc *blockchain.Blockchain) MessageHandler {
	return func(msg Message, peer *Peer) error {
		block, err := blockchain.DeserializeBlock(msg.Payload)
		if err != nil {
			return fmt.Errorf("invalid block data: %v", err)
		}

		log.Printf("Received block at height %d from %s", block.Header.Height, peer.ID)

		// Add block to blockchain
		err = bc.AddBlock(block)
		if err != nil {
			return fmt.Errorf("failed to add block: %v", err)
		}

		return nil
	}
}

// TransactionHandler processes incoming transactions
func TransactionHandler(txPool *xtx.TransactionPool) MessageHandler {
	return func(msg Message, peer *Peer) error {
		tx, err := xtx.DeserializeTransaction(msg.Payload)
		if err != nil {
			return fmt.Errorf("invalid transaction data: %v", err)
		}

		log.Printf("Received transaction %s from %s", tx.TxID, peer.ID)

		// Add transaction to pool
		txPool.Add(tx)

		return nil
	}
}

// StatusHandler processes status messages
func StatusHandler(bc *blockchain.Blockchain, node *Node) MessageHandler {
	return func(msg Message, peer *Peer) error {
		status, err := deserializeStatus(msg.Payload)
		if err != nil {
			return fmt.Errorf("invalid status data: %v", err)
		}

		log.Printf("Received status from %s: height=%d", peer.ID, status.Height)

		// If peer has higher blocks, request them
		ourHeight := bc.GetLatestBlock().Header.Height
		if status.Height > ourHeight {
			requestBlocks(node, peer.ID, ourHeight+1, status.Height)
		}

		return nil
	}
}

// Broadcast functions

// BroadcastBlock sends a block to all peers
func BroadcastBlock(node *Node, block *blockchain.Block) error {
	data, err := blockchain.SerializeBlock(block)
	if err != nil {
		return err
	}

	node.Broadcast(BlockMsg, data)
	return nil
}

// BroadcastTransaction sends a transaction to all peers
func BroadcastTransaction(node *Node, tx *xtx.Transaction) error {
	data, err := tx.Serialize()
	if err != nil {
		return err
	}

	node.Broadcast(TransactionMsg, data)
	return nil
}

// BroadcastStatus sends our current status to all peers
func BroadcastStatus(node *Node, bc *blockchain.Blockchain) error {
	latestBlock := bc.GetLatestBlock()

	status := Status{
		Height:  latestBlock.Header.Height,
		Hash:    latestBlock.Header.Hash(),
		Version: 1,
	}

	data, err := serializeStatus(&status)
	if err != nil {
		return err
	}

	node.Broadcast(StatusMsg, data)
	return nil
}

// Helper functions for requesting blocks
func requestBlocks(node *Node, peerID string, startHeight, endHeight uint64) error {
	request := BlockRequest{
		StartHeight: startHeight,
		EndHeight:   endHeight,
	}

	data, err := serializeBlockRequest(&request)
	if err != nil {
		return err
	}

	return node.SendTo(peerID, RequestBlockMsg, data)
}

// Data structures for messages

// Status represents a node's blockchain status
type Status struct {
	Height  uint64
	Hash    string
	Version uint32
}

// BlockRequest represents a request for blocks
type BlockRequest struct {
	StartHeight uint64
	EndHeight   uint64
}

// Serialization helpers

func serializeStatus(status *Status) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(status); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func deserializeStatus(data []byte) (*Status, error) {
	var status Status
	buf := bytes.NewReader(data)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(&status)
	if err != nil {
		return nil, err
	}
	return &status, nil
}

func serializeBlockRequest(req *BlockRequest) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(req); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
