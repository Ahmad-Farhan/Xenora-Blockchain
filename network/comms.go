package network

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net"
	"sync"
	"time"
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
	RequestBLockMsg
	RequestStateMsg
)

type Message struct {
	Type    MessageType
	From    string
	To      string
	Payload []byte
}

type MessageHandler func(msg Message, peer *Peer) error

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
	_, err = conn.Write([]byte(n.ID))
	if err != nil {
		conn.Close()
		return err
	}
	idBuf := make([]byte, 32)
	_, err = conn.Read(idBuf)
	if err != nil {
		conn.Close()
		return err
	}

	peerID := string(idBuf)

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
	_, err := conn.Write([]byte(n.ID))
	if err != nil {
		conn.Close()
		return
	}

	idBuf := make([]byte, 32)
	_, err = conn.Read(idBuf)
	if err != nil {
		conn.Close()
		return
	}

	peerID := string(idBuf)
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
	for {
		typeBuf := make([]byte, 1)
		_, err := conn.Read(typeBuf)
		if err != nil {
			n.disconnectPeer(peerID)
			return
		}

		lenBuf := make([]byte, 4)
		_, err = conn.Read(lenBuf)
		if err != nil {
			n.disconnectPeer(peerID)
			return
		}

		msgLen := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])

		payLoad := make([]byte, msgLen)
		_, err = conn.Read(payLoad)
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
			Payload: payLoad,
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
		return fmt.Error("Peer %s not connected", peerId)
	}
	return n.sendToPeer(peer, msgType, payload)
}

func (n *Node) sendToPeer(peer *Peer, msgType MessageType, payload []byte) error {
	msgLen := len(payload)
	msg := make([]byte, 5+msgLen)

	msg[0] = byte(msgType)
	msg[1] = byte(msgLen >> 24)
	msg[1] = byte(msgLen >> 16)
	msg[1] = byte(msgLen >> 8)
	msg[1] = byte(msgLen)

	copy(msg[5:], payload)
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
		peer.isActive = true
		peer.conn.Close()
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
