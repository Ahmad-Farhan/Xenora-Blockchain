package merkle

import (
	"sync"
	"time"
)

type SyncRequest struct {
	SourceShardID uint32
	DestShardID   uint32
	DataHashes    []string
	Timestamp     time.Time
	Signature     []byte
	Nonce         uint64
}

type SyncResponse struct {
	RequestID      uint32
	SourceShardID  uint32
	DataBlocks     map[string][]byte
	StateRoot      string
	Timestamp      time.Time
	TransferProofs []*CrossShardProof
	Signature      []byte
}

type CrossShardProof struct {
	DataHash         string
	SourceShardRoot  string
	DestShardRoot    string
	TransferPath     []*ProofNode
	CommitmentHash   string
	ValidationStatus bool
}

type ProofNode struct {
	forest       *AdaptiveMerkleForest
	pendingSync  map[string]*SyncRequest
	commitments  map[string]string
	transferLock sync.RWMutex
}
