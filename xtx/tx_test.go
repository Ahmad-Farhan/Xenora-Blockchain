package xtx

import (
	"bytes"
	"log"
	"testing"

	"xenora/crypto"
)

func TestNewTransaction(t *testing.T) {
	tx := NewTransaction(TransferTx, "alice", "bob", 100, 1, 10, nil)
	if tx.Type != TransferTx {
		t.Errorf("Expected transaction type %d, got %d", TransferTx, tx.Type)
	}
	if tx.From != "alice" {
		t.Errorf("Expected from 'alice', got '%s'", tx.From)
	}
	if tx.To != "bob" {
		t.Errorf("Expected to 'bob', got '%s'", tx.To)
	}
	if tx.Value != 100 {
		t.Errorf("Expected value 100, got %d", tx.Value)
	}
	if tx.Nonce != 1 {
		t.Errorf("Expected nonce 1, got %d", tx.Nonce)
	}
	if tx.Fee != 10 {
		t.Errorf("Expected fee 10, got %d", tx.Fee)
	}
	if tx.Timestamp.IsZero() {
		t.Error("Transaction timestamp should be set")
	}
}

func TestCreateCoinbaseTx(t *testing.T) {
	cbTx := CreateCoinbaseTx("miner", 50, 1)
	if cbTx.Type != RewardTx {
		t.Errorf("Expected transaction type %d, got %d", RewardTx, cbTx.Type)
	}
	if cbTx.To != "miner" {
		t.Errorf("Expected to 'miner', got '%s'", cbTx.To)
	}
	if cbTx.Value != 50 {
		t.Errorf("Expected value 50, got %d", cbTx.Value)
	}
	if cbTx.Nonce != 0 {
		t.Errorf("Expected nonce 0, got %d", cbTx.Nonce)
	}
	if cbTx.Fee != 0 {
		t.Errorf("Expected fee 0, got %d", cbTx.Fee)
	}
	if cbTx.TxID == "" {
		t.Error("Transaction ID should not be empty")
	}
	if cbTx.Timestamp.IsZero() {
		t.Error("Transaction timestamp should be set")
	}
	if string(cbTx.Data) != "Reward for block 1" {
		t.Errorf("Expected data 'Reward for block 1', got '%s'", string(cbTx.Data))
	}
}

func TestTransactionHash(t *testing.T) {
	tx := NewTransaction(TransferTx, "alice", "bob", 100, 1, 10, nil)
	hash1 := tx.Hash()
	hash2 := tx.Hash()
	if hash1 != hash2 {
		t.Errorf("Transaction hash is not deterministic: %s != %s", hash1, hash2)
	}
	tx.Value = 200
	hash3 := tx.Hash()
	if hash1 == hash3 {
		t.Error("Expected different hash after modifying transaction")
	}
}

func TestTransactionSignAndVerify(t *testing.T) {
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	tx := NewTransaction(TransferTx, keyPair.GetAddress(), "bob", 100, 1, 10, nil)
	err = tx.Sign(keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to sign transaction: %v", err)
	}
	if !tx.isSigned() {
		t.Error("Transaction should be signed")
	}
	verified, err := tx.Verify()
	if err != nil {
		t.Fatalf("Failed to verify transaction: %v", err)
	}
	if !verified {
		t.Error("Expected transaction signature to be valid")
	}
	tx.Value = 200
	verified, err = tx.Verify()
	if err != nil {
		t.Fatalf("Failed to verify transaction: %v", err)
	}
	if verified {
		t.Error("Expected transaction signature to be invalid after modification")
	}
}

func TestTransactionSerializeDeserialize(t *testing.T) {
	tx := NewTransaction(TransferTx, "alice", "bob", 100, 1, 10, nil)
	data, err := tx.Serialize()
	if err != nil {
		t.Fatalf("Failed to serialize transaction: %v", err)
	}
	deserializedTx, err := DeserializeTransaction(data)
	if err != nil {
		t.Fatalf("Failed to deserialize transaction: %v", err)
	}
	if deserializedTx.TxID != tx.TxID {
		t.Errorf("Expected TxID %s, got %s", tx.TxID, deserializedTx.TxID)
	}
	if deserializedTx.Type != tx.Type {
		t.Errorf("Expected Type %d, got %d", tx.Type, deserializedTx.Type)
	}
	if deserializedTx.From != tx.From {
		t.Errorf("Expected From %s, got %s", tx.From, deserializedTx.From)
	}
	if deserializedTx.To != tx.To {
		t.Errorf("Expected To %s, got %s", tx.To, deserializedTx.To)
	}
	if deserializedTx.Value != tx.Value {
		t.Errorf("Expected Value %d, got %d", tx.Value, deserializedTx.Value)
	}
	if deserializedTx.Nonce != tx.Nonce {
		t.Errorf("Expected Nonce %d, got %d", tx.Nonce, deserializedTx.Nonce)
	}
	if deserializedTx.Fee != tx.Fee {
		t.Errorf("Expected Fee %d, got %d", tx.Fee, deserializedTx.Fee)
	}
	if !bytes.Equal(deserializedTx.Data, tx.Data) {
		t.Errorf("Expected Data %v, got %v", tx.Data, deserializedTx.Data)
	}
	if !deserializedTx.Timestamp.Equal(tx.Timestamp) {
		t.Errorf("Expected Timestamp %v, got %v", tx.Timestamp, deserializedTx.Timestamp)
	}
}

func TestTransactionPool(t *testing.T) {
	pool := NewTransactionPool()
	kpAlice, _ := crypto.GenerateKeyPair()
	kpCharlie, _ := crypto.GenerateKeyPair()

	tx1 := NewTransaction(TransferTx, kpAlice.GetAddress(), "bob", 100, 1, 10, nil)
	tx2 := NewTransaction(TransferTx, kpCharlie.GetAddress(), "dave", 200, 1, 20, nil)
	tx1.Sign(kpAlice.PrivateKey)
	tx2.Sign(kpCharlie.PrivateKey)
	if !pool.Add(tx1) || !pool.Add(tx2) {
		t.Errorf("Transactions Failed")
	}
	pending := pool.GetPending()
	log.Print("Pending: ", pool)
	if len(pending) != 2 {
		t.Errorf("Expected 2 pending transactions, got %d", len(pending))
	}
	pool.Remove(tx1.TxID)
	pending = pool.GetPending()
	if len(pending) != 1 {
		t.Errorf("Expected 1 pending transaction after removal, got %d", len(pending))
	}
	if pending[0].TxID != tx2.TxID {
		t.Errorf("Expected remaining transaction to be tx2, got %s", pending[0].TxID)
	}
}

func TestTransactionWithData(t *testing.T) {
	data := []byte("some data")
	tx := NewTransaction(DataTx, "alice", "", 0, 1, 0, data)
	if tx.Type != DataTx {
		t.Errorf("Expected transaction type %d, got %d", DataTx, tx.Type)
	}
	if !bytes.Equal(tx.Data, data) {
		t.Errorf("Expected data %v, got %v", data, tx.Data)
	}
}

func TestTransactionExtraFields(t *testing.T) {
	tx := NewTransaction(TransferTx, "alice", "bob", 100, 1, 10, nil)
	tx.ExtraFields["custom"] = "value"
	data, err := tx.Serialize()
	if err != nil {
		t.Fatalf("Failed to serialize transaction: %v", err)
	}
	deserializedTx, err := DeserializeTransaction(data)
	if err != nil {
		t.Fatalf("Failed to deserialize transaction: %v", err)
	}
	if val, ok := deserializedTx.ExtraFields["custom"]; !ok || val != "value" {
		t.Errorf("Expected extra field 'custom' with value 'value', got %v", deserializedTx.ExtraFields)
	}
}

func TestTransactionSignWithoutFrom(t *testing.T) {
	tx := NewTransaction(TransferTx, "", "bob", 100, 1, 10, nil)
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	err = tx.Sign(keyPair.PrivateKey)
	if err != nil {
		t.Errorf("Expected no error when signing transaction without 'from', got %v", err)
	}
	if tx.Signature != nil {
		t.Error("Expected signature to be nil for transaction without 'from'")
	}
}

func TestTransactionVerifyWithoutFrom(t *testing.T) {
	tx := NewTransaction(TransferTx, "", "bob", 100, 1, 10, nil)
	verified, err := tx.Verify()
	if err != nil {
		t.Fatalf("Failed to verify transaction: %v", err)
	}
	if verified {
		t.Error("Expected verification to fail for transaction without 'from'")
	}
}

func TestTransactionVerifyWithInvalidSignature(t *testing.T) {
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	tx := NewTransaction(TransferTx, keyPair.GetAddress(), "bob", 100, 1, 10, nil)
	tx.Signature = []byte("invalid")
	verified, err := tx.Verify()
	if err != nil {
		t.Fatalf("Failed to verify transaction: %v", err)
	}
	if verified {
		t.Error("Expected verification to fail with invalid signature")
	}
}

func TestTransactionPoolAddAndRemove(t *testing.T) {
	pool := NewTransactionPool()
	kp, _ := crypto.GenerateKeyPair()
	tx := NewTransaction(TransferTx, kp.GetAddress(), "bob", 100, 1, 10, nil)
	tx.Sign(kp.PrivateKey)
	pool.Add(tx)
	if len(pool.pending) != 1 {
		t.Errorf("Expected 1 transaction in pool, got %d", len(pool.pending))
	}
	pool.Remove(tx.TxID)
	if len(pool.pending) != 0 {
		t.Errorf("Expected 0 transactions in pool after removal, got %d", len(pool.pending))
	}
}

func TestTransactionPoolGetPending(t *testing.T) {
	pool := NewTransactionPool()
	kpA, _ := crypto.GenerateKeyPair()
	kpB, _ := crypto.GenerateKeyPair()

	tx1 := NewTransaction(TransferTx, kpA.GetAddress(), "bob", 100, 1, 10, nil)
	tx2 := NewTransaction(TransferTx, kpB.GetAddress(), "dave", 200, 1, 20, nil)
	tx1.Sign(kpA.PrivateKey)
	tx2.Sign(kpB.PrivateKey)

	pool.Add(tx1)
	pool.Add(tx2)
	pending := pool.GetPending()
	if len(pending) != 2 {
		t.Errorf("Expected 2 pending transactions, got %d", len(pending))
	}
	foundTx1 := false
	foundTx2 := false
	for _, ptx := range pending {
		if ptx.TxID == tx1.TxID {
			foundTx1 = true
		}
		if ptx.TxID == tx2.TxID {
			foundTx2 = true
		}
	}
	if !foundTx1 || !foundTx2 {
		t.Error("Expected both transactions to be in the pending list")
	}
}
