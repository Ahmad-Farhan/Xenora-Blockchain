package crypto

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	if keyPair.PrivateKey == nil {
		t.Error("Private key is nil")
	}
	if keyPair.PublicKey == nil {
		t.Error("Public key is nil")
	}
	if keyPair.PublicKey != &keyPair.PrivateKey.PublicKey {
		t.Error("Public key does not match private key's public key")
	}
	// Check if public key is stored
	pubKey, err := PublicKeyFromAddress(keyPair.GetAddress())
	if err != nil {
		t.Errorf("Failed to retrieve stored public key: %v", err)
	}
	if pubKey != keyPair.PublicKey {
		t.Error("Stored public key does not match generated public key")
	}
}

func TestGetAddress(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	address := keyPair.GetAddress()
	if address == "" {
		t.Error("Generated address is empty")
	}
	// Verify address format (SHA256 hash encoded as hex)
	pubKeyBytes := elliptic.Marshal(keyPair.PublicKey.Curve, keyPair.PublicKey.X, keyPair.PublicKey.Y)
	hash := sha256.Sum256(pubKeyBytes)
	expectedAddress := hex.EncodeToString(hash[:])
	if address != expectedAddress {
		t.Errorf("Generated address %s does not match expected %s", address, expectedAddress)
	}
}

func TestSignData(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	data := []byte("test data")
	signature, err := keyPair.SignData(data)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}
	if len(signature) != 64 {
		t.Errorf("Expected signature length 64, got %d", len(signature))
	}
	// Verify signature
	verified := VerifySignature(keyPair.PublicKey, data, signature)
	if !verified {
		t.Error("Signature verification failed")
	}
}

func TestSignDataWithPrivateKey(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	data := []byte("test data")
	signature, err := SignData(keyPair.PrivateKey, data)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}
	if len(signature) != 64 {
		t.Errorf("Expected signature length 64, got %d", len(signature))
	}
	// Verify signature
	verified := VerifySignature(keyPair.PublicKey, data, signature)
	if !verified {
		t.Error("Signature verification failed")
	}
}

func TestVerifySignature(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	data := []byte("test data")
	signature, err := keyPair.SignData(data)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}
	// Valid signature
	verified := VerifySignature(keyPair.PublicKey, data, signature)
	if !verified {
		t.Error("Expected valid signature to verify")
	}
	// Invalid data
	invalidData := []byte("different data")
	verified = VerifySignature(keyPair.PublicKey, invalidData, signature)
	if verified {
		t.Error("Expected verification to fail with invalid data")
	}
	// Invalid signature (wrong length)
	verified = VerifySignature(keyPair.PublicKey, data, []byte("short"))
	if verified {
		t.Error("Expected verification to fail with invalid signature length")
	}
	// Invalid signature (corrupted)
	corruptedSignature := make([]byte, 64)
	copy(corruptedSignature, signature)
	corruptedSignature[0] ^= 0xFF
	verified = VerifySignature(keyPair.PublicKey, data, corruptedSignature)
	if verified {
		t.Error("Expected verification to fail with corrupted signature")
	}
}

func TestPublicKeyFromAddress(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	address := keyPair.GetAddress()
	pubKey, err := PublicKeyFromAddress(address)
	if err != nil {
		t.Errorf("Failed to retrieve public key: %v", err)
	}
	if pubKey.X.Cmp(keyPair.PublicKey.X) != 0 || pubKey.Y.Cmp(keyPair.PublicKey.Y) != 0 {
		t.Error("Retrieved public key does not match original")
	}
	// Non-existent address
	_, err = PublicKeyFromAddress("invalid_address")
	if err == nil {
		t.Error("Expected error for non-existent address")
	}
}

func TestStorePublicKey(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	newAddress := "custom_address"
	StorePublicKey(newAddress, keyPair.PublicKey)
	pubKey, err := PublicKeyFromAddress(newAddress)
	if err != nil {
		t.Errorf("Failed to retrieve stored public key: %v", err)
	}
	if pubKey != keyPair.PublicKey {
		t.Error("Stored public key does not match original")
	}
}

func TestSaveAndLoadPrivateKey(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	pemStr, err := SavePrivateKey(keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to save private key: %v", err)
	}
	loadedKey, err := LoadPrivateKey(pemStr)
	if err != nil {
		t.Fatalf("Failed to load private key: %v", err)
	}
	if loadedKey.D.Cmp(keyPair.PrivateKey.D) != 0 {
		t.Error("Loaded private key does not match original")
	}
	// Test invalid PEM
	_, err = LoadPrivateKey("invalid PEM data")
	if err == nil {
		t.Error("Expected error for invalid PEM data")
	}
}

func TestSaveAndLoadPublicKey(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	pemStr, err := SavePublicKey(keyPair.PublicKey)
	if err != nil {
		t.Fatalf("Failed to save public key: %v", err)
	}
	loadedKey, err := LoadPublicKey(pemStr)
	if err != nil {
		t.Fatalf("Failed to load public key: %v", err)
	}
	if loadedKey.X.Cmp(keyPair.PublicKey.X) != 0 || loadedKey.Y.Cmp(keyPair.PublicKey.Y) != 0 {
		t.Error("Loaded public key does not match original")
	}
	// Test invalid PEM
	_, err = LoadPublicKey("invalid PEM data")
	if err == nil {
		t.Error("Expected error for invalid PEM data")
	}
}

func TestSignDataDeterminism(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	data := []byte("test data")
	// Sign twice and compare
	sig1, err := keyPair.SignData(data)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}
	sig2, err := keyPair.SignData(data)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}
	// ECDSA signatures are non-deterministic due to random k
	if len(sig1) != len(sig2) {
		t.Errorf("Signature lengths differ: %d vs %d", len(sig1), len(sig2))
	}
	// Verify both signatures
	if !VerifySignature(keyPair.PublicKey, data, sig1) {
		t.Error("First signature verification failed")
	}
	if !VerifySignature(keyPair.PublicKey, data, sig2) {
		t.Error("Second signature verification failed")
	}
}
