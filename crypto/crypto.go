package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
)

// KeyPair represents a public/private key pair
type KeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

// GenerateKeyPair creates a new public/private key pair
func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// GetAddress returns the address (hex encoded public key hash)
func (kp *KeyPair) GetAddress() string {
	pubKeyBytes := elliptic.Marshal(elliptic.P256(), kp.PublicKey.X, kp.PublicKey.Y)
	hash := sha256.Sum256(pubKeyBytes)
	return hex.EncodeToString(hash[:])
}

// SignData signs data with the private key
func (kp *KeyPair) SignData(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, kp.PrivateKey, hash[:])
	if err != nil {
		return nil, err
	}

	signature := append(r.Bytes(), s.Bytes()...)
	return signature, nil
}

// VerifySignature verifies a signature against a public key
func VerifySignature(pubKey *ecdsa.PublicKey, data, signature []byte) bool {
	if len(signature) != 64 {
		return false
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	hash := sha256.Sum256(data)
	return ecdsa.Verify(pubKey, hash[:], r, s)
}

// PublicKeyFromAddress converts an address back to a public key
// Note: Store public keys, lookup the public key from a registry,
func PublicKeyFromAddress(address string) (*ecdsa.PublicKey, error) {
	return nil, errors.New("not implemented - requires key storage")
}

// SavePrivateKey exports a private key to PEM format
func SavePrivateKey(key *ecdsa.PrivateKey) (string, error) {
	x509Encoded, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509Encoded,
	}
	data := pem.EncodeToMemory(pemBlock)
	return string(data), nil
}

// LoadPrivateKey imports a private key from PEM format
func LoadPrivateKey(pemEncoded string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemEncoded))
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}

	x509Encoded := block.Bytes
	privateKey, err := x509.ParseECPrivateKey(x509Encoded)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}
