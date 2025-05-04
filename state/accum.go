package state

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"math/big"
	"sync"
)

// CryptoAccumulator implements compact state representation
type CryptoAccumulator struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	value      *big.Int
	elements   map[string]bool
	lock       sync.RWMutex
}

// // ZKProofSystem handles zero-knowledge proofs for state
// type ZKProofSystem struct {
// 	curve      elliptic.Curve    // Elliptic curve for commitments
// 	g          *ecdsa.PublicKey  // Generator point
// 	h          *ecdsa.PublicKey  // Blinding factor generator
// 	privateKey *ecdsa.PrivateKey // System private key
// }

// // PedersenCommitment represents a commitment in the form g^v * h^r
// type PedersenCommitment struct {
// 	C []byte   // Commitment value (point on curve)
// 	V []byte   // Value being committed to
// 	R *big.Int // Random blinding factor
// }

// // ZKStateProof contains zero-knowledge proof elements
// type ZKStateProof struct {
// 	Commitment []byte
// 	Challenge  []byte
// 	Response   *big.Int
// 	Key        string
// 	StateRoot  []byte
// }

// func newZKProofSystem() *ZKProofSystem {
// 	curve := elliptic.P256()
// 	privateKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
// 	g := &ecdsa.PublicKey{
// 		Curve: curve,
// 		X:     new(big.Int).Set(privateKey.PublicKey.X),
// 		Y:     new(big.Int).Set(privateKey.PublicKey.Y),
// 	}

// 	// Create h as a different point
// 	k, _ := rand.Int(rand.Reader, curve.Params().N)
// 	hX, hY := curve.ScalarBaseMult(k.Bytes())
// 	h := &ecdsa.PublicKey{
// 		Curve: curve,
// 		X:     hX,
// 		Y:     hY,
// 	}

// 	return &ZKProofSystem{
// 		curve:      curve,
// 		g:          g,
// 		h:          h,
// 		privateKey: privateKey,
// 	}
// }

// updateAccumulator updates the cryptographic accumulator
func (s *EnhancedState) updateAccumulator() {
	// Reset accumulator
	s.accumulator.reset()

	// Add each state element to accumulator
	for addr := range s.accounts {
		s.accumulator.add("acct:" + addr)
	}

	for addr := range s.nonces {
		s.accumulator.add("nonce:" + addr)
	}

	for key := range s.data {
		s.accumulator.add("data:" + key)
	}
}

func newCryptoAccumulator() *CryptoAccumulator {
	// Generate RSA key for accumulator
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("Failed to generate RSA key for accumulator")
	}

	return &CryptoAccumulator{
		privateKey: key,
		publicKey:  &key.PublicKey,
		value:      big.NewInt(1),
		elements:   make(map[string]bool),
	}
}

func (ca *CryptoAccumulator) add(element string) {
	ca.lock.Lock()
	defer ca.lock.Unlock()

	// Skip if already in accumulator
	if ca.elements[element] {
		return
	}

	// Update accumulator value: value^prime mod N
	prime := hashToPrime(element)
	ca.value.Exp(ca.value, prime, ca.publicKey.N)
	ca.elements[element] = true
}

func (ca *CryptoAccumulator) verify(element string, proof *big.Int) bool {
	ca.lock.RLock()
	defer ca.lock.RUnlock()

	// Hash element to prime
	prime := hashToPrime(element)

	// Verify: proof^prime mod N == value
	result := new(big.Int).Exp(proof, prime, ca.publicKey.N)
	return result.Cmp(ca.value) == 0
}

func (ca *CryptoAccumulator) reset() {
	ca.lock.Lock()
	defer ca.lock.Unlock()

	ca.value = big.NewInt(1)
	ca.elements = make(map[string]bool)
}

func compress(data []byte) ([]byte, error) {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)

	if _, err := w.Write(data); err != nil {
		return nil, err
	}

	if err := w.Close(); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func decompress(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()

	return io.ReadAll(r)
}

// func (zk *ZKProofSystem) generateProof(key string, value []byte, stateRoot []byte) (*ZKStateProof, error) {
// 	// Create a Pedersen commitment to the value
// 	valueInt := new(big.Int).SetBytes(value)
// 	r, err := rand.Int(rand.Reader, zk.curve.Params().N)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Compute commitment C = g^value * h^r
// 	vX, vY := zk.curve.ScalarMult(zk.g.X, zk.g.Y, valueInt.Bytes())
// 	rX, rY := zk.curve.ScalarMult(zk.h.X, zk.h.Y, r.Bytes())
// 	cX, cY := zk.curve.Add(vX, vY, rX, rY)

// 	commitment := elliptic.Marshal(zk.curve, cX, cY)
// 	w, _ := rand.Int(rand.Reader, zk.curve.Params().N)

// 	// Compute witness commitment A = g^w * h^0
// 	aX, aY := zk.curve.ScalarMult(zk.g.X, zk.g.Y, w.Bytes())
// 	witnessCommitment := elliptic.Marshal(zk.curve, aX, aY)

// 	// Create challenge e = H(commitment || witnessCommitment || key || stateRoot)
// 	challengeInput := append(commitment, witnessCommitment...)
// 	challengeInput = append(challengeInput, []byte(key)...)
// 	challengeInput = append(challengeInput, stateRoot...)
// 	challengeHash := sha256.Sum256(challengeInput)
// 	e := new(big.Int).SetBytes(challengeHash[:])
// 	e.Mod(e, zk.curve.Params().N)

// 	// Compute response z = w + e * value (in Z_q)
// 	valueTimesE := new(big.Int).Mul(valueInt, e)
// 	z := new(big.Int).Add(w, valueTimesE)
// 	z.Mod(z, zk.curve.Params().N)

// 	return &ZKStateProof{
// 		Commitment: commitment,
// 		Challenge:  challengeHash[:],
// 		Response:   z,
// 		Key:        key,
// 		StateRoot:  stateRoot,
// 	}, nil
// }

// func (zk *ZKProofSystem) verifyProof(proof *ZKStateProof) bool {
// 	e := new(big.Int).SetBytes(proof.Challenge)
// 	cX, cY := elliptic.Unmarshal(zk.curve, proof.Commitment)
// 	if cX == nil {
// 		return false
// 	}

// 	// Compute g^z and C^e
// 	zX, zY := zk.curve.ScalarBaseMult(proof.Response.Bytes())
// 	eX, eY := zk.curve.ScalarMult(cX, cY, e.Bytes())

// 	// For verification, we need to compute A = g^z * (C^e)^-1
// 	negEY := new(big.Int).Sub(zk.curve.Params().P, eY)

// 	// Compute A = g^z - C^e
// 	aX, aY := zk.curve.Add(zX, zY, eX, negEY)

// 	// Reconstruct challenge
// 	witnessCommitment := elliptic.Marshal(zk.curve, aX, aY)
// 	challengeInput := append(proof.Commitment, witnessCommitment...)
// 	challengeInput = append(challengeInput, []byte(proof.Key)...)
// 	challengeInput = append(challengeInput, proof.StateRoot...)
// 	challengeHash := sha256.Sum256(challengeInput)

// 	// Verify challenge matches
// 	return bytes.Equal(challengeHash[:], proof.Challenge)
// }
