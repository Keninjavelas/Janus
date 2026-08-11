//go:build liboqs

package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// KEMResult holds the cryptographic artifacts from a KEM operation.
type KEMResult struct {
	Algorithm    string
	PublicKey    string
	Ciphertext   string
	SharedSecret string
	FullPublic   []byte
	FullCipher   []byte
	FullSecret   []byte
	KeySize      int
}

var kemPool = sync.Pool{
	New: func() interface{} {
		return &oqs.KEM{}
	},
}

// Encapsulate performs a KEM encapsulation using standardized Janus names.
// The current liboqs-go binding still expects legacy Kyber-family identifiers
// internally, so Janus translates them here.
func Encapsulate(algName string) (*KEMResult, error) {
	liboqsAlg := mapToLiboqs(algName)
	if liboqsAlg == "" {
		return nil, fmt.Errorf("unsupported algorithm: %s", algName)
	}

	kem := kemPool.Get().(*oqs.KEM)
	defer kemPool.Put(kem)

	if err := kem.Init(liboqsAlg, nil); err != nil {
		return nil, fmt.Errorf("kem init failed: %w", err)
	}
	defer kem.Clean()

	pubKey, err := kem.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("keypair generation failed: %w", err)
	}

	ciphertext, sharedSecret, err := kem.EncapSecret(pubKey)
	if err != nil {
		return nil, fmt.Errorf("encapsulation failed: %w", err)
	}

	return &KEMResult{
		Algorithm:    algName,
		PublicKey:    hex.EncodeToString(pubKey),
		Ciphertext:   hex.EncodeToString(ciphertext),
		SharedSecret: hex.EncodeToString(sharedSecret),
		FullPublic:   pubKey,
		FullCipher:   ciphertext,
		FullSecret:   sharedSecret,
		KeySize:      len(sharedSecret),
	}, nil
}

// mapToLiboqs converts Janus names to the identifiers expected by liboqs-go.
// Legacy Kyber aliases remain accepted for compatibility with older inputs.
func mapToLiboqs(alg string) string {
	switch alg {
	case "ML-KEM-512", "Kyber512":
		return "Kyber512"
	case "ML-KEM-768", "Kyber768":
		return "Kyber768"
	case "ML-KEM-1024", "Kyber1024":
		return "Kyber1024"
	default:
		return ""
	}
}

func IsSupported(alg string) bool {
	return mapToLiboqs(alg) != ""
}

func GenerateRandomSecret(size int) ([]byte, error) {
	secret := make([]byte, size)
	_, err := rand.Read(secret)
	return secret, err
}
