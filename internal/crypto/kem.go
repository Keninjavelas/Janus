// internal/crypto/kem.go
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
    Algorithm    string // e.g., "ML-KEM-768"
    PublicKey    string // hex-encoded (truncated for logs)
    Ciphertext   string // hex-encoded (truncated)
    SharedSecret string // hex-encoded (truncated)
    FullPublic   []byte // full raw bytes (for actual use)
    FullCipher   []byte
    FullSecret   []byte
    KeySize      int // bytes
}

// kemPool reuses KEM objects to reduce allocations during high throughput.
var kemPool = sync.Pool{
    New: func() interface{} {
        return &oqs.KEM{}
    },
}

// Encapsulate performs a KEM encapsulation for the given algorithm name.
// Supported names: "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"
// Returns a KEMResult or an error.
func Encapsulate(algName string) (*KEMResult, error) {
    // Map to liboqs internal naming
    liboqsAlg := mapToLiboqs(algName)
    if liboqsAlg == "" {
        return nil, fmt.Errorf("unsupported algorithm: %s", algName)
    }

    // Get KEM object from pool
    kem := kemPool.Get().(*oqs.KEM)
    defer kemPool.Put(kem)

    // Initialize with the algorithm
    if err := kem.Init(liboqsAlg, nil); err != nil {
        return nil, fmt.Errorf("kem init failed: %w", err)
    }
    defer kem.Clean() // securely zero out sensitive data

    // Generate keypair (public key)
    pubKey, err := kem.GenerateKeyPair()
    if err != nil {
        return nil, fmt.Errorf("keypair generation failed: %w", err)
    }

    // Encapsulate – produce ciphertext and shared secret
    ciphertext, sharedSecret, err := kem.EncapSecret(pubKey)
    if err != nil {
        return nil, fmt.Errorf("encapsulation failed: %w", err)
    }

    // Build result
    result := &KEMResult{
        Algorithm:    algName,
        PublicKey:    hex.EncodeToString(pubKey),
        Ciphertext:   hex.EncodeToString(ciphertext),
        SharedSecret: hex.EncodeToString(sharedSecret),
        FullPublic:   pubKey,
        FullCipher:   ciphertext,
        FullSecret:   sharedSecret,
        KeySize:      len(sharedSecret),
    }
    return result, nil
}

// mapToLiboqs converts Janus algorithm names to liboqs names.
func mapToLiboqs(alg string) string {
    switch alg {
    case "ML-KEM-512":
        return "Kyber512"
    case "ML-KEM-768":
        return "Kyber768"
    case "ML-KEM-1024":
        return "Kyber1024"
    default:
        return ""
    }
}

// IsSupported checks if the algorithm is available in liboqs.
func IsSupported(alg string) bool {
    return mapToLiboqs(alg) != ""
}

// GenerateRandomSecret is a utility that generates a random shared secret (fallback).
func GenerateRandomSecret(size int) ([]byte, error) {
    secret := make([]byte, size)
    _, err := rand.Read(secret)
    return secret, err
}
