//go:build !liboqs

package crypto

import (
	"crypto/rand"
	"fmt"
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

func Encapsulate(algName string) (*KEMResult, error) {
	return nil, fmt.Errorf("liboqs support is not enabled; rebuild with -tags=liboqs")
}

func IsSupported(string) bool {
	return false
}

func GenerateRandomSecret(size int) ([]byte, error) {
	secret := make([]byte, size)
	_, err := rand.Read(secret)
	return secret, err
}
