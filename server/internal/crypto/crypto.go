package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/pierrec/lz4/v4"
)

// GenerateSessionKey creates a random 32-byte key for ChaCha20-Poly1305.
func GenerateSessionKey() ([]byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	return key, nil
}

// GenerateKey creates a random 32-byte shared secret key.
func GenerateKey() ([]byte, error) {
	return GenerateSessionKey()
}

// EncryptPayload encrypts data using ChaCha20-Poly1305 AEAD.
// Returns: nonce (12 bytes) || ciphertext (len(plaintext) + 16 bytes tag).
func EncryptPayload(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// nonce || ciphertext
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptPayload decrypts data encrypted by EncryptPayload.
// Input format: nonce (12 bytes) || ciphertext.
func DecryptPayload(key, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("data too short for nonce")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// CompressLZ4 compresses data using LZ4.
func CompressLZ4(data []byte) ([]byte, error) {
	maxSize := lz4.CompressBlockBound(len(data))
	compressed := make([]byte, maxSize)

	var c lz4.Compressor
	n, err := c.CompressBlock(data, compressed)
	if err != nil {
		return nil, fmt.Errorf("lz4 compress: %w", err)
	}
	if n == 0 {
		// Data is incompressible, return original
		return data, nil
	}

	return compressed[:n], nil
}

// DecompressLZ4 decompresses LZ4-compressed data.
// maxOutputSize is the maximum expected decompressed size.
func DecompressLZ4(compressed []byte, maxOutputSize int) ([]byte, error) {
	decompressed := make([]byte, maxOutputSize)

	n, err := lz4.UncompressBlock(compressed, decompressed)
	if err != nil {
		return nil, fmt.Errorf("lz4 decompress: %w", err)
	}

	return decompressed[:n], nil
}
