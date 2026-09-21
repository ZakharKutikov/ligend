package crypto

import (
	"bytes"
	"testing"
)

func TestChaCha20EncryptionDecryption(t *testing.T) {
	key, err := GenerateSessionKey()
	if err != nil {
		t.Fatalf("GenerateSessionKey failed: %v", err)
	}

	plaintext := []byte("Sensitive IP Packet Payload for Ligend Tunnel")

	ciphertext, err := EncryptPayload(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptPayload failed: %v", err)
	}

	decrypted, err := DecryptPayload(key, ciphertext)
	if err != nil {
		t.Fatalf("DecryptPayload failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Decrypted text mismatch: got %s, want %s", string(decrypted), string(plaintext))
	}
}

func TestLZ4CompressionDecompression(t *testing.T) {
	data := bytes.Repeat([]byte("LigendStealthVPNProtocol2026"), 50)

	compressed, err := CompressLZ4(data)
	if err != nil {
		t.Fatalf("CompressLZ4 failed: %v", err)
	}

	if len(compressed) >= len(data) {
		t.Fatalf("Compression did not reduce size: compressed %d, original %d", len(compressed), len(data))
	}

	decompressed, err := DecompressLZ4(compressed, len(data))
	if err != nil {
		t.Fatalf("DecompressLZ4 failed: %v", err)
	}

	if !bytes.Equal(decompressed, data) {
		t.Fatal("Decompressed data does not match original data")
	}
}
