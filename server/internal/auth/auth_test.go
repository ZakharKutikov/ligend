package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"testing"
	"time"
)

func TestAuthValidateSuccess(t *testing.T) {
	key := []byte("01234567890123456789012345678901") // 32 bytes
	auth := NewAuthenticator(key)

	now := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "a1b2c3d4e5f60718"

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(now + nonce))
	requestID := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	err := auth.Validate(requestID, now, nonce)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}
}

func TestAuthReplayProtection(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	auth := NewAuthenticator(key)

	now := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "deadbeefcafebabe"

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(now + nonce))
	requestID := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	// First attempt should succeed
	if err := auth.Validate(requestID, now, nonce); err != nil {
		t.Fatalf("First validation should succeed: %v", err)
	}

	// Replay with the same nonce should fail immediately
	if err := auth.Validate(requestID, now, nonce); err == nil {
		t.Fatal("Replay validation should have failed")
	}
}

func TestAuthTimestampDrift(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	auth := NewAuthenticator(key)

	// 40 seconds in the past (> 30s drift)
	oldTime := strconv.FormatInt(time.Now().Add(-40*time.Second).Unix(), 10)
	nonce := "1122334455667788"

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(oldTime + nonce))
	requestID := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if err := auth.Validate(requestID, oldTime, nonce); err == nil {
		t.Fatal("Validation with expired timestamp should have failed")
	}
}

func TestAuthInvalidHMAC(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	auth := NewAuthenticator(key)

	now := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "9988776655443322"
	fakeRequestID := base64.StdEncoding.EncodeToString([]byte("invalid_hmac_signature_data_here!"))

	if err := auth.Validate(fakeRequestID, now, nonce); err == nil {
		t.Fatal("Validation with invalid HMAC should have failed")
	}
}
