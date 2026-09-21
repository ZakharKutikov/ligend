package protocol

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeDataFrame(t *testing.T) {
	payload := []byte("Hello, VPN tunnel!")
	f := NewDataFrame(payload, 42)

	encoded := f.Encode()
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decoded.Version != Version {
		t.Errorf("version: got %d, want %d", decoded.Version, Version)
	}
	if decoded.Type != TypeData {
		t.Errorf("type: got %d, want %d", decoded.Type, TypeData)
	}
	if decoded.Sequence != 42 {
		t.Errorf("sequence: got %d, want 42", decoded.Sequence)
	}
	if !bytes.Equal(decoded.Payload, payload) {
		t.Errorf("payload mismatch: got %x, want %x", decoded.Payload, payload)
	}
}

func TestEncodeDecodeWithPadding(t *testing.T) {
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	f := NewDataFrame(payload, 100)
	f.Flags |= FlagHasPadding

	encoded := f.Encode()
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode with padding failed: %v", err)
	}

	if !bytes.Equal(decoded.Payload, payload) {
		t.Errorf("payload mismatch: got %x, want %x", decoded.Payload, payload)
	}
	if decoded.Flags&FlagHasPadding == 0 {
		t.Error("HAS_PADDING flag not preserved")
	}
	// Encoded should be larger than header + payload due to padding
	if len(encoded) <= HeaderSize+len(payload) {
		t.Error("encoded frame should be larger due to padding")
	}
}

func TestControlFrame(t *testing.T) {
	data := []byte{10, 8, 0, 2} // IP: 10.8.0.2
	f := NewControlFrame(CtrlIPAssign, data, 5)

	encoded := f.Encode()
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode control frame failed: %v", err)
	}

	subtype, err := decoded.ControlSubtype()
	if err != nil {
		t.Fatalf("ControlSubtype failed: %v", err)
	}
	if subtype != CtrlIPAssign {
		t.Errorf("subtype: got %d, want %d", subtype, CtrlIPAssign)
	}

	ctrlData := decoded.ControlData()
	if !bytes.Equal(ctrlData, data) {
		t.Errorf("control data: got %x, want %x", ctrlData, data)
	}
}

func TestPaddingFrame(t *testing.T) {
	f := NewPaddingFrame(64)
	encoded := f.Encode()
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode padding frame failed: %v", err)
	}
	if decoded.Type != TypePadding {
		t.Errorf("type: got %d, want %d", decoded.Type, TypePadding)
	}
	if len(decoded.Payload) != 64 {
		t.Errorf("payload length: got %d, want 64", len(decoded.Payload))
	}
}

func TestKeepaliveFrame(t *testing.T) {
	f := NewKeepaliveFrame(999)
	encoded := f.Encode()
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode keepalive failed: %v", err)
	}
	if decoded.Type != TypeKeepalive {
		t.Errorf("type: got %d, want %d", decoded.Type, TypeKeepalive)
	}
	if decoded.Sequence != 999 {
		t.Errorf("sequence: got %d, want 999", decoded.Sequence)
	}
}

func TestDataFragFrame(t *testing.T) {
	fragPayload := []byte("fragment data here")
	f := NewDataFragFrame(0x1234, fragPayload, 7)

	encoded := f.Encode()
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode data frag failed: %v", err)
	}
	if decoded.Type != TypeDataFrag {
		t.Errorf("type: got %d, want %d", decoded.Type, TypeDataFrag)
	}
	// First 2 bytes should be fragment ID
	if len(decoded.Payload) < 2 {
		t.Fatal("payload too short for frag ID")
	}
	fragID := uint16(decoded.Payload[0])<<8 | uint16(decoded.Payload[1])
	if fragID != 0x1234 {
		t.Errorf("frag ID: got %x, want %x", fragID, 0x1234)
	}
}

func TestMigrateFrame(t *testing.T) {
	sessionID := []byte("session-abc-123")
	f := NewMigrateFrame(sessionID, 50)

	encoded := f.Encode()
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode migrate failed: %v", err)
	}
	if decoded.Type != TypeMigrate {
		t.Errorf("type: got %d, want %d", decoded.Type, TypeMigrate)
	}
	if !bytes.Equal(decoded.Payload, sessionID) {
		t.Errorf("session ID mismatch")
	}
}

func TestDecodeInvalidFrame(t *testing.T) {
	// Too short
	_, err := Decode([]byte{0x01, 0x02})
	if err == nil {
		t.Error("expected error for short frame")
	}

	// Wrong version
	bad := make([]byte, HeaderSize)
	bad[0] = 0x31 // version 3
	_, err = Decode(bad)
	if err == nil {
		t.Error("expected error for wrong version")
	}
}

func TestEncodeDecodeAllFlags(t *testing.T) {
	payload := []byte("test payload with flags")
	f := &Frame{
		Version:  Version,
		Type:     TypeData,
		Flags:    FlagCompressed | FlagUrgent | FlagEncrypted,
		Sequence: 12345,
		Payload:  payload,
	}

	encoded := f.Encode()
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode with flags failed: %v", err)
	}

	if decoded.Flags != (FlagCompressed | FlagUrgent | FlagEncrypted) {
		t.Errorf("flags: got %02x, want %02x", decoded.Flags, FlagCompressed|FlagUrgent|FlagEncrypted)
	}
	if !bytes.Equal(decoded.Payload, payload) {
		t.Error("payload mismatch with flags")
	}
}

func TestEmptyPayload(t *testing.T) {
	f := NewKeepaliveFrame(0)
	encoded := f.Encode()
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode empty payload failed: %v", err)
	}
	if len(decoded.Payload) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(decoded.Payload))
	}
}

func TestLargePayload(t *testing.T) {
	payload := make([]byte, 1500) // MTU-size packet
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	f := NewDataFrame(payload, 99999)

	encoded := f.Encode()
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode large payload failed: %v", err)
	}
	if !bytes.Equal(decoded.Payload, payload) {
		t.Error("large payload mismatch")
	}
}

func BenchmarkEncode(b *testing.B) {
	payload := make([]byte, 1280)
	f := NewDataFrame(payload, 0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Sequence = uint32(i)
		_ = f.Encode()
	}
}

func BenchmarkDecode(b *testing.B) {
	payload := make([]byte, 1280)
	f := NewDataFrame(payload, 0)
	encoded := f.Encode()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decode(encoded)
	}
}
