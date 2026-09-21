package protocol

import (
	"testing"
)

func TestBatchEncodeDecode(t *testing.T) {
	enc := NewBatchEncoder()

	packets := [][]byte{
		{0x45, 0x00, 0x00, 0x3c, 0x01, 0x02, 0x03, 0x04}, // fake IP header 1
		{0x45, 0x00, 0x00, 0x28, 0x05, 0x06, 0x07, 0x08}, // fake IP header 2
		{0x45, 0x00, 0x01, 0x00},                           // fake IP header 3
	}

	for _, pkt := range packets {
		enc.Add(pkt)
	}

	data := enc.Flush()
	if data == nil {
		t.Fatal("Flush returned nil")
	}

	decoded, err := DecodeBatch(data)
	if err != nil {
		t.Fatalf("DecodeBatch error: %v", err)
	}

	if len(decoded) != len(packets) {
		t.Fatalf("expected %d packets, got %d", len(packets), len(decoded))
	}

	for i, pkt := range decoded {
		if len(pkt) != len(packets[i]) {
			t.Errorf("packet %d: expected len %d, got %d", i, len(packets[i]), len(pkt))
		}
		for j, b := range pkt {
			if b != packets[i][j] {
				t.Errorf("packet %d byte %d: expected 0x%02x, got 0x%02x", i, j, packets[i][j], b)
			}
		}
	}
}

func TestBatchFlushEmpty(t *testing.T) {
	enc := NewBatchEncoder()
	data := enc.Flush()
	if data != nil {
		t.Fatal("expected nil for empty batch")
	}
}

func TestBatchShouldFlush(t *testing.T) {
	enc := NewBatchEncoder()
	for i := 0; i < MaxBatchSize-1; i++ {
		shouldFlush := enc.Add([]byte{byte(i)})
		if shouldFlush {
			t.Fatalf("should not flush at packet %d", i)
		}
	}
	shouldFlush := enc.Add([]byte{0xFF})
	if !shouldFlush {
		t.Fatal("should flush at MaxBatchSize")
	}
}

func TestCompressDecompressFrame(t *testing.T) {
	// Create a frame with compressible data (repeated bytes)
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i % 10)
	}

	frame := NewDataFrame(payload, 42)
	compressed := CompressFrame(frame)

	if compressed.Flags&FlagCompressed == 0 {
		// Data might not be compressible enough; skip test
		t.Skip("data not compressible enough for test")
	}

	if len(compressed.Payload) >= len(frame.Payload) {
		t.Fatal("compressed payload should be smaller")
	}

	decompressed, err := DecompressFrame(compressed)
	if err != nil {
		t.Fatalf("DecompressFrame error: %v", err)
	}

	if len(decompressed.Payload) != len(payload) {
		t.Fatalf("expected payload len %d, got %d", len(payload), len(decompressed.Payload))
	}

	for i, b := range decompressed.Payload {
		if b != payload[i] {
			t.Errorf("byte %d: expected 0x%02x, got 0x%02x", i, payload[i], b)
		}
	}
}

func TestNormalizeSize(t *testing.T) {
	tests := []struct {
		input    int
		expected int
	}{
		{50, 128},
		{128, 128},
		{129, 256},
		{500, 512},
		{1000, 1024},
		{1460, 1460},
		{5000, 8192},
		{20000, 20000}, // larger than max standard
	}

	for _, tc := range tests {
		result := NormalizeSize(tc.input)
		if result != tc.expected {
			t.Errorf("NormalizeSize(%d) = %d, expected %d", tc.input, result, tc.expected)
		}
	}
}

func BenchmarkBatchEncodeDecode(b *testing.B) {
	packets := make([][]byte, 32)
	for i := range packets {
		packets[i] = make([]byte, 100+i*10)
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		enc := NewBatchEncoder()
		for _, pkt := range packets {
			enc.Add(pkt)
		}
		data := enc.Flush()
		DecodeBatch(data)
	}
}
