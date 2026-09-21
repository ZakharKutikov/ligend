package protocol

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"

	lcrypto "github.com/ligend/ligend-server/internal/crypto"
)

// BatchFrame groups multiple IP packets into a single WebSocket message
// for reduced syscall overhead and improved throughput.
//
// Wire format:
//
//	┌──────────────┬─────────────────────────────┐
//	│ Count (2B)   │ Entries...                   │
//	│ big-endian   │                               │
//	├──────────────┤                               │
//	│ Entry 1:     │                               │
//	│  Len (2B)    │ Payload (Len bytes)           │
//	│ Entry 2:     │                               │
//	│  Len (2B)    │ Payload (Len bytes)           │
//	│ ...          │                               │
//	└──────────────┴─────────────────────────────┘
//
// The batch frame is wrapped inside a standard Ligend Frame with Type=TypeData
// and Flags|FlagBatchMode set.

const (
	// FlagBatchMode indicates the DATA payload contains multiple packets.
	FlagBatchMode = 0x10

	// MaxBatchSize is the maximum number of packets in a single batch.
	MaxBatchSize = 64

	// MaxBatchBytes is the maximum total bytes in a batch payload.
	MaxBatchBytes = 60000

	// BatchFlushInterval is how long to wait before flushing a partial batch.
	BatchFlushInterval = 2 * time.Millisecond
)

// BatchEncoder accumulates packets and produces batched frames.
type BatchEncoder struct {
	packets [][]byte
	size    int
}

// NewBatchEncoder creates a new batch encoder.
func NewBatchEncoder() *BatchEncoder {
	return &BatchEncoder{
		packets: make([][]byte, 0, MaxBatchSize),
	}
}

// Add adds a packet to the batch. Returns true if the batch should be flushed.
func (b *BatchEncoder) Add(packet []byte) bool {
	b.packets = append(b.packets, packet)
	b.size += len(packet) + 2 // 2 bytes for length prefix
	return len(b.packets) >= MaxBatchSize || b.size >= MaxBatchBytes
}

// Flush encodes all accumulated packets into a single batch payload and resets.
// Returns nil if no packets are accumulated.
func (b *BatchEncoder) Flush() []byte {
	if len(b.packets) == 0 {
		return nil
	}

	// Calculate total size: 2 (count) + sum(2 + len(pkt))
	total := 2 + b.size
	buf := make([]byte, total)
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(b.packets)))

	offset := 2
	for _, pkt := range b.packets {
		binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(pkt)))
		copy(buf[offset+2:], pkt)
		offset += 2 + len(pkt)
	}

	// Reset
	b.packets = b.packets[:0]
	b.size = 0

	return buf[:offset]
}

// Count returns the number of packets in the batch.
func (b *BatchEncoder) Count() int {
	return len(b.packets)
}

// Reset clears the batch.
func (b *BatchEncoder) Reset() {
	b.packets = b.packets[:0]
	b.size = 0
}

// DecodeBatch extracts individual packets from a batch payload.
func DecodeBatch(data []byte) ([][]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("batch too short")
	}

	count := int(binary.BigEndian.Uint16(data[0:2]))
	if count == 0 || count > MaxBatchSize {
		return nil, fmt.Errorf("invalid batch count: %d", count)
	}

	packets := make([][]byte, 0, count)
	offset := 2

	for i := 0; i < count; i++ {
		if offset+2 > len(data) {
			return nil, fmt.Errorf("batch truncated at packet %d/%d", i+1, count)
		}
		pktLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2

		if offset+pktLen > len(data) {
			return nil, fmt.Errorf("batch packet %d overflows: need %d bytes, have %d", i+1, pktLen, len(data)-offset)
		}
		pkt := make([]byte, pktLen)
		copy(pkt, data[offset:offset+pktLen])
		packets = append(packets, pkt)
		offset += pktLen
	}

	return packets, nil
}

// CompressFrame compresses the frame payload using LZ4 if beneficial.
// Returns the original frame if compression doesn't reduce size enough.
func CompressFrame(frame *Frame) *Frame {
	if len(frame.Payload) < 256 {
		return frame // Too small to benefit from compression
	}

	compressed, err := lcrypto.CompressLZ4(frame.Payload)
	if err != nil {
		return frame
	}

	// Only use compression if it saves at least 10%
	if len(compressed) >= len(frame.Payload)*9/10 {
		return frame
	}

	// Prepend original size (4 bytes big-endian) for decompression
	result := make([]byte, 4+len(compressed))
	binary.BigEndian.PutUint32(result[0:4], uint32(len(frame.Payload)))
	copy(result[4:], compressed)

	return &Frame{
		Version:  frame.Version,
		Type:     frame.Type,
		Flags:    frame.Flags | FlagCompressed,
		Sequence: frame.Sequence,
		Payload:  result,
	}
}

// DecompressFrame decompresses an LZ4-compressed frame payload.
func DecompressFrame(frame *Frame) (*Frame, error) {
	if frame.Flags&FlagCompressed == 0 {
		return frame, nil
	}

	if len(frame.Payload) < 4 {
		return nil, fmt.Errorf("compressed frame too short")
	}

	origSize := int(binary.BigEndian.Uint32(frame.Payload[0:4]))
	if origSize > 65535 {
		return nil, fmt.Errorf("decompressed size too large: %d", origSize)
	}

	decompressed, err := lcrypto.DecompressLZ4(frame.Payload[4:], origSize)
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}

	return &Frame{
		Version:  frame.Version,
		Type:     frame.Type,
		Flags:    frame.Flags &^ FlagCompressed, // Clear compressed flag
		Sequence: frame.Sequence,
		Payload:  decompressed,
	}, nil
}

// --- Anti-DPI: Traffic Shaping ---

// NormalizePacketSize pads data to standard HTTP chunk sizes to avoid
// characteristic VPN packet-length fingerprints.
// Common browser chunk sizes: 128, 256, 512, 1024, 1460, 2048, 4096, 8192
var standardSizes = []int{128, 256, 512, 1024, 1460, 2048, 4096, 8192, 16384}

// NormalizeSize returns the next standard size >= the input size.
// If size > max standard, returns the input as-is.
func NormalizeSize(size int) int {
	for _, s := range standardSizes {
		if size <= s {
			return s
		}
	}
	return size
}

// AddJitter introduces a random microsecond delay (0 to maxJitterUs)
// to break timing correlation analysis by DPI.
func AddJitter(maxJitterUs int) {
	if maxJitterUs <= 0 {
		return
	}
	jitter := rand.Intn(maxJitterUs)
	time.Sleep(time.Duration(jitter) * time.Microsecond)
}

// RandomKeepaliveInterval returns a random duration between min and max seconds.
func RandomKeepaliveInterval(minSec, maxSec int) time.Duration {
	if maxSec <= minSec {
		return time.Duration(minSec) * time.Second
	}
	return time.Duration(minSec+rand.Intn(maxSec-minSec+1)) * time.Second
}
