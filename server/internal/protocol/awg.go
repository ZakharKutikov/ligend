package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	lcrypto "github.com/ligend/ligend-server/internal/crypto"
)

// AWGPacketType defines message types matching AmneziaWG 3.1
const (
	AWGTypeJunk      = 0x00
	AWGTypeInit      = 0x01
	AWGTypeResponse  = 0x02
	AWGTypeCookie    = 0x03
	AWGTypeTransport = 0x04
)

// AWGParams stores AmneziaWG 3.1 parameters
type AWGParams struct {
	Jc   int    // Junk packet count
	Jmin int    // Min junk packet size
	Jmax int    // Max junk packet size
	S1   int    // Handshake junk prefix
	S2   int    // Response junk prefix
	H1   uint32 // Init header
	H2   uint32 // Response header
	H3   uint32 // Cookie header
	H4   uint32 // Transport data header
}

// DefaultAWGParams returns standard AmneziaWG 3.1 parameters
func DefaultAWGParams() AWGParams {
	return AWGParams{
		Jc:   4,
		Jmin: 40,
		Jmax: 70,
		S1:   16,
		S2:   16,
		H1:   0x7391b4a2,
		H2:   0x51c3d9e8,
		H3:   0x3f2a8c1e,
		H4:   0x9b4a1e7d,
	}
}

// GenerateJunkPacket creates an obfuscated junk packet (Jc)
func GenerateJunkPacket(minSize, maxSize int) []byte {
	if maxSize <= minSize {
		maxSize = minSize + 30
	}
	size := minSize
	b := make([]byte, 1)
	rand.Read(b)
	size += int(b[0]) % (maxSize - minSize + 1)

	buf := make([]byte, size)
	rand.Read(buf)
	return buf
}

// EncodeAWGDataPacket encodes an IP packet into an AmneziaWG transport packet (H4)
// Wire format: [H4: 4 bytes] [SessionID: 8 bytes] [Seq: 4 bytes] [EncryptedPayload]
func EncodeAWGDataPacket(h4 uint32, sessionID uint64, seq uint32, sessionKey []byte, ipPacket []byte) ([]byte, error) {
	encrypted, err := lcrypto.EncryptPayload(sessionKey, ipPacket)
	if err != nil {
		return nil, fmt.Errorf("encrypt packet: %w", err)
	}

	totalLen := 4 + 8 + 4 + len(encrypted)
	buf := make([]byte, totalLen)

	binary.BigEndian.PutUint32(buf[0:4], h4)
	binary.BigEndian.PutUint64(buf[4:12], sessionID)
	binary.BigEndian.PutUint32(buf[12:16], seq)
	copy(buf[16:], encrypted)

	return buf, nil
}

// DecodeAWGDataPacket decodes an AmneziaWG transport packet (H4)
// Returns sessionID, seq, decrypted IP packet
func DecodeAWGDataPacket(h4 uint32, sessionKey []byte, data []byte) (uint64, uint32, []byte, error) {
	if len(data) < 16+12+16 { // Header (16) + Nonce (12) + Poly1305 Tag (16)
		return 0, 0, nil, fmt.Errorf("packet too short for AWG data")
	}

	header := binary.BigEndian.Uint32(data[0:4])
	if header != h4 {
		return 0, 0, nil, fmt.Errorf("invalid AWG header: 0x%08x (expected 0x%08x)", header, h4)
	}

	sessionID := binary.BigEndian.Uint64(data[4:12])
	seq := binary.BigEndian.Uint32(data[12:16])

	decrypted, err := lcrypto.DecryptPayload(sessionKey, data[16:])
	if err != nil {
		return 0, 0, nil, fmt.Errorf("decrypt AWG packet: %w", err)
	}

	return sessionID, seq, decrypted, nil
}
