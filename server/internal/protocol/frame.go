package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
)

// Protocol version.
const Version = 0x02

// Frame types.
const (
	TypeData      = 0x01
	TypeDataFrag  = 0x02
	TypeControl   = 0x03
	TypePadding   = 0x04
	TypeKeepalive = 0x05
	TypeMigrate   = 0x06
)

// Frame flags.
const (
	FlagHasPadding = 0x01
	FlagCompressed = 0x02
	FlagUrgent     = 0x04
	FlagEncrypted  = 0x08
)

// Control subtypes (first byte of control payload).
const (
	CtrlSessionInit = 0x01
	CtrlIPAssign    = 0x02
	CtrlDNSConfig   = 0x03
	CtrlMTUUpdate   = 0x04
	CtrlDisconnect  = 0x05
	CtrlSessionKey  = 0x06
	CtrlConnID      = 0x07
	CtrlPing        = 0x08 // Client sends ping with 8-byte timestamp
	CtrlPong        = 0x09 // Server echoes back the same timestamp
)

// HeaderSize is the fixed header size in bytes.
const HeaderSize = 8

// Frame represents a single Ligend protocol frame.
//
// Wire format (8-byte header + payload + optional padding):
//
//	Byte 0:    [version:4][type:4]
//	Byte 1:    flags
//	Bytes 2-3: payload length (big-endian uint16)
//	Bytes 4-7: sequence number (big-endian uint32)
//	Bytes 8+:  payload
//	(optional): padding bytes; if HAS_PADDING flag is set, the last byte
//	            of the entire frame is the padding length.
type Frame struct {
	Version  uint8
	Type     uint8
	Flags    uint8
	Sequence uint32
	Payload  []byte
}

// NewDataFrame creates a DATA frame carrying an IP packet.
func NewDataFrame(payload []byte, seq uint32) *Frame {
	return &Frame{
		Version:  Version,
		Type:     TypeData,
		Flags:    0,
		Sequence: seq,
		Payload:  payload,
	}
}

// NewDataFragFrame creates a DATA_FRAG frame with a fragment ID prepended.
func NewDataFragFrame(fragID uint16, payload []byte, seq uint32) *Frame {
	p := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(p[:2], fragID)
	copy(p[2:], payload)
	return &Frame{
		Version:  Version,
		Type:     TypeDataFrag,
		Sequence: seq,
		Payload:  p,
	}
}

// NewControlFrame creates a CONTROL frame with the given subtype and data.
func NewControlFrame(subtype byte, data []byte, seq uint32) *Frame {
	p := make([]byte, 1+len(data))
	p[0] = subtype
	copy(p[1:], data)
	return &Frame{
		Version:  Version,
		Type:     TypeControl,
		Sequence: seq,
		Payload:  p,
	}
}

// NewPaddingFrame creates a PADDING frame with random content of the given size.
func NewPaddingFrame(size int) *Frame {
	payload := make([]byte, size)
	rand.Read(payload)
	return &Frame{
		Version: Version,
		Type:    TypePadding,
		Payload: payload,
	}
}

// NewKeepaliveFrame creates a KEEPALIVE frame.
func NewKeepaliveFrame(seq uint32) *Frame {
	return &Frame{
		Version:  Version,
		Type:     TypeKeepalive,
		Sequence: seq,
	}
}

// NewMigrateFrame creates a MIGRATE frame with session ID.
func NewMigrateFrame(sessionID []byte, seq uint32) *Frame {
	return &Frame{
		Version:  Version,
		Type:     TypeMigrate,
		Sequence: seq,
		Payload:  sessionID,
	}
}

// WithPadding returns a copy of the frame with random padding added.
func (f *Frame) WithPadding(minPad, maxPad int) *Frame {
	cp := *f
	cp.Flags |= FlagHasPadding
	return &cp
}

// Encode serializes the frame into bytes ready to send over WebSocket.
func (f *Frame) Encode() []byte {
	payloadLen := len(f.Payload)

	var padLen int
	hasPadding := f.Flags&FlagHasPadding != 0
	if hasPadding {
		padLen = rand.Intn(128) + 1 // 1-128 bytes of padding
	}

	totalLen := HeaderSize + payloadLen + padLen
	if hasPadding {
		totalLen++ // extra byte for padding length
	}

	buf := make([]byte, totalLen)

	// Byte 0: version (high nibble) | type (low nibble)
	buf[0] = (f.Version << 4) | (f.Type & 0x0F)
	// Byte 1: flags
	buf[1] = f.Flags
	// Bytes 2-3: payload length
	binary.BigEndian.PutUint16(buf[2:4], uint16(payloadLen))
	// Bytes 4-7: sequence
	binary.BigEndian.PutUint32(buf[4:8], f.Sequence)
	// Payload
	copy(buf[HeaderSize:], f.Payload)

	// Padding
	if hasPadding {
		padStart := HeaderSize + payloadLen
		rand.Read(buf[padStart : padStart+padLen])
		buf[totalLen-1] = byte(padLen)
	}

	return buf
}

// Decode reads a frame from a byte slice (received from WebSocket message).
func Decode(data []byte) (*Frame, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("frame too short: %d bytes", len(data))
	}

	f := &Frame{}
	f.Version = (data[0] >> 4) & 0x0F
	f.Type = data[0] & 0x0F
	f.Flags = data[1]
	payloadLen := binary.BigEndian.Uint16(data[2:4])
	f.Sequence = binary.BigEndian.Uint32(data[4:8])

	if f.Version != Version {
		return nil, fmt.Errorf("unsupported version: %d", f.Version)
	}

	// Determine actual payload (strip padding if present)
	remaining := data[HeaderSize:]

	if f.Flags&FlagHasPadding != 0 {
		if len(remaining) < 1 {
			return nil, fmt.Errorf("padding flag set but no data after header")
		}
		padLen := int(remaining[len(remaining)-1])
		// Total after header should be payloadLen + padLen + 1 (pad length byte)
		expectedLen := int(payloadLen) + padLen + 1
		if len(remaining) < expectedLen {
			return nil, fmt.Errorf("frame data too short for payload+padding: have %d, need %d", len(remaining), expectedLen)
		}
		f.Payload = make([]byte, payloadLen)
		copy(f.Payload, remaining[:payloadLen])
	} else {
		if len(remaining) < int(payloadLen) {
			return nil, fmt.Errorf("frame data too short for payload: have %d, need %d", len(remaining), payloadLen)
		}
		f.Payload = make([]byte, payloadLen)
		copy(f.Payload, remaining[:payloadLen])
	}

	return f, nil
}

// DecodeFromReader reads exactly one frame from an io.Reader.
func DecodeFromReader(r io.Reader) (*Frame, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	payloadLen := binary.BigEndian.Uint16(header[2:4])
	flags := header[1]

	// Read remaining data
	// We need at least payloadLen bytes, potentially more for padding
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("read payload: %w", err)
		}
	}

	f := &Frame{
		Version:  (header[0] >> 4) & 0x0F,
		Type:     header[0] & 0x0F,
		Flags:    flags,
		Sequence: binary.BigEndian.Uint32(header[4:8]),
		Payload:  payload,
	}

	// Skip padding if present (for stream-based reading)
	if flags&FlagHasPadding != 0 {
		// Read padding: we don't know the length yet, but for WebSocket
		// frames this function isn't typically used (Decode is used instead).
		// For stream mode, padding length would need a different encoding.
		// In WebSocket mode, we use Decode() which gets the full message.
	}

	return f, nil
}

// ControlSubtype returns the control subtype if this is a CONTROL frame.
func (f *Frame) ControlSubtype() (byte, error) {
	if f.Type != TypeControl {
		return 0, fmt.Errorf("not a control frame")
	}
	if len(f.Payload) < 1 {
		return 0, fmt.Errorf("control frame has empty payload")
	}
	return f.Payload[0], nil
}

// ControlData returns the control payload data (without the subtype byte).
func (f *Frame) ControlData() []byte {
	if f.Type != TypeControl || len(f.Payload) < 2 {
		return nil
	}
	return f.Payload[1:]
}
