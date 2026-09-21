package tunnel

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	lcrypto "github.com/ligend/ligend-server/internal/crypto"
	"github.com/ligend/ligend-server/internal/protocol"
)

// Session represents an active VPN client session.
type Session struct {
	ID          string
	IP          net.IP
	SessionKey  []byte
	Connections []*websocket.Conn
	connMu      sync.RWMutex
	CreatedAt   time.Time
	LastActive  atomic.Int64
	sequence    atomic.Uint32
	writeMu     sync.Mutex
	// AmneziaWG 3.1 UDP Datagram Support
	IsUDP     bool
	UDPAddr   *net.UDPAddr
	UDPConn   *net.UDPConn
	NumericID uint64
	GameMode  bool
	AWGH4     uint32
}

// NewSession creates a new VPN session.
func NewSession(id string, ip net.IP) (*Session, error) {
	sessionKey, err := lcrypto.GenerateSessionKey()
	if err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}

	// Generate a numeric session ID for fast AWG datagram header routing
	var numID uint64
	if len(sessionKey) >= 8 {
		numID = binary.BigEndian.Uint64(sessionKey[:8])
	}

	s := &Session{
		ID:          id,
		IP:          ip,
		SessionKey:  sessionKey,
		Connections: make([]*websocket.Conn, 0, 4),
		CreatedAt:   time.Now(),
		NumericID:   numID,
		GameMode:    true,       // Default to ultra-low latency for games
		AWGH4:       0x9b4a1e7d, // Default AWG transport header
	}
	s.LastActive.Store(time.Now().Unix())
	return s, nil
}

// AddConnection adds a WebSocket connection to the session.
func (s *Session) AddConnection(conn *websocket.Conn) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	s.Connections = append(s.Connections, conn)
}

// RemoveConnection removes a WebSocket connection from the session.
func (s *Session) RemoveConnection(conn *websocket.Conn) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	for i, c := range s.Connections {
		if c == conn {
			s.Connections = append(s.Connections[:i], s.Connections[i+1:]...)
			return
		}
	}
}

// PrimaryConn returns the first (primary) connection or nil.
func (s *Session) PrimaryConn() *websocket.Conn {
	s.connMu.RLock()
	defer s.connMu.RUnlock()
	if len(s.Connections) == 0 {
		return nil
	}
	return s.Connections[0]
}

// NextSeq returns the next sequence number.
func (s *Session) NextSeq() uint32 {
	return s.sequence.Add(1)
}

// SendFrame sends a protocol frame through the primary connection.
func (s *Session) SendFrame(frame *protocol.Frame) error {
	conn := s.PrimaryConn()
	if conn == nil {
		return fmt.Errorf("no active connection")
	}

	data := frame.Encode()
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return conn.WriteMessage(websocket.BinaryMessage, data)
}

// SendDataToClient sends an IP packet to the client with AmneziaWG 3.1 ultra-low latency.
func (s *Session) SendDataToClient(packet []byte) error {
	// 1. If this is an AmneziaWG UDP datagram session: direct wire-speed UDP transmission!
	if s.IsUDP && s.UDPAddr != nil && s.UDPConn != nil {
		wire, err := protocol.EncodeAWGDataPacket(s.AWGH4, s.NumericID, s.NextSeq(), s.SessionKey, packet)
		if err != nil {
			return err
		}
		_, err = s.UDPConn.WriteToUDP(wire, s.UDPAddr)
		return err
	}

	// 2. WebSocket transmission:
	// Detect if packet is UDP (protocol 17, games/voice) or ICMP (protocol 1, ping)
	isGamePacket := false
	if len(packet) >= 20 && (packet[0]>>4) == 4 {
		proto := packet[9]
		if proto == 17 || proto == 1 { // UDP or ICMP
			isGamePacket = true
		}
	}

	frame := protocol.NewDataFrame(packet, s.NextSeq())

	// If GameMode is active or it's a gaming packet, transmit with 0 delay and ZERO padding
	if s.GameMode || isGamePacket {
		frame.Flags |= protocol.FlagUrgent
	} else {
		// Only add padding to background bulk TCP frames if not gaming
		if s.sequence.Load()%4 == 0 {
			frame.Flags |= protocol.FlagHasPadding
		}
	}

	return s.SendFrame(frame)
}

// Touch updates the last active timestamp.
func (s *Session) Touch() {
	s.LastActive.Store(time.Now().Unix())
}

// --- Session Manager ---

// SessionManager manages all active VPN sessions and IP address allocation.
type SessionManager struct {
	sessions map[string]*Session // session ID -> session
	ipMap    map[string]*Session // IP string -> session
	mu       sync.RWMutex
	ipPool   *IPPool
	logger   *slog.Logger
}

// NewSessionManager creates a new session manager.
func NewSessionManager(subnet string, logger *slog.Logger) (*SessionManager, error) {
	pool, err := NewIPPool(subnet)
	if err != nil {
		return nil, fmt.Errorf("create IP pool: %w", err)
	}

	return &SessionManager{
		sessions: make(map[string]*Session),
		ipMap:    make(map[string]*Session),
		ipPool:   pool,
		logger:   logger,
	}, nil
}

// CreateSession allocates an IP and creates a new session.
func (sm *SessionManager) CreateSession(id string) (*Session, error) {
	ip, err := sm.ipPool.Allocate()
	if err != nil {
		return nil, fmt.Errorf("allocate IP: %w", err)
	}

	session, err := NewSession(id, ip)
	if err != nil {
		sm.ipPool.Release(ip)
		return nil, err
	}

	sm.mu.Lock()
	sm.sessions[id] = session
	sm.ipMap[ip.String()] = session
	sm.mu.Unlock()

	sm.logger.Info("session created",
		"session_id", id,
		"ip", ip.String(),
	)

	return session, nil
}

// GetSession returns a session by ID.
func (sm *SessionManager) GetSession(id string) *Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessions[id]
}

// GetSessionByIP returns a session by its assigned IP.
func (sm *SessionManager) GetSessionByIP(ip net.IP) *Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.ipMap[ip.String()]
}

// RemoveSession destroys a session and releases its IP.
func (sm *SessionManager) RemoveSession(id string) {
	sm.mu.Lock()
	session, ok := sm.sessions[id]
	if !ok {
		sm.mu.Unlock()
		return
	}
	delete(sm.sessions, id)
	delete(sm.ipMap, session.IP.String())
	sm.mu.Unlock()

	sm.ipPool.Release(session.IP)

	// Close all connections
	session.connMu.Lock()
	for _, conn := range session.Connections {
		conn.Close()
	}
	session.connMu.Unlock()

	sm.logger.Info("session removed",
		"session_id", id,
		"ip", session.IP.String(),
	)
}

// RoutePacket reads the destination IP from a packet and forwards it to the correct session.
func (sm *SessionManager) RoutePacket(packet []byte) error {
	if len(packet) < 20 {
		return fmt.Errorf("packet too short: %d bytes", len(packet))
	}

	// Extract destination IP from IPv4 header (bytes 16-19)
	version := packet[0] >> 4
	var dstIP net.IP
	if version == 4 {
		dstIP = net.IP(packet[16:20])
	} else if version == 6 && len(packet) >= 40 {
		dstIP = net.IP(packet[24:40])
	} else {
		return fmt.Errorf("unsupported IP version: %d", version)
	}

	session := sm.GetSessionByIP(dstIP)
	if session == nil {
		return fmt.Errorf("no session for IP %s", dstIP)
	}

	return session.SendDataToClient(packet)
}

// ActiveSessions returns the count of active sessions.
func (sm *SessionManager) ActiveSessions() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

// ListSessions returns a snapshot of all active sessions.
func (sm *SessionManager) ListSessions() []*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	list := make([]*Session, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		list = append(list, s)
	}
	return list
}

// --- IP Pool ---

// IPPool manages a pool of available IP addresses within a subnet.
type IPPool struct {
	network   *net.IPNet
	gateway   net.IP
	available []net.IP
	used      map[string]bool
	mu        sync.Mutex
}

// NewIPPool creates an IP pool for the given CIDR subnet.
// Reserves .0 (network), .1 (gateway), .255 (broadcast).
func NewIPPool(cidr string) (*IPPool, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR: %w", err)
	}

	pool := &IPPool{
		network: network,
		used:    make(map[string]bool),
	}

	// Generate available IPs (.2 to .254 for /24)
	ip := make(net.IP, len(network.IP))
	copy(ip, network.IP)

	// Gateway is .1
	gateway := make(net.IP, len(ip))
	copy(gateway, ip)
	gateway[len(gateway)-1] = 1
	pool.gateway = gateway

	// Available addresses: .2 to .254
	for i := 2; i <= 254; i++ {
		addr := make(net.IP, len(ip))
		copy(addr, ip)
		addr[len(addr)-1] = byte(i)
		if network.Contains(addr) {
			pool.available = append(pool.available, addr)
		}
	}

	return pool, nil
}

// Allocate returns an available IP address.
func (p *IPPool) Allocate() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.available) == 0 {
		return nil, fmt.Errorf("no available IP addresses")
	}

	ip := p.available[0]
	p.available = p.available[1:]
	p.used[ip.String()] = true

	return ip, nil
}

// Release returns an IP address to the pool.
func (p *IPPool) Release(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()

	key := ip.String()
	if !p.used[key] {
		return
	}

	delete(p.used, key)
	p.available = append(p.available, ip)
}

// Gateway returns the gateway IP (.1).
func (p *IPPool) Gateway() net.IP {
	return p.gateway
}

// Network returns the network in CIDR notation.
func (p *IPPool) Network() *net.IPNet {
	return p.network
}

// MaskSize returns the prefix length (e.g., 24 for /24).
func (p *IPPool) MaskSize() int {
	ones, _ := p.network.Mask.Size()
	return ones
}

// --- Helper to extract source IP from packet ---

// SrcIPFromPacket extracts the source IP from an IP packet.
func SrcIPFromPacket(packet []byte) net.IP {
	if len(packet) < 20 {
		return nil
	}
	version := packet[0] >> 4
	if version == 4 {
		return net.IP(packet[12:16])
	}
	if version == 6 && len(packet) >= 40 {
		return net.IP(packet[8:24])
	}
	return nil
}

// DstIPFromPacket extracts the destination IP from an IP packet.
func DstIPFromPacket(packet []byte) net.IP {
	if len(packet) < 20 {
		return nil
	}
	version := packet[0] >> 4
	if version == 4 {
		return net.IP(packet[16:20])
	}
	if version == 6 && len(packet) >= 40 {
		return net.IP(packet[24:40])
	}
	return nil
}

// IPToUint32 converts an IPv4 address to a uint32.
func IPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}
