package server

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ligend/ligend-server/internal/auth"
	"github.com/ligend/ligend-server/internal/config"
	"github.com/ligend/ligend-server/internal/protocol"
	"github.com/ligend/ligend-server/internal/tunnel"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  65536,
	WriteBufferSize: 65536,
	CheckOrigin: func(r *http.Request) bool {
		return true // Accept any origin — auth is via HMAC
	},
}

// Server is the main Ligend VPN server.
type Server struct {
	cfg          *config.Config
	auth         *auth.Authenticator
	sessions     *tunnel.SessionManager
	natTable     *tunnel.NATTable
	tun          *tunnel.TUNDevice
	httpServer   *http.Server
	httpServerMu sync.Mutex
	udpConn      *net.UDPConn
	logger       *slog.Logger
	bufPool      sync.Pool
}

// New creates a new Ligend server.
func New(cfg *config.Config, logger *slog.Logger) (*Server, error) {
	secretKey, err := cfg.SecretKey()
	if err != nil {
		return nil, fmt.Errorf("decode secret key: %w", err)
	}

	sessionMgr, err := tunnel.NewSessionManager(cfg.VPNSubnet, logger)
	if err != nil {
		return nil, fmt.Errorf("create session manager: %w", err)
	}

	s := &Server{
		cfg:      cfg,
		auth:     auth.NewAuthenticator(secretKey),
		sessions: sessionMgr,
		natTable: tunnel.NewNATTable(logger),
		logger:   logger,
		bufPool: sync.Pool{
			New: func() any {
				buf := make([]byte, cfg.MTU+128) // MTU + overhead
				return &buf
			},
		},
	}

	return s, nil
}

// Start initializes the TUN device and starts the HTTP server.
func (s *Server) Start() error {
	// Create TUN device
	// Gateway IP: x.x.x.1/24
	_, ipNet, err := net.ParseCIDR(s.cfg.VPNSubnet)
	if err != nil {
		return fmt.Errorf("parse VPN subnet: %w", err)
	}
	gatewayIP := make(net.IP, len(ipNet.IP))
	copy(gatewayIP, ipNet.IP)
	gatewayIP[len(gatewayIP)-1] = 1
	ones, _ := ipNet.Mask.Size()
	tunAddr := fmt.Sprintf("%s/%d", gatewayIP.String(), ones)

	tun, err := tunnel.NewTUNDevice(s.cfg.TUNName, tunAddr, s.cfg.MTU, s.logger)
	if err != nil {
		return fmt.Errorf("create TUN: %w", err)
	}
	s.tun = tun

	// Setup NAT
	if err := tunnel.SetupNAT(s.cfg.VPNSubnet, s.logger); err != nil {
		s.logger.Warn("NAT setup issue (may require manual config)", "error", err)
	}

	// Start TUN reader goroutine (reads packets from TUN, routes to clients)
	go s.tunReadLoop()

	// Start AmneziaWG 3.1 UDP engine for ultra-low gaming latency
	go s.startAWGListener()

	// Setup HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc(s.cfg.WebSocketPath, s.handleWebSocket)
	mux.Handle("/", http.FileServer(http.Dir(s.cfg.WebRoot)))

	s.httpServerMu.Lock()
	s.httpServer = &http.Server{
		Addr:         s.cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  0, // WebSocket needs no timeout
		WriteTimeout: 0,
		IdleTimeout:  0,
	}
	s.httpServerMu.Unlock()

	s.logger.Info("Ligend server starting",
		"listen", s.cfg.ListenAddr,
		"udp_gaming_port", s.cfg.UDPPort,
		"game_mode", s.cfg.GameMode,
		"ws_path", s.cfg.WebSocketPath,
		"vpn_subnet", s.cfg.VPNSubnet,
		"tun", s.tun.Name(),
	)

	return s.httpServer.ListenAndServe()
}

// UpdateListenAddr allows changing the VPN listening port dynamically from the panel.
func (s *Server) UpdateListenAddr(newAddr string) error {
	s.httpServerMu.Lock()
	defer s.httpServerMu.Unlock()

	s.logger.Info("updating VPN listening address", "old", s.cfg.ListenAddr, "new", newAddr)
	s.cfg.ListenAddr = newAddr

	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = s.httpServer.Shutdown(ctx)
		cancel()
	}

	mux := http.NewServeMux()
	mux.HandleFunc(s.cfg.WebSocketPath, s.handleWebSocket)
	mux.Handle("/", http.FileServer(http.Dir(s.cfg.WebRoot)))

	s.httpServer = &http.Server{
		Addr:         newAddr,
		Handler:      mux,
		ReadTimeout:  0,
		WriteTimeout: 0,
		IdleTimeout:  0,
	}

	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("restart HTTP listener error", "error", err)
		}
	}()

	return nil
}

// startAWGListener starts the AmneziaWG 3.1 UDP engine for ultra-low gaming latency.
func (s *Server) startAWGListener() {
	if s.cfg.UDPPort <= 0 {
		return
	}
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", s.cfg.UDPPort))
	if err != nil {
		s.logger.Error("resolve UDP addr for AWG failed", "error", err)
		return
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		s.logger.Warn("listen UDP for AWG failed (port might be in use)", "port", s.cfg.UDPPort, "error", err)
		return
	}
	s.udpConn = conn
	s.logger.Info("⚡ AmneziaWG 3.1 UDP Gaming Engine running",
		"port", s.cfg.UDPPort,
		"jc", s.cfg.AWGJc,
		"h1", fmt.Sprintf("0x%08x", s.cfg.AWGH1),
		"h4", fmt.Sprintf("0x%08x", s.cfg.AWGH4),
	)

	s.awgReadLoop()
}

// awgReadLoop handles high-performance AmneziaWG 3.1 UDP datagrams.
func (s *Server) awgReadLoop() {
	buf := make([]byte, 65535)
	for {
		n, remoteAddr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			if s.udpConn == nil {
				return
			}
			s.logger.Debug("UDP read error", "error", err)
			continue
		}
		if n < 4 {
			continue
		}

		magic := binary.BigEndian.Uint32(buf[0:4])

		// 1. Data transport packet (H4)
		if magic == s.cfg.AWGH4 {
			if n < 16+12+16 {
				continue
			}
			sessID := binary.BigEndian.Uint64(buf[4:12])
			// Find session
			var sess *tunnel.Session
			for _, item := range s.sessions.ListSessions() {
				if item.NumericID == sessID || item.IsUDP {
					sess = item
					break
				}
			}
			if sess == nil {
				continue
			}
			sess.Touch()
			sess.UDPAddr = remoteAddr
			sess.UDPConn = s.udpConn

			_, _, ipPacket, err := protocol.DecodeAWGDataPacket(s.cfg.AWGH4, sess.SessionKey, buf[:n])
			if err != nil {
				s.logger.Debug("AWG packet decode error", "error", err)
				continue
			}
			if len(ipPacket) > 0 {
				_, _ = s.tun.Write(ipPacket)
			}
			continue
		}

		// 2. Handshake Initiation (H1)
		if magic == s.cfg.AWGH1 {
			sessionID := generateSessionID()
			session, err := s.sessions.CreateSession(sessionID)
			if err != nil {
				continue
			}
			session.IsUDP = true
			session.UDPAddr = remoteAddr
			session.UDPConn = s.udpConn
			session.GameMode = true
			session.AWGH4 = s.cfg.AWGH4
			s.natTable.Register(session.IP, session)

			// Send H2 response
			resp := make([]byte, 4+8+4+4)
			binary.BigEndian.PutUint32(resp[0:4], s.cfg.AWGH2)
			binary.BigEndian.PutUint64(resp[4:12], session.NumericID)
			copy(resp[12:16], session.IP.To4())
			binary.BigEndian.PutUint32(resp[16:20], uint32(s.cfg.MTU))

			_, _ = s.udpConn.WriteToUDP(resp, remoteAddr)
			s.logger.Info("⚡ AWG 3.1 UDP client connected", "ip", session.IP.String(), "remote", remoteAddr.String())
			continue
		}

		// 3. Junk packet (Jc) - ignore safely
	}
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down server")

	s.httpServerMu.Lock()
	if s.httpServer != nil {
		s.httpServer.Shutdown(ctx)
	}
	s.httpServerMu.Unlock()

	if s.udpConn != nil {
		_ = s.udpConn.Close()
	}

	if s.tun != nil {
		tunnel.CleanupNAT(s.cfg.VPNSubnet, s.logger)
		s.tun.Close()
	}

	return nil
}

// handleWebSocket handles WebSocket upgrade requests at the secret path.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Validate HMAC authentication
	requestID := r.Header.Get("X-Request-ID")
	timestamp := r.Header.Get("X-Timestamp")
	nonce := r.Header.Get("X-Nonce")

	if requestID == "" || timestamp == "" || nonce == "" {
		// No auth headers — serve cover website with 200 OK
		s.serveCoverSite(w, r)
		return
	}

	if err := s.auth.Validate(requestID, timestamp, nonce); err != nil {
		s.logger.Warn("auth failed",
			"error", err,
			"remote", r.RemoteAddr,
		)
		// Invalid auth — serve cover website (not 404!)
		s.serveCoverSite(w, r)
		return
	}

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error("websocket upgrade failed", "error", err)
		return
	}

	// Optimize socket for ultra-low gaming latency (disable Nagle's algorithm)
	if tcpConn, ok := conn.UnderlyingConn().(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetReadBuffer(1024 * 1024)
		_ = tcpConn.SetWriteBuffer(1024 * 1024)
	}

	s.logger.Info("client connected", "remote", r.RemoteAddr)

	// Check if this is a session migration
	// For now, create a new session for each connection
	// Migration is handled via MIGRATE control frame after connection
	go s.handleClient(conn)
}

// serveCoverSite serves the cover website on auth failure or direct browsing.
func (s *Server) serveCoverSite(w http.ResponseWriter, r *http.Request) {
	// Serve the cover website — looks like a normal site
	http.FileServer(http.Dir(s.cfg.WebRoot)).ServeHTTP(w, r)
}

// handleClient manages a single VPN client connection.
func (s *Server) handleClient(conn *websocket.Conn) {
	defer conn.Close()

	// Generate session ID
	sessionID := generateSessionID()

	// Create session with allocated IP
	session, err := s.sessions.CreateSession(sessionID)
	if err != nil {
		s.logger.Error("create session failed", "error", err)
		return
	}
	defer s.cleanupSession(session)

	session.GameMode = s.cfg.GameMode
	session.AWGH4 = s.cfg.AWGH4

	// Add connection to session
	session.AddConnection(conn)

	// Register in NAT table
	s.natTable.Register(session.IP, session)

	// Send initial control messages
	if err := s.sendInitialControls(session); err != nil {
		s.logger.Error("send initial controls failed", "error", err, "session", sessionID)
		return
	}

	// Start padding generator only if NOT in game mode (to keep gaming ping ultra-low)
	if !s.cfg.GameMode {
		padGen := protocol.NewPaddingGenerator(conn, s.cfg.PaddingMin, s.cfg.PaddingMax, s.logger)
		padGen.Start()
		defer padGen.Stop()
	}

	s.logger.Info("session active",
		"session_id", sessionID,
		"client_ip", session.IP.String(),
		"game_mode", session.GameMode,
	)

	// Main read loop: read frames from WebSocket, process them
	s.clientReadLoop(session, conn)
}

// sendInitialControls sends the handshake control messages to a new client.
func (s *Server) sendInitialControls(session *Session) error {
	// 1. SESSION_INIT: send session ID
	initPayload := []byte(session.ID)
	frame := protocol.NewControlFrame(protocol.CtrlSessionInit, initPayload, session.NextSeq())
	if err := session.SendFrame(frame); err != nil {
		return fmt.Errorf("send SESSION_INIT: %w", err)
	}

	// 2. SESSION_KEY: send ChaCha20 session key
	frame = protocol.NewControlFrame(protocol.CtrlSessionKey, session.SessionKey, session.NextSeq())
	if err := session.SendFrame(frame); err != nil {
		return fmt.Errorf("send SESSION_KEY: %w", err)
	}

	// 3. IP_ASSIGN: send assigned IP + prefix length
	ipBytes := session.IP.To4()
	if ipBytes == nil {
		return fmt.Errorf("invalid IPv4 address")
	}
	prefixLen := byte(24) // /24
	ipPayload := make([]byte, 0, 9)
	ipPayload = append(ipPayload, ipBytes...)
	ipPayload = append(ipPayload, prefixLen)
	// Also append gateway IP
	_, ipNet, _ := net.ParseCIDR(s.cfg.VPNSubnet)
	gw := make(net.IP, 4)
	copy(gw, ipNet.IP.To4())
	gw[3] = 1
	ipPayload = append(ipPayload, gw.To4()...)
	frame = protocol.NewControlFrame(protocol.CtrlIPAssign, ipPayload, session.NextSeq())
	if err := session.SendFrame(frame); err != nil {
		return fmt.Errorf("send IP_ASSIGN: %w", err)
	}

	// 4. DNS_CONFIG: send DNS servers
	var dnsPayload []byte
	for _, dns := range s.cfg.DNS {
		ip := net.ParseIP(dns).To4()
		if ip != nil {
			dnsPayload = append(dnsPayload, ip...)
		}
	}
	frame = protocol.NewControlFrame(protocol.CtrlDNSConfig, dnsPayload, session.NextSeq())
	if err := session.SendFrame(frame); err != nil {
		return fmt.Errorf("send DNS_CONFIG: %w", err)
	}

	// 5. MTU_UPDATE: send MTU value
	mtuPayload := []byte{byte(s.cfg.MTU >> 8), byte(s.cfg.MTU & 0xFF)}
	frame = protocol.NewControlFrame(protocol.CtrlMTUUpdate, mtuPayload, session.NextSeq())
	if err := session.SendFrame(frame); err != nil {
		return fmt.Errorf("send MTU_UPDATE: %w", err)
	}

	return nil
}

// clientReadLoop reads frames from a WebSocket connection and processes them.
// Supports protocol v3: batch mode and LZ4 compression.
func (s *Server) clientReadLoop(session *Session, conn *websocket.Conn) {
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				s.logger.Warn("client read error", "error", err, "session", session.ID)
			}
			return
		}

		session.Touch()

		frame, err := protocol.Decode(message)
		if err != nil {
			s.logger.Warn("frame decode error", "error", err, "session", session.ID)
			continue
		}

		// v3: Decompress LZ4 if compressed flag is set
		if frame.Flags&protocol.FlagCompressed != 0 {
			frame, err = protocol.DecompressFrame(frame)
			if err != nil {
				s.logger.Warn("decompress error", "error", err, "session", session.ID)
				continue
			}
		}

		switch frame.Type {
		case protocol.TypeData:
			if len(frame.Payload) == 0 {
				continue
			}

			// v3: Check for batch mode (multiple packets in one frame)
			if frame.Flags&protocol.FlagBatchMode != 0 {
				packets, err := protocol.DecodeBatch(frame.Payload)
				if err != nil {
					s.logger.Warn("batch decode error", "error", err, "session", session.ID)
					continue
				}
				for _, pkt := range packets {
					if _, err := s.tun.Write(pkt); err != nil {
						s.logger.Debug("TUN write error", "error", err)
					}
				}
			} else {
				// Single packet mode (v2 compatible)
				if _, err := s.tun.Write(frame.Payload); err != nil {
					s.logger.Warn("TUN write error", "error", err)
				}
			}

		case protocol.TypeDataFrag:
			s.logger.Debug("received fragment", "session", session.ID)

		case protocol.TypeControl:
			s.handleControlFrame(session, conn, frame)

		case protocol.TypeKeepalive:
			// Respond with keepalive
			resp := protocol.NewKeepaliveFrame(session.NextSeq())
			data := resp.Encode()
			conn.WriteMessage(websocket.BinaryMessage, data)

		case protocol.TypePadding:
			// Ignore padding frames — they're just for traffic shaping

		case protocol.TypeMigrate:
			s.handleMigrate(session, conn, frame)

		default:
			s.logger.Warn("unknown frame type", "type", frame.Type, "session", session.ID)
		}
	}
}

// handleControlFrame processes control messages from clients.
func (s *Server) handleControlFrame(session *Session, conn *websocket.Conn, frame *protocol.Frame) {
	subtype, err := frame.ControlSubtype()
	if err != nil {
		s.logger.Warn("invalid control frame", "error", err)
		return
	}

	switch subtype {
	case protocol.CtrlDisconnect:
		s.logger.Info("client requested disconnect", "session", session.ID)
		conn.Close()

	case protocol.CtrlPing:
		// Real RTT: client sends 8-byte timestamp, we echo it back as PONG immediately
		pingData := frame.ControlData()
		pongFrame := protocol.NewControlFrame(protocol.CtrlPong, pingData, session.NextSeq())
		data := pongFrame.Encode()
		conn.WriteMessage(websocket.BinaryMessage, data)

	case protocol.CtrlSessionInit:
		// Client sending its init — acknowledge
		s.logger.Debug("client session init received", "session", session.ID)

	default:
		s.logger.Debug("unhandled control subtype", "subtype", subtype, "session", session.ID)
	}
}

// handleMigrate handles session migration to a new connection.
func (s *Server) handleMigrate(session *Session, newConn *websocket.Conn, frame *protocol.Frame) {
	oldSessionID := string(frame.Payload)
	s.logger.Info("session migration requested",
		"old_session", oldSessionID,
		"new_session", session.ID,
	)

	// Find old session
	oldSession := s.sessions.GetSession(oldSessionID)
	if oldSession == nil {
		s.logger.Warn("migration: old session not found", "old_session", oldSessionID)
		return
	}

	// Send migration ACK
	ackFrame := protocol.NewControlFrame(protocol.CtrlSessionInit, []byte("migrate_ack"), session.NextSeq())
	data := ackFrame.Encode()
	newConn.WriteMessage(websocket.BinaryMessage, data)
}

// tunReadLoop continuously reads IP packets from TUN and routes them to clients.
func (s *Server) tunReadLoop() {
	buf := make([]byte, s.cfg.MTU+128)

	for {
		n, err := s.tun.Read(buf)
		if err != nil {
			s.logger.Error("TUN read error", "error", err)
			return
		}

		if n == 0 {
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		// Find destination session via NAT table
		session := s.natTable.LookupByPacketDst(packet)
		if session == nil {
			// Packet not for any VPN client — drop silently
			continue
		}

		// Send to client
		if err := session.SendDataToClient(packet); err != nil {
			s.logger.Debug("send to client failed", "error", err, "session", session.ID)
		}
	}
}

// cleanupSession removes a session and frees resources.
func (s *Server) cleanupSession(session *Session) {
	s.natTable.Unregister(session.IP)
	s.sessions.RemoveSession(session.ID)
}

// generateSessionID creates a random session ID.
func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Sessions returns the session manager.
func (s *Server) Sessions() *tunnel.SessionManager {
	return s.sessions
}

// KickSession kicks an active session by its ID.
func (s *Server) KickSession(sessionID string) bool {
	sess := s.sessions.GetSession(sessionID)
	if sess == nil {
		return false
	}
	s.cleanupSession(sess)
	return true
}

// Session re-export for use in sendInitialControls.
type Session = tunnel.Session

