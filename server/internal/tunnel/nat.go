package tunnel

import (
	"log/slog"
	"net"
	"sync"
)

// NATTable maps client VPN IPs to sessions for packet routing.
type NATTable struct {
	entries map[uint32]*Session // IP as uint32 -> session
	mu      sync.RWMutex
	logger  *slog.Logger
}

// NewNATTable creates a new NAT table.
func NewNATTable(logger *slog.Logger) *NATTable {
	return &NATTable{
		entries: make(map[uint32]*Session),
		logger:  logger,
	}
}

// Register adds a mapping from IP to session.
func (n *NATTable) Register(ip net.IP, session *Session) {
	key := IPToUint32(ip)
	n.mu.Lock()
	n.entries[key] = session
	n.mu.Unlock()
	n.logger.Debug("NAT registered", "ip", ip.String(), "session", session.ID)
}

// Unregister removes the mapping for an IP.
func (n *NATTable) Unregister(ip net.IP) {
	key := IPToUint32(ip)
	n.mu.Lock()
	delete(n.entries, key)
	n.mu.Unlock()
	n.logger.Debug("NAT unregistered", "ip", ip.String())
}

// LookupByIP finds the session for a given IP address.
func (n *NATTable) LookupByIP(ip net.IP) *Session {
	key := IPToUint32(ip)
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.entries[key]
}

// LookupByPacketDst finds the session for a packet's destination IP.
func (n *NATTable) LookupByPacketDst(packet []byte) *Session {
	dstIP := DstIPFromPacket(packet)
	if dstIP == nil {
		return nil
	}
	return n.LookupByIP(dstIP)
}

// LookupByPacketSrc finds the session for a packet's source IP.
func (n *NATTable) LookupByPacketSrc(packet []byte) *Session {
	srcIP := SrcIPFromPacket(packet)
	if srcIP == nil {
		return nil
	}
	return n.LookupByIP(srcIP)
}

// Count returns the number of entries in the NAT table.
func (n *NATTable) Count() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.entries)
}
