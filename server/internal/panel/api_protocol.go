package panel

import (
	"encoding/json"
	"net/http"
)

type ProtocolConfig struct {
	Transport           string `json:"transport"`            // "websocket", "udp_awg", or "h2"
	TLSFingerprint      string `json:"tls_fingerprint"`      // "chrome", "firefox", "safari", "random"
	GameMode            bool   `json:"game_mode"`            // Ultra-low latency for games (AmneziaWG style)
	PaddingEnabled      bool   `json:"padding_enabled"`
	PaddingMinSec       int    `json:"padding_min_sec"`
	PaddingMaxSec       int    `json:"padding_max_sec"`
	CompressionEnabled  bool   `json:"compression_enabled"`  // LZ4
	KeepaliveMinSec     int    `json:"keepalive_min_sec"`
	KeepaliveMaxSec     int    `json:"keepalive_max_sec"`
	JitterEnabled       bool   `json:"jitter_enabled"`
	JitterMaxMs         int    `json:"jitter_max_ms"`
	PacketNormalization bool   `json:"packet_normalization"`
	// AmneziaWG 3.1 Parameters
	AWGJc   int    `json:"awg_jc"`
	AWGJmin int    `json:"awg_jmin"`
	AWGJmax int    `json:"awg_jmax"`
	AWGH1   uint32 `json:"awg_h1"`
	AWGH2   uint32 `json:"awg_h2"`
	AWGH3   uint32 `json:"awg_h3"`
	AWGH4   uint32 `json:"awg_h4"`
}

func (p *Panel) handleProtocol(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		proto := ProtocolConfig{
			Transport:           "udp_awg",
			TLSFingerprint:      "chrome",
			GameMode:            p.cfg.GameMode,
			PaddingEnabled:      !p.cfg.GameMode,
			PaddingMinSec:       p.cfg.PaddingMin,
			PaddingMaxSec:       p.cfg.PaddingMax,
			CompressionEnabled:  true,
			KeepaliveMinSec:     15,
			KeepaliveMaxSec:     45,
			JitterEnabled:       !p.cfg.GameMode,
			JitterMaxMs:         0,
			PacketNormalization: !p.cfg.GameMode,
			AWGJc:               p.cfg.AWGJc,
			AWGJmin:             p.cfg.AWGJmin,
			AWGJmax:             p.cfg.AWGJmax,
			AWGH1:               p.cfg.AWGH1,
			AWGH2:               p.cfg.AWGH2,
			AWGH3:               p.cfg.AWGH3,
			AWGH4:               p.cfg.AWGH4,
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    proto,
		})

	case http.MethodPut:
		var proto ProtocolConfig
		if err := json.NewDecoder(r.Body).Decode(&proto); err != nil {
			http.Error(w, `{"success":false,"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}

		p.cfg.GameMode = proto.GameMode
		if proto.PaddingMinSec > 0 {
			p.cfg.PaddingMin = proto.PaddingMinSec
		}
		if proto.PaddingMaxSec > 0 {
			p.cfg.PaddingMax = proto.PaddingMaxSec
		}
		if proto.AWGJc > 0 {
			p.cfg.AWGJc = proto.AWGJc
		}
		if proto.AWGJmin > 0 {
			p.cfg.AWGJmin = proto.AWGJmin
		}
		if proto.AWGJmax > 0 {
			p.cfg.AWGJmax = proto.AWGJmax
		}
		if proto.AWGH1 > 0 {
			p.cfg.AWGH1 = proto.AWGH1
		}
		if proto.AWGH2 > 0 {
			p.cfg.AWGH2 = proto.AWGH2
		}
		if proto.AWGH3 > 0 {
			p.cfg.AWGH3 = proto.AWGH3
		}
		if proto.AWGH4 > 0 {
			p.cfg.AWGH4 = proto.AWGH4
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    proto,
			"message": "protocol settings updated",
		})

	default:
		http.Error(w, `{"success":false,"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}
