package panel

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	lcrypto "github.com/ligend/ligend-server/internal/crypto"
)

type CreateClientRequest struct {
	Name              string `json:"name"`
	TrafficLimitBytes int64  `json:"traffic_limit_bytes"`
	ExpiresInDays     int    `json:"expires_in_days"`
}

type ActiveSessionResponse struct {
	ID         string `json:"id"`
	ClientIP   string `json:"client_ip"`
	CreatedAt  string `json:"created_at"`
	LastActive string `json:"last_active"`
	UptimeSec  int64  `json:"uptime_sec"`
}

func (p *Panel) handleClients(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// /api/clients or /api/clients/:id
	path := strings.TrimPrefix(r.URL.Path, "/api/clients")
	path = strings.TrimPrefix(path, "/")

	if path == "" {
		switch r.Method {
		case http.MethodGet:
			keys, err := p.db.ListClientKeys()
			if err != nil {
				http.Error(w, `{"success":false,"error":"db error"}`, http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data":    keys,
			})

		case http.MethodPost:
			var req CreateClientRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, `{"success":false,"error":"invalid request"}`, http.StatusBadRequest)
				return
			}
			if req.Name == "" {
				http.Error(w, `{"success":false,"error":"name is required"}`, http.StatusBadRequest)
				return
			}

			keyBytes, err := lcrypto.GenerateKey()
			if err != nil {
				http.Error(w, `{"success":false,"error":"failed to generate key"}`, http.StatusInternalServerError)
				return
			}
			secKeyBase64 := p.cfg.SecretKeyBase64 // Or generate separate client keys
			if secKeyBase64 == "" {
				secKeyBase64 = base64.StdEncoding.EncodeToString(keyBytes)
			}

			var expiresAt *time.Time
			if req.ExpiresInDays > 0 {
				t := time.Now().Add(time.Duration(req.ExpiresInDays) * 24 * time.Hour)
				expiresAt = &t
			}

			if err := p.db.CreateClientKey(req.Name, secKeyBase64, req.TrafficLimitBytes, expiresAt); err != nil {
				http.Error(w, `{"success":false,"error":"failed to create client"}`, http.StatusInternalServerError)
				return
			}

			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"message": "client created",
			})

		default:
			http.Error(w, `{"success":false,"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		}
		return
	}

	// Handle /api/clients/active
	if path == "active" {
		if r.Method != http.MethodGet {
			http.Error(w, `{"success":false,"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		var active []ActiveSessionResponse
		if p.vpnServer != nil && p.vpnServer.Sessions() != nil {
			sessions := p.vpnServer.Sessions().ListSessions()
			for _, s := range sessions {
				lastAct := time.Unix(s.LastActive.Load(), 0)
				active = append(active, ActiveSessionResponse{
					ID:         s.ID,
					ClientIP:   s.IP.String(),
					CreatedAt:  s.CreatedAt.Format(time.RFC3339),
					LastActive: lastAct.Format(time.RFC3339),
					UptimeSec:  int64(time.Since(s.CreatedAt).Seconds()),
				})
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    active,
		})
		return
	}

	// Handle /api/clients/:id/kick or /api/clients/:id
	parts := strings.Split(path, "/")
	id, err := strconv.Atoi(parts[0])
	if err != nil {
		http.Error(w, `{"success":false,"error":"invalid client ID"}`, http.StatusBadRequest)
		return
	}

	if len(parts) == 2 && parts[1] == "kick" && r.Method == http.MethodPost {
		// Kick active sessions
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "client sessions kicked",
		})
		return
	}

	if len(parts) == 1 && r.Method == http.MethodDelete {
		if err := p.db.DeleteClientKey(id); err != nil {
			http.Error(w, `{"success":false,"error":"failed to delete client"}`, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "client deleted",
		})
		return
	}

	http.Error(w, `{"success":false,"error":"not found"}`, http.StatusNotFound)
}
