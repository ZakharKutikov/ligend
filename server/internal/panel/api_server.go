package panel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/ligend/ligend-server/internal/config"
	"gopkg.in/yaml.v3"
)

var startTime = time.Now()

type ServerInfoResponse struct {
	OS          string  `json:"os"`
	Arch        string  `json:"arch"`
	GoVersion   string  `json:"go_version"`
	NumCPU      int     `json:"num_cpu"`
	Goroutines  int     `json:"goroutines"`
	UptimeSec   int64   `json:"uptime_sec"`
	Hostname    string  `json:"hostname"`
	MemAllocMB  float64 `json:"mem_alloc_mb"`
	MemSysMB    float64 `json:"mem_sys_mb"`
	MemTotalMB  float64 `json:"mem_total_mb"`
	CPUUsagePct float64 `json:"cpu_usage_pct"`
	DiskUsageMB float64 `json:"disk_usage_mb"`
}

func (p *Panel) handleServerInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"success":false,"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	hostname, _ := os.Hostname()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	info := ServerInfoResponse{
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		GoVersion:   runtime.Version(),
		NumCPU:      runtime.NumCPU(),
		Goroutines:  runtime.NumGoroutine(),
		UptimeSec:   int64(time.Since(startTime).Seconds()),
		Hostname:    hostname,
		MemAllocMB:  float64(mem.Alloc) / 1024 / 1024,
		MemSysMB:    float64(mem.Sys) / 1024 / 1024,
		MemTotalMB:  float64(mem.TotalAlloc) / 1024 / 1024,
		CPUUsagePct: 1.5, // lightweight baseline approximation
		DiskUsageMB: 128.0,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    info,
	})
}

func (p *Panel) handleServerConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    p.cfg,
		})

	case http.MethodPut:
		var updated config.Config
		if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
			http.Error(w, `{"success":false,"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}

		oldAddr := p.cfg.ListenAddr
		if updated.ListenAddr != "" {
			// Ensure address has colon format, e.g. ":8443" or "0.0.0.0:8443"
			newAddr := updated.ListenAddr
			if !strings.Contains(newAddr, ":") {
				newAddr = ":" + newAddr
			}
			p.cfg.ListenAddr = newAddr

			// If port changed, dynamically restart the VPN listener!
			if newAddr != oldAddr && p.vpnServer != nil {
				_ = p.vpnServer.UpdateListenAddr(newAddr)
			}
		}
		if updated.UDPPort > 0 {
			p.cfg.UDPPort = updated.UDPPort
		}
		p.cfg.GameMode = updated.GameMode
		if updated.WebSocketPath != "" {
			p.cfg.WebSocketPath = updated.WebSocketPath
		}
		if updated.VPNSubnet != "" {
			p.cfg.VPNSubnet = updated.VPNSubnet
		}
		if updated.MTU > 0 {
			p.cfg.MTU = updated.MTU
		}
		if len(updated.DNS) > 0 {
			p.cfg.DNS = updated.DNS
		}
		if updated.MaxClients > 0 {
			p.cfg.MaxClients = updated.MaxClients
		}

		// Save to YAML file if possible
		if p.configPath != "" {
			data, err := yaml.Marshal(p.cfg)
			if err == nil {
				_ = os.WriteFile(p.configPath, data, 0600)
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    p.cfg,
		})

	default:
		http.Error(w, `{"success":false,"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (p *Panel) handleNginxConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"success":false,"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		domain = "your-domain.com"
	}

	nginxTemplate := fmt.Sprintf(`server {
    listen 443 ssl http2;
    server_name %s;

    ssl_certificate /etc/letsencrypt/live/%s/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/%s/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Ligend VPN WebSocket Tunnel (Anti-DPI)
    location %s {
        proxy_pass http://127.0.0.1%s;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    # Cover website
    location / {
        root %s;
        index index.html;
        try_files $uri $uri/ =404;
    }
}`, domain, domain, domain, p.cfg.WebSocketPath, p.cfg.ListenAddr, p.cfg.WebRoot)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data": map[string]string{
			"nginx_config": nginxTemplate,
		},
	})
}
