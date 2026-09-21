package panel

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	lcrypto "github.com/ligend/ligend-server/internal/crypto"
)

func (p *Panel) handleKeys(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	path := strings.TrimPrefix(r.URL.Path, "/api/keys")
	path = strings.TrimPrefix(path, "/")

	if path == "generate" && r.Method == http.MethodPost {
		keyBytes, err := lcrypto.GenerateKey()
		if err != nil {
			http.Error(w, `{"success":false,"error":"generate key failed"}`, http.StatusInternalServerError)
			return
		}
		b64 := base64.StdEncoding.EncodeToString(keyBytes)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data": map[string]string{
				"key": b64,
			},
		})
		return
	}

	if strings.HasPrefix(path, "uri/") && r.Method == http.MethodGet {
		idStr := strings.TrimPrefix(path, "uri/")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			http.Error(w, `{"success":false,"error":"invalid key ID"}`, http.StatusBadRequest)
			return
		}

		keys, _ := p.db.ListClientKeys()
		var found *ClientKey
		for _, k := range keys {
			if k.ID == id {
				found = &k
				break
			}
		}

		if found == nil {
			http.Error(w, `{"success":false,"error":"key not found"}`, http.StatusNotFound)
			return
		}

		domain := "legendprotocol.duckdns.org"
		port := "443"
		cleanPath := strings.TrimPrefix(p.cfg.WebSocketPath, "/")
		uri := fmt.Sprintf("ligend://%s:%s/%s?key=%s&transport=ws&fp=chrome", domain, port, cleanPath, found.SecretKey)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data": map[string]string{
				"uri":  uri,
				"name": found.Name,
			},
		})
		return
	}

	http.Error(w, `{"success":false,"error":"not found"}`, http.StatusNotFound)
}
