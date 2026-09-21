package panel

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Source    string `json:"source"`
}

type LogBuffer struct {
	entries []LogEntry
	max     int
	mu      sync.RWMutex
}

func NewLogBuffer(max int) *LogBuffer {
	return &LogBuffer{
		entries: make([]LogEntry, 0, max),
		max:     max,
	}
}

func (lb *LogBuffer) Add(level, msg, src string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	entry := LogEntry{
		Timestamp: time.Now().Format("15:04:05.000"),
		Level:     level,
		Message:   msg,
		Source:    src,
	}

	if len(lb.entries) >= lb.max {
		lb.entries = lb.entries[1:]
	}
	lb.entries = append(lb.entries, entry)
}

func (lb *LogBuffer) Recent(limit int) []LogEntry {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	if limit <= 0 || limit > len(lb.entries) {
		limit = len(lb.entries)
	}

	res := make([]LogEntry, limit)
	copy(res, lb.entries[len(lb.entries)-limit:])
	return res
}

func (p *Panel) handleLogs(w http.ResponseWriter, r *http.Request) {
	// If websocket upgrade requested for streaming
	if r.Header.Get("Upgrade") == "websocket" {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				entries := p.logs.Recent(5)
				if len(entries) > 0 {
					data, _ := json.Marshal(entries)
					if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
						return
					}
				}
			}
		}
	}

	// Normal GET /api/logs
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    p.logs.Recent(100),
	})
}
