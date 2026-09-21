package panel

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gorilla/websocket"
	"github.com/ligend/ligend-server/internal/config"
	"github.com/ligend/ligend-server/internal/server"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type Panel struct {
	db         *DB
	auth       *Auth
	vpnServer  *server.Server
	cfg        *config.Config
	configPath string
	logger     *slog.Logger
	logs       *LogBuffer
	httpServer *http.Server
}

func New(db *DB, vpnServer *server.Server, cfg *config.Config, configPath string, logger *slog.Logger) (*Panel, error) {
	auth, err := NewAuth(db)
	if err != nil {
		return nil, fmt.Errorf("create auth: %w", err)
	}

	p := &Panel{
		db:         db,
		auth:       auth,
		vpnServer:  vpnServer,
		cfg:        cfg,
		configPath: configPath,
		logger:     logger,
		logs:       NewLogBuffer(1000),
	}

	p.logs.Add("INFO", "GOmp Studios Panel initialized", "system")
	return p, nil
}

func (p *Panel) Start(port int) error {
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/api/auth/login", p.auth.LoginHandler)

	// Protected routes
	mux.HandleFunc("/api/server/info", p.auth.AuthMiddleware(p.handleServerInfo))
	mux.HandleFunc("/api/server/config", p.auth.AuthMiddleware(p.handleServerConfig))
	mux.HandleFunc("/api/server/nginx", p.auth.AuthMiddleware(p.handleNginxConfig))

	mux.HandleFunc("/api/clients", p.auth.AuthMiddleware(p.handleClients))
	mux.HandleFunc("/api/clients/", p.auth.AuthMiddleware(p.handleClients))

	mux.HandleFunc("/api/stats/overview", p.auth.AuthMiddleware(p.handleStatsOverview))
	mux.HandleFunc("/api/stats/traffic", p.auth.AuthMiddleware(p.handleStatsTraffic))
	mux.HandleFunc("/api/stats/system", p.auth.AuthMiddleware(p.handleStatsSystem))

	mux.HandleFunc("/api/protocol", p.auth.AuthMiddleware(p.handleProtocol))

	mux.HandleFunc("/api/keys", p.auth.AuthMiddleware(p.handleKeys))
	mux.HandleFunc("/api/keys/", p.auth.AuthMiddleware(p.handleKeys))

	mux.HandleFunc("/api/logs", p.auth.AuthMiddleware(p.handleLogs))
	mux.HandleFunc("/api/logs/stream", p.handleLogs)

	// Serve Frontend SPA
	mux.HandleFunc("/", p.serveFrontend)

	addr := fmt.Sprintf(":%d", port)
	p.httpServer = &http.Server{
		Addr:    addr,
		Handler: corsMiddleware(mux),
	}

	p.logger.Info("GOmp Studios Panel starting",
		"port", port,
		"url", fmt.Sprintf("http://localhost:%d", port),
	)

	return p.httpServer.ListenAndServe()
}

func (p *Panel) Shutdown(ctx context.Context) error {
	if p.httpServer != nil {
		return p.httpServer.Shutdown(ctx)
	}
	return nil
}

func (p *Panel) serveFrontend(w http.ResponseWriter, r *http.Request) {
	// Try looking for panel/index.html in various likely paths
	candidates := []string{
		"panel/index.html",
		"../panel/index.html",
		"/etc/ligend/panel/index.html",
		"c:/Users/zakha/Desktop/Ligend/server/panel/index.html",
	}

	for _, c := range candidates {
		if data, err := os.ReadFile(filepath.Clean(c)); err == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(data)
			return
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body><h2>GOmp Studios Ligend Panel</h2><p>Frontend file not found.</p></body></html>")
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
