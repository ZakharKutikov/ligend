package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/ligend/ligend-server/internal/config"
	"github.com/ligend/ligend-server/internal/panel"
	"github.com/ligend/ligend-server/internal/server"
)

func main() {
	configPath := flag.String("config", "/etc/ligend/ligend.yaml", "Path to configuration file")
	dbPath := flag.String("db", "/etc/ligend/ligend.db", "Path to SQLite database")
	panelPortFlag := flag.Int("panel-port", 0, "GOmp Studios Panel port (0 for auto/random saved in DB)")
	flag.Parse()

	// Setup structured logging
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	logger.Info("Ligend VPN Server starting",
		"version", "3.5.0",
		"config", *configPath,
		"studio", "GOmp Studios",
	)

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Validate secret key
	if _, err := cfg.SecretKey(); err != nil {
		logger.Error("invalid secret key", "error", err)
		os.Exit(1)
	}

	// Create VPN server
	srv, err := server.New(cfg, logger)
	if err != nil {
		logger.Error("failed to create server", "error", err)
		os.Exit(1)
	}

	// Initialize SQLite Database for GOmp Studios Panel
	_ = os.MkdirAll(filepath.Dir(*dbPath), 0755)
	db, err := panel.NewDB(*dbPath)
	if err != nil {
		logger.Warn("could not init sqlite db at given path, fallback to local ligend.db", "error", err)
		db, err = panel.NewDB("ligend.db")
		if err != nil {
			logger.Error("failed to create panel database", "error", err)
			os.Exit(1)
		}
	}

	// Determine Panel Port (like 3X-UI: random port saved in DB if not set)
	panelPort := *panelPortFlag
	if panelPort == 0 {
		savedPortStr, _ := db.GetPanelConfig("panel_port")
		if savedPortStr != "" {
			panelPort, _ = strconv.Atoi(savedPortStr)
		}
		if panelPort == 0 {
			// Generate random port between 10000 and 60000 (like 3X-UI)
			panelPort = 10000 + rand.Intn(50000)
			_ = db.SetPanelConfig("panel_port", strconv.Itoa(panelPort))
		}
	}

	// Create GOmp Studios Management Panel
	p, err := panel.New(db, srv, cfg, *configPath, logger)
	if err != nil {
		logger.Error("failed to create management panel", "error", err)
		os.Exit(1)
	}

	// Start Panel in background
	go func() {
		logger.Info("==================================================")
		logger.Info("🚀 GOmp Studios Panel (Ligend v3.5) is running!")
		logger.Info(fmt.Sprintf("🔗 URL: http://0.0.0.0:%d", panelPort))
		logger.Info("👤 Default Login: admin / admin")
		logger.Info("==================================================")
		if err := p.Start(panelPort); err != nil {
			logger.Error("panel server error", "error", err)
		}
	}()

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)

		shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 10*time.Second)
		defer shutdownCancel()

		_ = p.Shutdown(shutdownCtx)
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("shutdown error", "error", err)
		}
		cancel()
	}()

	// Start VPN server
	if err := srv.Start(); err != nil {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
}
