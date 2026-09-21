package config

import (
	"encoding/base64"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds all server configuration.
type Config struct {
	ListenAddr      string   `yaml:"listen_addr"`
	UDPPort         int      `yaml:"udp_port"` // UDP port for AmneziaWG 3.1 engine (default 51820)
	GameMode        bool     `yaml:"game_mode"` // Ultra-low latency gaming mode (zero delay, zero padding)
	WebSocketPath   string   `yaml:"ws_path"`
	SecretKeyBase64 string   `yaml:"secret_key"`
	VPNSubnet       string   `yaml:"vpn_subnet"`
	TUNName         string   `yaml:"tun_name"`
	MTU             int      `yaml:"mtu"`
	DNS             []string `yaml:"dns"`
	WebRoot         string   `yaml:"web_root"`
	PaddingMin      int      `yaml:"padding_min_sec"`
	PaddingMax      int      `yaml:"padding_max_sec"`
	MaxClients      int      `yaml:"max_clients"`
	// AmneziaWG 3.1 Obfuscation Parameters
	AWGJc   int    `yaml:"awg_jc"`   // Junk packet count (default 4)
	AWGJmin int    `yaml:"awg_jmin"` // Junk packet min size (default 40)
	AWGJmax int    `yaml:"awg_jmax"` // Junk packet max size (default 70)
	AWGH1   uint32 `yaml:"awg_h1"`   // Handshake init header magic
	AWGH2   uint32 `yaml:"awg_h2"`   // Handshake response header magic
	AWGH3   uint32 `yaml:"awg_h3"`   // Cookie reply header magic
	AWGH4   uint32 `yaml:"awg_h4"`   // Transport data header magic
}

// Defaults returns a Config with sane defaults.
func Defaults() *Config {
	return &Config{
		ListenAddr:      ":8443",
		UDPPort:         51820,
		GameMode:        true,
		WebSocketPath:   "/ws",
		VPNSubnet:       "10.8.0.0/24",
		TUNName:         "ligend0",
		MTU:             1280,
		DNS:             []string{"1.1.1.1", "8.8.8.8"},
		WebRoot:         "./web",
		PaddingMin:      3,
		PaddingMax:      15,
		MaxClients:      254,
		AWGJc:           4,
		AWGJmin:         40,
		AWGJmax:         70,
		AWGH1:           0x7391b4a2,
		AWGH2:           0x51c3d9e8,
		AWGH3:           0x3f2a8c1e,
		AWGH4:           0x9b4a1e7d,
	}
}

// Load reads and parses a YAML config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := Defaults()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// SecretKey decodes the base64 secret key.
func (c *Config) SecretKey() ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(c.SecretKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("decode secret key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("secret key must be 32 bytes, got %d", len(key))
	}
	return key, nil
}
