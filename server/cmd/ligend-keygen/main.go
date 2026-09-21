package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"strings"
)

const (
	keySize    = 32 // 256-bit key
	pathChars  = "abcdefghijklmnopqrstuvwxyz0123456789"
	pathLength = 16
)

func main() {
	fmt.Println("=== Ligend VPN — Key Generator ===")
	fmt.Println()

	// Generate secret key
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
		os.Exit(1)
	}
	keyB64 := base64.StdEncoding.EncodeToString(key)

	// Generate random WebSocket path
	var pathBuilder strings.Builder
	pathBuilder.WriteByte('/')
	for i := 0; i < pathLength; i++ {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(pathChars))))
		pathBuilder.WriteByte(pathChars[idx.Int64()])
	}
	wsPath := pathBuilder.String()

	// Output
	fmt.Println("Generated credentials:")
	fmt.Println()
	fmt.Println("Secret Key (base64):")
	fmt.Printf("  %s\n", keyB64)
	fmt.Println()
	fmt.Println("WebSocket Path:")
	fmt.Printf("  %s\n", wsPath)
	fmt.Println()

	fmt.Println("─── Server Config (ligend.yaml) ───")
	fmt.Println()
	fmt.Printf("listen_addr: \":8443\"\n")
	fmt.Printf("ws_path: \"%s\"\n", wsPath)
	fmt.Printf("secret_key: \"%s\"\n", keyB64)
	fmt.Printf("vpn_subnet: \"10.8.0.0/24\"\n")
	fmt.Printf("tun_name: \"ligend0\"\n")
	fmt.Printf("mtu: 1280\n")
	fmt.Printf("dns:\n")
	fmt.Printf("  - \"1.1.1.1\"\n")
	fmt.Printf("  - \"8.8.8.8\"\n")
	fmt.Printf("web_root: \"./web\"\n")
	fmt.Printf("padding_min_sec: 3\n")
	fmt.Printf("padding_max_sec: 15\n")
	fmt.Printf("max_clients: 254\n")
	fmt.Println()

	fmt.Println("─── Android Client Config ───")
	fmt.Println()
	fmt.Printf("Server Address: <YOUR_DOMAIN>\n")
	fmt.Printf("Server Port:    443\n")
	fmt.Printf("Secret Path:    %s\n", wsPath[1:]) // without leading /
	fmt.Printf("Secret Key:     %s\n", keyB64)
	fmt.Printf("CDN Mode:       false\n")
	fmt.Println()

	fmt.Println("─── Quick Start ───")
	fmt.Println()
	fmt.Println("1. Copy the Server Config to /etc/ligend/ligend.yaml")
	fmt.Println("2. Enter the Android Client Config into the Ligend app")
	fmt.Println("3. Start the server: systemctl start ligend")
	fmt.Println("4. Connect from the Android app")
}
