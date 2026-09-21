#!/bin/bash
set -euo pipefail

# ═══════════════════════════════════════════════════════
# Ligend VPN Server — Auto Setup Script
# For Ubuntu 22.04+ / Debian 12+
# Run as root: sudo bash setup.sh
# ═══════════════════════════════════════════════════════

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info() { echo -e "${CYAN}[INFO]${NC} $1"; }
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check root
[[ $EUID -ne 0 ]] && err "Run as root: sudo bash setup.sh"

echo ""
echo "═══════════════════════════════════════════"
echo "  Ligend VPN Server — Setup"
echo "═══════════════════════════════════════════"
echo ""

# ─── Get domain ───
read -p "Enter your domain (e.g., myblog.example.com): " DOMAIN
[[ -z "$DOMAIN" ]] && err "Domain is required"

read -p "Enter your email (for Let's Encrypt): " EMAIL
[[ -z "$EMAIL" ]] && err "Email is required"

# ─── Install dependencies ───
info "Installing dependencies..."
apt-get update -qq
apt-get install -y -qq wget curl git nginx certbot python3-certbot-nginx iptables-persistent > /dev/null 2>&1
ok "Dependencies installed"

# ─── Install Go ───
GO_VERSION="1.22.5"
if ! command -v go &> /dev/null; then
    info "Installing Go ${GO_VERSION}..."
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    export PATH=$PATH:/usr/local/go/bin
    ok "Go ${GO_VERSION} installed"
else
    ok "Go already installed: $(go version)"
fi

# ─── Build Ligend ───
info "Building Ligend server..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_DIR="$(dirname "$SCRIPT_DIR")"

cd "$SERVER_DIR"
go mod tidy
go build -o /usr/local/bin/ligend-server ./cmd/ligend-server/
go build -o /usr/local/bin/ligend-keygen ./cmd/ligend-keygen/
chmod +x /usr/local/bin/ligend-server /usr/local/bin/ligend-keygen
ok "Ligend binaries built"

# ─── Generate keys ───
info "Generating secret key and WebSocket path..."
mkdir -p /etc/ligend

# Generate 32-byte key
SECRET_KEY=$(openssl rand -base64 32)

# Generate random WebSocket path (16 hex chars)
WS_PATH="/$(openssl rand -hex 8)"

ok "Key generated"

# ─── Create config ───
cat > /etc/ligend/ligend.yaml << EOF
listen_addr: ":8443"
ws_path: "${WS_PATH}"
secret_key: "${SECRET_KEY}"
vpn_subnet: "10.8.0.0/24"
tun_name: "ligend0"
mtu: 1280
dns:
  - "1.1.1.1"
  - "8.8.8.8"
web_root: "${SERVER_DIR}/web"
padding_min_sec: 3
padding_max_sec: 15
max_clients: 254
EOF
chmod 600 /etc/ligend/ligend.yaml
ok "Config created at /etc/ligend/ligend.yaml"

# ─── Enable IP forwarding ───
info "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-ligend.conf
sysctl --system > /dev/null 2>&1
ok "IP forwarding enabled"

# ─── Configure iptables NAT ───
info "Configuring NAT..."
# Detect default interface
DEFAULT_IF=$(ip route show default | awk '/default/ {print $5}' | head -1)
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$DEFAULT_IF" -j MASQUERADE
iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT
iptables -A FORWARD -d 10.8.0.0/24 -j ACCEPT
netfilter-persistent save > /dev/null 2>&1 || true
ok "NAT configured (interface: $DEFAULT_IF)"

# ─── Setup Nginx ───
info "Configuring Nginx..."

# Create Nginx config with correct domain and WS path
cat > /etc/nginx/sites-available/ligend << NGINXEOF
server {
    listen 80;
    server_name ${DOMAIN};
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ${DOMAIN};

    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 1.1.1.1 8.8.8.8 valid=300s;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=63072000" always;

    location ${WS_PATH} {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Request-ID \$http_x_request_id;
        proxy_set_header X-Timestamp \$http_x_timestamp;
        proxy_set_header X-Nonce \$http_x_nonce;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }

    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }

    location ~ /\\. { deny all; }
}
NGINXEOF

ln -sf /etc/nginx/sites-available/ligend /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
ok "Nginx configured"

# ─── Get TLS certificate ───
info "Obtaining TLS certificate from Let's Encrypt..."
# Temporarily stop nginx for standalone cert
systemctl stop nginx 2>/dev/null || true
certbot certonly --standalone -d "$DOMAIN" --email "$EMAIL" --agree-tos --non-interactive || {
    warn "Certbot failed. Make sure DNS A record points to this server."
    warn "You can run manually: certbot certonly --standalone -d $DOMAIN"
}
ok "TLS certificate obtained"

# ─── Install systemd service ───
info "Installing systemd service..."
cp "${SERVER_DIR}/configs/ligend.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable ligend
ok "Systemd service installed"

# ─── Start services ───
info "Starting services..."
systemctl start ligend
systemctl start nginx
ok "Services started"

# ─── Print summary ───
echo ""
echo "═══════════════════════════════════════════════════"
echo -e "  ${GREEN}Ligend VPN Server — Setup Complete!${NC}"
echo "═══════════════════════════════════════════════════"
echo ""
echo -e "${CYAN}Server Config:${NC} /etc/ligend/ligend.yaml"
echo ""
echo -e "${CYAN}Android Client Settings:${NC}"
echo "  Server Address: ${DOMAIN}"
echo "  Server Port:    443"
echo "  Secret Path:    ${WS_PATH#/}"
echo "  Secret Key:     ${SECRET_KEY}"
echo "  CDN Mode:       false"
echo ""
echo -e "${CYAN}Useful commands:${NC}"
echo "  Status:   systemctl status ligend"
echo "  Logs:     journalctl -u ligend -f"
echo "  Restart:  systemctl restart ligend"
echo "  Nginx:    systemctl restart nginx"
echo ""
echo -e "${YELLOW}Optional — Cloudflare CDN Mode:${NC}"
echo "  1. Add domain to Cloudflare (free plan)"
echo "  2. Enable 'Proxied' (orange cloud) for DNS A record"
echo "  3. In Cloudflare SSL/TLS: set to 'Full (Strict)'"
echo "  4. In Android app: enable CDN Mode"
echo ""
