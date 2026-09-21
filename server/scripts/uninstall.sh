#!/bin/bash
#
# Ligend VPN — Uninstaller by GOmp Studios
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}"
echo "  ╔════════════════════════════════════════╗"
echo "  ║  Ligend VPN — Удаление                ║"
echo "  ╚════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${YELLOW}Это удалит Ligend VPN Server полностью.${NC}"
echo -n "Продолжить? (y/N): "
read -r CONFIRM

if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    echo "Отменено."
    exit 0
fi

echo -e "${CYAN}[1/6]${NC} Остановка сервиса..."
systemctl stop ligend 2>/dev/null || true
systemctl disable ligend 2>/dev/null || true

echo -e "${CYAN}[2/6]${NC} Удаление systemd unit..."
rm -f /etc/systemd/system/ligend.service
systemctl daemon-reload

echo -e "${CYAN}[3/6]${NC} Удаление бинарника..."
rm -f /usr/local/bin/ligend-server
rm -f /usr/bin/ligend-server

echo -e "${CYAN}[4/6]${NC} Удаление Nginx конфигурации..."
rm -f /etc/nginx/sites-enabled/ligend
rm -f /etc/nginx/sites-available/ligend
systemctl restart nginx 2>/dev/null || true

echo -e "${CYAN}[5/6]${NC} Очистка iptables..."
DEFAULT_IFACE=$(ip route show default | awk '/default/ {print $5}' | head -1)
if [[ -n "$DEFAULT_IFACE" ]]; then
    iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o "$DEFAULT_IFACE" -j MASQUERADE 2>/dev/null || true
fi

echo -e "${CYAN}[6/6]${NC} Удаление файлов конфигурации..."
echo -n "Удалить /etc/ligend (конфиг + БД)? (y/N): "
read -r DEL_CONF
if [[ "$DEL_CONF" == "y" || "$DEL_CONF" == "Y" ]]; then
    rm -rf /etc/ligend
    echo -e "${GREEN}Конфигурация удалена${NC}"
else
    echo -e "${YELLOW}Конфигурация сохранена в /etc/ligend${NC}"
fi

echo ""
echo -e "${GREEN}✓ Ligend VPN успешно удалён.${NC}"
