#!/usr/bin/env bash
set -Eeuo pipefail

REPO_DIR="${REPO_DIR:-/opt/mammotion-rtk3-reverse-engineering}"
SERVICE_USER="${SERVICE_USER:-$SUDO_USER}"
SERVICE_USER="${SERVICE_USER:-$(id -un)}"

if [[ $EUID -ne 0 ]]; then exec sudo REPO_DIR="$REPO_DIR" SERVICE_USER="$SERVICE_USER" bash "$0" "$@"; fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y git curl ca-certificates tcpdump nmap bluez iproute2 usbutils pciutils net-tools iw rfkill avahi-utils dnsutils socat python3 xxd binutils

if ! command -v node >/dev/null 2>&1 || [[ "$(node -p 'Number(process.versions.node.split(".")[0])')" -lt 20 ]]; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y nodejs
fi

mkdir -p "$REPO_DIR"
if [[ -d "$REPO_DIR/.git" ]]; then
  git -C "$REPO_DIR" fetch origin
  git -C "$REPO_DIR" reset --hard origin/main
else
  git clone https://github.com/guy16510/mammotion-rtk3-reverse-engineering.git "$REPO_DIR"
fi

cd "$REPO_DIR"
npm ci || npm install
chmod +x capture.sh analyze.js install.sh
mkdir -p rtk3-captures
chown -R "$SERVICE_USER:$SERVICE_USER" "$REPO_DIR"

if [[ ! -f /etc/mammotion-rtk3-mcp.env ]]; then
  TOKEN="$(openssl rand -hex 32)"
  cat > /etc/mammotion-rtk3-mcp.env <<EOF
HOST=127.0.0.1
PORT=8787
MCP_BEARER_TOKEN=$TOKEN
RTK3_ROOT=$REPO_DIR
RTK3_CAPTURE_ROOT=$REPO_DIR/rtk3-captures
RTK3_ALLOWED_TARGETS=
RTK3_MAX_CAPTURE_SECONDS=1800
EOF
  chmod 600 /etc/mammotion-rtk3-mcp.env
fi

sed "s|__REPO_DIR__|$REPO_DIR|g; s|__SERVICE_USER__|$SERVICE_USER|g" systemd/mammotion-rtk3-mcp.service > /etc/systemd/system/mammotion-rtk3-mcp.service
systemctl daemon-reload
systemctl enable --now mammotion-rtk3-mcp.service

echo "Installed. Configure RTK3_ALLOWED_TARGETS in /etc/mammotion-rtk3-mcp.env, then restart the service."
echo "Bearer token is stored in /etc/mammotion-rtk3-mcp.env."
