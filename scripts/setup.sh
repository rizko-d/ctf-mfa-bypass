#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# setup.sh — Proxmox VM Provisioning Script
# Run this ONCE inside the Ubuntu/Debian VM that will host the CTF lab.
# Installs Docker, Docker Compose, sets up networking, and deploys the lab.
# ─────────────────────────────────────────────────────────────────────────────
set -e

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=================================================="
echo " CTF Lab: Red vs. Blue — Setup Script"
echo " Target: Proxmox VM (Ubuntu 22.04 recommended)"
echo "=================================================="

# ── 1. Update system ──────────────────────────────────────────────────────────
echo "[1/5] Updating system packages..."
apt-get update -qq && apt-get upgrade -y -qq

# ── 2. Install Docker ─────────────────────────────────────────────────────────
echo "[2/5] Installing Docker & Docker Compose..."
if ! command -v docker &>/dev/null; then
  apt-get install -y -qq ca-certificates curl gnupg lsb-release
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin
  systemctl enable docker
  systemctl start docker
  echo "  [OK] Docker installed"
else
  echo "  [SKIP] Docker already installed"
fi

# ── 3. Add /etc/hosts entry for lab hostname ──────────────────────────────────
echo "[3/5] Configuring hostname resolution..."
if ! grep -q "feedback.admin.local" /etc/hosts; then
  echo "127.0.0.1  feedback.admin.local" >> /etc/hosts
  echo "  [OK] Added feedback.admin.local → /etc/hosts"
else
  echo "  [SKIP] Already in /etc/hosts"
fi

# ── 4. Open firewall ports ─────────────────────────────────────────────────────
echo "[4/5] Configuring UFW firewall..."
if command -v ufw &>/dev/null; then
  ufw allow 3075/tcp comment "CTF Web App"  || true
  ufw allow 2275/tcp comment "CTF SSH"      || true
  echo "  [OK] Ports 3075 and 2275 opened"
else
  echo "  [SKIP] UFW not found — configure firewall manually"
fi

# ── 5. Build & deploy lab ─────────────────────────────────────────────────────
echo "[5/5] Building and deploying CTF lab..."
cd "$REPO_DIR"
docker compose down --remove-orphans 2>/dev/null || true
docker compose up -d --build

echo ""
echo "=================================================="
echo " ✅  Lab deployed successfully!"
echo "=================================================="
echo ""
echo "  Web App  → http://feedback.admin.local:3075"
echo "  SSH      → ssh analyst@feedback.admin.local -p 2275"
echo "  Password → blue_team_rocks"
echo ""
echo "  Logs     → /opt/admin/logs (inside container)"
echo "  View     → docker exec admin-feedback-system cat /opt/admin/logs/access.log"
echo ""
