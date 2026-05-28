#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Entrypoint: runs on container start
# 1. Injects simulated attack logs into /opt/admin/logs
# 2. Starts the SSH daemon
# 3. Starts the Node.js web application
# ─────────────────────────────────────────────────────────────────────────────
set -e

echo "[*] Injecting simulated attack logs..."
/opt/inject-logs.sh

echo "[*] Starting SSH daemon on port 2275..."
/usr/sbin/sshd

echo "[*] Starting Admin Feedback System on port 3075..."
exec node /app/index.js
