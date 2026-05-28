#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# inject-logs.sh
# Seeds /opt/admin/logs/access.log and error.log with a realistic attack
# timeline for Blue Team log forensics.
#
# All CTF flags embedded per the SCENARIO75{answer} format spec.
# ─────────────────────────────────────────────────────────────────────────────

LOG_DIR="/opt/admin/logs"
ACCESS_LOG="$LOG_DIR/access.log"
ERROR_LOG="$LOG_DIR/error.log"

mkdir -p "$LOG_DIR"

# Reset logs on each deploy (fresh scenario)
> "$ACCESS_LOG"
> "$ERROR_LOG"

# ─────────────────────────────────────────────────────────────────────────────
# BASELINE: Legitimate admin traffic from 192.168.1.100
# SCENARIO75{192.168.1.100}
# ─────────────────────────────────────────────────────────────────────────────

cat >> "$ACCESS_LOG" << 'BASELINE'
192.168.1.100 - admin [2024-06-15 18:44:01] "GET / HTTP/1.1" 200 4521 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36" X-Forwarded-For: -
192.168.1.100 - admin [2024-06-15 18:44:10] "POST /api/login HTTP/1.1" 302 - "/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" X-Forwarded-For: -
192.168.1.100 - admin [2024-06-15 18:44:11] "GET /feedback HTTP/1.1" 200 3215 "/api/login" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" X-Forwarded-For: -
192.168.1.100 - admin [2024-06-15 18:44:25] "POST /api/feedback HTTP/1.1" 200 512 "/feedback" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" X-Forwarded-For: -
192.168.1.100 - admin [2024-06-15 18:44:30] "GET /api/verify-mfa HTTP/1.1" 200 2048 "/feedback" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" X-Forwarded-For: -
192.168.1.100 - admin [2024-06-15 18:44:35] "POST /api/verify-mfa HTTP/1.1" 302 - "/api/verify-mfa" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" X-Forwarded-For: -
192.168.1.100 - admin [2024-06-15 18:44:36] "GET /dashboard HTTP/1.1" 200 8432 "/api/verify-mfa" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" X-Forwarded-For: -
BASELINE

cat >> "$ERROR_LOG" << 'BASELINE_ERR'
[2024-06-15 18:44:36] [INFO] Legitimate admin session created for 192.168.1.100 — session adm_sess_4dm1n_s3cr3t_t0k3n_2024
BASELINE_ERR

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1: Attacker Reconnaissance (SCENARIO75{10.10.14.50}, SCENARIO75{Mozilla/5.0})
# Attacker subnet: 10.10.14.0/24 (SCENARIO75{10.10.14.0/24})
# ─────────────────────────────────────────────────────────────────────────────

cat >> "$ACCESS_LOG" << 'RECON'
10.10.14.50 - - [2024-06-15 18:48:50] "GET / HTTP/1.1" 200 4521 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" X-Forwarded-For: -
10.10.14.50 - - [2024-06-15 18:48:55] "GET /robots.txt HTTP/1.1" 200 62 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" X-Forwarded-For: -
10.10.14.50 - - [2024-06-15 18:49:02] "GET /api/verify-mfa HTTP/1.1" 200 2048 "/robots.txt" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" X-Forwarded-For: -
10.10.14.50 - - [2024-06-15 18:49:10] "GET /dashboard HTTP/1.1" 403 512 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" X-Forwarded-For: -
10.10.14.50 - - [2024-06-15 18:49:20] "GET /feedback HTTP/1.1" 200 3215 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" X-Forwarded-For: -
RECON

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2: WAF evasion attempts
# First <script> block at 18:50:15 (SCENARIO75{18:50:15}, SCENARIO75{<script>})
# Error log: /opt/admin/logs/error.log (SCENARIO75{/opt/admin/logs/error.log})
# ─────────────────────────────────────────────────────────────────────────────

cat >> "$ACCESS_LOG" << 'WAF_ATTEMPTS'
10.10.14.50 - - [2024-06-15 18:50:15] "POST /api/feedback HTTP/1.1" 403 89 "/feedback" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" X-Forwarded-For: -
10.10.14.50 - - [2024-06-15 18:50:33] "POST /api/feedback HTTP/1.1" 403 89 "/feedback" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" X-Forwarded-For: -
WAF_ATTEMPTS

# First WAF block entry — MUST be at 18:50:15 for SCENARIO75{18:50:15}
cat >> "$ERROR_LOG" << 'WAF_ERR'
[2024-06-15 18:50:15] [WARN] WAF BLOCK from 10.10.14.50: detected payload "<script>" at /api/feedback
[2024-06-15 18:50:33] [WARN] WAF BLOCK from 10.10.14.50: detected payload "document.cookie" at /api/feedback
WAF_ERR

# Attacker finds <svg> bypass (SCENARIO75{<svg>}) + obfuscated cookie access
# window['docu'+'ment']['coo'+'kie'] — passes WAF
cat >> "$ACCESS_LOG" << 'XSS_SUCCESS'
10.10.14.50 - - [2024-06-15 18:51:10] "POST /api/feedback HTTP/1.1" 200 512 "/feedback" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" X-Forwarded-For: -
XSS_SUCCESS

cat >> "$ERROR_LOG" << 'XSS_INFO'
[2024-06-15 18:51:10] [INFO] Feedback accepted from 10.10.14.50 — SVG/obfuscated payload bypassed WAF checks
XSS_INFO

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3: Session Replay / Dashboard Access (SCENARIO75{18:51:55}, SCENARIO75{200})
# X-Forwarded-For header contains Base64 encoded exfil string
# SCENARIO75{UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0}
# Decoded: PHANTOMGRID{BLUE_L0g_Hunt3r_M4st3r}
# String length: 44 chars (SCENARIO75{44}) → encoding: Base64 (SCENARIO75{Base64})
# ─────────────────────────────────────────────────────────────────────────────

# NOTE: The attacker's IP (10.10.14.50) NEVER hits /api/verify-mfa after the
# WAF bypass — it goes straight to /dashboard with the stolen cookie.
# SCENARIO75{No} — attacker's IP never reached the MFA endpoint post-exploit.

cat >> "$ACCESS_LOG" << 'SESSION_REPLAY'
10.10.14.50 - - [2024-06-15 18:51:55] "GET /dashboard HTTP/1.1" 200 8432 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" X-Forwarded-For: UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0
SESSION_REPLAY

# CRITICAL: Authentication bypass + cookie reuse events (SCENARIO75{CRITICAL})
cat >> "$ERROR_LOG" << 'BYPASS_ERR'
[2024-06-15 18:51:55] [CRITICAL] Authentication bypass anomaly detected from 10.10.14.50 - session cookie replayed without MFA
[2024-06-15 18:51:55] [CRITICAL] Cookie reuse detected - session adm_sess_4dm1n_s3cr3t... accessed /dashboard from 10.10.14.50
BYPASS_ERR

# Post-exploitation browsing
cat >> "$ACCESS_LOG" << 'POST_EXPLOIT'
10.10.14.50 - - [2024-06-15 18:52:05] "GET /dashboard HTTP/1.1" 200 8432 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" X-Forwarded-For: -
10.10.14.50 - - [2024-06-15 18:52:20] "GET /api/users HTTP/1.1" 404 32 "/dashboard" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" X-Forwarded-For: -
10.10.14.50 - - [2024-06-15 18:52:45] "GET /api/export HTTP/1.1" 404 32 "/dashboard" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" X-Forwarded-For: -
POST_EXPLOIT

# Anomaly timestamp at 18:53:10 — EXACT string: "Authentication bypass anomaly"
# SCENARIO75{18:53:10}, SCENARIO75{Authentication bypass anomaly}
cat >> "$ERROR_LOG" << 'ANOMALY'
[2024-06-15 18:53:10] [CRITICAL] Authentication bypass anomaly — repeated unauthorized access to /dashboard from 10.10.14.50 without completing MFA verification
ANOMALY

# Return to baseline traffic
cat >> "$ACCESS_LOG" << 'TRAIL_BASELINE'
192.168.1.100 - admin [2024-06-15 18:54:00] "GET /dashboard HTTP/1.1" 200 8432 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" X-Forwarded-For: -
192.168.1.100 - admin [2024-06-15 18:55:30] "GET / HTTP/1.1" 200 4521 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" X-Forwarded-For: -
TRAIL_BASELINE

cat >> "$ERROR_LOG" << 'TRAIL_INFO'
[2024-06-15 18:55:30] [INFO] Routine admin access from 192.168.1.100
TRAIL_INFO

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
echo "[+] Logs injected into $LOG_DIR"
echo "    access.log : $(wc -l < "$ACCESS_LOG") lines"
echo "    error.log  : $(wc -l < "$ERROR_LOG") lines"

# Verify the Base64 exfil string length (must be 44)
B64="UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0"
echo "    Base64 string length: ${#B64} chars (expected: 44)"
echo "    Decoded: $(echo "$B64" | base64 -d 2>/dev/null || echo '[base64 decode failed]')"
