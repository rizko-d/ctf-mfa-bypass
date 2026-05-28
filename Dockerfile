# ─────────────────────────────────────────────────────────────────────────────
# CTF Lab: Admin Feedback System
# Base OS: Alpine Linux (lightweight, Proxmox-friendly)
# Web app port: 3075 | SSH port: 2275
# ─────────────────────────────────────────────────────────────────────────────

FROM node:18-alpine

LABEL maintainer="CTF Lab Developer"
LABEL description="Red vs. Blue CTF Lab – Cookies Reuse & MFA Bypass"

# ── System packages ───────────────────────────────────────────────────────────
RUN apk add --no-cache \
    openssh \
    bash \
    shadow

# ── SSH setup ─────────────────────────────────────────────────────────────────
# Generate host keys
RUN ssh-keygen -A

# Patch sshd_config: custom port 2275, password auth on, no root
RUN sed -i 's/#Port 22/Port 2275/' /etc/ssh/sshd_config 2>/dev/null || true && \
    echo "Port 2275"                     >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes"   >> /etc/ssh/sshd_config && \
    echo "PermitRootLogin no"           >> /etc/ssh/sshd_config && \
    echo "ChallengeResponseAuthentication no" >> /etc/ssh/sshd_config

# Create Blue Team analyst user (credentials: analyst / blue_team_rocks)
RUN adduser -D -s /bin/bash analyst && \
    echo "analyst:blue_team_rocks" | chpasswd

# ── Log directory ──────────────────────────────────────────────────────────────
RUN mkdir -p /opt/admin/logs && chmod 777 /opt/admin/logs

# ── Application ────────────────────────────────────────────────────────────────
WORKDIR /app
COPY app/package*.json ./
RUN npm install --production
COPY app/index.js ./

# ── Scripts ───────────────────────────────────────────────────────────────────
COPY scripts/inject-logs.sh /opt/inject-logs.sh
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /opt/inject-logs.sh /entrypoint.sh

# ── Expose ports ──────────────────────────────────────────────────────────────
EXPOSE 3075
EXPOSE 2275

CMD ["/entrypoint.sh"]
