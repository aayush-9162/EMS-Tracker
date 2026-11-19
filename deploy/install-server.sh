#!/usr/bin/env bash
# Sets up the EMS server on a Debian or Ubuntu VPS in one step.
#
#   sudo ./install-server.sh ems.example.com   # HTTPS on that name (recommended)
#   sudo ./install-server.sh                   # no name yet: plain HTTP on port 2021
#
# Put this script in a folder together with:
#   ems-server      the Linux server program
#   ems-agent.exe   the Windows agent (optional; lets the console hand out a ready-made installer)
#
# Safe to run again: it upgrades the program and keeps the database.

set -euo pipefail

DOMAIN="${1:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA=/var/lib/ems

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this with sudo." >&2
  exit 1
fi
if [ ! -f "$HERE/ems-server" ]; then
  echo "ems-server was not found next to this script ($HERE)." >&2
  exit 1
fi
if [ -n "$DOMAIN" ] && ! printf '%s' "$DOMAIN" | grep -Eq '^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'; then
  echo "\"$DOMAIN\" does not look like a domain name such as ems.example.com." >&2
  exit 1
fi

echo "==> Installing the EMS server"
id ems >/dev/null 2>&1 || useradd --system --home "$DATA" --shell /usr/sbin/nologin ems
install -d -o ems -g ems -m 750 "$DATA"
systemctl stop ems-server 2>/dev/null || true
install -m 755 "$HERE/ems-server" /usr/local/bin/ems-server
if [ -f "$HERE/ems-agent.exe" ]; then
  # Copied under another name and renamed into place, so the server never reads half a file.
  install -o ems -g ems -m 644 "$HERE/ems-agent.exe" "$DATA/ems-agent.exe.new"
  mv -f "$DATA/ems-agent.exe.new" "$DATA/ems-agent.exe"
  echo "    agent installer will be downloadable from the console"
fi

# Behind Caddy the server listens on this machine only; without a name it is reached directly.
if [ -n "$DOMAIN" ]; then
  BIND=127.0.0.1:2021
  TRUST_PROXY=1
else
  BIND=0.0.0.0:2021
  TRUST_PROXY=0
fi

cat > /etc/systemd/system/ems-server.service <<EOF
[Unit]
Description=EMS server
After=network-online.target
Wants=network-online.target

[Service]
User=ems
Group=ems
WorkingDirectory=$DATA
ExecStart=/usr/local/bin/ems-server
Environment=EMS_BIND=$BIND
Environment=EMS_DATA_DIR=$DATA
Environment=EMS_TRUST_PROXY=$TRUST_PROXY
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DATA

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now ems-server

if [ -n "$DOMAIN" ]; then
  echo "==> Setting up HTTPS for $DOMAIN"
  if ! command -v caddy >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y caddy
  fi
  install -d /etc/caddy
  touch /etc/caddy/Caddyfile
  # Add our site; anything already configured in Caddy is left as it is.
  if ! grep -q "^$DOMAIN[[:space:]]*{" /etc/caddy/Caddyfile; then
    printf '\n%s {\n\treverse_proxy 127.0.0.1:2021\n}\n' "$DOMAIN" >> /etc/caddy/Caddyfile
  fi
  systemctl enable --now caddy
  systemctl reload caddy
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow 80/tcp >/dev/null
    ufw allow 443/tcp >/dev/null
  fi
  ADDRESS="https://$DOMAIN"
else
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow 2021/tcp >/dev/null
  fi
  ADDRESS="http://$(hostname -I 2>/dev/null | awk '{print $1}'):2021"
fi

sleep 2
if ! systemctl is-active --quiet ems-server; then
  echo "The server did not start. See: journalctl -u ems-server -n 50" >&2
  exit 1
fi

echo
echo "==> Done. Open $ADDRESS"
# The very first start creates the administrator and prints its password once.
if journalctl -u ems-server --no-pager 2>/dev/null | grep -q "First start"; then
  journalctl -u ems-server --no-pager | grep -A 3 "First start" | tail -4
  echo "    Sign in, then change the password under Settings."
else
  echo "    Sign in with your existing administrator account."
  echo "    Forgotten password: sudo -u ems EMS_DATA_DIR=$DATA /usr/local/bin/ems-server set-password admin <new-password>"
fi
if [ -z "$DOMAIN" ]; then
  echo
  echo "    Note: without a domain name the connection is not encrypted."
  echo "    Point a name at this server and run this script again with it to switch to HTTPS."
fi
