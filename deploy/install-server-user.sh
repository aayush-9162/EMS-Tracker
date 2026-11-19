#!/usr/bin/env bash
# Installs the EMS server under an ordinary account, with no root access.
#
# For hosting panels (CloudPanel and similar) where you get a site user and
# the panel's own web server already handles HTTPS for the domain and
# forwards it to a local "app port". This runs the EMS server on that port
# and keeps it running with a cron entry.
#
#   ./install-server-user.sh <app-port>
#
# Put this script in a folder together with:
#   ems-server      the Linux server program
#   ems-agent.exe   the Windows agent (optional; lets the console hand out each
#                   organisation's installer, and is what installed agents update to)
#
# Safe to run again: it upgrades the program and keeps the database. A new
# ems-agent.exe is rolled out to the installed computers by the server itself.

set -euo pipefail

PORT="${1:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="$HOME/ems"

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1024 ] || [ "$PORT" -gt 65535 ]; then
  echo "usage: $0 <app-port>   (the local port the panel forwards the site to, e.g. 3000)" >&2
  exit 1
fi
if [ ! -f "$HERE/ems-server" ]; then
  echo "ems-server was not found next to this script ($HERE)." >&2
  exit 1
fi
for tool in flock crontab curl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "This server has no '$tool' command, which this script needs." >&2; exit 1; }
done

echo "==> Installing into $APP"
umask 077
mkdir -p "$APP/data" "$APP/logs"
chmod 700 "$APP"

# If we are not running yet, the port must be free; otherwise it belongs to some other program.
if ! pgrep -u "$(id -u)" -x ems-server >/dev/null 2>&1; then
  if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$PORT\$"; then
    echo "Port $PORT is already in use by another program. Check the app port set for this site in the panel." >&2
    exit 1
  fi
fi

# Replace the program first and stop the old copy afterwards, so that
# whatever starts next (this script or cron) runs the new one.
cp "$HERE/ems-server" "$APP/ems-server.new"
chmod 700 "$APP/ems-server.new"
mv -f "$APP/ems-server.new" "$APP/ems-server"
if [ -f "$HERE/ems-agent.exe" ]; then
  # Copied under another name and renamed into place, so the server never reads half a file.
  cp "$HERE/ems-agent.exe" "$APP/data/ems-agent.exe.new"
  mv -f "$APP/data/ems-agent.exe.new" "$APP/data/ems-agent.exe"
  echo "    agent installers will be downloadable from the console"
fi

cat > "$APP/run.sh" <<EOF
#!/bin/bash
# Starts the EMS server. cron runs this every minute under a lock, so it
# exits at once while the server is running and restarts it if it stopped.
cd "$APP" || exit 1
export EMS_BIND=127.0.0.1:$PORT
export EMS_DATA_DIR="$APP/data"
export EMS_TRUST_PROXY=1
exec ./ems-server >> logs/server.log 2>&1
EOF
chmod 700 "$APP/run.sh"

echo "==> Keeping it running (cron, once a minute)"
LINE="* * * * * /usr/bin/env flock -n $APP/server.lock $APP/run.sh >/dev/null 2>&1"
( crontab -l 2>/dev/null | grep -vF "$APP/run.sh" || true; echo "$LINE" ) | crontab -

echo "==> Starting"
# Stop a previous copy of ours (only this account's own processes can be touched).
pkill -u "$(id -u)" -x ems-server 2>/dev/null || true
for _ in $(seq 1 20); do
  pgrep -u "$(id -u)" -x ems-server >/dev/null 2>&1 || break
  sleep 0.5
done
LOG_BEFORE=0
if [ -f "$APP/logs/server.log" ]; then
  LOG_BEFORE=$(wc -c < "$APP/logs/server.log")
fi
setsid nohup flock -n "$APP/server.lock" "$APP/run.sh" >/dev/null 2>&1 < /dev/null &
STARTED=no
for _ in $(seq 1 30); do
  if curl -fsS -m 2 "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1; then
    STARTED=yes
    break
  fi
  sleep 0.5
done
if [ "$STARTED" != yes ]; then
  echo "The server did not start. Last lines of $APP/logs/server.log:" >&2
  tail -n 15 "$APP/logs/server.log" >&2 || true
  exit 1
fi

echo
echo "==> Done. The server is running on 127.0.0.1:$PORT; open the site's own address in a browser."
# The very first start creates the administrator and prints its password once.
if tail -c "+$((LOG_BEFORE + 1))" "$APP/logs/server.log" 2>/dev/null | grep -q "First start"; then
  tail -c "+$((LOG_BEFORE + 1))" "$APP/logs/server.log" | grep -A 3 "First start" | tail -4
  echo "    Sign in, change the password under Settings, then create the first organisation."
else
  echo "    Sign in with your existing administrator account."
  echo "    Forgotten password: EMS_DATA_DIR=$APP/data $APP/ems-server set-password admin <new-password>"
fi
echo
echo "    The site needs a real certificate (for example Let's Encrypt, issued in the panel):"
echo "    agents refuse to report to a self-signed one."
