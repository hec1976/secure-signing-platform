#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/signing-platform/server"
PY_BIN="${PY_BIN:-python3.11}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$INSTALL_DIR/venv"

SERVER_UNIT_FILE="/etc/systemd/system/signing-platform-server.service"
DASHBOARD_UNIT_FILE="/etc/systemd/system/signing-dashboard.service"

command -v "$PY_BIN" >/dev/null 2>&1 || { echo "FEHLER: python fehlt" >&2; exit 1; }
command -v rsync >/dev/null 2>&1 || { echo "FEHLER: rsync fehlt" >&2; exit 1; }

[[ $EUID -eq 0 ]] || { echo "FEHLER: bitte als root ausfuehren" >&2; exit 1; }

mkdir -p "$INSTALL_DIR"

rsync -a --delete \
  --exclude '__pycache__/' \
  --exclude 'venv/' \
  "$SCRIPT_DIR/" "$INSTALL_DIR/"

"$PY_BIN" -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

pip install --upgrade pip setuptools wheel
pip install -r "$INSTALL_DIR/requirements.txt"

mkdir -p "$INSTALL_DIR/keys" "$INSTALL_DIR/audit"
touch "$INSTALL_DIR/audit/audit.log"
touch "$INSTALL_DIR/audit/central_logs.db"

if [[ ! -f "$INSTALL_DIR/systemd/signing-server.service" ]]; then
  echo "FEHLER: $INSTALL_DIR/systemd/signing-server.service nicht gefunden" >&2
  exit 1
fi

if [[ ! -f "$INSTALL_DIR/systemd/signing-dashboard.service" ]]; then
  echo "FEHLER: $INSTALL_DIR/systemd/signing-dashboard.service nicht gefunden" >&2
  exit 1
fi

cp "$INSTALL_DIR/systemd/signing-server.service" "$SERVER_UNIT_FILE"
cp "$INSTALL_DIR/systemd/signing-dashboard.service" "$DASHBOARD_UNIT_FILE"

sed -i "s|/opt/signing-platform/server|$INSTALL_DIR|g" "$SERVER_UNIT_FILE"
sed -i "s|/opt/signing-platform/server|$INSTALL_DIR|g" "$DASHBOARD_UNIT_FILE"

systemctl daemon-reload

systemctl enable signing-platform-server.service >/dev/null 2>&1 || true
systemctl enable signing-dashboard.service >/dev/null 2>&1 || true

systemctl restart signing-platform-server.service
systemctl restart signing-dashboard.service

echo "Installation abgeschlossen."
echo "Server Service:    signing-platform-server.service"
echo "Dashboard Service: signing-dashboard.service"