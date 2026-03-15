#!/usr/bin/env bash
set -euo pipefail

# Client Basisverzeichnis bestimmen
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BIN="$BASE_DIR/bin/sign.py"
CONFIG="$BASE_DIR/config/client.yaml"

if [[ $# -lt 1 ]]; then
  echo "Usage:"
  echo "  sign.sh <file>"
  exit 1
fi

FILE="$1"

if [[ ! -f "$FILE" ]]; then
  echo "FEHLER: Datei nicht gefunden: $FILE"
  exit 2
fi

# Python ausführen
exec python3.11 "$BIN" "$FILE" --config "$CONFIG"