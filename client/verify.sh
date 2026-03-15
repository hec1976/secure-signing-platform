#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "FEHLER: $*" >&2
    exit 1
}

# --- Konfiguration ---
CONFIG="/opt/signing-platform/client/config/client.yaml"
FILE=""
VERIFY_ONLY="false"
ALLOW_DIRS=()  # Array explizit initialisieren

# --- Argument-Parsing ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config) CONFIG="${2:-}"; shift 2 ;;
        --file) FILE="${2:-}"; shift 2 ;;
        --verify-only) VERIFY_ONLY="true"; shift ;;
        *) if [[ -z "$FILE" ]]; then FILE="$1"; shift; else break; fi ;;
    esac
done

[[ -n "$FILE" ]] || fail "Kein File angegeben. Usage: $0 [--verify-only] [--config CONFIG] --file DATEI"
[[ -f "$CONFIG" ]] || fail "Config nicht gefunden: $CONFIG"
[[ -f "$FILE" ]] || fail "Datei nicht gefunden: $FILE"

# --- Konfiguration einlesen (mit PYTHONPATH für PyYAML) ---
readarray -t CFG < <(PYTHONPATH=/usr/lib/python3.10/site-packages python3 - <<'PY' "$CONFIG" "$FILE"
import sys, yaml, hashlib
from pathlib import Path

cfg = yaml.safe_load(open(sys.argv[1], 'r', encoding='utf-8')) or {}
file_path = Path(sys.argv[2]).resolve()

# 1. Public Key für Verifizierung
pub_key_path = cfg['paths'].get('active_public_key', '/opt/signing-platform/client/keys/active_public.pem')
print(f"PUB|{pub_key_path}")

# 2. Sicherheitsrichtlinien
print('REQSIG|' + str(cfg['policy'].get('require_sig_file', True)).lower())
print('REQEXEC|' + str(cfg['policy'].get('require_executable_bit', True)).lower())
print('REJCRLF|' + str(cfg['policy'].get('reject_crlf', True)).lower())
print('RNS|' + str(cfg['policy'].get('require_no_symlink', True)).lower())

# 3. Erlaubte Verzeichnisse (falls vorhanden)
for d in cfg['policy'].get('allow_dirs', []):
    print('ALLOW|' + d)

# 4. SHA256 der Datei
with open(file_path, 'rb') as f:
    file_sha = hashlib.sha256(f.read()).hexdigest()
print(f"FILE_SHA256|{file_sha}")
PY
)

# --- Variablen parsen ---
PUBKEY=""
REQSIG="true"
REQEXEC="true"
REJCRLF="true"
RNS="true"
FILE_SHA256=""

for line in "${CFG[@]}"; do
    case "$line" in
        PUB\|*) PUBKEY="${line#PUB|}" ;;
        REQSIG\|*) REQSIG="${line#REQSIG|}" ;;
        REQEXEC\|*) REQEXEC="${line#REQEXEC|}" ;;
        REJCRLF\|*) REJCRLF="${line#REJCRLF|}" ;;
        RNS\|*) RNS="${line#RNS|}" ;;
        ALLOW\|*) ALLOW_DIRS+=("${line#ALLOW|}") ;;  # Array füllen
        FILE_SHA256\|*) FILE_SHA256="${line#FILE_SHA256|}" ;;
    esac
done

# --- Sicherheitsprüfungen ---
echo "[CHECK] Prüfe Datei: $FILE"

# 1. Signaturdatei (falls erforderlich)
SIG="${FILE}.sig"
if [[ "$REQSIG" == "true" && ! -f "$SIG" ]]; then
    fail "Signatur fehlt: $SIG"
fi

# 2. Erlaubter Pfad (nur prüfen, wenn allow_dirs definiert sind)
if [[ ${#ALLOW_DIRS[@]} -gt 0 ]]; then
    real="$(readlink -f "$FILE")"
    ok="false"
    for d in "${ALLOW_DIRS[@]}"; do
        dreal="$(readlink -f "$d" 2>/dev/null || true)"
        [[ -n "$dreal" && "$real" == "$dreal/"* ]] && ok="true" && break
    done
    [[ "$ok" == "true" ]] || echo "WARN: Pfad $real ist möglicherweise nicht erlaubt" >&2
fi

# 3. CRLF-Prüfung
if [[ "$REJCRLF" == "true" ]] && file "$FILE" | grep -qi 'CRLF'; then
    fail "Datei enthält CRLF-Zeilenumbrüche (nicht erlaubt)"
fi

# 4. Ausführbarkeitsbit (falls Ausführung geplant)
if [[ "$VERIFY_ONLY" != "true" && "$REQEXEC" == "true" && ! -x "$FILE" ]]; then
    fail "Datei ist nicht ausführbar (chmod +x fehlend)"
fi

# --- Aufruf von verify.py ---
echo "[VERIFY] Starte Signaturprüfung mit verify.py..."
VERIFY_ARGS=(
    "$FILE"
    --pub "$PUBKEY"
    --config "$CONFIG"
)

[[ "$RNS" == "true" ]] && VERIFY_ARGS+=(--require-no-symlink)

# Ausführung nur, wenn nicht --verify-only
if [[ "$VERIFY_ONLY" != "true" ]]; then
    echo "[EXEC] Führe Skript nach erfolgreicher Prüfung aus"
    PYTHONPATH=/usr/lib/python3.10/site-packages python3 /opt/signing-platform/client/bin/verify.py "${VERIFY_ARGS[@]}" && bash "$FILE"
    EXIT_CODE=$?
else
    echo "[VERIFY] Nur Prüfung (--verify-only)"
    PYTHONPATH=/usr/lib/python3.10/site-packages python3 /opt/signing-platform/client/bin/verify.py "${VERIFY_ARGS[@]}"
    EXIT_CODE=$?
fi

exit "$EXIT_CODE"
