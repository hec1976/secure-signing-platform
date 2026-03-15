#!/usr/bin/env python3

import argparse
import base64
import hashlib
import logging
import sys
import warnings
from pathlib import Path
from typing import Any

import requests
import yaml
from requests.packages.urllib3.exceptions import InsecureRequestWarning


BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = BASE_DIR / "config" / "client.yaml"


def setup_logging(level_name: str) -> None:
    level = getattr(logging, str(level_name).upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s"
    )


def load_cfg(path: Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError("Konfigurationsdatei ist kein gueltiges YAML Dictionary")
    return data


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def build_tls_verify(cfg: dict[str, Any]) -> bool | str:
    tls_cfg = cfg.get("tls", {}) or {}

    verify = tls_cfg.get("verify", True)
    insecure_skip_verify = tls_cfg.get("insecure_skip_verify", False)
    ca_file = tls_cfg.get("ca_file")

    if insecure_skip_verify:
        warnings.simplefilter("ignore", InsecureRequestWarning)
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        logging.warning("TLS Zertifikatspruefung ist deaktiviert")
        return False

    if ca_file:
        ca_path = Path(str(ca_file)).expanduser().resolve()
        if not ca_path.is_file():
            raise FileNotFoundError(f"CA-Datei nicht gefunden: {ca_path}")
        return str(ca_path)

    return bool(verify)


def get_server_cfg(cfg: dict[str, Any]) -> dict[str, Any]:
    server_cfg = cfg.get("server")
    if not isinstance(server_cfg, dict):
        raise KeyError("Abschnitt 'server' fehlt in der Konfiguration")
    return server_cfg


def get_sign_url(cfg: dict[str, Any], override: str | None = None) -> str:
    if override:
        return override.rstrip("/") + "/sign"

    server_cfg = get_server_cfg(cfg)
    base_url = str(server_cfg["base_url"]).rstrip("/")
    return base_url + "/sign"


def get_api_key(cfg: dict[str, Any], override: str | None = None) -> str:
    if override:
        return override

    server_cfg = get_server_cfg(cfg)
    api_key = server_cfg.get("api_key")
    if not api_key:
        raise KeyError("server.api_key fehlt in der Konfiguration")
    return str(api_key)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Datei via REST API signieren")
    parser.add_argument("file", help="Pfad zur Datei, die signiert werden soll")
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG),
        help="Pfad zur client.yaml"
    )
    parser.add_argument(
        "--url",
        default=None,
        help="Optionale Basis-URL des Servers, z. B. https://host:8443"
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="Optionaler API-Key Override"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="HTTP Timeout in Sekunden"
    )
    return parser.parse_args()


def save_signature(sig_path: Path, signature_b64: str) -> None:
    raw_signature = base64.b64decode(signature_b64)
    with open(sig_path, "wb") as f:
        f.write(raw_signature)


def main() -> int:
    args = parse_args()

    config_path = Path(args.config).expanduser().resolve()
    if not config_path.is_file():
        print(f"FEHLER: Konfigurationsdatei nicht gefunden: {config_path}")
        return 2

    try:
        cfg = load_cfg(config_path)
    except Exception as e:
        print(f"FEHLER: Konfiguration konnte nicht geladen werden: {e}")
        return 2

    log_level = cfg.get("logging", {}).get("level", "INFO")
    setup_logging(str(log_level))

    try:
        endpoint = get_sign_url(cfg, args.url)
        api_key = get_api_key(cfg, args.api_key)
        tls_verify = build_tls_verify(cfg)
    except Exception as e:
        print(f"FEHLER: Ungueltige Konfiguration: {e}")
        return 2

    file_path = Path(args.file).expanduser().resolve()
    if not file_path.is_file():
        print(f"FEHLER: Datei nicht gefunden: {file_path}")
        return 2

    local_sha = sha256_file(file_path)
    headers = {"X-API-Key": api_key}

    logging.info("Starte Signierung")
    logging.info("Datei: %s", file_path)
    logging.info("Endpoint: %s", endpoint)

    try:
        with open(file_path, "rb") as f:
            response = requests.post(
                endpoint,
                headers=headers,
                files={"file": (file_path.name, f, "application/octet-stream")},
                timeout=args.timeout,
                verify=tls_verify,
            )
    except requests.RequestException as e:
        print(f"FEHLER: Server nicht erreichbar: {e}")
        return 4

    if response.status_code != 200:
        print(f"FEHLER: HTTP {response.status_code}")
        print(response.text)
        return 4

    try:
        data = response.json()
    except Exception as e:
        print(f"FEHLER: Ungueltige Serverantwort: {e}")
        return 4

    signature_b64 = data.get("signature_b64")
    if not signature_b64:
        print("FEHLER: Antwort enthaelt kein Feld 'signature_b64'")
        return 4

    sig_path = Path(str(file_path) + ".sig")

    try:
        save_signature(sig_path, signature_b64)
    except Exception as e:
        print(f"FEHLER: Signatur konnte nicht gespeichert werden: {e}")
        return 5

    server_sha = data.get("sha256_hex")
    key_id = data.get("key_id")

    print(f"OK: Signatur gespeichert: {sig_path}")
    print(f"LOCAL_SHA256: {local_sha}")
    print(f"SERVER_SHA256: {server_sha}")
    print(f"KEY_ID: {key_id}")

    if server_sha and server_sha != local_sha:
        print("WARNUNG: Lokaler SHA256 und Server SHA256 sind unterschiedlich")
        return 6

    return 0


if __name__ == "__main__":
    sys.exit(main())