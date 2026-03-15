#!/usr/bin/env python3

import argparse
import hashlib
import json
import logging
import logging.handlers
import os
import socket
import sqlite3
import threading
import time
import uuid
import warnings
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

import requests
import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from requests.packages.urllib3.exceptions import InsecureRequestWarning


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = BASE_DIR / "config" / "client.yaml"


@dataclass
class LogEntry:
    event_id: str
    timestamp: str
    hostname: str
    username: str
    event_type: str
    file_path: str
    sha256: Optional[str] = None
    signature_valid: Optional[bool] = None
    executed: Optional[bool] = None
    exit_code: Optional[int] = None
    detail: Optional[str] = None


class ResilientLogger:
    def __init__(
        self,
        db_path: str,
        api_url: str,
        api_key: Optional[str],
        client_id: Optional[str] = None,
        sync_interval_sec: int = 10,
        tls_verify: Union[bool, str] = True,
    ):
        self.db_path = os.path.abspath(db_path)
        self.api_url = api_url
        self.api_key = api_key
        self.client_id = client_id or socket.gethostname()
        self.sync_interval_sec = int(sync_interval_sec)
        self.tls_verify = tls_verify

        log_dir = os.path.dirname(self.db_path)
        os.makedirs(log_dir, mode=0o755, exist_ok=True)

        self._init_db()
        self.running = True
        self.sync_thread = threading.Thread(target=self._sync_loop, daemon=True)
        self.sync_thread.start()

        self.syslog = logging.getLogger("signing_client")
        self.syslog.setLevel(logging.INFO)
        try:
            self.syslog.addHandler(logging.handlers.SysLogHandler(address="/dev/log"))
        except Exception:
            pass

    def _db(self):
        return sqlite3.connect(self.db_path, timeout=10)

    def _init_db(self):
        with self._db() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE,
                    data TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    synced INTEGER DEFAULT 0,
                    retry_count INTEGER DEFAULT 0,
                    next_retry_at TEXT
                )
                """
            )

    def log(self, entry: LogEntry) -> None:
        payload = asdict(entry)
        payload["client_id"] = self.client_id

        with self._db() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO logs
                (event_id, data, synced, retry_count, next_retry_at)
                VALUES (?, ?, 0, 0, NULL)
                """,
                (entry.event_id, json.dumps(payload, ensure_ascii=False)),
            )

        try:
            audit_log_path = os.path.join(os.path.dirname(self.db_path), "audit.log")
            with open(audit_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"WARN: Audit-Log konnte nicht geschrieben werden: {e}")

    def _sync_loop(self):
        while self.running:
            try:
                self._sync_unsynced()
            except Exception as e:
                print(f"WARN: Synchronisationsfehler: {e}")
            time.sleep(self.sync_interval_sec)

    def _sync_unsynced(self):
        now = datetime.utcnow().isoformat()
        with self._db() as conn:
            rows = conn.execute(
                """
                SELECT id, data, retry_count
                FROM logs
                WHERE synced = 0
                  AND (next_retry_at IS NULL OR next_retry_at <= ?)
                ORDER BY id
                LIMIT 100
                """,
                (now,),
            ).fetchall()

        for row_id, data, retry_count in rows:
            payload = json.loads(data)
            headers = {"X-Client-ID": self.client_id}
            if self.api_key:
                headers["X-API-Key"] = self.api_key

            try:
                response = requests.post(
                    self.api_url,
                    json={"entries": [payload]},
                    headers=headers,
                    timeout=5,
                    verify=self.tls_verify,
                )
                if response.status_code == 200:
                    with self._db() as conn:
                        conn.execute("UPDATE logs SET synced = 1 WHERE id = ?", (row_id,))
                else:
                    self._mark_retry(row_id, int(retry_count))
            except requests.RequestException as e:
                print(f"WARN: Server-Synchronisation fehlgeschlagen: {e}")
                self._mark_retry(row_id, int(retry_count))

    def _mark_retry(self, row_id: int, retry_count: int):
        next_retry = datetime.utcfromtimestamp(
            time.time() + min(3600, 2 ** min(12, retry_count))
        ).isoformat()
        with self._db() as conn:
            conn.execute(
                """
                UPDATE logs
                SET retry_count = retry_count + 1,
                    next_retry_at = ?
                WHERE id = ?
                """,
                (next_retry, row_id),
            )

    def stop(self):
        self.running = False
        self.sync_thread.join(timeout=5)


def load_cfg(path: Union[str, Path]) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def resolve_path(path_value: str, base_dir: Path) -> Path:
    p = Path(path_value).expanduser()
    if not p.is_absolute():
        p = base_dir / p
    return p.resolve()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> Optional[str]:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def build_tls_verify(cfg: dict) -> Union[bool, str]:
    tls_cfg = cfg.get("tls", {}) or {}

    verify = tls_cfg.get("verify", True)
    insecure_skip_verify = tls_cfg.get("insecure_skip_verify", False)
    ca_file = tls_cfg.get("ca_file")

    if isinstance(verify, str):
        verify_lower = verify.strip().lower()
        if verify_lower in ("false", "no", "0"):
            verify = False
        elif verify_lower in ("true", "yes", "1"):
            verify = True

    if isinstance(insecure_skip_verify, str):
        skip_lower = insecure_skip_verify.strip().lower()
        insecure_skip_verify = skip_lower in ("true", "yes", "1")

    if insecure_skip_verify:
        warnings.simplefilter("ignore", InsecureRequestWarning)
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        return False

    if ca_file:
        ca_path = resolve_path(ca_file, BASE_DIR)
        if not ca_path.is_file():
            raise RuntimeError(f"CA-Datei nicht gefunden: {ca_path}")
        return str(ca_path)

    return bool(verify)


def get_headers(cfg: dict) -> dict:
    headers = {}
    api_key = cfg.get("server", {}).get("api_key")
    if api_key:
        headers["X-API-Key"] = str(api_key)
    return headers


def get_public_key_url(cfg: dict) -> str:
    server_cfg = cfg.get("server", {}) or {}
    base_url = str(server_cfg.get("base_url", "")).rstrip("/")
    endpoint = str(server_cfg.get("public_key_endpoint", "/public-key")).strip()

    if not base_url:
        raise RuntimeError("server.base_url fehlt in der Konfiguration")

    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        return endpoint

    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint

    return base_url + endpoint


def get_client_log_url(cfg: dict) -> str:
    server_cfg = cfg.get("server", {}) or {}
    base_url = str(server_cfg.get("base_url", "")).rstrip("/")
    endpoint = str(server_cfg.get("client_log_endpoint", "/client-log")).strip()

    if not base_url:
        raise RuntimeError("server.base_url fehlt in der Konfiguration")

    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        return endpoint

    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint

    return base_url + endpoint


def ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def load_public_key(path: Path) -> ed25519.Ed25519PublicKey:
    with open(path, "rb") as f:
        key = serialization.load_pem_public_key(f.read())

    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError("Geladener Public Key ist kein Ed25519 Public Key")

    return key


def _extract_pem_from_response(response: requests.Response) -> bytes:
    text = response.text.strip()
    content_type = (response.headers.get("Content-Type") or "").lower()

    # JSON immer zuerst behandeln
    if "application/json" in content_type or text.startswith("{"):
        try:
            obj = response.json()
        except Exception as e:
            raise RuntimeError(f"JSON Antwort konnte nicht gelesen werden: {e}")

        public_key = (
            obj.get("public_key_pem")
            or obj.get("public_key")
            or obj.get("pem")
            or obj.get("key")
        )

        if not public_key:
            raise RuntimeError(
                "JSON Antwort enthält kein Feld "
                "'public_key_pem', 'public_key', 'pem' oder 'key'"
            )

        if not isinstance(public_key, str):
            raise RuntimeError("Public Key Feld in JSON ist kein String")

        cleaned = public_key.strip().replace("\\n", "\n").replace('\\"', '"')

        if "-----BEGIN PUBLIC KEY-----" not in cleaned:
            raise RuntimeError("JSON Feld enthält keinen gültigen PEM Inhalt")

        return cleaned.encode("utf-8")

    # Danach nur echtes rohes PEM akzeptieren
    raw = response.content.strip()
    if raw.startswith(b"-----BEGIN PUBLIC KEY-----"):
        if not raw.endswith(b"\n"):
            raw += b"\n"
        return raw

    # Fallback für Plaintext mit escaped Zeilenumbrüchen
    cleaned = text.strip().strip('"').replace("\\n", "\n").replace('\\"', '"')
    if cleaned.startswith("-----BEGIN PUBLIC KEY-----"):
        if not cleaned.endswith("\n"):
            cleaned += "\n"
        return cleaned.encode("utf-8")

    preview = text[:200].replace("\n", "\\n")
    raise RuntimeError(
        f"Antwort enthält keinen gültigen PEM Public Key. "
        f"Content-Type={content_type}, Anfang={preview!r}"
    )


def fetch_public_key_from_server(cfg: dict, tls_verify: Union[bool, str]) -> bytes:
    url = get_public_key_url(cfg)
    headers = get_headers(cfg)

    response = requests.get(url, headers=headers, timeout=10, verify=tls_verify)
    response.raise_for_status()

    pem_data = _extract_pem_from_response(response)

    try:
        key = serialization.load_pem_public_key(pem_data)
    except Exception as e:
        preview = pem_data[:200].decode("utf-8", errors="replace").replace("\n", "\\n")
        raise RuntimeError(
            f"Public-Key-Inhalt ist kein gültiges PEM. "
            f"HTTP {response.status_code}, Content-Type={response.headers.get('Content-Type')}, "
            f"PEM-Anfang={preview!r}, Fehler={e}"
        )

    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise RuntimeError("Server lieferte keinen Ed25519 Public Key")

    return pem_data


def update_public_key_if_needed(
    cfg: dict,
    local_pub_path: Path,
    tls_verify: Union[bool, str],
    logger: Optional[ResilientLogger] = None,
) -> ed25519.Ed25519PublicKey:
    ensure_parent_dir(local_pub_path)

    remote_pem = fetch_public_key_from_server(cfg, tls_verify)
    remote_hash = sha256_bytes(remote_pem)
    local_hash = sha256_file(local_pub_path)

    if local_hash != remote_hash:
        tmp_path = local_pub_path.with_suffix(local_pub_path.suffix + ".tmp")
        with open(tmp_path, "wb") as f:
            f.write(remote_pem)
        os.replace(tmp_path, local_pub_path)

        print(f"INFO: Public Key aktualisiert: {local_pub_path}")

        if logger:
            logger.log(
                LogEntry(
                    event_id=str(uuid.uuid4()),
                    timestamp=datetime.now().isoformat(),
                    hostname=socket.gethostname(),
                    username=os.getenv("USER", "unknown"),
                    event_type="public_key_updated",
                    file_path=str(local_pub_path),
                    sha256=remote_hash,
                    signature_valid=None,
                    executed=False,
                    exit_code=0,
                    detail="Public Key vom Webservice aktualisiert",
                )
            )
    else:
        print(f"INFO: Public Key ist aktuell: {local_pub_path}")

    return load_public_key(local_pub_path)


def verify_file(
    file_path: Path,
    sig_path: Path,
    pub_key: ed25519.Ed25519PublicKey,
    require_no_symlink: bool,
    logger: Optional[ResilientLogger],
) -> int:
    if not file_path.is_file():
        print(f"FAIL: Datei nicht gefunden: {file_path}")
        return 2

    if not sig_path.is_file():
        print(f"FAIL: Signatur nicht gefunden: {sig_path}")
        return 2

    if require_no_symlink and (file_path.is_symlink() or sig_path.is_symlink()):
        print(f"FAIL: Symlink nicht erlaubt für {file_path}")
        return 3

    with open(file_path, "rb") as f:
        data = f.read()

    with open(sig_path, "rb") as f:
        sig = f.read()

    sha256_hex = hashlib.sha256(data).hexdigest()

    try:
        pub_key.verify(sig, data)
        print(f"OK: {file_path}")
        print("SHA256:", sha256_hex)

        if logger:
            logger.log(
                LogEntry(
                    event_id=str(uuid.uuid4()),
                    timestamp=datetime.now().isoformat(),
                    hostname=socket.gethostname(),
                    username=os.getenv("USER", "unknown"),
                    event_type="signature_verification",
                    file_path=str(file_path),
                    sha256=sha256_hex,
                    signature_valid=True,
                    executed=True,
                    exit_code=0,
                )
            )
        return 0

    except InvalidSignature:
        print(f"FAIL: Ungültige Signatur für {file_path}")
        print("SHA256:", sha256_hex)

        if logger:
            logger.log(
                LogEntry(
                    event_id=str(uuid.uuid4()),
                    timestamp=datetime.now().isoformat(),
                    hostname=socket.gethostname(),
                    username=os.getenv("USER", "unknown"),
                    event_type="signature_verification",
                    file_path=str(file_path),
                    sha256=sha256_hex,
                    signature_valid=False,
                    executed=True,
                    exit_code=1,
                )
            )
        return 1

    except Exception as e:
        print(f"FAIL: Fehler bei {file_path}: {e}")
        print("SHA256:", sha256_hex)

        if logger:
            logger.log(
                LogEntry(
                    event_id=str(uuid.uuid4()),
                    timestamp=datetime.now().isoformat(),
                    hostname=socket.gethostname(),
                    username=os.getenv("USER", "unknown"),
                    event_type="signature_verification_error",
                    file_path=str(file_path),
                    sha256=sha256_hex,
                    signature_valid=False,
                    executed=False,
                    exit_code=1,
                    detail=str(e),
                )
            )
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify detached signatures with automatic public key update from webservice"
    )
    parser.add_argument("files", nargs="+", help="Pfade zu den Dateien")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="Pfad zur client.yaml")
    parser.add_argument("--pub", default=None, help="Optionaler Pfad zum lokalen Public Key")
    parser.add_argument("--require-no-symlink", action="store_true", help="Symlinks verbieten")
    args = parser.parse_args()

    try:
        cfg = load_cfg(args.config)
    except Exception as e:
        print(f"FAIL: Konfiguration konnte nicht geladen werden: {e}")
        return 2

    try:
        tls_verify = build_tls_verify(cfg)
    except Exception as e:
        print(f"FAIL: TLS-Konfiguration ungültig: {e}")
        return 2

    paths_cfg = cfg.get("paths", {}) or {}

    if args.pub:
        pub_path = Path(args.pub).expanduser().resolve()
    else:
        pub_path_value = paths_cfg.get("active_public_key", "./keys/active_public.pem")
        pub_path = resolve_path(pub_path_value, BASE_DIR)

    db_path_value = paths_cfg.get("log_db", "./logs/client_logs.db")
    db_path = str(resolve_path(db_path_value, BASE_DIR))

    sync_interval = int(cfg.get("logging", {}).get("sync_interval_sec", 10))

    logger = None
    try:
        logger = ResilientLogger(
            db_path=db_path,
            api_url=get_client_log_url(cfg),
            api_key=cfg.get("server", {}).get("api_key"),
            client_id=socket.gethostname(),
            sync_interval_sec=sync_interval,
            tls_verify=tls_verify,
        )
        print(f"INFO: Logging aktiviert. SQLite: {db_path}")
    except Exception as e:
        print(f"WARN: Logging konnte nicht initialisiert werden: {e}")

    try:
        pub_key = update_public_key_if_needed(cfg, pub_path, tls_verify, logger=logger)
    except Exception as e:
        print(f"FAIL: Public Key konnte nicht vom Webservice geladen oder aktualisiert werden: {e}")
        if logger:
            logger.log(
                LogEntry(
                    event_id=str(uuid.uuid4()),
                    timestamp=datetime.now().isoformat(),
                    hostname=socket.gethostname(),
                    username=os.getenv("USER", "unknown"),
                    event_type="public_key_update_error",
                    file_path=str(pub_path),
                    sha256=None,
                    signature_valid=None,
                    executed=False,
                    exit_code=2,
                    detail=str(e),
                )
            )
            logger.stop()
        return 2

    exit_code = 0

    for file_arg in args.files:
        file_path = Path(file_arg).expanduser().resolve()
        sig_path = Path(str(file_path) + ".sig").expanduser().resolve()

        result = verify_file(
            file_path=file_path,
            sig_path=sig_path,
            pub_key=pub_key,
            require_no_symlink=args.require_no_symlink,
            logger=logger,
        )
        if result > exit_code:
            exit_code = result

    if logger:
        logger.stop()

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())