#!/opt/signing-platform/client/venv/bin/python

import os
import time
import json
import yaml
import socket
import sqlite3
import threading
import logging
import logging.handlers
import requests
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional


CONFIG_PATH = "/opt/signing-platform/client/config/client.yaml"
BASE_DIR = "/opt/signing-platform/client"


def load_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        raise RuntimeError(f"Konnte Konfiguration nicht laden: {e}")


def resolve_path(config_path: str) -> Path:
    p = Path(config_path)
    if not p.is_absolute():
        p = Path(BASE_DIR) / p
    return p.resolve()


def get_log_level(level_name: str) -> int:
    level_name = str(level_name or "INFO").upper()
    return getattr(logging, level_name, logging.INFO)


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


class ResilientLogger:
    def __init__(
        self,
        db_path,
        api_url,
        api_key,
        client_id=None,
        sync_interval_sec=10,
        log_level="INFO",
        tls_verify=True,
        tls_ca_cert=None,
        tls_client_cert=None,
        tls_client_key=None,
    ):
        self.db_path = os.path.expanduser(db_path)
        self.api_url = api_url
        self.api_key = api_key
        self.client_id = client_id or socket.gethostname()
        self.sync_interval_sec = int(sync_interval_sec)
        self.log_level_name = str(log_level or "INFO").upper()
        self.log_level = get_log_level(self.log_level_name)

        self.tls_verify = tls_verify
        self.tls_ca_cert = tls_ca_cert
        self.tls_client_cert = tls_client_cert
        self.tls_client_key = tls_client_key

        logs_dir = "/opt/signing-platform/client/logs"
        os.makedirs(logs_dir, exist_ok=True)
        sync_log_path = os.path.join(logs_dir, "sync.log")

        self.logger = logging.getLogger("signing_client")
        self.logger.setLevel(self.log_level)
        self.logger.propagate = False

        if self.logger.handlers:
            self.logger.handlers.clear()

        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

        console_handler = logging.StreamHandler()
        console_handler.setLevel(self.log_level)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        try:
            syslog_handler = logging.handlers.SysLogHandler(address="/dev/log")
            syslog_handler.setLevel(self.log_level)
            syslog_handler.setFormatter(formatter)
            self.logger.addHandler(syslog_handler)
        except Exception as e:
            self.logger.warning(f"Syslog nicht verfügbar: {e}")

        file_handler = logging.handlers.RotatingFileHandler(
            sync_log_path,
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8"
        )
        file_handler.setLevel(self.log_level)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s - SYNC - %(levelname)s - %(message)s")
        )
        self.logger.addHandler(file_handler)

        self.logger.info(f"Log-Level ist auf {self.log_level_name} gesetzt")
        self.logger.info(
            f"Synchronisations-Logs werden nach {sync_log_path} geschrieben"
        )

        if self.tls_verify is False:
            self.logger.warning("TLS Zertifikatsprüfung ist deaktiviert")
        elif self.tls_ca_cert:
            self.logger.info(f"TLS CA/Zertifikat Datei: {self.tls_ca_cert}")
        else:
            self.logger.info("TLS Zertifikatsprüfung über System Trust Store aktiv")

        if self.tls_client_cert and self.tls_client_key:
            self.logger.info(
                f"TLS Client Zertifikat und Key aktiv: {self.tls_client_cert} / {self.tls_client_key}"
            )
        elif self.tls_client_cert:
            self.logger.info(f"TLS Client Zertifikat aktiv: {self.tls_client_cert}")

        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        self._init_db()

        self.running = True
        self.sync_thread = threading.Thread(target=self._sync_loop, daemon=True)
        self.sync_thread.start()

        self.logger.info(
            f"ResilientLogger gestartet (DB: {self.db_path}, API: {self.api_url})"
        )

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
            conn.commit()

    def _get_requests_verify(self):
        if self.tls_verify is False:
            return False
        if self.tls_ca_cert:
            return self.tls_ca_cert
        return True

    def _get_requests_cert(self):
        if self.tls_client_cert and self.tls_client_key:
            return (self.tls_client_cert, self.tls_client_key)
        if self.tls_client_cert:
            return self.tls_client_cert
        return None

    def log(self, entry: LogEntry):
        payload = asdict(entry)
        payload["client_id"] = self.client_id

        with self._db() as conn:
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO logs
                    (event_id, data, synced, retry_count, next_retry_at)
                    VALUES (?, ?, 0, 0, NULL)
                    """,
                    (entry.event_id, json.dumps(payload, ensure_ascii=False))
                )
                conn.commit()
                self.logger.info(f"Log-Eintrag gespeichert: {entry.event_id}")
            except Exception as e:
                self.logger.error(f"Fehler beim Speichern des Log-Eintrags: {e}")

        try:
            self.logger.info(
                f"EVENT={entry.event_type} FILE={entry.file_path} "
                f"VALID={entry.signature_valid} EXIT={entry.exit_code}"
            )
        except Exception as e:
            self.logger.error(f"Fehler beim Log-Ausgabe-Eintrag: {e}")

    def _sync_loop(self):
        self.logger.info("Sync-Thread gestartet")
        while self.running:
            try:
                self._sync_unsynced()
            except Exception as e:
                self.logger.error(f"Fehler im Sync-Thread: {e}")
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
                (now,)
            ).fetchall()

        unsynced = list(rows)

        if not unsynced:
            self.logger.debug("Keine unsynchronisierten Einträge gefunden.")
            return

        self.logger.info(f"--- {len(unsynced)} Einträge werden synchronisiert ---")

        for row_id, data, retry_count in unsynced:
            try:
                payload = json.loads(data)
            except Exception as e:
                self.logger.error(
                    f"Ungültiger JSON Payload in DB für ID {row_id}: {e}"
                )
                self._mark_retry(row_id, retry_count)
                continue

            headers = {"X-Client-ID": self.client_id}
            if self.api_key:
                headers["X-API-Key"] = self.api_key

            try:
                self.logger.info(
                    f"[Versuch {retry_count + 1}] Eintrag {payload.get('event_id')}:\n"
                    f"  Timestamp: {payload.get('timestamp')}\n"
                    f"  Datei: {payload.get('file_path')}\n"
                    f"  Event: {payload.get('event_type')}"
                )

                r = requests.post(
                    self.api_url,
                    json={"entries": [payload]},
                    headers=headers,
                    timeout=10,
                    verify=self._get_requests_verify(),
                    cert=self._get_requests_cert(),
                )

                if r.status_code == 200:
                    with self._db() as conn:
                        conn.execute(
                            "UPDATE logs SET synced = 1 WHERE id = ?",
                            (row_id,)
                        )
                        conn.commit()

                    self.logger.info(
                        f"ERFOLG: {payload.get('event_id')} | Status: {r.status_code}"
                    )
                else:
                    self._mark_retry(row_id, retry_count)
                    self.logger.warning(
                        f"FEHLGESCHLAGEN: {payload.get('event_id')} | "
                        f"Status: {r.status_code} | Antwort: {r.text}"
                    )

            except requests.exceptions.SSLError as e:
                self._mark_retry(row_id, retry_count)
                self.logger.error(
                    f"TLS/SSL FEHLER: {payload.get('event_id')} | {str(e)}"
                )

            except requests.RequestException as e:
                self._mark_retry(row_id, retry_count)
                self.logger.error(
                    f"NETZWERKFEHLER: {payload.get('event_id')} | {str(e)}"
                )

    def _mark_retry(self, row_id, retry_count):
        wait_seconds = min(3600, 2 ** min(12, retry_count))
        next_retry = datetime.utcfromtimestamp(
            time.time() + wait_seconds
        ).isoformat()

        with self._db() as conn:
            conn.execute(
                """
                UPDATE logs
                SET retry_count = retry_count + 1,
                    next_retry_at = ?
                WHERE id = ?
                """,
                (next_retry, row_id)
            )
            conn.commit()

        self.logger.debug(f"Nächster Versuch für {row_id} um {next_retry}")

    def stop(self):
        self.running = False
        self.sync_thread.join(timeout=5)
        self.logger.info("ResilientLogger beendet")


def validate_tls_config(tls_verify, tls_ca_cert, tls_client_cert, tls_client_key):
    if tls_verify not in (True, False):
        raise RuntimeError("tls_verify muss True oder False sein")

    if tls_ca_cert:
        ca_path = Path(tls_ca_cert)
        if not ca_path.exists():
            raise RuntimeError(
                f"TLS CA/Zertifikat Datei nicht gefunden: {tls_ca_cert}"
            )
        if not ca_path.is_file():
            raise RuntimeError(
                f"TLS CA/Zertifikat Pfad ist keine Datei: {tls_ca_cert}"
            )

    if tls_client_cert:
        cert_path = Path(tls_client_cert)
        if not cert_path.exists():
            raise RuntimeError(
                f"TLS Client Zertifikat nicht gefunden: {tls_client_cert}"
            )
        if not cert_path.is_file():
            raise RuntimeError(
                f"TLS Client Zertifikat Pfad ist keine Datei: {tls_client_cert}"
            )

    if tls_client_key:
        key_path = Path(tls_client_key)
        if not key_path.exists():
            raise RuntimeError(
                f"TLS Client Key nicht gefunden: {tls_client_key}"
            )
        if not key_path.is_file():
            raise RuntimeError(
                f"TLS Client Key Pfad ist keine Datei: {tls_client_key}"
            )

    if tls_client_key and not tls_client_cert:
        raise RuntimeError(
            "tls.client_key ist gesetzt, aber tls.client_cert fehlt"
        )


def main():
    try:
        config = load_config()
    except Exception as e:
        print(f"FEHLER: Konfiguration konnte nicht geladen werden: {e}")
        return 1

    try:
        api_url = config["server"]["base_url"].rstrip("/") + "/client-log"
        api_key = config["server"]["api_key"]
        db_path = resolve_path(config["paths"]["local_log_db"])
        log_level = config.get("logging", {}).get("level", "INFO")

        tls_cfg = config.get("tls", {})
        insecure_skip_verify = bool(tls_cfg.get("insecure_skip_verify", False))
        verify_cfg = bool(tls_cfg.get("verify", True))

        ca_cert_cfg = tls_cfg.get("ca_cert")
        client_cert_cfg = tls_cfg.get("client_cert")
        client_key_cfg = tls_cfg.get("client_key")

        tls_verify = False if insecure_skip_verify else verify_cfg
        tls_ca_cert = str(resolve_path(ca_cert_cfg)) if ca_cert_cfg else None
        tls_client_cert = (
            str(resolve_path(client_cert_cfg)) if client_cert_cfg else None
        )
        tls_client_key = (
            str(resolve_path(client_key_cfg)) if client_key_cfg else None
        )

    except KeyError as e:
        print(f"FEHLER: Ungültige Konfiguration: Fehlender Schlüssel {e}")
        return 1
    except Exception as e:
        print(f"FEHLER: Konfiguration konnte nicht verarbeitet werden: {e}")
        return 1

    try:
        validate_tls_config(
            tls_verify=tls_verify,
            tls_ca_cert=tls_ca_cert,
            tls_client_cert=tls_client_cert,
            tls_client_key=tls_client_key,
        )
    except Exception as e:
        print(f"FEHLER: Ungültige TLS Konfiguration: {e}")
        return 1

    db_path.parent.mkdir(parents=True, exist_ok=True)

    logger = ResilientLogger(
        db_path=str(db_path),
        api_url=api_url,
        api_key=api_key,
        client_id=os.getenv("SIGNING_CLIENT_ID", socket.gethostname()),
        sync_interval_sec=int(os.getenv("SIGNING_LOG_SYNC_INTERVAL", "10")),
        log_level=log_level,
        tls_verify=tls_verify,
        tls_ca_cert=tls_ca_cert,
        tls_client_cert=tls_client_cert,
        tls_client_key=tls_client_key,
    )

    print(f"Gestartet: Log-Sync (DB: {db_path}, API: {api_url})")
    print(f"Log-Level: {str(log_level).upper()}")
    print("Synchronisations-Logs: /opt/signing-platform/client/logs/sync.log")

    if tls_verify is False:
        print("WARNUNG: TLS Zertifikatsprüfung ist deaktiviert")
    elif tls_ca_cert:
        print(f"TLS Prüfung mit CA/Zertifikat: {tls_ca_cert}")
    else:
        print("TLS Prüfung über System Trust Store aktiv")

    if tls_client_cert and tls_client_key:
        print(f"mTLS aktiv mit Client Zertifikat: {tls_client_cert}")

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("Beende auf Benutzeranfrage...")
    finally:
        logger.stop()
        print("Beendet.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())