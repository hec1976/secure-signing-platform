#!/usr/bin/env python3

import os
import json
import ipaddress
import base64
import hashlib
import sqlite3
import hmac
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any

import bcrypt
import yaml
from fastapi import FastAPI, UploadFile, File, Header, HTTPException, Request, BackgroundTasks
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa

from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
)


BASE_DIR = Path(__file__).resolve().parents[1]
CONFIG_PATH = Path(
    os.getenv("SIGNING_SERVER_CONFIG", BASE_DIR / "config" / "service.yaml")
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_config() -> dict:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def resolve_path(raw: str) -> Path:
    path = Path(raw)
    if path.is_absolute():
        return path
    return (BASE_DIR / path).resolve()


def model_to_dict(obj: Any) -> dict:
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    return obj.dict()


def sha256_digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def looks_like_bcrypt(value: str) -> bool:
    return value.startswith("$2a$") or value.startswith("$2b$") or value.startswith("$2y$")


CFG = load_config()

SERVICE = CFG.get("service", {})
SECURITY = CFG.get("security", {})
PATHS = CFG.get("paths", {})
TLS = CFG.get("tls", {})

HOST = str(SERVICE.get("host", "0.0.0.0"))
PORT = int(SERVICE.get("port", 8000))
KEY_ALGO = str(SERVICE.get("key_algorithm", "Ed25519"))
ACTIVE_KEY_ID = str(SERVICE.get("active_key_id", "ed25519-2026-01"))
MAX_UPLOAD = int(SERVICE.get("max_upload_bytes", 10 * 1024 * 1024))

ALLOW_NO_API_KEYS = bool(SECURITY.get("allow_no_api_keys", False))
ALLOW_LEGACY_PLAINTEXT_KEYS = bool(SECURITY.get("allow_legacy_plaintext_keys", False))

RAW_API_KEYS = [str(x).strip() for x in SECURITY.get("api_keys", []) if str(x).strip()]
BCRYPT_API_KEYS = [x for x in RAW_API_KEYS if looks_like_bcrypt(x)]
PLAINTEXT_API_KEYS = [x for x in RAW_API_KEYS if not looks_like_bcrypt(x)]

KEY_DIR = resolve_path(PATHS.get("key_dir", "./keys"))
AUDIT_LOG = resolve_path(PATHS.get("audit_log", "./audit/audit.log"))
CENTRAL_DB = resolve_path(PATHS.get("central_audit_db", "./audit/central_logs.db"))
KEY_METADATA = resolve_path(PATHS.get("key_metadata", "./keys/keys.json"))

TLS_ENABLED = bool(TLS.get("enabled", False))
TLS_AUTO_GENERATE_SELF_SIGNED = bool(TLS.get("auto_generate_self_signed", False))
TLS_CERT_FILE = TLS.get("cert_file")
TLS_KEY_FILE = TLS.get("key_file")
TLS_CA_FILE = TLS.get("ca_file")
TLS_REQUIRE_CLIENT_CERT = bool(TLS.get("require_client_cert", False))
TLS_MIN_VERSION = str(TLS.get("min_version", "TLSv1_2"))
TLS_SELF_SIGNED = TLS.get("self_signed", {}) or {}

TLS_CERT_PATH = resolve_path(TLS_CERT_FILE) if TLS_CERT_FILE else None
TLS_KEY_PATH = resolve_path(TLS_KEY_FILE) if TLS_KEY_FILE else None
TLS_CA_PATH = resolve_path(TLS_CA_FILE) if TLS_CA_FILE else None

for path in [KEY_DIR, AUDIT_LOG.parent, CENTRAL_DB.parent, KEY_METADATA.parent]:
    path.mkdir(parents=True, exist_ok=True)

if TLS_CERT_PATH:
    TLS_CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
if TLS_KEY_PATH:
    TLS_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)


def audit(event: Dict[str, Any]) -> None:
    record = dict(event)
    record["ts_utc"] = utc_now()

    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as exc:
        print(f"WARNING audit write failed: {exc}")


def validate_auth_config() -> None:
    if not RAW_API_KEYS and not ALLOW_NO_API_KEYS:
        raise RuntimeError(
            "Keine API Keys konfiguriert. "
            "Setze security.api_keys oder explizit security.allow_no_api_keys: true."
        )


def ensure_self_signed_cert_if_needed() -> None:
    if not TLS_ENABLED:
        return

    if not TLS_CERT_PATH or not TLS_KEY_PATH:
        raise RuntimeError(
            "TLS ist aktiviert, aber cert_file oder key_file fehlt in der Konfiguration."
        )

    cert_exists = TLS_CERT_PATH.exists()
    key_exists = TLS_KEY_PATH.exists()

    if cert_exists and key_exists:
        return

    if not TLS_AUTO_GENERATE_SELF_SIGNED:
        missing = []
        if not cert_exists:
            missing.append(str(TLS_CERT_PATH))
        if not key_exists:
            missing.append(str(TLS_KEY_PATH))
        raise RuntimeError(
            "TLS Dateien fehlen und auto_generate_self_signed ist deaktiviert. "
            f"Fehlend: {', '.join(missing)}"
        )

    country = str(TLS_SELF_SIGNED.get("country", "CH"))
    state = str(TLS_SELF_SIGNED.get("state", "ZH"))
    locality = str(TLS_SELF_SIGNED.get("locality", "Zürich"))
    organization = str(TLS_SELF_SIGNED.get("organization", "heclab"))
    organizational_unit = str(TLS_SELF_SIGNED.get("organizational_unit", "NDS Sec"))
    common_name = str(TLS_SELF_SIGNED.get("common_name", "localhost"))

    dns_names = [str(x) for x in TLS_SELF_SIGNED.get("dns_names", ["localhost"])]
    ip_addresses = [str(x) for x in TLS_SELF_SIGNED.get("ip_addresses", ["127.0.0.1"])]

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    san_entries = []
    for name in dns_names:
        san_entries.append(x509.DNSName(name))

    for ip_str in ip_addresses:
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(ip_str)))
        except ValueError:
            pass

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=5))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=private_key, algorithm=hashes.SHA256())
    )

    TLS_KEY_PATH.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    TLS_CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    try:
        os.chmod(TLS_KEY_PATH, 0o600)
    except Exception:
        pass

    audit(
        {
            "event": "tls_self_signed_generated",
            "cert_file": str(TLS_CERT_PATH),
            "key_file": str(TLS_KEY_PATH),
            "common_name": common_name,
        }
    )


def validate_tls_config() -> None:
    if not TLS_ENABLED:
        return

    if not TLS_CERT_PATH or not TLS_KEY_PATH:
        raise RuntimeError(
            "TLS ist aktiviert, aber cert_file oder key_file fehlt in der Konfiguration."
        )

    if not TLS_CERT_PATH.exists():
        raise RuntimeError(f"TLS Zertifikat nicht gefunden: {TLS_CERT_PATH}")

    if not TLS_KEY_PATH.exists():
        raise RuntimeError(f"TLS Key nicht gefunden: {TLS_KEY_PATH}")

    if TLS_CA_PATH and not TLS_CA_PATH.exists():
        raise RuntimeError(f"TLS CA Datei nicht gefunden: {TLS_CA_PATH}")


class KeyManager:
    def __init__(self, key_dir: Path, metadata_path: Path, active_key_id: str):
        self.key_dir = key_dir
        self.metadata_path = metadata_path
        self.active_key_id = active_key_id
        self.ensure_active_key()

    def _private_key_path(self, key_id: str) -> Path:
        return self.key_dir / f"{key_id}.private.pem"

    def _public_key_path(self, key_id: str) -> Path:
        return self.key_dir / f"{key_id}.public.pem"

    def _read_metadata(self) -> dict:
        if not self.metadata_path.exists():
            return {}

        try:
            return json.loads(self.metadata_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _write_metadata(self, keys: List[str]) -> None:
        unique_keys = sorted(list(dict.fromkeys(keys)))
        data = {
            "active_key_id": self.active_key_id,
            "algorithm": KEY_ALGO,
            "keys": unique_keys,
            "updated_at": utc_now(),
        }
        self.metadata_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def ensure_active_key(self) -> None:
        private_key_path = self._private_key_path(self.active_key_id)
        public_key_path = self._public_key_path(self.active_key_id)

        if not private_key_path.exists() or not public_key_path.exists():
            private_key = Ed25519PrivateKey.generate()

            private_key_path.write_bytes(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
            public_key_path.write_bytes(
                private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

            try:
                os.chmod(private_key_path, 0o600)
            except Exception:
                pass

        metadata = self._read_metadata()
        keys = metadata.get("keys", [])
        keys.append(self.active_key_id)
        self._write_metadata(keys)

    def active_private_key(self):
        return serialization.load_pem_private_key(
            self._private_key_path(self.active_key_id).read_bytes(),
            password=None,
        )

    def active_public_pem(self) -> str:
        return self._public_key_path(self.active_key_id).read_text(encoding="utf-8")

    def all_public_keys(self) -> List[dict]:
        result = []
        metadata = self._read_metadata()

        for key_id in metadata.get("keys", []):
            public_key_path = self._public_key_path(key_id)
            if not public_key_path.exists():
                continue

            result.append(
                {
                    "key_id": key_id,
                    "algorithm": KEY_ALGO,
                    "status": "active" if key_id == self.active_key_id else "legacy",
                    "public_key_pem": public_key_path.read_text(encoding="utf-8"),
                }
            )

        return result


class ClientLogEntry(BaseModel):
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


class ClientLogBatch(BaseModel):
    entries: List[ClientLogEntry]
    client_id: Optional[str] = None


class CentralAuditStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_db()

    def _db(self):
        return sqlite3.connect(self.db_path, timeout=10)

    def _init_db(self) -> None:
        with self._db() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS client_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE,
                    client_id TEXT,
                    hostname TEXT,
                    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    data TEXT NOT NULL
                )
                """
            )

    def store(self, client_id: str, entries: List[dict]) -> None:
        with self._db() as conn:
            for entry in entries:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO client_logs (
                        event_id,
                        client_id,
                        hostname,
                        data
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        entry.get("event_id"),
                        client_id,
                        entry.get("hostname"),
                        json.dumps(entry, ensure_ascii=False),
                    ),
                )

    def read_logs(self, limit: int, client_id: Optional[str] = None) -> List[dict]:
        with self._db() as conn:
            conn.row_factory = sqlite3.Row

            query = "SELECT * FROM client_logs WHERE 1=1"
            params: List[Any] = []

            if client_id:
                query += " AND client_id = ?"
                params.append(client_id)

            query += " ORDER BY received_at DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]


validate_auth_config()
ensure_self_signed_cert_if_needed()
validate_tls_config()

KM = KeyManager(KEY_DIR, KEY_METADATA, ACTIVE_KEY_ID)
PRIVATE_KEY = KM.active_private_key()
CA = CentralAuditStore(CENTRAL_DB)

app = FastAPI(
    title="Signing Platform Server",
    version="3.3",
    docs_url="/docs",
    redoc_url="/redoc",
)

SIGN_REQUESTS_TOTAL = Counter(
    "signing_sign_requests_total",
    "Total number of successful sign requests",
)

SIGN_ERRORS_TOTAL = Counter(
    "signing_sign_errors_total",
    "Total number of failed sign requests",
)

CLIENT_LOG_BATCHES_TOTAL = Counter(
    "signing_client_log_batches_total",
    "Total number of received client log batches",
)

CLIENT_LOG_ENTRIES_TOTAL = Counter(
    "signing_client_log_entries_total",
    "Total number of received client log entries",
)

CLIENT_LOG_ERRORS_TOTAL = Counter(
    "signing_client_log_errors_total",
    "Total number of client log processing errors",
)

CLIENT_VERIFY_RESULTS_TOTAL = Counter(
    "signing_client_verify_results_total",
    "Total number of verification results reported by clients",
    ["result"],
)

ADMIN_LOGS_REQUESTS_TOTAL = Counter(
    "signing_admin_logs_requests_total",
    "Total number of admin log requests",
)

ADMIN_LOGS_ERRORS_TOTAL = Counter(
    "signing_admin_logs_errors_total",
    "Total number of admin log request errors",
)

AUTH_FAILURES_TOTAL = Counter(
    "signing_auth_failures_total",
    "Total number of authentication failures",
    ["scope", "reason"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "signing_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["endpoint"],
)

INFLIGHT_REQUESTS = Gauge(
    "signing_inflight_requests",
    "Current number of in-flight requests",
)


def require_api_key(
    x_api_key: Optional[str],
    request: Optional[Request] = None,
    scope: str = "default",
) -> None:
    client_ip = request.client.host if request and request.client else None

    if not RAW_API_KEYS:
        if ALLOW_NO_API_KEYS:
            audit(
                {
                    "event": "auth_bypass",
                    "scope": scope,
                    "reason": "allow_no_api_keys_enabled",
                    "client_ip": client_ip,
                }
            )
            return

        AUTH_FAILURES_TOTAL.labels(scope=scope, reason="no_api_keys_configured").inc()
        audit(
            {
                "event": "auth_config_error",
                "scope": scope,
                "reason": "no_api_keys_configured",
                "client_ip": client_ip,
            }
        )
        raise HTTPException(status_code=500, detail="Authentication not configured")

    if not x_api_key:
        AUTH_FAILURES_TOTAL.labels(scope=scope, reason="missing_api_key").inc()
        audit(
            {
                "event": "auth_failed",
                "scope": scope,
                "reason": "missing_api_key",
                "client_ip": client_ip,
            }
        )
        raise HTTPException(status_code=401, detail="Unauthorized")

    candidate_sha256 = sha256_digest(x_api_key)

    for stored_hash in BCRYPT_API_KEYS:
        try:
            if bcrypt.checkpw(candidate_sha256, stored_hash.encode("utf-8")):
                return
        except ValueError:
            AUTH_FAILURES_TOTAL.labels(scope=scope, reason="invalid_bcrypt_hash").inc()
            audit(
                {
                    "event": "auth_config_error",
                    "scope": scope,
                    "reason": "invalid_bcrypt_hash",
                    "hash_prefix": stored_hash[:7],
                    "client_ip": client_ip,
                }
            )
            continue
        except Exception as exc:
            AUTH_FAILURES_TOTAL.labels(scope=scope, reason="bcrypt_check_failed").inc()
            audit(
                {
                    "event": "auth_config_error",
                    "scope": scope,
                    "reason": "bcrypt_check_failed",
                    "error": str(exc),
                    "client_ip": client_ip,
                }
            )
            continue

    if ALLOW_LEGACY_PLAINTEXT_KEYS:
        for stored_key in PLAINTEXT_API_KEYS:
            if hmac.compare_digest(x_api_key, stored_key):
                audit(
                    {
                        "event": "auth_legacy_plaintext_used",
                        "scope": scope,
                        "client_ip": client_ip,
                    }
                )
                return

    AUTH_FAILURES_TOTAL.labels(scope=scope, reason="invalid_api_key").inc()
    audit(
        {
            "event": "auth_failed",
            "scope": scope,
            "reason": "invalid_api_key",
            "client_ip": client_ip,
        }
    )
    raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/health", response_class=PlainTextResponse)
def health():
    return "ok"


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/public-key")
def public_key():
    return {
        "status": "ok",
        "algorithm": KEY_ALGO,
        "key_id": ACTIVE_KEY_ID,
        "public_key_pem": KM.active_public_pem(),
        "ts_utc": utc_now(),
    }


@app.get("/public-keys")
def public_keys():
    return {
        "status": "ok",
        "active_key_id": ACTIVE_KEY_ID,
        "keys": KM.all_public_keys(),
        "ts_utc": utc_now(),
    }


@app.post("/sign")
async def sign_file(
    request: Request,
    file: UploadFile = File(...),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    INFLIGHT_REQUESTS.inc()
    with HTTP_REQUEST_DURATION_SECONDS.labels(endpoint="/sign").time():
        try:
            require_api_key(x_api_key, request=request, scope="sign")

            try:
                data = await file.read()
            except Exception as exc:
                SIGN_ERRORS_TOTAL.inc()
                raise HTTPException(status_code=400, detail=f"File read failed: {exc}")

            if len(data) > MAX_UPLOAD:
                SIGN_ERRORS_TOTAL.inc()
                raise HTTPException(status_code=413, detail="File too large")

            sha256_hex = hashlib.sha256(data).hexdigest()

            try:
                signature_b64 = base64.b64encode(PRIVATE_KEY.sign(data)).decode("ascii")
            except Exception as exc:
                SIGN_ERRORS_TOTAL.inc()
                audit(
                    {
                        "event": "sign_error",
                        "filename": file.filename,
                        "error": str(exc),
                        "client_ip": request.client.host if request.client else None,
                    }
                )
                raise HTTPException(status_code=500, detail="Signing failed")

            SIGN_REQUESTS_TOTAL.inc()

            audit(
                {
                    "event": "sign",
                    "filename": file.filename,
                    "sha256": sha256_hex,
                    "key_id": ACTIVE_KEY_ID,
                    "client_ip": request.client.host if request.client else None,
                }
            )

            return {
                "status": "ok",
                "filename": file.filename,
                "sha256_hex": sha256_hex,
                "key_id": ACTIVE_KEY_ID,
                "algorithm": KEY_ALGO,
                "signature_b64": signature_b64,
                "ts_utc": utc_now(),
            }
        finally:
            INFLIGHT_REQUESTS.dec()


@app.post("/client-log")
async def client_log(
    batch: ClientLogBatch,
    request: Request,
    background_tasks: BackgroundTasks,
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-ID"),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    INFLIGHT_REQUESTS.inc()
    with HTTP_REQUEST_DURATION_SECONDS.labels(endpoint="/client-log").time():
        try:
            require_api_key(x_api_key, request=request, scope="client-log")

            client_id = x_client_id or batch.client_id
            if not client_id:
                client_id = request.client.host if request.client else "unknown"

            try:
                entries = [model_to_dict(entry) for entry in batch.entries]
            except Exception as exc:
                CLIENT_LOG_ERRORS_TOTAL.inc()
                audit(
                    {
                        "event": "client_log_error",
                        "client_id": client_id,
                        "error": f"serialize_failed: {exc}",
                    }
                )
                raise HTTPException(status_code=500, detail="Entry serialization failed")

            for entry in entries:
                sig_valid = entry.get("signature_valid")

                if sig_valid is True:
                    CLIENT_VERIFY_RESULTS_TOTAL.labels(result="valid").inc()
                elif sig_valid is False:
                    CLIENT_VERIFY_RESULTS_TOTAL.labels(result="invalid").inc()
                else:
                    CLIENT_VERIFY_RESULTS_TOTAL.labels(result="unknown").inc()

            try:
                background_tasks.add_task(CA.store, client_id, entries)
            except Exception as exc:
                CLIENT_LOG_ERRORS_TOTAL.inc()
                audit(
                    {
                        "event": "client_log_error",
                        "client_id": client_id,
                        "error": f"store_schedule_failed: {exc}",
                    }
                )
                raise HTTPException(status_code=500, detail="Client log scheduling failed")

            CLIENT_LOG_BATCHES_TOTAL.inc()
            CLIENT_LOG_ENTRIES_TOTAL.inc(len(entries))

            audit(
                {
                    "event": "client_log",
                    "client_id": client_id,
                    "count": len(entries),
                    "client_ip": request.client.host if request.client else None,
                }
            )

            return {
                "status": "accepted",
                "received": len(entries),
                "client_id": client_id,
                "ts_utc": utc_now(),
            }
        finally:
            INFLIGHT_REQUESTS.dec()


@app.get("/admin/logs")
async def admin_logs(
    request: Request,
    limit: int = 100,
    client_id: Optional[str] = None,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    INFLIGHT_REQUESTS.inc()
    with HTTP_REQUEST_DURATION_SECONDS.labels(endpoint="/admin/logs").time():
        try:
            require_api_key(x_api_key, request=request, scope="admin-logs")
            ADMIN_LOGS_REQUESTS_TOTAL.inc()

            if limit < 1:
                ADMIN_LOGS_ERRORS_TOTAL.inc()
                raise HTTPException(status_code=400, detail="limit must be >= 1")

            if limit > 1000:
                limit = 1000

            try:
                logs = CA.read_logs(limit=limit, client_id=client_id)
            except Exception as exc:
                ADMIN_LOGS_ERRORS_TOTAL.inc()
                audit(
                    {
                        "event": "admin_logs_error",
                        "client_id": client_id,
                        "error": str(exc),
                    }
                )
                raise HTTPException(status_code=500, detail="Failed to read logs")

            return {
                "status": "ok",
                "count": len(logs),
                "logs": logs,
                "ts_utc": utc_now(),
            }
        finally:
            INFLIGHT_REQUESTS.dec()


def start_server() -> None:
    import uvicorn

    ssl_cert = str(TLS_CERT_PATH) if TLS_ENABLED and TLS_CERT_PATH else None
    ssl_key = str(TLS_KEY_PATH) if TLS_ENABLED and TLS_KEY_PATH else None

    print("Starting Signing Platform Server")
    print(f"Config: {CONFIG_PATH}")
    print(f"Host: {HOST}")
    print(f"Port: {PORT}")
    print(f"TLS Enabled: {TLS_ENABLED}")

    if TLS_ENABLED:
        print(f"TLS Cert: {ssl_cert}")
        print(f"TLS Key: {ssl_key}")

    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        reload=False,
        ssl_certfile=ssl_cert,
        ssl_keyfile=ssl_key,
        log_level="info",
    )


if __name__ == "__main__":
    start_server()