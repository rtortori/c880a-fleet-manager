"""Versioned, passphrase-encrypted installation and claimed-server archives.

The archive is a single authenticated ciphertext. No decrypted payload or BMC
credential is written to a staging file or returned to the browser.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import tempfile
import zlib

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .storage import Store
from .build_info import build_info
from .deployment import (local_addresses, read_config, validate_certificate,
                         validate_network)


MAGIC_V1 = b"C880A-BACKUP\x00\x01"
MAGIC_V2 = b"C880A-BACKUP\x00\x02"
MAGIC = b"C880A-BACKUP\x00\x03"
FORMAT_VERSION = 3
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_PLAINTEXT_BYTES = 768 * 1024 * 1024
KDF_N = 2**17
SERVER_TABLES = (
    "servers", "events", "event_cursors", "inventory_snapshots",
    "manager_metric_pauses", "server_action_jobs", "metric_series",
    "metric_points", "tracked_series",
)
FULL_ROOT_FILES = (
    "master.key", "deployment.json", "deployment.previous.json",
    "deployment.recovery.json", "deployment.last.json", "discovery-token",
    "bootstrap-token", "installation-id",
)
_CERT_FILE = re.compile(r"certificates/[0-9a-f]{32}/(server\.pem|server\.key|source\.json)\Z")
_CA_FILE = re.compile(r"bmc-ca-[0-9a-f]{24}\.pem\Z")
_SERVER_ID = re.compile(r"[0-9a-f]{32}\Z")


class BackupError(ValueError):
    """A safe error suitable for an administrator-facing validation message."""


def _release_version(value: object) -> tuple[int, int, int]:
    if (not isinstance(value, str) or len(value) > 32 or
            not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value)):
        raise BackupError("Backup application version cannot be verified. Create a new backup from the source installation.")
    return tuple(int(part) for part in value.split("."))


def validate_application_version(payload: dict) -> None:
    if not isinstance(payload, dict) or not isinstance(payload.get("manifest"), dict):
        raise BackupError("Backup manifest is missing")
    source = payload["manifest"].get("application_version")
    source_version = _release_version(source)
    destination = build_info()["version"]
    try:
        destination_version = _release_version(destination)
    except BackupError:
        raise BackupError("This installation's application version cannot be verified. Repair the installation before restoring.") from None
    if source_version > destination_version:
        raise BackupError(f"Backup version {source} is newer than this installation ({destination}). "
                          f"Upgrade to {source} or later, then preview again.")


def _encoded(value: object) -> object:
    if isinstance(value, bytes):
        return {"b64": base64.b64encode(value).decode("ascii")}
    return value


def _decoded(value: object) -> object:
    if isinstance(value, dict) and set(value) == {"b64"} and isinstance(value["b64"], str):
        return base64.b64decode(value["b64"], validate=True)
    return value


def _snapshot(database: Path) -> bytes:
    # SQLite's backup API gives a consistent snapshot while collectors write.
    # The private temporary file is removed before the encrypted response is sent.
    with tempfile.TemporaryDirectory(prefix="c880a-backup-") as directory:
        path = Path(directory) / "snapshot.db"
        with sqlite3.connect(database, timeout=10) as source, sqlite3.connect(path) as target:
            source.backup(target)
        if path.stat().st_size > MAX_PLAINTEXT_BYTES:
            raise BackupError("Database exceeds the backup size limit")
        return path.read_bytes()


def _full_files(data_dir: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    candidates = [data_dir / name for name in FULL_ROOT_FILES]
    certificates = data_dir / "certificates"
    if certificates.is_symlink():
        raise BackupError("Certificate directory must not be a symlink")
    if certificates.exists():
        for directory in certificates.iterdir():
            if directory.is_symlink() or not directory.is_dir():
                raise BackupError("Unexpected certificate directory entry")
            candidates.extend(directory.iterdir())
    candidates.extend(data_dir.glob("bmc-ca-*.pem"))
    for path in candidates:
        if not path.exists():
            continue
        relative = path.relative_to(data_dir).as_posix()
        if relative not in FULL_ROOT_FILES and not _CERT_FILE.fullmatch(relative) and not _CA_FILE.fullmatch(relative):
            continue
        if path.is_symlink() or not path.is_file():
            raise BackupError("Unexpected symlink or non-file in durable state")
        if path.stat().st_size > 2 * 1024 * 1024:
            raise BackupError("A durable configuration file exceeds the size limit")
        files[relative] = base64.b64encode(path.read_bytes()).decode("ascii")
    if "master.key" not in files or "deployment.json" not in files:
        raise BackupError("Installation key or deployment configuration is missing")
    return files


def _server_rows(store: Store) -> dict[str, list[dict]]:
    with store.connect() as db:
        db.execute("BEGIN")  # One read snapshot for identities and every related table.
        active = [row[0] for row in db.execute("SELECT id FROM servers WHERE state='active' ORDER BY port")]
        rows: dict[str, list[dict]] = {}
        for table in SERVER_TABLES:
            if not active:
                rows[table] = []
                continue
            placeholders = ",".join("?" for _ in active)
            query = (f"SELECT * FROM {table} WHERE " +
                     ("id" if table == "servers" else "server_id") + f" IN ({placeholders})")
            rows[table] = [{key: _encoded(row[key]) for key in row.keys()}
                           for row in db.execute(query, active)]
        for row in rows["servers"]:
            credential = store.decrypt({key: _decoded(value) for key, value in row.items()})
            row.pop("password_cipher")
            row["credential"] = credential
        return rows


def _seal(payload: dict, passphrase: str) -> bytes:
    if not 16 <= len(passphrase) <= 1024:
        raise BackupError("Passphrase must be 16–1024 characters")
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    if len(raw) > MAX_PLAINTEXT_BYTES:
        raise BackupError("Backup exceeds the size limit")
    compressed = zlib.compress(raw, level=6)
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    key = hashlib.scrypt(passphrase.encode(), salt=salt, n=KDF_N, r=8, p=1,
                         dklen=32, maxmem=256 * 1024 * 1024)
    header = MAGIC + salt + nonce
    ciphertext = AESGCM(key).encrypt(nonce, compressed, header)
    archive = header + hashlib.sha256(ciphertext).digest() + ciphertext
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise BackupError("Encrypted backup exceeds the upload/download limit")
    return archive


def archive_payload(store: Store, scope: str) -> dict:
    if scope not in ("full", "servers"):
        raise BackupError("Unsupported backup scope")
    source_deployment = read_config(store.data_dir)
    manifest = {"format": FORMAT_VERSION, "scope": scope,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "server_count": 0,
                "source_installation_id": store.installation_id}
    manifest["application_version"] = build_info()["version"]
    _release_version(manifest["application_version"])
    source_origin = source_deployment.get("manager_origin")
    if isinstance(source_origin, str) and source_origin.startswith("https://") and len(source_origin) <= 512:
        # The origin identifies the source to an admin without exposing its data path.
        manifest["source_manager_origin"] = source_origin
    if scope == "full":
        payload = {"manifest": manifest, "source_data_dir": str(store.data_dir.resolve()),
                   "database": base64.b64encode(_snapshot(store.database)).decode("ascii"),
                   "files": _full_files(store.data_dir)}
    else:
        manifest["source_bmc_ca_custom"] = bool(source_deployment.get("bmc_ca"))
        if source_deployment.get("bmc_ca"):
            source_ca = Path(source_deployment["bmc_ca"])
            if source_ca.is_symlink() or not source_ca.is_file() or source_ca.stat().st_size > 2 * 1024 * 1024:
                raise BackupError("Source BMC CA bundle is unavailable or oversized")
            manifest["source_bmc_ca_sha256"] = hashlib.sha256(source_ca.read_bytes()).hexdigest()
        payload = {"manifest": manifest, "tables": _server_rows(store)}
    if scope == "full":
        with sqlite3.connect(":memory:") as snapshot:
            snapshot.deserialize(base64.b64decode(payload["database"], validate=True))
            manifest["server_count"] = snapshot.execute("SELECT count(*) FROM servers WHERE state='active'").fetchone()[0]
    else:
        manifest["server_count"] = len(payload["tables"]["servers"])
    return payload


def create_archive(store: Store, scope: str, passphrase: str) -> bytes:
    return _seal(archive_payload(store, scope), passphrase)


def open_archive(archive: bytes, passphrase: str) -> dict:
    if not isinstance(archive, bytes) or len(archive) > MAX_ARCHIVE_BYTES:
        raise BackupError("Archive exceeds the upload limit")
    if len(archive) < len(MAGIC) + 16 + 12 + 16 or not archive.startswith((MAGIC, MAGIC_V2, MAGIC_V1)):
        raise BackupError("Unsupported or corrupt backup format")
    offset = len(MAGIC)
    salt, nonce = archive[offset:offset + 16], archive[offset + 16:offset + 28]
    header = archive[:offset + 28]
    ciphertext = archive[offset + 28:]
    if not archive.startswith(MAGIC_V1):
        if len(ciphertext) < 32 + 16:
            raise BackupError("Archive is corrupt or incomplete")
        checksum, ciphertext = ciphertext[:32], ciphertext[32:]
        if not secrets.compare_digest(checksum, hashlib.sha256(ciphertext).digest()):
            raise BackupError("Archive is corrupt or incomplete")
    try:
        key = hashlib.scrypt(passphrase.encode(), salt=salt, n=KDF_N, r=8, p=1,
                             dklen=32, maxmem=256 * 1024 * 1024)
        compressed = AESGCM(key).decrypt(nonce, ciphertext, header)
    except (InvalidTag, ValueError):
        raise BackupError("Wrong passphrase or archive authentication failed") from None
    try:
        decoder = zlib.decompressobj()
        raw = decoder.decompress(compressed, MAX_PLAINTEXT_BYTES + 1)
        if len(raw) > MAX_PLAINTEXT_BYTES or decoder.unconsumed_tail or not decoder.eof:
            raise BackupError("Backup payload exceeds the size limit or is incomplete")
        raw += decoder.flush()
        if len(raw) > MAX_PLAINTEXT_BYTES:
            raise BackupError("Backup payload exceeds the size limit")
        payload = json.loads(raw)
    except (zlib.error, UnicodeError, json.JSONDecodeError) as exc:
        raise BackupError("Backup payload is corrupt") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("manifest"), dict):
        raise BackupError("Backup manifest is missing")
    manifest = payload["manifest"]
    expected_format = 1 if archive.startswith(MAGIC_V1) else 2 if archive.startswith(MAGIC_V2) else FORMAT_VERSION
    if manifest.get("format") != expected_format or manifest.get("scope") not in ("full", "servers"):
        raise BackupError("Backup version or scope is incompatible")
    validate_application_version(payload)
    if not isinstance(manifest.get("server_count"), int) or manifest["server_count"] < 0:
        raise BackupError("Backup manifest is invalid")
    source_id = manifest.get("source_installation_id")
    if source_id is not None and (not isinstance(source_id, str) or
                                  not re.fullmatch(r"[0-9a-f]{32}", source_id)):
        raise BackupError("Backup source installation identity is invalid")
    try:
        created = datetime.fromisoformat(manifest["created_at"])
        if created.tzinfo is None:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise BackupError("Backup creation time is invalid") from None
    if manifest["scope"] == "full":
        _validate_full(payload)
    else:
        _validate_servers(payload)
    return payload


def _validate_full(payload: dict) -> None:
    validate_application_version(payload)
    files = payload.get("files")
    if not isinstance(files, dict) or not set(FULL_ROOT_FILES[:2]).issubset(files):
        raise BackupError("Full backup is missing required files")
    if any(not isinstance(name, str) or not isinstance(data, str) or
           (name not in FULL_ROOT_FILES and not _CERT_FILE.fullmatch(name) and not _CA_FILE.fullmatch(name))
           for name, data in files.items()):
        raise BackupError("Full backup contains an unexpected path")
    try:
        if len(base64.b64decode(files["master.key"], validate=True)) != 32:
            raise BackupError("Full backup has an invalid master key")
        database = base64.b64decode(payload["database"], validate=True)
        if len(database) > MAX_PLAINTEXT_BYTES:
            raise BackupError("Full backup database exceeds the size limit")
        if not database.startswith(b"SQLite format 3\x00"):
            raise BackupError("Full backup has an invalid database")
        for data in files.values():
            if len(data) > 3 * 1024 * 1024:
                raise BackupError("Full backup contains an oversized configuration file")
            base64.b64decode(data, validate=True)
        if "installation-id" in files:
            archived_id = base64.b64decode(files["installation-id"], validate=True)
            if not re.fullmatch(rb"[0-9a-f]{32}\n?", archived_id):
                raise BackupError("Full backup installation identity is invalid")
            if payload["manifest"].get("source_installation_id") and archived_id.strip().decode() != payload["manifest"]["source_installation_id"]:
                raise BackupError("Full backup installation identity does not match its manifest")
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, BackupError):
            raise
        raise BackupError("Full backup data is corrupt") from exc
    try:
        with sqlite3.connect(":memory:") as db:
            db.deserialize(database)
            if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise BackupError("Full backup database failed integrity validation")
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            required = {"users", "sessions", "servers", "events", "settings", "inventory_snapshots",
                        "metric_series", "metric_points", "dashboard_widgets", "tracked_series"}
            if not required <= tables:
                raise BackupError("Full backup database schema is incompatible")
            if "prometheus_deletions" in tables and db.execute("SELECT count(*) FROM prometheus_deletions").fetchone()[0]:
                raise BackupError("Source target history cleanup is incomplete; finish it and create a new backup")
            active = db.execute("SELECT count(*) FROM servers WHERE state='active'").fetchone()[0]
            if active != payload["manifest"]["server_count"]:
                raise BackupError("Full backup server count does not match its manifest")
            if any(not isinstance(row[0], str) or not _SERVER_ID.fullmatch(row[0])
                   for row in db.execute("SELECT id FROM servers")):
                raise BackupError("Full backup contains an invalid server identity")
            server_columns = {row[1] for row in db.execute("PRAGMA table_info(servers)")}
            if "bmc_port" in server_columns and any(
                    isinstance(row[0], bool) or not isinstance(row[0], int) or
                    not 1 <= row[0] <= 65535 for row in db.execute("SELECT bmc_port FROM servers")):
                raise BackupError("Full backup contains an invalid BMC port")
            source_key = base64.b64decode(files["master.key"], validate=True)
            for server_id, cipher in db.execute("SELECT id, password_cipher FROM servers WHERE state='active'"):
                if not isinstance(cipher, bytes) or len(cipher) < 29:
                    raise BackupError("Full backup has a missing server credential")
                try:
                    AESGCM(source_key).decrypt(cipher[:12], cipher[12:], server_id.encode())
                except InvalidTag:
                    raise BackupError("Full backup key cannot decrypt a server credential") from None
        source_root = Path(payload["source_data_dir"])
        if not source_root.is_absolute():
            raise BackupError("Full backup source path is invalid")
        deployment = json.loads(base64.b64decode(files["deployment.json"], validate=True))
        referenced = [deployment.get("certificate", {}).get(field) for field in ("cert", "key")]
        if deployment.get("bmc_ca"):
            referenced.append(deployment["bmc_ca"])
        for reference in referenced:
            if not isinstance(reference, str):
                raise BackupError("Full backup certificate reference is missing")
            path = Path(reference)
            if not path.is_relative_to(source_root) or path.relative_to(source_root).as_posix() not in files:
                raise BackupError("Full backup is missing referenced certificate or CA material")
    except (sqlite3.Error, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        if isinstance(exc, BackupError):
            raise
        raise BackupError("Full backup database or deployment data is corrupt") from exc


def _validate_servers(payload: dict) -> None:
    validate_application_version(payload)
    tables = payload.get("tables")
    if not isinstance(tables, dict) or set(tables) != set(SERVER_TABLES):
        raise BackupError("Server backup table manifest is invalid")
    if any(not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows)
           for rows in tables.values()):
        raise BackupError("Server backup rows are invalid")
    if len(tables["servers"]) != payload["manifest"]["server_count"]:
        raise BackupError("Server count does not match the manifest")
    if payload["manifest"].get("source_bmc_ca_custom") and not re.fullmatch(
            r"[0-9a-f]{64}", str(payload["manifest"].get("source_bmc_ca_sha256", ""))):
        raise BackupError("Source BMC CA fingerprint is invalid")
    raw_ids = [row.get("id") for row in tables["servers"]]
    if any(not isinstance(item, str) or not _SERVER_ID.fullmatch(item) for item in raw_ids):
        raise BackupError("Server identities are invalid")
    ids = set(raw_ids)
    if len(ids) != len(raw_ids):
        raise BackupError("Server identities are invalid")
    for table, rows in tables.items():
        for row in rows:
            related = row.get("id") if table == "servers" else row.get("server_id")
            if not isinstance(related, str) or related not in ids:
                raise BackupError("Server backup contains an unrelated row")
    for row in tables["servers"]:
        if "password_cipher" in row or not isinstance(row.get("credential"), str):
            raise BackupError("Server credential manifest is invalid")
        port = row.get("bmc_port", 443)
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise BackupError("Server backup BMC port is invalid")


def _destination_state(store: Store) -> str:
    with store.connect() as db:
        state = {
            "users": [tuple(row) for row in db.execute("SELECT id, username, role, disabled FROM users ORDER BY id")],
            "servers": [tuple(row) for row in db.execute("SELECT id, name, port, state FROM servers ORDER BY id")],
            "settings": [tuple(row) for row in db.execute("SELECT key, value FROM settings ORDER BY key")],
        }
    state["deployment"] = read_config(store.data_dir)
    return hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()


def plan_server_restore(store: Store, payload: dict) -> dict:
    """Show exact mapping before any mutation; destination must be empty."""
    _validate_servers(payload)
    if payload["manifest"]["scope"] != "servers":
        raise BackupError("Archive is not a server-only backup")
    with store.connect() as db:
        if db.execute("SELECT count(*) FROM servers").fetchone()[0]:
            raise BackupError("Server-only restore requires an installation with no claimed servers")
    config = read_config(store.data_dir)
    try:
        start, end, offset = (int(config[key]) for key in
                              ("port_start", "port_end", "console_port_offset"))
        manager_port = int(config["manager_port"])
    except (KeyError, TypeError, ValueError):
        raise BackupError("Destination deployment port range is unavailable") from None
    if not (1 <= start <= end <= 65535 and 1 <= start + offset <= end + offset <= 65535):
        raise BackupError("Destination deployment port range is invalid")
    if manager_port in range(start, end + 1) or manager_port in range(start + offset, end + offset + 1):
        raise BackupError("Destination manager port overlaps the exporter or console range")
    servers = sorted(payload["tables"]["servers"], key=lambda row: (row.get("port", 0), row.get("id", "")))
    if len(servers) > end - start + 1:
        raise BackupError("Destination exporter port range has insufficient capacity")
    available = list(range(start, end + 1))
    mapping = []
    for row in servers:
        old = row.get("port")
        if not isinstance(old, int) or not 1 <= old <= 65535:
            raise BackupError("Archive contains an invalid exporter port")
        new = old if old in available else available[0]
        available.remove(new)
        mapping.append({"server_id": row["id"], "name": row.get("name", ""),
                        "source_exporter_port": old, "exporter_port": new,
                        "console_port": new + offset})
    source_ca = bool(payload["manifest"].get("source_bmc_ca_custom"))
    destination_ca = bool(config.get("bmc_ca"))
    destination_ca_hash = ""
    if destination_ca:
        ca_path = Path(config["bmc_ca"])
        if ca_path.is_symlink() or not ca_path.is_file() or ca_path.stat().st_size > 2 * 1024 * 1024:
            raise BackupError("Destination BMC CA bundle is unavailable or oversized")
        destination_ca_hash = hashlib.sha256(ca_path.read_bytes()).hexdigest()
    trust_match = ((not source_ca and not destination_ca) or
                   (source_ca and destination_ca_hash == payload["manifest"].get("source_bmc_ca_sha256")))
    return {"scope": "servers", "server_count": len(mapping), "mapping": mapping,
            "destination_exporter_range": [start, end],
            "destination_console_range": [start + offset, end + offset],
            "destination_capacity": end - start + 1,
            "source_bmc_ca_custom": source_ca, "destination_bmc_ca_custom": destination_ca,
            "bmc_trust_gap": not trust_match, "bmc_trust_match": trust_match,
            "destination_manager_origin": config.get("manager_origin"),
            "destination_state_sha256": _destination_state(store)}


def apply_server_restore(store: Store, payload: dict, reviewed_plan: dict) -> None:
    """Import in one SQLite transaction, re-encrypting under the destination key."""
    current = plan_server_restore(store, payload)
    if current != reviewed_plan:
        raise BackupError("Destination changed since preview; review the restore again")
    if not current["bmc_trust_match"]:
        raise BackupError("Destination BMC CA bundle must match the source before restoring servers")
    mapping = {row["server_id"]: row["exporter_port"] for row in current["mapping"]}
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT count(*) FROM servers").fetchone()[0]:
            raise BackupError("Destination gained a server since preview")
        for table in SERVER_TABLES:
            columns = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
            for encoded in payload["tables"][table]:
                row = {key: _decoded(value) for key, value in encoded.items()}
                if table == "servers":
                    server_id = row["id"]
                    row["port"] = mapping[server_id]
                    row.setdefault("bmc_port", 443)
                    row["password_cipher"] = store.encrypt(server_id, row.pop("credential"))
                if table in ("events", "manager_metric_pauses"):
                    row.pop("id", None)  # Destination-local SQLite row identity.
                    columns.remove("id")
                if set(row) != columns:
                    raise BackupError(f"Archive {table} columns are incompatible with this version")
                names = list(row)
                placeholders = ",".join("?" for _ in names)
                db.execute(f"INSERT INTO {table} ({','.join(names)}) VALUES ({placeholders})",
                           [row[name] for name in names])


def plan_full_restore(store: Store, payload: dict, replacement_address: str | None = None) -> dict:
    """Validate network and certificate before an installation replacement."""
    _validate_full(payload)
    if payload["manifest"]["scope"] != "full":
        raise BackupError("Archive is not a full backup")
    files = payload["files"]
    original = json.loads(base64.b64decode(files["deployment.json"], validate=True))
    proposed = original.copy()
    cert_action = "preserve"
    if replacement_address:
        if replacement_address not in local_addresses():
            raise BackupError("Replacement address is not on a current local interface")
        proposed.update(manager_bind=replacement_address, manager_host=replacement_address,
                        exporter_bind=replacement_address, exporter_host=replacement_address,
                        console_bind=replacement_address, console_host=replacement_address)
        proposed.pop("manager_origin", None)
        cert_action = "generate-self-signed"
    try:
        proposed = validate_network(proposed)
    except (KeyError, TypeError, ValueError) as exc:
        raise BackupError(f"Archived network cannot activate here: {exc}. Select a local replacement address") from None
    source_root = Path(payload["source_data_dir"])
    cert_ref = original["certificate"]
    cert = base64.b64decode(files[Path(cert_ref["cert"]).relative_to(source_root).as_posix()])
    key = base64.b64decode(files[Path(cert_ref["key"]).relative_to(source_root).as_posix()])
    if cert_action == "preserve":
        leaf_end = cert.find(b"-----END CERTIFICATE-----") + len(b"-----END CERTIFICATE-----")
        try:
            validate_certificate(cert[:leaf_end], key, cert[leaf_end:],
                                 [proposed["manager_host"], proposed["exporter_host"], proposed["console_host"]])
        except ValueError as exc:
            raise BackupError(f"Archived HTTPS certificate cannot activate here: {exc}") from None
    current = read_config(store.data_dir)
    with store.connect() as db:
        destination_servers = db.execute("SELECT count(*) FROM servers WHERE state='active'").fetchone()[0]
    with sqlite3.connect(":memory:") as source_db:
        source_db.deserialize(base64.b64decode(payload["database"], validate=True))
        source_admins = [username for username, salt, digest in source_db.execute(
            "SELECT username, salt, password_hash FROM users WHERE role='admin' AND disabled=0 ORDER BY username")
            if isinstance(username, str) and username and isinstance(salt, bytes) and len(salt) == 16
            and isinstance(digest, bytes) and len(digest) == 32]
    if not source_admins:
        raise BackupError("Full backup has no active administrator with usable sign-in material")
    return {"scope": "full", "server_count": payload["manifest"]["server_count"],
            "result_url": proposed["manager_origin"],
            "current_url": current.get("manager_origin"),
            "destination_server_count": destination_servers,
            "source_admin_users": source_admins,
            "certificate_action": cert_action,
            "sessions_invalidated": True,
            "replaces": ["users", "servers", "settings", "history", "network", "certificates", "tokens"],
            "manager_bind": proposed["manager_bind"], "exporter_bind": proposed["exporter_bind"],
            "console_bind": proposed["console_bind"], "manager_port": proposed["manager_port"],
            "exporter_port_range": [proposed["port_start"], proposed["port_end"]],
            "console_port_range": [proposed["port_start"] + proposed["console_port_offset"],
                                   proposed["port_end"] + proposed["console_port_offset"]],
            "destination_state_sha256": _destination_state(store)}
