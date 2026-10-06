"""Private staging and reversible application of an administrator-reviewed restore.

The supervisor receives the one-time key through its restart pipe. Only an
authenticated ciphertext and non-secret operation metadata persist while the
manager worker is running. Activation happens after that worker has stopped.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import time
import zlib

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .backup import (BackupError, FULL_ROOT_FILES, _CA_FILE, _CERT_FILE,
                     _validate_full, _validate_servers, apply_server_restore,
                     plan_full_restore, plan_server_restore, validate_application_version)
from .deployment import (atomic_config, generate_certificate, read_config,
                         stage_certificate, validate_network, write_private)
from .storage import Store


_ID = re.compile(r"[0-9a-f]{32}\Z")
_PENDING = "restore.pending.json"
_JOURNAL = "restore.transaction.json"
_RESULT = "restore.last.json"


def _state_file(data_dir: Path, operation_id: str) -> Path:
    if not _ID.fullmatch(operation_id):
        raise BackupError("Restore operation identity is invalid")
    return data_dir / f"restore-{operation_id}.sealed"


def _rollback_dir(data_dir: Path, operation_id: str) -> Path:
    if not _ID.fullmatch(operation_id):
        raise BackupError("Restore operation identity is invalid")
    return data_dir / f"restore-rollback-{operation_id}"


def stage_restore(data_dir: Path, payload: dict, plan: dict,
                  replacement_address: str | None = None) -> tuple[str, bytes]:
    """Persist only encrypted staging material; return a pipe-only AES key."""
    validate_application_version(payload)
    if (data_dir / _PENDING).exists() or (data_dir / _JOURNAL).exists():
        raise BackupError("Another restore is already pending")
    operation_id = secrets.token_hex(16)
    key, nonce = AESGCM.generate_key(bit_length=256), secrets.token_bytes(12)
    plaintext = zlib.compress(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    ciphertext = nonce + AESGCM(key).encrypt(nonce, plaintext, operation_id.encode())
    stage_path = _state_file(data_dir, operation_id)
    write_private(stage_path, ciphertext)
    try:
        atomic_config(data_dir, _PENDING, {"id": operation_id, "scope": payload["manifest"]["scope"],
                                           "plan": plan, "replacement_address": replacement_address,
                                           "requested_at": datetime.now(timezone.utc).isoformat()})
    except BaseException:
        stage_path.unlink(missing_ok=True)
        raise
    return operation_id, key


def _open_stage(data_dir: Path, operation_id: str, key: bytes) -> dict:
    path = _state_file(data_dir, operation_id)
    if path.is_symlink() or not path.is_file() or len(key) != 32:
        raise BackupError("Private restore stage is unavailable")
    ciphertext = path.read_bytes()
    try:
        raw = AESGCM(key).decrypt(ciphertext[:12], ciphertext[12:], operation_id.encode())
        decoder = zlib.decompressobj()
        content = decoder.decompress(raw, 768 * 1024 * 1024 + 1)
        if decoder.unconsumed_tail or not decoder.eof or len(content) > 768 * 1024 * 1024:
            raise BackupError("Private restore stage exceeds the size limit")
        payload = json.loads(content)
    except (InvalidTag, zlib.error, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        if isinstance(exc, BackupError):
            raise
        raise BackupError("Private restore stage is corrupt") from None
    if payload.get("manifest", {}).get("scope") == "full":
        _validate_full(payload)
    else:
        _validate_servers(payload)
    return payload


def _durable_paths(data_dir: Path) -> list[Path]:
    paths = [data_dir / "manager.db", *(data_dir / name for name in FULL_ROOT_FILES)]
    paths.extend(data_dir.glob("bmc-ca-*.pem"))
    certificates = data_dir / "certificates"
    if certificates.is_symlink():
        raise BackupError("Certificate directory must not be a symlink")
    if certificates.exists():
        for directory in certificates.iterdir():
            if directory.is_symlink() or not directory.is_dir():
                raise BackupError("Unexpected certificate directory entry")
            paths.extend(directory.iterdir())
    selected = [path for path in paths if path.exists()]
    if any(path.is_symlink() or not path.is_file() for path in selected):
        raise BackupError("Unexpected non-file in durable installation state")
    return selected


def _cache_paths(data_dir: Path) -> list[Path]:
    paths = [path for path in data_dir.glob("metrics-*.prom*")
             if re.fullmatch(r"metrics-[0-9a-f]{32}\.prom(?:\.cache|\.catalog|\.status)?", path.name)]
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise BackupError("Unexpected exporter cache file")
    return paths


def _copy_rollback(data_dir: Path, operation_id: str, scope: str) -> Path:
    rollback = _rollback_dir(data_dir, operation_id)
    rollback.mkdir(mode=0o700)
    paths = (_durable_paths(data_dir) + _cache_paths(data_dir)
             if scope == "full" else [data_dir / "manager.db"] + _cache_paths(data_dir))
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise BackupError("Unexpected symlink in installation state")
        target = rollback / path.relative_to(data_dir)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copy2(path, target)
        os.chmod(target, 0o600)
        with target.open("rb") as copy:
            os.fsync(copy.fileno())
    return rollback


def _remove_durable(data_dir: Path) -> None:
    for path in _durable_paths(data_dir) + _cache_paths(data_dir):
        path.unlink(missing_ok=True)
    certificates = data_dir / "certificates"
    if certificates.exists():
        shutil.rmtree(certificates)


def _restore_rollback(data_dir: Path, operation_id: str, scope: str, *, native: bool = False) -> None:
    rollback = _rollback_dir(data_dir, operation_id)
    if not rollback.is_dir():
        raise BackupError("Restore rollback snapshot is missing")
    if scope == "full":
        _remove_durable(data_dir)
        paths = [path for path in rollback.rglob("*") if path.is_file() and
                 not (native and path.relative_to(rollback).parts[0] == "prometheus")]
    else:
        for cache_path in _cache_paths(data_dir):
            cache_path.unlink()
        paths = [rollback / "manager.db", *rollback.glob("metrics-*.prom*")]
    for path in paths:
        target = data_dir / path.relative_to(rollback)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copy2(path, target)
        os.chmod(target, 0o600)


def _apply_full(data_dir: Path, payload: dict, replacement_address: str | None) -> dict:
    source = Path(payload["source_data_dir"])
    files = payload["files"]
    original = json.loads(base64.b64decode(files["deployment.json"], validate=True))
    _remove_durable(data_dir)
    write_private(data_dir / "manager.db", base64.b64decode(payload["database"], validate=True))
    for name, encoded in files.items():
        if name not in FULL_ROOT_FILES and not _CERT_FILE.fullmatch(name) and not _CA_FILE.fullmatch(name):
            raise BackupError("Restore contains an unexpected file")
        if name.startswith("deployment."):
            continue  # Rebuild deployment recovery for this destination.
        path = data_dir / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_private(path, base64.b64decode(encoded, validate=True))
    proposal = original.copy()
    for field in ("cert", "key"):
        proposal["certificate"][field] = str(data_dir / Path(original["certificate"][field]).relative_to(source))
    if original.get("bmc_ca"):
        proposal["bmc_ca"] = str(data_dir / Path(original["bmc_ca"]).relative_to(source))
    if replacement_address:
        proposal.update(manager_bind=replacement_address, manager_host=replacement_address,
                        exporter_bind=replacement_address, exporter_host=replacement_address,
                        console_bind=replacement_address, console_host=replacement_address)
        proposal.pop("manager_origin", None)
        hosts = [proposal["manager_host"], proposal["console_host"], proposal["exporter_host"]]
        cert, key = generate_certificate(hosts)
        proposal["certificate"] = stage_certificate(data_dir, cert, key, b"", hosts,
                                                     "installation-generated")
    proposal = validate_network(proposal)
    atomic_config(data_dir, "deployment.json", proposal)
    # Keep a local HTTPS recovery listener available if the selected interface
    # later disappears. The recovery certificate is distinct and owner-only.
    recovery = proposal.copy()
    recovery.update(manager_bind="127.0.0.1", manager_host="localhost",
                    exporter_bind="127.0.0.1", exporter_host="127.0.0.1",
                    console_bind="127.0.0.1", console_host="localhost")
    recovery.pop("manager_origin", None)
    cert, key = generate_certificate(["localhost", "127.0.0.1"])
    recovery["certificate"] = stage_certificate(data_dir, cert, key, b"", ["localhost", "127.0.0.1"],
                                                "installation-generated")
    atomic_config(data_dir, "deployment.recovery.json", validate_network(recovery))
    with sqlite3.connect(data_dir / "manager.db") as db:
        db.execute("DELETE FROM sessions")
    return proposal


def apply_staged_restore(data_dir: Path, key: bytes) -> dict:
    """Called only after the supervisor has stopped its current worker."""
    pending = read_config(data_dir, name=_PENDING)
    if pending.get("format") == 4:
        from .restore_history import apply_file_restore
        return apply_file_restore(data_dir, key)
    operation_id = pending.get("id", "")
    if not _ID.fullmatch(operation_id):
        raise BackupError("Restore pending record is invalid")
    payload = _open_stage(data_dir, operation_id, key)
    if payload["manifest"]["scope"] != pending.get("scope"):
        raise BackupError("Restore scope changed after review")
    store = Store(data_dir)
    reviewed = pending.get("plan")
    current = (plan_full_restore(store, payload, pending.get("replacement_address"))
               if pending["scope"] == "full" else plan_server_restore(store, payload))
    if reviewed != current:
        raise BackupError("Destination changed since preview; review the restore again")
    rollback = _copy_rollback(data_dir, operation_id, pending["scope"])
    try:
        atomic_config(data_dir, _JOURNAL, {"id": operation_id, "scope": pending["scope"],
                                            "started_at": time.time()})
        if pending["scope"] == "full":
            proposal = _apply_full(data_dir, payload, pending.get("replacement_address"))
        else:
            for path in _cache_paths(data_dir):
                path.unlink()
            apply_server_restore(store, payload, reviewed)
            proposal = read_config(data_dir)
        return {"id": operation_id, "scope": pending["scope"], "deployment": proposal,
                "rollback": rollback}
    except BaseException:
        if (data_dir / _JOURNAL).exists():
            _restore_rollback(data_dir, operation_id, pending["scope"])
            (data_dir / _JOURNAL).unlink(missing_ok=True)
        raise


def finish_restore(data_dir: Path, operation_id: str, *, applied: bool,
                   reason: str = "") -> None:
    journal = read_config(data_dir, name=_JOURNAL)
    if journal.get("id") != operation_id:
        raise BackupError("Restore transaction identity is invalid")
    pending = read_config(data_dir, name=_PENDING)
    plan = pending.get("plan", {}) if pending.get("id") == operation_id else {}
    if not applied:
        _restore_rollback(data_dir, operation_id, journal["scope"])
    atomic_config(data_dir, _RESULT, {"id": operation_id, "scope": journal["scope"],
                                      "status": "applied" if applied else "reverted",
                                      "reason": reason if not applied else None, "at": time.time(),
                                      "current_url": plan.get("current_url") or plan.get("destination_manager_origin"),
                                      "result_url": plan.get("result_url") or plan.get("destination_manager_origin")})
    (data_dir / _JOURNAL).unlink(missing_ok=True)
    (data_dir / _PENDING).unlink(missing_ok=True)
    _state_file(data_dir, operation_id).unlink(missing_ok=True)
    shutil.rmtree(_rollback_dir(data_dir, operation_id), ignore_errors=True)


def mark_restore_health_check(data_dir: Path, operation_id: str) -> None:
    journal = read_config(data_dir, name=_JOURNAL)
    if journal.get("id") != operation_id:
        raise BackupError("Restore transaction identity is invalid")
    atomic_config(data_dir, _JOURNAL, {**journal, "phase": "checking-https"})


def recover_interrupted_restore(data_dir: Path, *,
                                reason: str = "Supervisor interrupted during restore") -> bool:
    """Fail closed after supervisor death; never launch an unverified candidate."""
    journal = read_config(data_dir, name=_JOURNAL)
    pending = read_config(data_dir, name=_PENDING)
    if not journal and not pending:
        return False
    record = journal or pending
    operation_id = record.get("id", "")
    if not _ID.fullmatch(operation_id):
        raise BackupError("Interrupted restore record is invalid")
    if journal:
        _restore_rollback(data_dir, operation_id, journal["scope"])
        (data_dir / _JOURNAL).unlink(missing_ok=True)
    plan = pending.get("plan", {})
    atomic_config(data_dir, _RESULT, {"id": operation_id, "scope": record["scope"],
                                      "status": "reverted", "reason": reason,
                                      "at": time.time(),
                                      "current_url": plan.get("current_url") or plan.get("destination_manager_origin"),
                                      "result_url": plan.get("result_url") or plan.get("destination_manager_origin")})
    (data_dir / _PENDING).unlink(missing_ok=True)
    _state_file(data_dir, operation_id).unlink(missing_ok=True)
    shutil.rmtree(_rollback_dir(data_dir, operation_id), ignore_errors=True)
    return True
