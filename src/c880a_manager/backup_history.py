"""Compose encrypted installation/claim archives with portable native history.

Transport artifacts own their lifetime. No native runtime paths, activation
journals or private service identities are restored from another installation.
The public job and supervisor application layers consume these boundaries.
"""
from __future__ import annotations

from contextlib import nullcontext
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import time

from .backup import (BackupError, archive_payload, _validate_full, _validate_servers,
                     plan_full_restore, plan_server_restore)
from .backup_stream import Limits, _check, _regular, _space, _workspace, create_file_archive
from .deployment import read_config
from .prometheus import DEFAULTS, GIB, validate_settings
from .prometheus_runtime import MAX_EXECUTABLE, VERSION
from .prometheus_history import (HistorySnapshot, _api, _copy_files,
                                claimed_history_exclusions, isolated_engine,
                                prepare_claimed_history, prepare_full_history)
from .state_operation import installation_lease


def managed_present(managed) -> bool:
    # A partial installation must fail, rather than masquerade as unmanaged.
    if managed.root.is_symlink():
        raise BackupError("Managed Prometheus directory is unsafe; repair the installation")
    if not managed.root.exists():
        return False
    managed.installation()
    managed.generation()
    runtime = Path(managed.installation()["runtime_dir"])
    if runtime.is_symlink() or not runtime.is_dir():
        raise BackupError("Prometheus runtime is unavailable; re-run the installer before restoring")
    for name in ("prometheus", "promtool"):
        path = runtime / name
        try:
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid()) or
                    info.st_mode & 0o022 or not 0 < info.st_size <= MAX_EXECUTABLE or
                    not os.access(path, os.X_OK)):
                raise OSError
            checked = subprocess.run([str(path), "--version"], capture_output=True, check=True, timeout=5)
            if f"{name}, version {VERSION} ".encode() not in checked.stdout:
                raise OSError
        except (OSError, subprocess.SubprocessError):
            raise BackupError("Prometheus runtime is unavailable or incompatible; re-run the installer before restoring") from None
    return True


def archived_ids(payload: dict) -> list[str]:
    if payload["manifest"]["scope"] == "servers":
        result = [row["id"] for row in payload["tables"]["servers"]]
    else:
        with sqlite3.connect(":memory:") as db:
            db.deserialize(base64.b64decode(payload["database"], validate=True))
            result = [row[0] for row in db.execute("SELECT id FROM servers WHERE state='active'")]
    claimed_history_exclusions(result)
    return sorted(result)


def create_history_archive(store, managed, scope: str, passphrase: str, workspace: Path,
                           *, cancel=None, progress=None):
    """Capture metadata/all claims and immutable native history, then encrypt.

    The lease excludes foreground installation mutations. Collectors may keep
    updating SQLite: archive_payload uses one consistent SQLite snapshot.
    Mutable source snapshots are detached before releasing the capture lease.
    """
    private = None
    try:
        with installation_lease(store.data_dir):
            if store.pending_prometheus_deletions() or (managed.root / "delete.pending.json").exists():
                raise BackupError("Finish target history cleanup before backing up")
            if any((store.data_dir / name).exists() for name in
                   ("deployment.pending.json", "deployment.prometheus.json", "restore.pending.json", "restore.transaction.json")):
                raise BackupError("Finish installation recovery before backing up")
            _check(cancel)
            payload = archive_payload(store, scope)
            ids = archived_ids(payload)
            metadata_bytes = len(json.dumps(payload, separators=(",", ":")).encode())
            if not managed_present(managed):
                payload["prometheus"] = {"managed": False}
                files = {}
            else:
                prepare = prepare_full_history if scope == "full" else prepare_claimed_history
                args = () if scope == "full" else (ids,)
                with prepare(managed, workspace, *args, additional_bytes=metadata_bytes,
                             cancel=cancel, progress=progress) as snapshot:
                    private = _workspace(workspace)
                    root = Path(private.name) / "tsdb"
                    root.mkdir(mode=0o700)
                    _space(workspace, snapshot.summary["bytes"] * 2 + metadata_bytes, Limits())
                    _copy_files({str(Path(name).relative_to("prometheus/tsdb")): path
                                 for name, path in snapshot.files.items()}, root,
                                cancel=cancel, progress=progress)
                    files = {name: root / Path(name).relative_to("prometheus/tsdb")
                             for name in snapshot.files}
                    payload["prometheus"] = {"managed": True, "scope": scope,
                        "settings": snapshot.settings, "history": snapshot.summary,
                        "server_ids": ids}
        # No captured plaintext metadata is persisted. The returned archive is
        # encrypted; the passphrase/key remain in the worker's memory only.
        return create_file_archive(payload, files, passphrase, workspace,
                                   cancel=cancel, progress=progress)
    finally:
        if private is not None:
            private.cleanup()


def validate_history_archive(opened, managed, workspace: Path, *, cancel=None) -> dict:
    """Validate authenticated metadata and native block/scope semantics."""
    payload = opened.metadata
    scope = payload.get("manifest", {}).get("scope") if isinstance(payload, dict) else None
    if scope == "full":
        _validate_full(payload)
    elif scope == "servers":
        _validate_servers(payload)
    else:
        raise BackupError("Backup scope is incompatible")
    value = payload.get("prometheus")
    if not isinstance(value, dict) or type(value.get("managed")) is not bool:
        raise BackupError("Backup Prometheus state cannot be verified")
    if not value["managed"]:
        if set(value) != {"managed"} or opened.files:
            raise BackupError("Unmanaged backup contains unexpected history")
        return value
    if set(value) != {"managed", "scope", "settings", "history", "server_ids"} or value["scope"] != scope:
        raise BackupError("Backup Prometheus scope is incompatible")
    try:
        validate_settings(value["settings"])
    except ValueError:
        raise BackupError("Backup Prometheus settings are invalid") from None
    if value["server_ids"] != archived_ids(payload):
        raise BackupError("Backup history identities do not match its complete claimed-server archive")
    if not managed_present(managed):
        raise BackupError("This backup includes managed Prometheus history; re-run the installer before restoring")
    _complete_blocks(opened.files)
    directory = _workspace(workspace)
    try:
        private = Path(directory.name)
        db = private / "tsdb"
        db.mkdir(mode=0o700)
        _space(workspace, sum(path.stat().st_size for path in opened.files.values()), Limits())
        _copy_files({str(Path(name).relative_to("prometheus/tsdb")):path
                     for name, path in opened.files.items()}, db, cancel=cancel)
        # Native reopen validates chunk/index/metadata agreement; it never
        # acquires source credentials, scrapes, or applies retention.
        if opened.files:
            with isolated_engine(Path(managed.installation()["runtime_dir"]), db, private, cancel=cancel) as client:
                if scope == "servers":
                    foreign = _api(client, "POST", "api/v1/series", hostname="127.0.0.1",
                                   data={"match[]":claimed_history_exclusions(value["server_ids"])})
                    if foreign != []:
                        raise BackupError("Servers-only backup contains unrelated Prometheus history")
        # The engine may create WAL/head files. Compare the authenticated
        # completed blocks, rather than counting disposable replay files.
        block_root = private / "blocks"
        block_root.mkdir(mode=0o700)
        _copy_files({str(Path(name).relative_to("prometheus/tsdb")):path
                     for name, path in opened.files.items()}, block_root, cancel=cancel)
        snapshot = HistorySnapshot(directory, block_root, value["settings"])
        if value["history"] != snapshot.summary:
            raise BackupError("Backup history size, samples or time bounds do not match its native blocks")
        _check(cancel)
        return value
    finally:
        directory.cleanup()


def _complete_blocks(files: dict[str, Path]) -> None:
    blocks = {}
    for name, path in files.items():
        relative = Path(name).relative_to("prometheus/tsdb")
        blocks.setdefault(relative.parts[0], {})[relative.relative_to(relative.parts[0]).as_posix()] = path
    for identity, block in blocks.items():
        if not {"meta.json", "index"} <= set(block):
            raise BackupError("Backup contains an incomplete Prometheus block")
        with _regular(block["meta.json"]) as source:
            raw = source.read(65537)
        try:
            if len(raw) > 65536:
                raise ValueError
            value = json.loads(raw)
            counts = [value["stats"][name] for name in ("numSamples", "numSeries", "numChunks")]
            if (value["ulid"] != identity or type(value["version"]) is not int or value["version"] != 1 or
                    any(type(count) is not int or count < 0 for count in counts) or
                    counts[0] > 0 and (not all(counts) or not any(name.startswith("chunks/") for name in block))):
                raise ValueError
        except (ValueError, KeyError, TypeError):
            raise BackupError("Backup Prometheus block metadata is incomplete or inconsistent") from None


def _destination_bytes(managed) -> int:
    if (managed.root / "tsdb").is_symlink() or not (managed.root / "tsdb").is_dir():
        raise BackupError("Destination Prometheus history is unavailable or unsafe")
    total = 0
    for base, dirs, names in os.walk(managed.root / "tsdb", followlinks=False):
        base = Path(base)
        if any((base / name).is_symlink() for name in dirs + names):
            raise BackupError("Destination Prometheus history contains an unsafe path")
        if base == managed.root / "tsdb" and "snapshots" in dirs:
            dirs.remove("snapshots")
        for name in names:
            try:
                total += (base / name).stat().st_size
            except FileNotFoundError:  # Live native compaction may rename files.
                pass
    return total


def _reject_history_conflicts(managed, workspace: Path, identities: list[str], *, cancel=None):
    if not identities:
        return
    with prepare_full_history(managed, workspace, cancel=cancel) as snapshot:
        if not snapshot.files:
            return
        directory = _workspace(workspace)
        try:
            private = Path(directory.name)
            db = private / "tsdb"
            db.mkdir(mode=0o700)
            _copy_files({str(Path(name).relative_to("prometheus/tsdb")):path
                         for name, path in snapshot.files.items()}, db, cancel=cancel)
            with isolated_engine(Path(managed.installation()["runtime_dir"]), db, private, cancel=cancel) as client:
                matching = _api(client, "POST", "api/v1/series", hostname="127.0.0.1",
                    data={"match[]":'{job="c880a",server_id=~"' + '|'.join(identities) + '"}'})
                if matching != []:
                    raise BackupError("Destination retains history for an archived server identity; use a fresh installation or resolve that history before restoring")
        finally:
            directory.cleanup()


def _retention_discards_blocks(files: dict[str, Path], retention_hours: int) -> bool:
    # Native time retention deletes whole blocks using their maximum times.
    # Using the oldest sample would wrongly reject a block spanning the cutoff.
    cutoff = (time.time() - retention_hours * 3600) * 1000
    for name, path in files.items():
        if name.endswith("/meta.json"):
            metadata = json.loads(path.read_bytes())  # Already bounded/validated.
            if metadata["maxTime"] <= cutoff:
                return True
    return False


def plan_history_restore(store, managed, opened, workspace: Path, replacement_address=None,
                         *, cancel=None, _lease: bool = True) -> dict:
    """Preview the complete archive; no destination mutation or service stop."""
    with installation_lease(store.data_dir) if _lease else nullcontext():
        if (store.pending_prometheus_deletions() or (managed.root / "delete.pending.json").exists() or
                (store.data_dir / "deployment.prometheus.json").exists()):
            raise BackupError("Finish installation recovery and target history cleanup before restoring")
        value = validate_history_archive(opened, managed, workspace, cancel=cancel)
        payload = opened.metadata
        scope = payload["manifest"]["scope"]
        plan = (plan_full_restore(store, payload, replacement_address) if scope == "full" else
                plan_server_restore(store, payload))
        destination_managed = managed_present(managed)
        if not destination_managed:
            plan["prometheus"] = {"managed": False}
            return plan
        if workspace.stat().st_dev != (managed.root / "tsdb").stat().st_dev:
            raise BackupError("Restore staging must be on the Prometheus data filesystem")
        if read_config(managed.root, name="pending.json"):
            raise BackupError("Recover the unconfirmed Prometheus change before restoring")
        settings = (value["settings"] if scope == "full" and value["managed"] else
                    dict(DEFAULTS) if scope == "full" else managed.settings())
        summary = value.get("history", {"bytes":0,"samples":0,"min_time_ms":None,"max_time_ms":None})
        existing = _destination_bytes(managed)
        resulting = summary["bytes"] + (existing if scope == "servers" else 0)
        # Reject before mutation if enabling would immediately prune the
        # complete archive. The pinned native flag uses powers-of-two units.
        if settings["enabled"]:
            remedy = ("Increase the source setting or disable source scraping, then create a new Full backup" if scope == "full" else
                      "Increase the destination setting or disable destination scraping, then preview again")
            if resulting > settings["storage_gib"] * GIB:
                raise BackupError("Restored history exceeds the enabled Prometheus storage limit. " + remedy)
            if _retention_discards_blocks(opened.files, settings["retention_hours"]):
                raise BackupError("Restored history is older than the enabled Prometheus retention. " + remedy)
        required = 4 * (existing + summary["bytes"]) + len(json.dumps(payload).encode())
        _space(workspace, required, Limits())
        if scope == "servers" and value["managed"]:
            _reject_history_conflicts(managed, workspace, value["server_ids"], cancel=cancel)
        # Bind logical service/configuration state, not continuously arriving
        # samples or free-space readings, into the reviewed destination identity.
        state = {"active":managed.active(), "pending":read_config(managed.root, name="pending.json"),
                 "installation":managed.installation()}
        plan["prometheus"] = {"managed":True, "archived_managed":value["managed"],
            "history":summary, "settings":settings, "settings_action":"replace" if scope == "full" else "preserve",
            "required_bytes":required + Limits().reserve_bytes,
            "destination_state_sha256":hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()}
        return plan


def history_plan_matches(reviewed: dict, current: dict) -> bool:
    """Disk estimates are rechecked, never a stable destination identity."""
    def stable(value):
        if not isinstance(value, dict):
            raise ValueError
        value = dict(value)
        if "prometheus" in value:
            if not isinstance(value["prometheus"], dict):
                raise ValueError
            value["prometheus"] = dict(value["prometheus"])
            value["prometheus"].pop("required_bytes", None)
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    try:
        return stable(reviewed) == stable(current)
    except (ValueError, TypeError):
        return False
