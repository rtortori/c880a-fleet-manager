"""Encrypted file-backed restore stages and matched native-state recovery."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import secrets
import shutil
import time

from .backup import BackupError, apply_server_restore, validate_application_version
from .backup_history import _complete_blocks, history_plan_matches, plan_history_restore, managed_present
from .backup_stream import Limits, _check, _space, _workspace, create_file_archive, open_file_archive
from .deployment import atomic_config, read_config
from .prometheus import DEFAULTS
from .prometheus_history import (HistorySnapshot, _copy_files, _native_snapshot,
                                history_files, isolated_engine, prepare_full_history)
from .prometheus_service import ManagedPrometheus, startup_marker
from .restore import (_ID, _PENDING, _JOURNAL, _RESULT, _state_file, _rollback_dir,
                      _copy_rollback, _restore_rollback, _apply_full, _cache_paths)
from .state_operation import installation_lease
from .storage import Store


def stage_file_restore(store, managed, opened, reviewed: dict, workspace: Path,
                       replacement_address=None, *, cancel=None, progress=None) -> tuple[str, bytes]:
    """Seal a reviewed complete archive; the supervisor key travels only by pipe.

    The installation lease covers final preview checking and publication. The
    pending record is published last, after the authenticated stage is durable.
    """
    with installation_lease(store.data_dir):
        return _stage_file_restore(store, managed, opened, reviewed, workspace,
                                   replacement_address, cancel=cancel, progress=progress)


def _stage_file_restore(store, managed, opened, reviewed, workspace, replacement_address,
                        *, cancel=None, progress=None):
    validate_application_version(opened.metadata)
    current = plan_history_restore(store, managed, opened, workspace, replacement_address,
                                   cancel=cancel, _lease=False)
    if not history_plan_matches(reviewed, current):
        raise BackupError("Destination changed since preview; review the restore again")
    if current["scope"] == "servers" and not current["bmc_trust_match"]:
        raise BackupError("Destination BMC CA bundle must match the source before restoring servers")
    if not isinstance(opened.archive_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", opened.archive_sha256):
        raise BackupError("Original archive identity cannot be verified")
    data_dir = store.data_dir
    if any((data_dir / name).exists() for name in (_PENDING, _JOURNAL, "deployment.pending.json")):
        raise BackupError("Another installation change is pending")
    identifier = secrets.token_hex(16)
    key = secrets.token_bytes(32)
    metadata = {**opened.metadata, "private_restore":{
        "id":identifier, "archive_sha256":opened.archive_sha256}}
    path = _state_file(data_dir, identifier)
    try:
        with create_file_archive(metadata, opened.files, key.hex(), workspace,
                                 cancel=cancel, progress=progress) as archive:
            _check(cancel)
            if path.exists() or path.is_symlink():
                raise BackupError("Restore staging identity already exists")
            os.replace(archive.path, path)
        descriptor = os.open(data_dir, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _check(cancel)
        atomic_config(data_dir, _PENDING, {"id":identifier,"format":4,
            "scope":opened.metadata["manifest"]["scope"], "archive_sha256":opened.archive_sha256,
            "plan":current, "replacement_address":replacement_address,
            "requested_at":datetime.now(timezone.utc).isoformat()})
        return identifier, key
    except BaseException:
        path.unlink(missing_ok=True)
        if read_config(data_dir, name=_PENDING).get("id") == identifier:
            (data_dir / _PENDING).unlink(missing_ok=True)
        raise


@contextmanager
def open_file_stage(data_dir: Path, identifier: str, key: bytes, workspace: Path,
                    *, cancel=None):
    """Authenticate the complete stage and its operation binding before use."""
    pending = read_config(data_dir, name=_PENDING)
    if (not isinstance(identifier, str) or not _ID.fullmatch(identifier) or not isinstance(key, bytes) or len(key) != 32 or
            pending.get("id") != identifier or pending.get("format") != 4):
        raise BackupError("Private restore stage identity is invalid")
    with open_file_archive(_state_file(data_dir, identifier), key.hex(), workspace, cancel=cancel) as opened:
        binding = opened.metadata.pop("private_restore", None)
        if binding != {"id":identifier, "archive_sha256":pending.get("archive_sha256")}:
            raise BackupError("Private restore stage does not match its operation")
        if opened.metadata["manifest"]["scope"] != pending.get("scope"):
            raise BackupError("Private restore scope changed after review")
        yield opened


def prepare_replacement_history(managed, opened, workspace: Path, *, cancel=None, progress=None):
    """Build complete native replacement while the original engine is stopped.

    Servers-only keeps all destination WAL/head data and incoming blocks. Full
    uses only archived history/settings, including explicit unmanaged defaults.
    Neither scope rewrites historical endpoint labels or reconstructs samples.
    """
    if managed.control.active():
        raise BackupError("Prometheus must be stopped before preparing restored history")
    scope = opened.metadata["manifest"]["scope"]
    value = opened.metadata["prometheus"]
    if scope not in ("full", "servers"):
        raise BackupError("Restore scope is incompatible")
    _complete_blocks(opened.files)
    directory = _workspace(workspace)
    try:
        private = Path(directory.name)
        database = private / "tsdb"
        database.mkdir(mode=0o700)
        incoming = {str(Path(name).relative_to("prometheus/tsdb")):path
                    for name, path in opened.files.items()}
        if scope == "servers":
            with prepare_full_history(managed, workspace, stopped=True, cancel=cancel, progress=progress) as source:
                retained = {str(Path(name).relative_to("prometheus/tsdb")):path
                            for name, path in source.files.items()}
                if {Path(name).parts[0] for name in retained} & {Path(name).parts[0] for name in incoming}:
                    raise BackupError("Destination retains an archived Prometheus block identity; use a fresh installation or resolve that history before restoring")
                _space(workspace, 3 * (source.summary["bytes"] + sum(path.stat().st_size for path in incoming.values())), Limits())
                _copy_files(retained, database, cancel=cancel, progress=progress)
                settings = source.settings
        else:
            settings = value["settings"] if value["managed"] else dict(DEFAULTS)
            _space(workspace, 3 * sum(path.stat().st_size for path in incoming.values()), Limits())
        _copy_files(incoming, database, cancel=cancel, progress=progress)
        _check(cancel)
        if any(database.iterdir()):
            with isolated_engine(Path(managed.installation()["runtime_dir"]), database, private, cancel=cancel) as client:
                snapshot = _native_snapshot(client, database, "127.0.0.1")
                result = HistorySnapshot(directory, snapshot, settings)
        else:
            result = HistorySnapshot(directory, database, settings)
        _check(cancel)
        if managed.control.active():
            raise BackupError("Prometheus changed state while preparing restored history")
        return result
    except BaseException:
        directory.cleanup()
        raise


def _sync_tree(root: Path):
    for directory, _, _ in os.walk(root, topdown=False):
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _native_state_files(root: Path):
    """Copy only owned durable service state; keep lock inodes in place."""
    if root.is_symlink() or not root.is_dir():
        raise BackupError("Prometheus recovery directory is unsafe")
    result = {"tsdb/" + name:path for name,path in history_files(root / "tsdb", raw=True).items()}
    for name in ("installation.json", "active.json", "last.json", "enabled"):
        path = root / name
        if path.exists():
            if path.is_symlink() or not path.is_file():
                raise BackupError("Prometheus recovery metadata is unsafe")
            result[name] = path
    generations = root / "generations"
    if generations.is_symlink() or not generations.is_dir():
        raise BackupError("Prometheus recovery generations are unsafe")
    for directory in generations.iterdir():
        if directory.is_symlink() or not directory.is_dir() or not _ID.fullmatch(directory.name):
            raise BackupError("Prometheus recovery generation is unsafe")
        for path in directory.iterdir():
            if path.name not in {"client-ca.pem", "client.pem", "client.key", "scrape.json", "web.json"}:
                raise BackupError("Prometheus recovery generation contains an unexpected file")
            if path.is_symlink() or not path.is_file():
                raise BackupError("Prometheus recovery generation is unsafe")
            result[path.relative_to(root).as_posix()] = path
    return result


def _workspace_root(data_dir):
    root = data_dir / "restore-workspace"
    if root.is_symlink():
        raise BackupError("Restore workspace is unsafe")
    root.mkdir(mode=0o700, exist_ok=True)
    if not root.is_dir() or root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077:
        raise BackupError("Restore workspace permissions are unsafe")
    return root


def _stop_engine(managed):
    managed.control.set_enabled(False)
    if managed.control.active():
        raise BackupError("Prometheus stopped state could not be confirmed")


def _resume_engine(managed):
    enabled = managed.settings()["enabled"]
    managed.control.set_enabled(enabled)
    if enabled:
        if not managed.wait_ready(managed.active()):
            raise BackupError("Prometheus readiness could not be confirmed")
    elif managed.control.active():
        raise BackupError("Prometheus disabled state could not be confirmed")


def _candidate(journal, data_dir):
    return {"id":journal["id"], "scope":journal["scope"], "format":4,
            "recovering":journal.get("outcome") == "reverted" or journal["phase"] == "checking-prior",
            "deployment":read_config(data_dir), "managed":journal["managed"]}


def _outcome(data_dir, journal, status, reason=""):
    plan = read_config(data_dir, name=_PENDING).get("plan") or journal.get("plan", {})
    atomic_config(data_dir, _RESULT, {"id":journal["id"], "scope":journal["scope"],
        "status":status, "reason":reason or None, "at":time.time(),
        "current_url":plan.get("current_url") or plan.get("destination_manager_origin"),
        "result_url":plan.get("result_url") or plan.get("destination_manager_origin")})


def apply_file_restore(data_dir: Path, key: bytes, *, managed=None) -> dict:
    """Apply a reviewed file stage after worker stop; health remains unconfirmed.

    The journal records prior intent before stopping the engine and marks the
    matched rollback durable before exchanging either application's data.
    """
    managed = managed or ManagedPrometheus(data_dir)
    with installation_lease(data_dir):
        pending = read_config(data_dir, name=_PENDING)
        identifier = pending.get("id", "")
        workspace = _workspace_root(data_dir)
        with open_file_stage(data_dir, identifier, key, workspace) as opened:
            store = Store(data_dir)
            current = plan_history_restore(store, managed, opened, workspace,
                pending.get("replacement_address"), _lease=False)
            if not history_plan_matches(pending.get("plan"), current):
                raise BackupError("Destination changed since preview; review the restore again")
            present = managed_present(managed)
            journal = {"id":identifier, "scope":pending["scope"], "format":4,
                       "phase":"preparing", "managed":present,
                       "previous_prometheus":managed.active() if present else None,
                       "previous_deployment":read_config(data_dir), "started_at":time.time(),
                       "plan":current,
                       "rollback_ready":False, "mutation_started":False}
            atomic_config(data_dir, _JOURNAL, journal)
            if present:
                _stop_engine(managed)
            rollback = _copy_rollback(data_dir, identifier, pending["scope"])
            if present:
                destination = rollback / "prometheus"
                destination.mkdir(mode=0o700)
                _copy_files(_native_state_files(managed.root), destination)
                # Stopping clears the boot marker, but rollback retains the
                # previously applied logical startup choice.
                startup_marker(destination / "enabled", journal["previous_prometheus"]["settings"]["enabled"])
            _sync_tree(rollback)
            journal.update(phase="rollback-ready", rollback_ready=True)
            atomic_config(data_dir, _JOURNAL, journal)
            replacement = prepare_replacement_history(managed, opened, workspace) if present else None
            try:
                if present and managed.control.active():
                    raise BackupError("Prometheus changed state before restore application")
                journal.update(phase="applying", mutation_started=True)
                atomic_config(data_dir, _JOURNAL, journal)
                if pending["scope"] == "full":
                    _apply_full(data_dir, opened.metadata, pending.get("replacement_address"))
                else:
                    for path in _cache_paths(data_dir):
                        path.unlink()
                    apply_server_restore(store, opened.metadata,
                                         {name:value for name,value in current.items() if name != "prometheus"})
                if present:
                    files = {str(Path(name).relative_to("prometheus/tsdb")):path
                             for name,path in replacement.files.items()}
                    candidate_db = managed.root / ("restore-candidate-" + identifier)
                    candidate_db.mkdir(mode=0o700)
                    _copy_files(files, candidate_db)
                    _sync_tree(candidate_db)
                    generation = managed.prepare(replacement.settings)
                    (managed.root / "tsdb").rename(managed.root / ("restore-prior-" + identifier))
                    candidate_db.rename(managed.root / "tsdb")
                    atomic_config(managed.root, "active.json", generation)
                    _resume_engine(managed)
                journal["phase"] = "checking-candidate"
                atomic_config(data_dir, _JOURNAL, journal)
                return _candidate(journal, data_dir)
            finally:
                if replacement:
                    replacement.close()


def recover_file_restore(data_dir: Path, *, managed=None,
                         reason="Restore interrupted before activation was confirmed") -> dict:
    """Select the prior state for verification, independently of the lost key.

    Failure keeps the operation, rollback, and journal. It must never authorize
    a worker launch or claim that recovery succeeded.
    """
    managed = managed or ManagedPrometheus(data_dir)
    with installation_lease(data_dir):
        journal = read_config(data_dir, name=_JOURNAL)
        pending = read_config(data_dir, name=_PENDING)
        if not journal:
            identifier = pending.get("id", "")
            if pending.get("format") != 4 or not isinstance(identifier, str) or not _ID.fullmatch(identifier):
                raise BackupError("Interrupted restore identity is invalid")
            journal = {"id":identifier, "scope":pending["scope"], "format":4,
                       "managed":pending.get("plan", {}).get("prometheus", {}).get("managed", False), "rollback_ready":False,
                       "mutation_started":False, "phase":"preparing"}
        try:
            if journal.get("format") != 4 or not _ID.fullmatch(journal.get("id", "")):
                raise BackupError("Interrupted restore journal is invalid")
            if type(journal.get("managed")) is not bool or managed_present(managed) != journal["managed"]:
                raise BackupError("Restore installation state changed during recovery")
            if journal.get("outcome") in ("applied", "reverted"):
                if journal["managed"]:
                    _resume_engine(managed)
                journal["phase"] = "checking-prior" if journal["outcome"] == "reverted" else "checking-candidate"
                atomic_config(data_dir, _JOURNAL, journal)
                return _candidate(journal, data_dir)
            if journal["managed"]:
                _stop_engine(managed)
            journal["phase"] = "recovering"
            journal["reason"] = reason
            atomic_config(data_dir, _JOURNAL, journal)
            if journal["mutation_started"]:
                if not journal["rollback_ready"]:
                    raise BackupError("Matched restore recovery snapshot is unavailable")
                rollback = _rollback_dir(data_dir, journal["id"])
                native = _native_state_files(rollback / "prometheus") if journal["managed"] else None
                _restore_rollback(data_dir, journal["id"], journal["scope"], native=True)
                if native is not None:
                    # Do not replace the service operation-lock inode.
                    for name in ("tsdb", "generations"):
                        path = managed.root / name
                        if path.is_symlink():
                            raise BackupError("Prometheus recovery destination is unsafe")
                        if path.exists():
                            shutil.rmtree(path)
                        path.mkdir(mode=0o700)
                    for name in ("installation.json", "active.json", "last.json", "enabled"):
                        (managed.root / name).unlink(missing_ok=True)
                    _copy_files(native, managed.root)
                    _sync_tree(managed.root)
            elif journal.get("previous_prometheus"):
                atomic_config(managed.root, "active.json", journal["previous_prometheus"])
            if journal["managed"]:
                _resume_engine(managed)
            journal["phase"] = "checking-prior"
            atomic_config(data_dir, _JOURNAL, journal)
            return _candidate(journal, data_dir)
        except Exception:
            journal["phase"] = "unconfirmed"
            atomic_config(data_dir, _JOURNAL, journal)
            _outcome(data_dir, journal, "unconfirmed", "Restore recovery could not be confirmed; retained recovery files are required")
            raise BackupError("Restore recovery is unconfirmed; inspect the service before retrying") from None


def confirm_file_restore(data_dir: Path, identifier: str, *, applied: bool, managed=None):
    """Finalize only after the supervisor verifies manager/exporter HTTPS."""
    managed = managed or ManagedPrometheus(data_dir)
    with installation_lease(data_dir):
        journal = read_config(data_dir, name=_JOURNAL)
        if (journal.get("id") != identifier or journal.get("format") != 4 or
                journal.get("phase") != ("checking-candidate" if applied else "checking-prior")):
            raise BackupError("Restore confirmation does not match its verified state")
        if journal["managed"]:
            if managed.settings()["enabled"]:
                if not managed.control.active() or not managed.ready():
                    raise BackupError("Prometheus restore health is unconfirmed")
            elif managed.control.active():
                raise BackupError("Disabled Prometheus restore state is unconfirmed")
        journal["outcome"] = "applied" if applied else "reverted"
        atomic_config(data_dir, _JOURNAL, journal)
        _outcome(data_dir, journal, journal["outcome"], journal.get("reason", ""))
        (data_dir / _PENDING).unlink(missing_ok=True)
        _state_file(data_dir, identifier).unlink(missing_ok=True)
        shutil.rmtree(_rollback_dir(data_dir, identifier), ignore_errors=True)
        if journal["managed"]:
            for prefix in ("restore-candidate-", "restore-prior-"):
                path = managed.root / (prefix + identifier)
                if path.is_symlink():
                    raise BackupError("Restore cleanup directory is unsafe")
                if path.exists():
                    shutil.rmtree(path)
        (data_dir / _JOURNAL).unlink(missing_ok=True)


def fail_file_restore_health(data_dir: Path, identifier: str):
    with installation_lease(data_dir):
        journal = read_config(data_dir, name=_JOURNAL)
        if journal.get("id") != identifier or journal.get("format") != 4:
            raise BackupError("Restore recovery identity changed")
        journal["phase"] = "unconfirmed"
        atomic_config(data_dir, _JOURNAL, journal)
        _outcome(data_dir, journal, "unconfirmed",
                 "Previous installation health could not be confirmed; retained recovery files are required")
