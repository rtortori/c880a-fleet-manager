"""Idempotent native target-history deletion with durable unclaim intent."""
from contextlib import nullcontext
import fcntl
import os
from pathlib import Path
import re
import shutil
import time

from .backup import BackupError
from .backup_stream import Limits, _check, _space, _workspace
from .deployment import atomic_config, read_config
from .prometheus_history import (_api, _copy_files, _native_snapshot, history_files,
                                 isolated_engine, prepare_full_history)
from .prometheus_service import PrometheusError
from .restore_history import _sync_tree
from .state_operation import installation_lease

JOURNAL = "delete.pending.json"


def _remove(path):
    if path.is_symlink():
        raise BackupError("Prometheus cleanup path is unsafe")
    if path.exists():
        shutil.rmtree(path)


def _stopped(managed):
    managed.control.set_enabled(False)
    if managed.control.active():
        raise PrometheusError("Prometheus stopped state could not be confirmed")


def _resume(managed, enabled):
    managed.control.set_enabled(enabled)
    if enabled and not managed.wait_ready(managed.active()):
        raise PrometheusError("Prometheus history activation was not confirmed")
    if not enabled and managed.control.active():
        raise PrometheusError("Prometheus disabled state was not confirmed")


def _matches(identities):
    if not identities or any(not isinstance(identity, str) or not re.fullmatch(r"[0-9a-f]{32}", identity)
                             for identity in identities):
        raise BackupError("Prometheus deletion identity is invalid")
    return ['{job="c880a",server_id="' + identity + '"}' for identity in identities]


def _filtered(managed, workspace, identities, destination, *, cancel=None, _operation_lock=None):
    selectors = _matches(identities)
    with prepare_full_history(managed, workspace, stopped=True, cancel=cancel,
                              _operation_lock=_operation_lock) as full:
        _space(workspace, 4 * full.summary["bytes"], Limits())
        directory = _workspace(workspace)
        try:
            private = Path(directory.name)
            database = private / "tsdb"
            database.mkdir(mode=0o700)
            _copy_files({str(Path(name).relative_to("prometheus/tsdb")):path
                         for name,path in full.files.items()}, database, cancel=cancel)
            if not full.files:
                destination.mkdir(mode=0o700)
                return
            runtime = Path(managed.installation()["runtime_dir"])
            with isolated_engine(runtime, database, private, cancel=cancel) as client:
                _api(client, "POST", "api/v1/admin/tsdb/delete_series", hostname="127.0.0.1",
                     data={"match[]":selectors})
                _check(cancel)
                _api(client, "POST", "api/v1/admin/tsdb/clean_tombstones", hostname="127.0.0.1")
                snapshot = _native_snapshot(client, database, "127.0.0.1")
            verification = private / "verification"
            verification.mkdir(mode=0o700)
            with isolated_engine(runtime, snapshot, verification, cancel=cancel) as client:
                if _api(client, "POST", "api/v1/series", hostname="127.0.0.1", data={"match[]":selectors}) != []:
                    raise BackupError("Target history deletion could not be verified")
                final = _native_snapshot(client, snapshot, "127.0.0.1")
                destination.mkdir(mode=0o700)
                _copy_files(history_files(final), destination, cancel=cancel)
        finally:
            directory.cleanup()


def cleanup_history(store, managed, workspace, *, cancel=None, _lease=True):
    """No claim/credentials are recreated; failed cleanup is retried after restart."""
    with installation_lease(store.data_dir) if _lease else nullcontext():
        identities = store.pending_prometheus_deletions()
        record = read_config(managed.root, name=JOURNAL)
        if not identities and not record:
            return
        if managed.root.is_symlink() or not managed.root.is_dir():
            raise BackupError("Managed history cleanup requires a valid installation")
        if read_config(managed.root, name="pending.json"):
            raise BackupError("Recover Prometheus settings before deleting target history")
        descriptor = os.open(managed.root / "operation.lock", os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if not record:
                record = {"id":store.pending_prometheus_cleanup()["id"], "identities":identities,
                          "enabled":managed.settings()["enabled"], "phase":"preparing"}
                atomic_config(managed.root, JOURNAL, record)
            if not re.fullmatch(r"[0-9a-f]{32}", record.get("id", "")) or type(record.get("enabled")) is not bool:
                raise BackupError("Prometheus history recovery record is invalid")
            selectors = _matches(record["identities"])
            identifier = record["id"]
            previous = managed.root / ("delete-prior-" + identifier)
            candidate = managed.root / ("delete-next-" + identifier)
            database = managed.root / "tsdb"
            try:
                _stopped(managed)
                if record["phase"] == "recovering":
                    if previous.exists():
                        _remove(candidate)
                        if database.exists():
                            database.rename(candidate)
                        previous.rename(database)
                    if not database.is_dir():
                        raise BackupError("Prometheus prior history recovery is unconfirmed")
                    _sync_tree(managed.root)
                    record["phase"] = "preparing"
                    atomic_config(managed.root, JOURNAL, record)
                if record["phase"] == "preparing":
                    _remove(candidate)
                    _filtered(managed, workspace, record["identities"], candidate, cancel=cancel,
                              _operation_lock=descriptor)
                    _sync_tree(candidate)
                    record["phase"] = "swapping"
                    atomic_config(managed.root, JOURNAL, record)
                if record["phase"] == "swapping":
                    if not previous.exists():
                        database.rename(previous)
                    if not database.exists():
                        candidate.rename(database)
                    if candidate.exists():
                        raise BackupError("Prometheus history exchange is unconfirmed")
                    _sync_tree(managed.root)
                    record["phase"] = "checking"
                    atomic_config(managed.root, JOURNAL, record)
                if record["phase"] not in ("checking", "finished"):
                    raise BackupError("Prometheus history recovery phase is invalid")
                # A fresh reopen excludes stale head label metadata. No scrapes
                # or retention run while checking retained disabled history.
                directory = _workspace(workspace)
                try:
                    private = Path(directory.name)
                    with isolated_engine(Path(managed.installation()["runtime_dir"]), database, private, cancel=cancel) as client:
                        if _api(client, "POST", "api/v1/series", hostname="127.0.0.1", data={"match[]":selectors}) != []:
                            raise BackupError("Deleted target history remains present")
                finally:
                    directory.cleanup()
                _resume(managed, record["enabled"])
                record["phase"] = "finished"
                atomic_config(managed.root, JOURNAL, record)
                _remove(previous)
                _remove(candidate)
                store.finish_prometheus_deletions(record["identities"])
                atomic_config(managed.root, "last.json", {"id":identifier, "status":"applied",
                    "reason":"Target history deleted", "at":time.time()})
                (managed.root / JOURNAL).unlink()
            except Exception:
                # A failed new database activation restores the complete prior
                # database, but the SQL intent remains until deletion succeeds.
                try:
                    if record.get("phase") != "finished" and previous.exists():
                        record["phase"] = "recovering"
                        atomic_config(managed.root, JOURNAL, record)
                        _stopped(managed)
                        _remove(candidate)
                        if database.exists():
                            database.rename(candidate)
                        previous.rename(database)
                        record["phase"] = "preparing"
                        atomic_config(managed.root, JOURNAL, record)
                    _resume(managed, record["enabled"])
                except Exception:
                    # Keep both copies and the same recovery identity even if
                    # stopping, exchanging or resuming the prior state fails.
                    pass
                finally:
                    atomic_config(managed.root, "last.json", {"id":identifier, "status":"unconfirmed",
                        "reason":"Target unclaimed. Prometheus history cleanup is pending.", "at":time.time()})
                raise BackupError("Target unclaimed. Prometheus history cleanup is pending.") from None
        finally:
            os.close(descriptor)
