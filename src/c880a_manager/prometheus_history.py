"""Private coherent snapshots of enabled or retained disabled TSDB history.

A disabled source is copied/replayed in a disposable mutual-TLS engine with no
scrapes and explicitly disabled retention. Its service intent and original files
never change. Public backup jobs and restore application are separate.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time

import httpx

from .backup import BackupError
from .backup_stream import (CHUNK_BYTES, Limits, _BLOCK_FILE, _check, _private,
                            _regular, _report, _space, _workspace, workspace_descriptors)
from .deployment import generate_certificate, read_config, write_private
from .prometheus import config_bytes
from .prometheus_service import _client_material

_RAW = re.compile(r"(?:wal|wbl)/(?:[0-9]{8}|checkpoint\.[0-9]{8}/[0-9]{8})\Z|chunks_head/[0-9]{6}\Z")
_NAME = re.compile(r"[A-Za-z0-9-]{16,100}\Z")


def history_files(root: Path, *, raw: bool = False) -> dict[str, Path]:
    """Only durable native files, never locks/query logs/old snapshots."""
    if root.is_symlink() or not root.is_dir():
        raise BackupError("Prometheus history directory is unavailable or unsafe")
    files, total = {}, 0
    limits = Limits()
    for directory, dirs, names in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in list(dirs):
            path = base / name
            if path.is_symlink():
                raise BackupError("Prometheus history contains an unsafe directory")
            if base == root and raw and name == "snapshots":
                dirs.remove(name)
        for name in names:
            path = base / name
            relative = path.relative_to(root).as_posix()
            if raw and relative in ("lock", "queries.active"):
                if path.is_symlink():
                    raise BackupError("Prometheus history contains an unsafe file")
                continue
            if not (_BLOCK_FILE.fullmatch("prometheus/tsdb/" + relative) or
                    raw and _RAW.fullmatch(relative)):
                raise BackupError("Prometheus history contains an unexpected file; repair its service before backing up")
            with _regular(path) as source:
                total += os.fstat(source.fileno()).st_size
            if total > limits.content_bytes or len(files) >= limits.files:
                raise BackupError("Prometheus history exceeds the backup size or file-count limit")
            files[relative] = path
    return files


def _api(client, method: str, path: str, *, hostname: str, data=None):
    with client.stream(method, path, data=data,
                       extensions={"sni_hostname": hostname}) as response:
        value = bytearray()
        for chunk in response.iter_bytes(CHUNK_BYTES):
            if len(value) + len(chunk) > 65536:
                raise BackupError("Prometheus history response exceeded its limit")
            value.extend(chunk)
        if not 200 <= response.status_code < 300:
            raise BackupError("Prometheus history preparation failed; check its service and retry")
    if not value:
        return {}
    try:
        value = json.loads(value)
    except (ValueError, UnicodeError):
        raise BackupError("Prometheus history response was invalid") from None
    if not isinstance(value, dict) or value.get("status") != "success":
        raise BackupError("Prometheus history preparation was not confirmed")
    return value.get("data", {})


def _native_snapshot(client, tsdb: Path, hostname: str) -> Path:
    data = _api(client, "POST", "api/v1/admin/tsdb/snapshot", hostname=hostname,
                data={"skip_head": "false"})
    name = data.get("name") if isinstance(data, dict) else None
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise BackupError("Prometheus snapshot identity was invalid")
    parent = tsdb / "snapshots"
    path = parent / name
    if parent.is_symlink() or path.is_symlink() or not path.is_dir():
        raise BackupError("Prometheus snapshot is unavailable or unsafe")
    return path


def _copy_files(files: dict[str, Path], destination: Path, *, cancel=None, progress=None) -> None:
    total = sum(path.stat().st_size for path in files.values())
    current = 0
    for relative, path in sorted(files.items()):
        _check(cancel)
        target = destination / relative
        parent = destination
        for component in Path(relative).parts[:-1]:
            parent /= component
            parent.mkdir(mode=0o700, exist_ok=True)
        with _regular(path) as source, _private(target) as output:
            before = os.fstat(source.fileno())
            while chunk := source.read(CHUNK_BYTES):
                _check(cancel)
                output.write(chunk)
                current += len(chunk)
                _report(progress, "preparing-history", current, total)
            after = os.fstat(source.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise BackupError("Prometheus history changed during preparation; retry")
            output.flush()
            os.fsync(output.fileno())


@contextmanager
def isolated_engine(runtime: Path, tsdb: Path, private: Path, *, cancel=None):
    """Replay a private clone with no jobs or pruning; never touch systemd."""
    cert, key = generate_certificate(["127.0.0.1"])
    write_private(private / "server.pem", cert)
    write_private(private / "server.key", key)
    _client_material(private)
    config = {"global": {"scrape_interval": "30s"}, "scrape_configs": [],
              "storage": {"tsdb": {"retention": {"time": "0s", "size": "0B"}}}}
    write_private(private / "scrape.json", config_bytes(config))
    write_private(private / "web.json", config_bytes({"tls_server_config": {
        "cert_file": str(private / "server.pem"), "key_file": str(private / "server.key"),
        "client_auth_type": "RequireAndVerifyClientCert", "client_ca_file": str(private / "client-ca.pem"),
        "min_version": "TLS13"}}))
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    context = ssl.create_default_context(cafile=private / "server.pem")
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    context.load_cert_chain(private / "client.pem", private / "client.key")
    process = None
    try:
        with _private(private / "engine.log") as log:
            process = subprocess.Popen([sys.executable, "-m", "c880a_manager.private_history_process",
                str(os.getpid()), str(runtime / "prometheus"),
                f"--config.file={private / 'scrape.json'}", f"--web.config.file={private / 'web.json'}",
                f"--web.listen-address=127.0.0.1:{port}", "--web.route-prefix=/prometheus",
                "--web.enable-admin-api", "--query.timeout=15s", "--query.max-concurrency=1",
                f"--storage.tsdb.path={tsdb}", "--log.level=warn"],
                stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                pass_fds=workspace_descriptors(private))
            with httpx.Client(base_url=f"https://127.0.0.1:{port}/prometheus/", verify=context,
                              trust_env=False, follow_redirects=False, timeout=60) as client:
                deadline = time.monotonic() + 60
                while True:
                    _check(cancel)
                    if process.poll() is not None:
                        raise BackupError("Private history preparation failed; retained source data is unchanged")
                    try:
                        ready = client.get("-/ready", timeout=1)
                        if ready.status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    if time.monotonic() >= deadline:
                        raise BackupError("Private history preparation timed out; retained source data is unchanged")
                    time.sleep(0.1)
                yield client
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=15)


class HistorySnapshot:
    def __init__(self, directory: tempfile.TemporaryDirectory, path: Path, settings: dict,
                 *, source_snapshot: Path | None = None):
        self._directory, self.source_snapshot = directory, source_snapshot
        self.settings = dict(settings)
        self.files = {"prometheus/tsdb/" + name: file for name, file in history_files(path).items()}
        self.summary = {"bytes": sum(file.stat().st_size for file in self.files.values()),
                        "samples": 0, "min_time_ms": None, "max_time_ms": None}
        for name, file in self.files.items():
            if not name.endswith("/meta.json"):
                continue
            with _regular(file) as source:
                raw = source.read(65537)
            if len(raw) > 65536:
                raise BackupError("Prometheus block metadata exceeded its limit")
            try:
                metadata = json.loads(raw)
                low, high, samples = metadata["minTime"], metadata["maxTime"], metadata["stats"]["numSamples"]
                if any(type(value) is not int for value in (low, high, samples)) or high < low or samples < 0:
                    raise ValueError
            except (ValueError, TypeError, KeyError):
                raise BackupError("Prometheus block metadata is invalid") from None
            self.summary["samples"] += samples
            self.summary["min_time_ms"] = low if self.summary["min_time_ms"] is None else min(self.summary["min_time_ms"], low)
            self.summary["max_time_ms"] = high if self.summary["max_time_ms"] is None else max(self.summary["max_time_ms"], high)

    def close(self):
        if self.source_snapshot:
            shutil.rmtree(self.source_snapshot)
            self.source_snapshot = None
        self._directory.cleanup()
        self.files.clear()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def prepare_full_history(managed, workspace: Path, *, additional_bytes: int = 0,
                         cancel=None, progress=None, stopped: bool = False,
                         _operation_lock: int | None = None) -> HistorySnapshot:
    """Return head-inclusive native blocks; caller owns the returned lifetime."""
    if type(additional_bytes) is not int or not 0 <= additional_bytes <= Limits().metadata_bytes:
        raise BackupError("Backup metadata size is invalid")
    if type(stopped) is not bool:
        raise BackupError("History preparation state is invalid")
    installation = managed.installation()
    lock_path = managed.root / "operation.lock"
    lock = (os.dup(_operation_lock) if _operation_lock is not None else
            os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600))
    directory, source_snapshot = None, None
    try:
        if _operation_lock is not None:
            owned, expected = os.fstat(lock), lock_path.stat(follow_symlinks=False)
            if (owned.st_dev, owned.st_ino) != (expected.st_dev, expected.st_ino) or lock_path.is_symlink():
                raise BackupError("Prometheus operation ownership is invalid")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BackupError("Another Prometheus operation is in progress") from None
        if read_config(managed.root, name="pending.json"):
            raise BackupError("Recover the unconfirmed Prometheus change before backing up")
        settings = managed.settings()
        tsdb = managed.root / "tsdb"
        if tsdb.is_symlink() or not tsdb.is_dir():
            raise BackupError("Prometheus history directory is unavailable or unsafe")
        if workspace.stat().st_dev != tsdb.stat().st_dev:
            raise BackupError("Backup staging must be on the Prometheus data filesystem")
        _check(cancel)
        if settings["enabled"] and not stopped:
            # A running engine can rename compaction/WAL files. This is only a
            # headroom estimate; the coherent snapshot is validated separately.
            files, existing = {}, 0
            for base, dirs, names in os.walk(managed.root / "tsdb", followlinks=False):
                base = Path(base)
                for name in list(dirs):
                    if (base / name).is_symlink():
                        raise BackupError("Prometheus history contains an unsafe directory")
                    if base == managed.root / "tsdb" and name == "snapshots":
                        dirs.remove(name)
                for name in names:
                    try:
                        with _regular(base / name) as source:
                            existing += os.fstat(source.fileno()).st_size
                    except FileNotFoundError:
                        pass
                if existing > Limits().content_bytes:
                    raise BackupError("Prometheus history exceeds the backup size limit")
        else:
            files = history_files(managed.root / "tsdb", raw=True)
            existing = sum(path.stat().st_size for path in files.values())
        directory = _workspace(workspace)
        # Reserve clone + head snapshot + encrypted archive, and caller's known
        # installation metadata. The UI must explain this conservative estimate.
        _space(workspace, 3 * existing + additional_bytes, Limits())
        _report(progress, "preparing-history", 0, 0)
        if settings["enabled"] and not stopped:
            if not managed.control.active() or not managed.ready():
                raise BackupError("Prometheus is unavailable; recover it or disable scraping before backing up")
            with managed.client(timeout=60) as client:
                source_snapshot = _native_snapshot(client, managed.root / "tsdb", managed.active()["deployment"]["manager_host"])
            _check(cancel)
            result = HistorySnapshot(directory, source_snapshot, settings, source_snapshot=source_snapshot)
        else:
            if managed.control.active():
                raise BackupError("Prometheus must be stopped before preparing retained history")
            private = Path(directory.name)
            cloned = private / "tsdb"
            cloned.mkdir(mode=0o700)
            _copy_files(files, cloned, cancel=cancel, progress=progress)
            if managed.control.active():
                raise BackupError("Prometheus changed state while preparing; retry after recovery")
            if files:
                with isolated_engine(Path(installation["runtime_dir"]), cloned, private, cancel=cancel) as client:
                    path = _native_snapshot(client, cloned, "127.0.0.1")
                    _check(cancel)
                    result = HistorySnapshot(directory, path, settings)
            else:
                result = HistorySnapshot(directory, cloned, settings)
        _check(cancel)
        return result
    except BaseException as error:
        if source_snapshot is not None:
            shutil.rmtree(source_snapshot)
        if directory is not None:
            directory.cleanup()
        if not isinstance(error, BackupError) and isinstance(error, (OSError, ValueError, httpx.HTTPError)):
            raise BackupError("Could not prepare Prometheus history; check its service and disk space, then retry") from None
        raise
    finally:
        os.close(lock)


def claimed_history_exclusions(claimed_ids: list[str]) -> list[str]:
    """Internal whole-archive scope, never an operator selection control."""
    if (not isinstance(claimed_ids, list) or len(claimed_ids) > 10000 or
            any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value) for value in claimed_ids) or
            len(set(claimed_ids)) != len(claimed_ids)):
        raise BackupError("Archived claimed-server identities are invalid")
    if not claimed_ids:
        return ['{__name__!=""}']
    identities = '|'.join(sorted(claimed_ids))
    return ['{__name__!="",job!="c880a"}', '{job="c880a",server_id!~"' + identities + '"}']


def prepare_claimed_history(managed, workspace: Path, claimed_ids: list[str], *,
                            additional_bytes: int = 0, cancel=None, progress=None) -> HistorySnapshot:
    """Copy all archived claims' native history; never mutate the source DB.

    The public caller must pass every claim in its consistent server archive.
    Native deletion/compaction preserves retained chunk types and timestamps;
    a fresh block-only reopen verifies unrelated label metadata is also absent.
    """
    exclusions = claimed_history_exclusions(claimed_ids)
    directory = None
    try:
        with prepare_full_history(managed, workspace, additional_bytes=additional_bytes,
                                  cancel=cancel, progress=progress) as full:
            directory = _workspace(workspace)
            private = Path(directory.name)
            _space(workspace, 4 * full.summary["bytes"] + additional_bytes, Limits())
            cloned = private / "tsdb"
            cloned.mkdir(mode=0o700)
            source = {str(Path(name).relative_to("prometheus/tsdb")):path for name, path in full.files.items()}
            _copy_files(source, cloned, cancel=cancel, progress=progress)
            settings = full.settings
            if not source:
                _check(cancel)
                return HistorySnapshot(directory, cloned, settings)
            runtime = Path(managed.installation()["runtime_dir"])
            with isolated_engine(runtime, cloned, private, cancel=cancel) as client:
                _check(cancel)
                _api(client, "POST", "api/v1/admin/tsdb/delete_series", hostname="127.0.0.1",
                     data={"match[]":exclusions})
                _check(cancel)
                _api(client, "POST", "api/v1/admin/tsdb/clean_tombstones", hostname="127.0.0.1")
                filtered = _native_snapshot(client, cloned, "127.0.0.1")
            # Reopen block-only data: head label metadata in the first engine
            # can outlive deletion even after clean_tombstones. No scrapes run.
            verify = private / "verification"
            verify.mkdir(mode=0o700)
            with isolated_engine(runtime, filtered, verify, cancel=cancel) as client:
                foreign = _api(client, "POST", "api/v1/series", hostname="127.0.0.1",
                               data={"match[]":exclusions})
                if foreign != []:
                    raise BackupError("Archived history scope could not be verified; source data is unchanged")
                final = _native_snapshot(client, filtered, "127.0.0.1")
                result = HistorySnapshot(directory, final, settings)
            _check(cancel)
            return result
    except BaseException as error:
        if directory is not None:
            directory.cleanup()
        if not isinstance(error, BackupError) and isinstance(error, (OSError, ValueError, httpx.HTTPError)):
            raise BackupError("Could not prepare claimed-server history; source data is unchanged, retry after recovery") from None
        raise
