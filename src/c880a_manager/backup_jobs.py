"""Session-owned file-backed backup preparation and native browser downloads."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import secrets
import sqlite3
import threading
import time
from types import SimpleNamespace

from .backup import BackupError, MAX_ARCHIVE_BYTES, open_archive
from .backup_history import create_history_archive
from .backup_stream import (MAGIC, CHUNK_BYTES, Limits, CancelledBackup, _private,
                            _check, _space, _workspace, open_file_archive)


@contextmanager
def opened_upload(path: Path, passphrase: str, workspace: Path, *, cancel=None):
    _check(cancel)
    with path.open("rb") as source:
        marker = source.read(len(MAGIC))
    if marker == MAGIC:
        with open_file_archive(path, passphrase, workspace, cancel=cancel) as archive:
            yield archive
    else:
        if path.stat().st_size > MAX_ARCHIVE_BYTES:
            raise BackupError("Unsupported or oversized legacy backup")
        raw = path.read_bytes()
        metadata = open_archive(raw, passphrase)
        _check(cancel)
        metadata["prometheus"] = {"managed":False}
        yield SimpleNamespace(metadata=metadata, files={}, archive_sha256=hashlib.sha256(raw).hexdigest(), format=3)


@contextmanager
def private_upload(upload, workspace: Path, *, cancel=None):
    directory = _workspace(workspace)
    try:
        path = Path(directory.name) / "upload.c880ab"
        size = 0
        with _private(path) as destination:
            while chunk := upload.read(CHUNK_BYTES):
                _check(cancel)
                size += len(chunk)
                if size > Limits().archive_bytes:
                    raise BackupError("Archive exceeds the upload limit")
                _space(workspace, len(chunk), Limits())
                destination.write(chunk)
        if not size:
            raise BackupError("Archive is empty")
        yield path
    finally:
        directory.cleanup()


class BackupJobs:
    """One bounded preparation per installation; no persisted passphrases."""
    def __init__(self, store, managed, workspace):
        self.store, self.managed, self.workspace = store, managed, workspace
        self.lock = threading.Lock()
        self.job = None
        self.thread = None

    def _owner_valid(self, owner):
        try:
            session = self.store.session_by_hash(owner, touch=False)
        except (OSError, sqlite3.Error):
            return False
        return bool(session and session["role"] == "admin")

    def start(self, owner: str, scope: str, passphrase: str):
        with self.lock:
            if self.job and self.job["status"] == "ready" and self._cancelled(self.job):
                self.job["archive"].close()
                self.job.update(archive=None, status="expired", phase="expired")
            if self.job and self.job["status"] in ("preparing", "ready", "downloading"):
                raise BackupError("A backup is already prepared or in progress; " +
                    ("download or cancel it first" if self.job["owner"] == owner else "wait and retry"))
            identifier = secrets.token_hex(16)
            self.job = {"id":identifier, "owner":owner, "scope":scope, "status":"preparing",
                        "phase":"checking", "current":0, "total":0, "cancel":threading.Event(),
                        "expires":time.monotonic() + 900, "archive":None}
            self.thread = threading.Thread(target=self._prepare, args=(self.job, passphrase), daemon=True)
            self.thread.start()
            return identifier

    def _cancelled(self, job):
        return job["cancel"].is_set() or time.monotonic() >= job["expires"] or not self._owner_valid(job["owner"])

    def _prepare(self, job, passphrase):
        archive = None
        terminal = None
        try:
            def progress(phase, current, total):
                with self.lock:
                    job.update(phase=phase, current=current, total=total)
            archive = create_history_archive(self.store, self.managed, job["scope"], passphrase,
                self.workspace, cancel=lambda:self._cancelled(job), progress=progress)
            digest = archive.sha256(cancel=lambda:self._cancelled(job), progress=progress)
            with self.lock:
                if self._cancelled(job):
                    raise CancelledBackup("Backup preparation cancelled")
                job.update(status="ready", phase="ready", archive=archive,
                    bytes=archive.size, sha256=digest,
                    filename=f"c880a-{job['scope']}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.c880ab")
                archive = None
        except CancelledBackup:
            terminal = {"status":"cancelled", "phase":"cancelled"}
        except Exception as error:
            terminal = {"status":"failed", "phase":"failed", "detail":str(error) if isinstance(error, BackupError) else
                "Backup preparation failed; check service state and available disk space"}
        finally:
            if archive:
                archive.close()
            if terminal:
                with self.lock:
                    job.update(terminal)
            # A ready artifact expires even if the browser never polls again.
            timer = threading.Timer(5, self._expire, args=(job,))
            timer.daemon = True
            timer.start()

    def _expire(self, job):
        with self.lock:
            if job["status"] != "ready":
                return
            if self._cancelled(job):
                job["cancel"].set()
                job["archive"].close()
                job.update(archive=None, status="expired", phase="expired")
            else:
                timer = threading.Timer(5, self._expire, args=(job,))
                timer.daemon = True
                timer.start()

    def _get(self, owner, identifier):
        job = self.job
        if not job or job["owner"] != owner or job["id"] != identifier or not self._owner_valid(owner):
            raise BackupError("Backup is unavailable for this session; prepare it again")
        return job

    def status(self, owner, identifier):
        with self.lock:
            job = self._get(owner, identifier)
            if time.monotonic() >= job["expires"]:
                job["cancel"].set()
                if job["status"] == "ready":
                    job["archive"].close()
                    job.update(archive=None, status="expired", phase="expired")
            return {key:job[key] for key in ("id", "scope", "status", "phase", "current", "total",
                                           "bytes", "sha256", "filename", "detail") if key in job}

    def current(self, owner):
        with self.lock:
            identifier = self.job["id"] if self.job and self.job["owner"] == owner else None
        return self.status(owner, identifier) if identifier else None

    def cancel(self, owner, identifier):
        with self.lock:
            job = self._get(owner, identifier)
            if job["status"] == "downloading":
                raise BackupError("Use the browser download controls to cancel this transfer")
            job["cancel"].set()
            if job["status"] == "ready":
                job["archive"].close()
                job.update(archive=None, status="cancelled", phase="cancelled")

    def wait_ready(self, owner, identifier, *, cancel=None):
        while True:
            try:
                _check(cancel)
                state = self.status(owner, identifier)
                if state["status"] == "ready":
                    return state
                if state["status"] != "preparing":
                    raise BackupError(state.get("detail") or "Backup preparation cancelled or expired")
                time.sleep(.1)
            except BaseException:
                with self.lock:
                    if self.job and self.job["id"] == identifier:
                        self.job["cancel"].set()
                raise

    def download(self, owner, identifier):
        with self.lock:
            job = self._get(owner, identifier)
            if job["status"] != "ready" or self._cancelled(job):
                raise BackupError("Backup is not ready or has expired; check its status")
            source = job["archive"].path.open("rb")
            job["source"] = source
            job["status"] = "downloading"
            headers = {"Content-Disposition":f'attachment; filename="{job["filename"]}"',
                       "Content-Length":str(job["bytes"]), "X-Archive-SHA256":job["sha256"],
                       "X-Backup-Scope":job["scope"]}
        def chunks():
            complete = False
            try:
                with source:
                    while chunk := source.read(CHUNK_BYTES):
                        if self._cancelled(job):
                            return
                        yield chunk
                    complete = True
            finally:
                self.finish_download(owner, identifier, complete=complete)
        return chunks(), headers

    def finish_download(self, owner, identifier, *, complete=False):
        # Also invoked by the response background cleanup if streaming never starts.
        with self.lock:
            job = self.job
            if not job or job["owner"] != owner or job["id"] != identifier or job["status"] != "downloading":
                return
            job.pop("source").close()
            job["archive"].close()
            status = "downloaded" if complete else "interrupted"
            job.update(archive=None, status=status, phase=status)

    def close(self):
        job = self.job
        if job:
            job["cancel"].set()
        if self.thread:
            self.thread.join(timeout=10)
        if job and job["archive"] and job["status"] != "downloading":
            job["archive"].close()
            job.update(archive=None, status="cancelled", phase="cancelled")
        if job and job["status"] == "downloading":
            self.finish_download(job["owner"], job["id"])

    def logout(self, owner):
        with self.lock:
            job = self.job
            if job and job["owner"] == owner:
                job["cancel"].set()
                if job["status"] == "ready":
                    job["archive"].close()
                    job.update(archive=None, status="cancelled", phase="cancelled")
