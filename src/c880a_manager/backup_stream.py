"""Private, bounded file transport for installation metadata and TSDB snapshots.

Format 4 uses the library's AES-256-GCM for each fixed-size chunk, with distinct
nonces and authenticated ordering/length. An authenticated final record rejects
truncation. Decrypted files are never parsed/extracted before the entire archive
has authenticated. This module does not select/snapshot/restore a live database.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import struct
import tempfile
from typing import Callable, Mapping
import weakref

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .backup import BackupError, KDF_N, MAX_PLAINTEXT_BYTES, validate_application_version

MAGIC = b"C880A-BACKUP\x00\x04"
CHUNK_BYTES = 1024 * 1024
_HEADER_BYTES = len(MAGIC) + 16 + 4
_RECORD = struct.Struct(">IB")
_SIZE = struct.Struct(">Q")
_LENGTH = struct.Struct(">I")
_PATH_LENGTH = struct.Struct(">H")
# Only completed native blocks enter the transport. WAL/head replay belongs to
# snapshot preparation; copying a running WAL is not a coherent backup.
_BLOCK_FILE = re.compile(r"prometheus/tsdb/[0-9A-HJKMNP-TV-Z]{26}/"
                         r"(?:meta\.json|index|tombstones|chunks/[0-9]{6})\Z")
Progress = Callable[[str, int, int], None]
Cancel = Callable[[], bool]


@dataclass(frozen=True)
class Limits:
    archive_bytes: int = 256 * 1024**3
    content_bytes: int = 256 * 1024**3 - 2 * 1024**3
    metadata_bytes: int = MAX_PLAINTEXT_BYTES
    files: int = 262144
    reserve_bytes: int = 1024**3


class CancelledBackup(BackupError):
    pass


class PrivateArchive:
    """Owner-only prepared artifact; caller must close after download/preview."""
    def __init__(self, directory: tempfile.TemporaryDirectory, path: Path,
                 *, metadata: dict | None = None, files: dict[str, Path] | None = None,
                 archive_sha256: str | None = None):
        self._directory = directory
        self.path = path
        self.metadata = metadata
        self.files = files or {}
        self.size = path.stat().st_size
        self.archive_sha256 = archive_sha256
        self.format = 4

    def close(self) -> None:
        self._directory.cleanup()
        self.metadata = None
        self.files.clear()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def sha256(self, *, cancel=None, progress=None) -> str:
        digest = hashlib.sha256()
        current = 0
        with _regular(self.path) as source:
            while chunk := source.read(CHUNK_BYTES):
                _check(cancel)
                digest.update(chunk)
                current += len(chunk)
                _report(progress, "verifying", current, self.size)
        _check(cancel)
        return digest.hexdigest()


def _check(cancel: Cancel | None) -> None:
    if cancel and cancel():
        raise CancelledBackup("Backup preparation cancelled")


def _report(progress: Progress | None, phase: str, current: int, total: int) -> None:
    if progress:
        progress(phase, current, total)


def _regular(path: Path):
    # Staging parents are private and never provided by an uploaded archive.
    # Reject links before opening, and O_NOFOLLOW protects the terminal race.
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise BackupError("Backup source contains an unsafe file or directory")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                         getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise BackupError("Backup source must be a regular file")
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def _directory_lock(path, *, nonblocking=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise BackupError("Backup staging directory must be private and owned by the application")
        fcntl.flock(descriptor, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
        yield descriptor
    finally:
        os.close(descriptor)


_workspace_descriptors = {}


def workspace_descriptors(private):
    """Keep a clone leased until its private native helper has exited."""
    return tuple(descriptor for root, descriptor in tuple(_workspace_descriptors.items())
                 if private == root or root in private.parents)


def _cleanup_workspace(directory, descriptor):
    try:
        directory.cleanup()
    finally:
        _workspace_descriptors.pop(Path(directory.name), None)
        os.close(descriptor)


class _PrivateWorkspace:
    def __init__(self, directory, descriptor):
        self.name = directory.name
        self._cleanup = weakref.finalize(self, _cleanup_workspace, directory, descriptor)

    def cleanup(self):
        self._cleanup()


def reap_workspaces(path):
    """Reclaim killed workers' temporary files, never durable restore state."""
    with _directory_lock(path):
        for child in path.iterdir():
            if not re.fullmatch(r"archive-[A-Za-z0-9_-]{8}", child.name):
                continue
            if child.is_symlink() or not child.is_dir():
                raise BackupError("Backup workspace contains an unsafe artifact")
            try:
                with _directory_lock(child, nonblocking=True):
                    shutil.rmtree(child)
            except BlockingIOError:
                continue  # A preparation, upload, download or helper still owns it.


def _workspace(path: Path) -> _PrivateWorkspace:
    if (not path.is_dir() or any(p.is_symlink() for p in (path, *path.parents)) or
            path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077):
        raise BackupError("Backup staging directory must be private and owned by the application")
    # Serialize creation and ownership against another worker's startup reaper.
    with _directory_lock(path):
        directory = tempfile.TemporaryDirectory(prefix="archive-", dir=path)
        descriptor = None
        try:
            descriptor = os.open(directory.name, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            _workspace_descriptors[Path(directory.name)] = descriptor
            return _PrivateWorkspace(directory, descriptor)
        except BaseException:
            directory.cleanup()
            if descriptor is not None:
                os.close(descriptor)
            raise


def _key(passphrase: str, salt: bytes) -> bytes:
    if not isinstance(passphrase, str) or not 16 <= len(passphrase) <= 1024:
        raise BackupError("Passphrase must be 16–1024 characters")
    return hashlib.scrypt(passphrase.encode(), salt=salt, n=KDF_N, r=8, p=1,
                          dklen=32, maxmem=256 * 1024 * 1024)


def _private(path: Path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
    return os.fdopen(descriptor, "wb")


def _read(source, length: int) -> bytes:
    value = source.read(length)
    if len(value) != length:
        raise BackupError("Archive is corrupt or incomplete")
    return value


def _space(workspace: Path, needed: int, limits: Limits) -> None:
    if shutil.disk_usage(workspace).free < needed + limits.reserve_bytes:
        raise BackupError("Insufficient disk space for backup staging; free space and retry")


class _Sealer:
    def __init__(self, output, key: bytes, header: bytes, limit: int, cancel: Cancel | None):
        self.output, self.cipher, self.header = output, AESGCM(key), header
        self.limit, self.cancel = limit, cancel
        self.buffer = bytearray()
        self.index, self.written = 0, len(header)
        output.write(header)

    def _record(self, data: bytes, final: bool = False) -> None:
        _check(self.cancel)
        prefix = _RECORD.pack(len(data), int(final))
        counter = _SIZE.pack(self.index)
        # Salt creates a fresh derived key per archive; its random nonce prefix
        # plus monotonic 64-bit counter never repeats under that key.
        ciphertext = self.cipher.encrypt(self.header[-4:] + counter, data,
                                         self.header + counter + prefix)
        self.written += len(prefix) + len(ciphertext)
        if self.written > self.limit:
            raise BackupError("Encrypted backup exceeds the archive size limit")
        self.output.write(prefix)
        self.output.write(ciphertext)
        self.index += 1

    def write(self, value: bytes) -> None:
        view = memoryview(value)
        while view:
            count = min(CHUNK_BYTES - len(self.buffer), len(view))
            self.buffer.extend(view[:count])
            view = view[count:]
            if len(self.buffer) == CHUNK_BYTES:
                self._record(bytes(self.buffer))
                self.buffer.clear()

    def finish(self) -> None:
        if self.buffer:
            self._record(bytes(self.buffer))
            self.buffer.clear()
        self._record(b"", final=True)
        self.output.flush()
        os.fsync(self.output.fileno())


def create_file_archive(metadata: dict, files: Mapping[str, Path], passphrase: str,
                        workspace: Path, *, limits: Limits = Limits(),
                        cancel: Cancel | None = None, progress: Progress | None = None) -> PrivateArchive:
    """Seal already-consistent metadata/block files without buffering the TSDB."""
    validate_application_version(metadata)
    if metadata["manifest"].get("scope") not in ("full", "servers"):
        raise BackupError("Unsupported backup scope")
    if len(files) > limits.files or any(not isinstance(p, str) or not _BLOCK_FILE.fullmatch(p) for p in files):
        raise BackupError("Backup contains an unexpected history path or too many files")
    metadata = {**metadata, "manifest": {**metadata["manifest"], "format": 4}}
    raw = json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode()
    if len(raw) > limits.metadata_bytes:
        raise BackupError("Backup metadata exceeds the size limit")
    sizes, identities = {}, {}
    total = len(raw)
    _report(progress, "checking-space", 0, 0)
    for name, path in sorted(files.items()):
        _check(cancel)
        with _regular(path) as source:
            info = os.fstat(source.fileno())
            identities[name] = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            sizes[name] = info.st_size
        total += sizes[name]
        if total > limits.content_bytes:
            raise BackupError("Backup contents exceed the size limit")
    # Exact framing upper bound plus chunk tags; no compression or zip bomb.
    framed = total + 8 + sum(2 + len(name.encode()) + 8 for name in files)
    needed = framed + ((framed + CHUNK_BYTES - 1) // CHUNK_BYTES + 1) * 21 + _HEADER_BYTES
    if needed > limits.archive_bytes:
        raise BackupError("Encrypted backup exceeds the archive size limit")
    directory = _workspace(workspace)
    try:
        _space(workspace, needed, limits)
        _check(cancel)
        salt = secrets.token_bytes(16)
        key = _key(passphrase, salt)
        header = MAGIC + salt + secrets.token_bytes(4)
        path = Path(directory.name) / "backup.sealed"
        with _private(path) as output:
            sealer = _Sealer(output, key, header, limits.archive_bytes, cancel)
            sealer.write(_LENGTH.pack(len(raw)))
            sealer.write(raw)
            sealer.write(_LENGTH.pack(len(files)))
            current = len(raw)
            _report(progress, "encrypting", current, total)
            for name, source_path in sorted(files.items()):
                name_bytes = name.encode("ascii")
                sealer.write(_PATH_LENGTH.pack(len(name_bytes)))
                sealer.write(name_bytes)
                sealer.write(_SIZE.pack(sizes[name]))
                with _regular(source_path) as source:
                    info = os.fstat(source.fileno())
                    if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != identities[name]:
                        raise BackupError("Backup source changed while preparing; retry")
                    remaining = sizes[name]
                    while remaining:
                        _check(cancel)
                        chunk = _read(source, min(CHUNK_BYTES, remaining))
                        sealer.write(chunk)
                        remaining -= len(chunk)
                        current += len(chunk)
                        _report(progress, "encrypting", current, total)
                    info = os.fstat(source.fileno())
                    if source.read(1) or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != identities[name]:
                        raise BackupError("Backup source changed while preparing; retry")
            sealer.finish()
        _check(cancel)
        return PrivateArchive(directory, path)
    except BaseException:
        directory.cleanup()
        raise


def open_file_archive(archive: Path, passphrase: str, workspace: Path, *,
                      limits: Limits = Limits(), cancel: Cancel | None = None,
                      progress: Progress | None = None) -> PrivateArchive:
    """Authenticate the entire upload, then validate/extract into a private tree."""
    directory = _workspace(workspace)
    root = Path(directory.name)
    decrypted = root / "authenticated.payload"
    try:
        with _regular(archive) as source:
            size = os.fstat(source.fileno()).st_size
            if size > limits.archive_bytes:
                raise BackupError("Archive exceeds the upload limit")
            header = _read(source, _HEADER_BYTES)
            digest = hashlib.sha256(header)
            if not header.startswith(MAGIC):
                raise BackupError("Unsupported or corrupt backup format")
            key = _key(passphrase, header[len(MAGIC):len(MAGIC) + 16])
            _space(workspace, size * 2, limits)
            cipher = AESGCM(key)
            current, index = 0, 0
            with _private(decrypted) as output:
                while True:
                    _check(cancel)
                    prefix = _read(source, _RECORD.size)
                    length, final = _RECORD.unpack(prefix)
                    if length > CHUNK_BYTES or final not in (0, 1) or (final and length) or (not final and not length):
                        raise BackupError("Archive is corrupt or incomplete")
                    counter = _SIZE.pack(index)
                    ciphertext = _read(source, length + 16)
                    digest.update(prefix)
                    digest.update(ciphertext)
                    try:
                        chunk = cipher.decrypt(header[-4:] + counter, ciphertext,
                                               header + counter + prefix)
                    except InvalidTag:
                        raise BackupError("Wrong passphrase or archive authentication failed") from None
                    index += 1
                    if final:
                        if source.read(1):
                            raise BackupError("Archive contains trailing data")
                        break
                    current += len(chunk)
                    if current > limits.content_bytes + limits.metadata_bytes + limits.files * 160 + 8:
                        raise BackupError("Backup payload exceeds the size limit")
                    output.write(chunk)
                    _report(progress, "authenticating", source.tell(), size)
                output.flush()
                os.fsync(output.fileno())
        # No JSON or archive path is interpreted until the final AEAD record
        # and EOF have authenticated. Failed uploads leave no extracted tree.
        files: dict[str, Path] = {}
        with _regular(decrypted) as source:
            length = _LENGTH.unpack(_read(source, 4))[0]
            if length > limits.metadata_bytes:
                raise BackupError("Backup metadata exceeds the size limit")
            try:
                metadata = json.loads(_read(source, length))
            except (ValueError, UnicodeError):
                raise BackupError("Backup metadata is corrupt") from None
            validate_application_version(metadata)
            if metadata["manifest"].get("format") != 4 or metadata["manifest"].get("scope") not in ("full", "servers"):
                raise BackupError("Backup version or scope is incompatible")
            count = _LENGTH.unpack(_read(source, 4))[0]
            if count > limits.files:
                raise BackupError("Backup contains too many files")
            total = length
            for _ in range(count):
                _check(cancel)
                name_length = _PATH_LENGTH.unpack(_read(source, 2))[0]
                if name_length > 128:
                    raise BackupError("Backup contains an unexpected history path")
                try:
                    name = _read(source, name_length).decode("ascii")
                except UnicodeError:
                    raise BackupError("Backup contains an unexpected history path") from None
                if not _BLOCK_FILE.fullmatch(name) or name in files:
                    raise BackupError("Backup contains an unexpected or duplicate history path")
                length = _SIZE.unpack(_read(source, 8))[0]
                total += length
                if total > limits.content_bytes:
                    raise BackupError("Backup contents exceed the size limit")
                target = root / name
                parent = root
                for component in Path(name).parts[:-1]:
                    parent = parent / component
                    parent.mkdir(mode=0o700, exist_ok=True)
                with _private(target) as output:
                    remaining = length
                    while remaining:
                        _check(cancel)
                        chunk = _read(source, min(CHUNK_BYTES, remaining))
                        output.write(chunk)
                        remaining -= len(chunk)
                    output.flush()
                    os.fsync(output.fileno())
                files[name] = target
                _report(progress, "validating", source.tell(), current)
            if source.read(1):
                raise BackupError("Backup payload contains trailing data")
        _check(cancel)
        decrypted.unlink()
        # Retain a small artifact path for the shared lifetime interface. The
        # returned metadata/files are private; never serve this extraction tree.
        marker = root / "validated"
        with _private(marker):
            pass
        return PrivateArchive(directory, marker, metadata=metadata, files=files,
                              archive_sha256=digest.hexdigest())
    except BaseException:
        directory.cleanup()
        raise
