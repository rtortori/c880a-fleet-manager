"""Short cross-process lease for coherent installation changes/capture."""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat

from .backup import BackupError


@contextmanager
def installation_lease(data_dir: Path):
    path = data_dir / "state.operation.lock"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise BackupError("Installation operation lock is unsafe; repair its permissions")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BackupError("Another installation operation is in progress; wait and retry") from None
        yield
    finally:
        os.close(descriptor)
