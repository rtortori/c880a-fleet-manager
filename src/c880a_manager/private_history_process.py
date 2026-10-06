"""Linux private-history helper lifetime, without threaded preexec callbacks."""
import ctypes
import os
import signal
import sys


def main():
    # Called only by the private engine with its already-verified pinned runtime.
    # Linux preserves this signal across exec. Recheck the parent to close the
    # race where it died before the kernel signal was installed.
    if not sys.platform.startswith("linux") or len(sys.argv) < 3:
        raise SystemExit("Private history replay requires Linux")
    parent = int(sys.argv[1])
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    if prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        raise SystemExit("Private history preparation owner is unavailable")
    os.execv(sys.argv[2], sys.argv[2:])


if __name__ == "__main__":
    main()
