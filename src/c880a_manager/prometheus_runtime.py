"""Pinned official Prometheus binaries, shared by both Linux architectures.

Installation alone downloads material. Runtime operation is entirely local.
Only named executable/license files are copied; tar paths are never extracted.
"""

from __future__ import annotations

import hashlib
import argparse
import os
from pathlib import Path
import platform
import shutil
import tarfile
import tempfile
import urllib.request


VERSION = "3.13.4"
SHA256 = {
    "amd64": "87f21a66f96c597a189cef8d640e8921b621fc17a9feff707c332c4f3b3ddd56",
    "arm64": "ffa86c7d6e7f7e7dc8a79c81c5c2a6c9164464b79335f25613f4327c863b8489",
}
MAX_DOWNLOAD = 200 * 1024 * 1024
MAX_EXECUTABLE = 300 * 1024 * 1024


def architecture(machine: str | None = None) -> str:
    value = (machine or platform.machine()).lower()
    try:
        return {"x86_64": "amd64", "amd64": "amd64",
                "aarch64": "arm64", "arm64": "arm64"}[value]
    except KeyError:
        raise RuntimeError("Managed Prometheus requires Linux AMD64 or ARM64") from None


def release_url(arch: str) -> str:
    if arch not in SHA256:
        raise ValueError("Unsupported Prometheus architecture")
    return (f"https://github.com/prometheus/prometheus/releases/download/v{VERSION}/"
            f"prometheus-{VERSION}.linux-{arch}.tar.gz")


def install(destination: Path, *, machine: str | None = None) -> None:
    """Verify downloaded bytes before opening the archive or replacing binaries."""
    arch = architecture(machine)
    if destination.is_symlink():
        raise RuntimeError("Prometheus runtime directory must not be a symbolic link")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".prometheus-install-",
                                     dir=destination.parent) as directory:
        staging = Path(directory)
        archive = staging / "release.tar.gz"
        digest = hashlib.sha256()
        size = 0
        try:
            with urllib.request.urlopen(release_url(arch), timeout=60) as response, archive.open("xb") as output:
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > MAX_DOWNLOAD:
                        raise RuntimeError("Prometheus download exceeds the size limit")
                    digest.update(chunk)
                    output.write(chunk)
        except (OSError, ValueError):
            raise RuntimeError("Official Prometheus download failed; check Internet access and retry installation") from None
        if digest.hexdigest() != SHA256[arch]:
            raise RuntimeError("Prometheus integrity verification failed; runtime was not installed")
        candidate = staging / "runtime"
        candidate.mkdir(mode=0o755)
        # Installer umask is deliberately private. Verified public binaries must
        # remain traversable by the unprivileged service after atomic promotion.
        candidate.chmod(0o755)
        prefix = f"prometheus-{VERSION}.linux-{arch}/"
        with tarfile.open(archive, "r:gz") as release:
            for name in ("prometheus", "promtool", "LICENSE", "NOTICE"):
                member = release.getmember(prefix + name)
                limit = MAX_EXECUTABLE if name in ("prometheus", "promtool") else 1024 * 1024
                if not member.isfile() or not 0 < member.size <= limit:
                    raise RuntimeError("Unexpected Prometheus release content")
                source = release.extractfile(member)
                if source is None:
                    raise RuntimeError("Incomplete Prometheus release")
                with source, (candidate / name).open("xb") as output:
                    shutil.copyfileobj(source, output)
                (candidate / name).chmod(0o755 if name in ("prometheus", "promtool") else 0o644)
        # Called inside the installer's backed-up installation transaction.
        if destination.exists():
            shutil.rmtree(destination)
        os.replace(candidate, destination)


def main() -> None:
    parser = argparse.ArgumentParser(description="Install the verified official Prometheus runtime")
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    install(args.destination)


if __name__ == "__main__":
    main()
