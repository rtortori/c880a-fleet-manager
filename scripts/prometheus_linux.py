"""Shared root-side Linux service provisioning; never an architecture-specific path.

The administrator installs an exact-unit grant for the dedicated account. The
manager keeps NoNewPrivileges and cannot install units or execute root helpers.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import uuid


_USER = re.compile(r"c880a-[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_PROM_UNIT = re.compile(r"c880a-(?:[a-z0-9]+-)*prometheus\.service\Z")
_MANAGER_UNIT = re.compile(r"c880a-(?:[a-z0-9]+-)*manager\.service\Z")
_PATH = re.compile(r"/[A-Za-z0-9_./-]+\Z")


@dataclass(frozen=True)
class ServiceFiles:
    app: Path
    data: Path
    user: str
    manager_unit: str
    unit: Path
    policy: Path

    def __post_init__(self):
        if (not _USER.fullmatch(self.user) or not _PROM_UNIT.fullmatch(self.unit.name) or
                not _MANAGER_UNIT.fullmatch(self.manager_unit)):
            raise ValueError("Invalid product service identity")
        for path in (self.app, self.data, self.unit, self.policy):
            if not _PATH.fullmatch(str(path)) or ".." in path.parts:
                raise ValueError("Invalid product service path")

    def service_unit(self) -> str:
        return ("# C880A managed Prometheus — installer-owned\n"
                "[Unit]\nDescription=Cisco UCS C880A Prometheus\n"
                f"Requires={self.manager_unit}\nAfter={self.manager_unit}\nPartOf={self.manager_unit}\n"
                f"ConditionPathExists={self.data}/prometheus/enabled\n\n"
                f"[Service]\nType=simple\nUser={self.user}\nGroup={self.user}\n"
                f"WorkingDirectory={self.app}/source\n"
                f"ExecStart={self.app}/venv/bin/python -m c880a_manager.prometheus_service "
                f"--data-dir {self.data} --runtime-dir {self.app}/prometheus\n"
                "Restart=on-failure\nRestartSec=3\nTimeoutStopSec=90\n"
                "NoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\n"
                "ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n"
                f"ReadWritePaths={self.data}/prometheus\nUMask=0077\n\n"
                "[Install]\nWantedBy=multi-user.target\n")

    def authorization(self) -> str:
        # Literal identities are validated and JSON encoded, never interpolated
        # from browser settings. Unit-file administration remains root-only.
        return ("// C880A managed Prometheus — installer-owned\n"
                "polkit.addRule(function(action, subject) {\n"
                f"    if (subject.user !== {json.dumps(self.user)}) return;\n"
                "    if (action.id === 'org.freedesktop.systemd1.manage-unit-files') return polkit.Result.NO;\n"
                "    if (action.id !== 'org.freedesktop.systemd1.manage-units') return;\n"
                f"    if (action.lookup('unit') === {json.dumps(self.unit.name)} &&\n"
                "        ['start', 'stop', 'restart'].indexOf(action.lookup('verb')) !== -1)\n"
                "        return polkit.Result.YES;\n"
                "    return polkit.Result.NO;\n"
                "});\n")

    def _receipt(self, receipt: Path | None) -> dict:
        if receipt is not None and receipt.is_symlink():
            raise RuntimeError("Prometheus ownership receipt is unsafe")
        if receipt is None or not receipt.exists():
            return {}
        if (receipt.is_symlink() or not receipt.is_file() or receipt.stat().st_uid != os.geteuid() or
                receipt.stat().st_mode & 0o022 or receipt.parent.is_symlink() or
                receipt.parent.stat().st_uid != os.geteuid() or receipt.parent.stat().st_mode & 0o022):
            raise RuntimeError("Prometheus ownership receipt is unsafe")
        try:
            value = json.loads(receipt.read_text())
            if set(value) != {"unit", "policy"}:
                raise ValueError()
            for key, path in (("unit", self.unit), ("policy", self.policy)):
                entry = value[key]
                if (set(entry) != {"path", "sha256"} or entry["path"] != str(path) or
                        not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])):
                    raise ValueError()
            return value
        except (OSError, ValueError, TypeError, KeyError):
            raise RuntimeError("Prometheus ownership receipt is invalid") from None

    def preflight(self, receipt: Path | None = None) -> None:
        """Never replace an unrelated or mutable root service/policy file."""
        prior = self._receipt(receipt)
        for key, path, expected in (("unit", self.unit, self.service_unit()),
                                    ("policy", self.policy, self.authorization())):
            if (path.parent.is_symlink() or not path.parent.is_dir() or
                    path.parent.stat().st_uid != os.geteuid() or path.parent.stat().st_mode & 0o022):
                raise RuntimeError(f"Service directory ownership is unconfirmed: {path.parent}")
            if path.is_symlink():
                raise RuntimeError(f"Product service path is a symbolic link: {path}")
            if path.exists():
                if not path.is_file() or path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o022:
                    raise RuntimeError(f"Product service ownership is unconfirmed: {path}")
                content = path.read_bytes()
                if (content != expected.encode() and
                        hashlib.sha256(content).hexdigest() != prior.get(key, {}).get("sha256")):
                    raise RuntimeError(f"Product service ownership is unconfirmed: {path}")

    def verify(self, receipt: Path) -> None:
        """A running installation must match its root-owned receipt exactly."""
        self.preflight(receipt)
        prior = self._receipt(receipt)
        if not prior:
            raise RuntimeError("Prometheus ownership receipt is missing")
        for key, path in (("unit", self.unit), ("policy", self.policy)):
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != prior[key]["sha256"]:
                raise RuntimeError("Prometheus ownership receipt does not match installed service files")

    def install(self, receipt: Path | None = None) -> None:
        self.preflight(receipt)
        for path, text in ((self.unit, self.service_unit()), (self.policy, self.authorization())):
            if not path.parent.is_dir() or path.parent.is_symlink():
                raise RuntimeError(f"Service directory is unavailable: {path.parent}")
            temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".pending")
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                with os.fdopen(descriptor, "w") as output:
                    output.write(text)
                    output.flush()
                    os.fchmod(output.fileno(), 0o644)
                    os.fsync(output.fileno())
                temporary.replace(path)
                directory = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            finally:
                temporary.unlink(missing_ok=True)
        if receipt is not None:
            value = {key: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                     for key, path in (("unit", self.unit), ("policy", self.policy))}
            temporary = receipt.with_name(receipt.name + "." + uuid.uuid4().hex + ".pending")
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                with os.fdopen(descriptor, "w") as output:
                    json.dump(value, output)
                    output.flush()
                    os.fsync(output.fileno())
                temporary.replace(receipt)
                descriptor = os.open(receipt.parent, os.O_RDONLY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            finally:
                temporary.unlink(missing_ok=True)


def ensure_authority() -> None:
    """Installation may add the shared OS authority; purge never removes it."""
    if not Path("/usr/lib/polkit-1/polkitd").is_file():
        try:
            subprocess.run(["apt-get", "install", "-y", "polkitd"], check=True,
                           capture_output=True, timeout=300)
        except (OSError, subprocess.SubprocessError):
            raise RuntimeError("Service authorization is unavailable; check package access and retry installation") from None
    if not Path("/etc/polkit-1/rules.d").is_dir():
        raise RuntimeError("Service authorization directory is unavailable; repair polkitd before installing")
