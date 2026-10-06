#!/usr/bin/env python3
"""Interactive Ubuntu installer. Run via the repository's install.sh."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
import errno
import ipaddress
import hashlib
from http.client import HTTPSConnection
import json
import os
import platform
from pathlib import Path
import pwd
import re
import shutil
import socket
import ssl
import sqlite3
import subprocess
import sys
import tempfile
import time
import tomllib
import uuid

try:
    from scripts.prometheus_linux import ServiceFiles, ensure_authority
except ModuleNotFoundError:  # Direct invocation through install.sh.
    from prometheus_linux import ServiceFiles, ensure_authority


APP_ROOT = Path("/opt/c880a-manager")
DATA_DIR = Path("/var/lib/c880a-manager")
UNIT_PATH = Path("/etc/systemd/system/c880a-manager.service")
SERVICE_USER = "c880a-manager"
SERVICE_HOME = "/nonexistent"
PENDING_PLAN = APP_ROOT / ".installing.json"
PLAN_PATH = APP_ROOT / "install.json"
BACKUP_ROOT = Path("/var/backups/c880a-manager")
UPGRADE_PENDING = BACKUP_ROOT / "upgrade-pending.json"
EXPORTER_START = 9838
EXPORTER_END = 9937
CONSOLE_OFFSET = 2000
PROM_UNIT_PATH = Path("/etc/systemd/system/c880a-prometheus.service")
PROM_POLICY_PATH = Path("/etc/polkit-1/rules.d/50-c880a-manager-prometheus.rules")


def prometheus_files() -> ServiceFiles:
    return ServiceFiles(APP_ROOT, DATA_DIR, SERVICE_USER, UNIT_PATH.name,
                        PROM_UNIT_PATH, PROM_POLICY_PATH)


def prometheus_receipt() -> Path:
    return APP_ROOT / "prometheus-owned.json"


def prometheus_installed() -> bool:
    if prometheus_receipt().is_symlink():
        raise RuntimeError("Prometheus ownership receipt is unsafe")
    return prometheus_receipt().exists()


def lifecycle_guard() -> None:
    for path in (DATA_DIR / "deployment.pending.json", DATA_DIR / "deployment.prometheus.json", DATA_DIR / "restore.pending.json",
                 DATA_DIR / "restore.transaction.json", DATA_DIR / "prometheus/pending.json", DATA_DIR / "prometheus/delete.pending.json"):
        if path.exists() or path.is_symlink():
            raise RuntimeError("An application operation is pending; resolve its recovery before installation or removal")
    if (DATA_DIR / "prometheus").is_symlink():
        raise RuntimeError("Prometheus data must not be a symbolic link")
    database = DATA_DIR / "manager.db"
    if database.exists():
        try:
            with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
                tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if "prometheus_deletions" in tables and connection.execute("SELECT count(*) FROM prometheus_deletions").fetchone()[0]:
                    raise RuntimeError("Target history cleanup is pending; finish it before installation or removal")
        except sqlite3.DatabaseError:
            raise RuntimeError("Manager database could not be inspected; recover it before installation or removal") from None


def verify_prometheus_ownership(*, staging: bool = False, allow_partial: bool = False) -> None:
    if not prometheus_installed():
        artifacts = (APP_ROOT / "source/src/c880a_manager/prometheus_runtime.py",
                     APP_ROOT / "prometheus", DATA_DIR / "prometheus",
                     PROM_UNIT_PATH, PROM_POLICY_PATH)
        if not allow_partial and any(path.exists() or path.is_symlink() for path in artifacts):
            raise RuntimeError("Prometheus ownership receipt is missing; recover the installation before continuing")
        if allow_partial and any(path.exists() or path.is_symlink() for path in (PROM_UNIT_PATH, PROM_POLICY_PATH)):
            prometheus_files().preflight(prometheus_receipt())
        return
    if prometheus_installed():
        files = prometheus_files()
        if staging:
            files.preflight(prometheus_receipt())
        else:
            files.verify(prometheus_receipt())
        if not all(path.is_file() for path in (files.unit, files.policy,
                       APP_ROOT / "prometheus/prometheus", APP_ROOT / "prometheus/promtool")):
            raise RuntimeError("Managed Prometheus installation is incomplete; recover it before continuing")
        runtime = APP_ROOT / "prometheus"
        if runtime.is_symlink() or runtime.stat().st_uid != os.geteuid() or runtime.stat().st_mode & 0o022:
            raise RuntimeError("Prometheus runtime ownership is unconfirmed")
        for path in (runtime / "prometheus", runtime / "promtool"):
            if path.is_symlink() or path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o022:
                raise RuntimeError("Prometheus executable ownership is unconfirmed")


def prometheus_cli(mode: str) -> None:
    try:
        run("runuser", "-u", SERVICE_USER, "--", str(APP_ROOT / "venv/bin/python"),
            "-m", "c880a_manager.prometheus_service", "--data-dir", str(DATA_DIR),
            "--runtime-dir", str(APP_ROOT / "prometheus"), "--unit", PROM_UNIT_PATH.name,
            mode, capture=True)
    except subprocess.CalledProcessError:
        raise RuntimeError("Prometheus activation/state check failed; inspect its service and rerun the installer") from None


def start_prometheus() -> None:
    verify_prometheus_ownership()
    if prometheus_installed():
        run("systemctl", "enable", PROM_UNIT_PATH.name, capture=True)
        prometheus_cli("--initialise")


def check_prometheus() -> None:
    verify_prometheus_ownership()
    if prometheus_installed():
        prometheus_cli("--check")


def stop_prometheus(*, staging: bool = False) -> None:
    verify_prometheus_ownership(staging=staging, allow_partial=staging)
    if prometheus_installed():
        run("systemctl", "stop", PROM_UNIT_PATH.name, capture=True)
        state = run("systemctl", "is-active", "--quiet", PROM_UNIT_PATH.name, check=False, capture=True)
        if state.returncode != 3:
            raise RuntimeError("Prometheus stopped state is unconfirmed; no data will be copied or removed")


def stop_manager() -> None:
    run("systemctl", "stop", UNIT_PATH.name)
    state = run("systemctl", "is-active", "--quiet", UNIT_PATH.name, check=False, capture=True)
    if state.returncode != 3:
        raise RuntimeError("Manager stopped state is unconfirmed; no data will be copied or removed")


def prometheus_settings() -> dict:
    path = DATA_DIR / "prometheus/active.json"
    if not path.exists():
        return {"enabled": True, "retention_hours": 24, "storage_gib": 1}
    try:
        value = json.loads(path.read_text())["settings"]
        if (type(value["enabled"]) is not bool or type(value["storage_gib"]) is not int or
                not 1 <= value["storage_gib"] <= 128 or type(value["retention_hours"]) is not int or
                not 1 <= value["retention_hours"] <= 720):
            raise ValueError()
        return value
    except (OSError, ValueError, KeyError, TypeError):
        raise RuntimeError("Saved Prometheus settings are invalid; recover them before installation") from None


def allocated_bytes(path: Path) -> int:
    seen = set()
    total = 0
    if path.exists():
        for entry in [path, *path.rglob("*")]:
            stat = entry.lstat()
            identity = stat.st_dev, stat.st_ino
            if identity not in seen:
                total += stat.st_blocks * 512
                seen.add(identity)
    return total


def prometheus_preflight(*, upgrade: bool = False, repo: Path | None = None) -> None:
    lifecycle_guard()
    if platform.machine().lower() not in {"x86_64", "amd64", "aarch64", "arm64"}:
        raise RuntimeError("Managed Prometheus supports Linux AMD64 and ARM64")
    files = prometheus_files()
    if upgrade and not prometheus_installed() and any(path.exists() or path.is_symlink() for path in
                 (files.unit, files.policy, APP_ROOT / "prometheus")):
        raise RuntimeError("Prometheus ownership receipt is missing; inspect the installation before upgrading")
    # A missing shared Polkit directory is provisioned after confirmation.
    if files.policy.parent.exists():
        files.preflight(prometheus_receipt())
    else:
        if files.unit.exists() or files.unit.is_symlink() or files.policy.is_symlink():
            raise RuntimeError("Prometheus service ownership is unconfirmed")
    verify_prometheus_ownership()
    settings = prometheus_settings()
    cap = settings["storage_gib"] * 1024**3
    data_parent = DATA_DIR if DATA_DIR.exists() else DATA_DIR.parent
    reserve = max(1024**3, cap // 5)
    needed = max(0, cap - allocated_bytes(DATA_DIR / "prometheus/tsdb")) + reserve if settings["enabled"] else 0
    # Provisioning has bounded download/executable staging, plus Python package
    # replacement. Backups count allocated bytes, including WAL/head data.
    demands = [(APP_ROOT.parent, 1024**3), (data_parent, needed)]
    if upgrade:
        backup_parent = BACKUP_ROOT if BACKUP_ROOT.exists() else BACKUP_ROOT.parent
        demands.append((backup_parent, allocated_bytes(APP_ROOT) + allocated_bytes(DATA_DIR)))
    grouped = {}
    for path, size in demands:
        while not path.exists():
            path = path.parent
        dev = path.stat().st_dev
        old_size, old_path = grouped.get(dev, (0, path))
        grouped[dev] = old_size + size, old_path
    for size, path in grouped.values():
        free = shutil.disk_usage(path).free
        print(f"Disk headroom: {size / 1024**3:.2f} GiB required · {free / 1024**3:.2f} GiB available")
        if free < size:
            raise RuntimeError("Insufficient disk headroom for Prometheus and upgrade safety copies; free space before retrying")
    state = "enabled" if settings["enabled"] else "disabled · stored history kept"
    if upgrade and not prometheus_installed():
        state += " (new managed service)"
    print(f"Managed Prometheus: {state} · up to {settings['retention_hours']} hours of history · "
          f"{settings['storage_gib']} GiB storage budget")
    if repo is not None:
        match = re.search(r'^VERSION = "(\d+\.\d+\.\d+)"$',
                          (repo / "src/c880a_manager/prometheus_runtime.py").read_text(), re.MULTILINE)
        if not match:
            raise RuntimeError("Pinned Prometheus release version is invalid")
        print(f"Prometheus runtime: {match[1]} · official release · SHA-256 verification required")


def provision_prometheus() -> None:
    print("Provisioning verified Prometheus runtime and service…")
    ensure_authority()
    files = prometheus_files()
    files.preflight(prometheus_receipt())
    try:
        run(str(APP_ROOT / "venv/bin/python"), "-m", "c880a_manager.prometheus_runtime",
            "--destination", str(APP_ROOT / "prometheus"), capture=True)
    except subprocess.CalledProcessError:
        raise RuntimeError("Pinned Prometheus provisioning failed; check official-release connectivity/integrity and retry") from None
    # Condition/read-write path must exist before systemd starts the unit.
    directory = DATA_DIR / "prometheus"
    directory.mkdir(mode=0o700, exist_ok=True)
    run("chown", f"{SERVICE_USER}:{SERVICE_USER}", str(directory))
    files.install(prometheus_receipt())


def remove_prometheus_files(*, partial: bool = False) -> None:
    if not prometheus_installed() and not partial:
        return
    prometheus_files().preflight(prometheus_receipt())
    run("systemctl", "disable", "--now", PROM_UNIT_PATH.name, capture=True, check=not partial)
    state = run("systemctl", "is-active", "--quiet", PROM_UNIT_PATH.name, capture=True, check=False)
    if state.returncode not in ((3, 4) if partial else (3,)):
        raise RuntimeError("Prometheus stopped state is unconfirmed; service files retained")
    PROM_UNIT_PATH.unlink(missing_ok=True)
    PROM_POLICY_PATH.unlink(missing_ok=True)
    prometheus_receipt().unlink(missing_ok=True)


def progress(step: int, total: int, label: str) -> None:
    """Show the current stage without estimating package-download progress."""
    filled = 12 * step // total
    print(f"[{'█' * filled}{'░' * (12 - filled)}] {step}/{total}  {label}", flush=True)


def run(*args: str, check: bool = True, capture: bool = False,
        locale_c: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=check, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None,
                          env={**os.environ, "LC_ALL": "C"} if locale_c else None)


def candidates(ip_output: str) -> list[tuple[str, str]]:
    """Only up, assigned, non-loopback addresses can serve remote clients."""
    result: list[tuple[str, str]] = []
    for interface in json.loads(ip_output):
        if interface.get("operstate") not in ("UP", "UNKNOWN") or interface.get("ifname") == "lo":
            continue
        for entry in interface.get("addr_info", []):
            try:
                address = ipaddress.ip_address(entry["local"].split("%", 1)[0])
            except (KeyError, ValueError):
                continue
            if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
                continue
            result.append((interface["ifname"], str(address)))
    return sorted(set(result), key=lambda item: (item[0], ipaddress.ip_address(item[1]).version, item[1]))


def port_groups(manager_port: int, start: int = EXPORTER_START,
                end: int = EXPORTER_END, offset: int = CONSOLE_OFFSET) -> list[tuple[str, range]]:
    if not 1 <= manager_port <= 65535:
        raise ValueError("Manager port must be 1–65535")
    if not (1 <= start <= end <= 65535 and 1 <= start + offset <= end + offset <= 65535):
        raise ValueError("Exporter or console port range is invalid")
    exporters = range(start, end + 1)
    consoles = range(start + offset, end + offset + 1)
    if set(exporters) & set(consoles) or manager_port in exporters or manager_port in consoles:
        raise ValueError("Manager port overlaps the exporter or console range")
    return [("Manager", range(manager_port, manager_port + 1)),
            ("Exporters", exporters), ("Consoles", consoles)]


def occupied(address: str, ports: range) -> list[int]:
    family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
    conflicts: list[int] = []
    for port in ports:
        with socket.socket(family, socket.SOCK_STREAM) as listener:
            # A recently stopped HTTPS listener can leave active/closing TCP
            # connections behind. Match the service's reusable bind behavior.
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            try:
                listener.bind((address, port))
            except OSError as exc:
                if exc.errno == errno.EADDRINUSE:
                    # Linux may reject a bind while old TCP connections close.
                    # Only an active listener should block the upgrade.
                    sockets = run("ss", "-H", "-ltn", "sport", "=", f":{port}",
                                  check=False, capture=True)
                    if sockets.returncode == 0 and not sockets.stdout.strip():
                        continue
                conflicts.append(port)
    return conflicts


def origin(address: str, port: int) -> str:
    host = f"[{address}]" if ":" in address else address
    return f"https://{host}:{port}"


def choose_address(available: list[tuple[str, str]], default_interfaces: set[str]) -> tuple[str, str]:
    if not available:
        raise RuntimeError("No active non-loopback IPv4 or IPv6 address found")
    print("\nAvailable management addresses:")
    for index, (interface, address) in enumerate(available, 1):
        route = "default route; may be NAT" if interface in default_interfaces else "no default route"
        print(f"  {index}. {interface} · {address} · {route}")
    if len(available) == 1:
        print(f"Using {available[0][0]} · {available[0][1]}")
        return available[0]
    while True:
        answer = input("Select a browser-reachable address number: ").strip()
        if answer.isdecimal() and 1 <= int(answer) <= len(available):
            return available[int(answer) - 1]
        print("Enter one of the listed numbers.")


def choose_port(address: str) -> int:
    suggested = 443 if not occupied(address, range(443, 444)) else 8443
    if suggested == 8443:
        print(f"TCP 443 is occupied on this address{port_owner(443)}; 8443 is suggested.")
    while True:
        answer = input(f"Manager HTTPS port [{suggested}]: ").strip()
        try:
            port = int(answer) if answer else suggested
            port_groups(port)
        except ValueError as exc:
            print(f"Invalid port: {exc}")
            continue
        if occupied(address, range(port, port + 1)):
            print(f"TCP {port} is occupied on {address}{port_owner(port)}. Choose another port.")
            continue
        return port


def port_owner(port: int) -> str:
    if not shutil.which("ss"):
        return ""
    listing = run("ss", "-H", "-ltnp", check=False, capture=True)
    for line in listing.stdout.splitlines():
        if re.search(rf":{port}\s", line):
            owner = re.search(r'users:\(\("([^"]{1,80})"', line)
            if owner:
                name = re.sub(r"[^A-Za-z0-9._-]", "", owner.group(1))[:40]
                return f" (used by {name})" if name else ""
            return ""
    return ""


def firewall_state() -> str:
    for service in ("firewalld", "nftables"):
        if run("systemctl", "is-active", "--quiet", service, check=False).returncode == 0:
            raise RuntimeError(
                f"Active {service} firewall is not supported by this installer; "
                "configure the required HTTPS ports with that firewall or use UFW, then rerun"
            )
    if shutil.which("ufw"):
        status = run("ufw", "status", check=False, capture=True, locale_c=True)
        if status.returncode == 0 and "Status: active" in status.stdout:
            return "ufw"
        if status.returncode != 0:
            raise RuntimeError("Cannot inspect UFW; resolve the firewall state before installing")
    return "none"


def firewall_rules(interface: str, address: str, manager_port: int,
                   start: int = EXPORTER_START, end: int = EXPORTER_END,
                   offset: int = CONSOLE_OFFSET) -> list[list[str]]:
    return [["ufw", "allow", "in", "on", interface, "to", address,
             "port", str(group.start) if len(group) == 1 else f"{group.start}:{group.stop - 1}",
             "proto", "tcp", "comment", "c880a-manager"]
            for _, group in port_groups(manager_port, start, end, offset)]


def default_route_interfaces(ip_output: str) -> set[str]:
    return {item["dev"] for item in json.loads(ip_output)
            if item.get("dst") == "default" and item.get("dev")}


def ensure_platform() -> None:
    if sys.version_info < (3, 11):
        raise RuntimeError("Python 3.11 or newer is required")
    release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            release[key] = value.strip('"')
    if release.get("ID") != "ubuntu" or release.get("VERSION_ID") != "24.04":
        raise RuntimeError("This installer currently supports Ubuntu 24.04 only")
    for binary in ("ip", "ss", "systemctl", "useradd", "runuser", "apt-get"):
        if not shutil.which(binary):
            raise RuntimeError(f"Required system command is missing: {binary}")
    if os.geteuid() != 0:
        raise RuntimeError("Run this installer with sudo")


def ensure_venv() -> None:
    with tempfile.TemporaryDirectory(prefix="c880a-venv-check-") as temporary:
        probe = run(sys.executable, "-m", "venv", str(Path(temporary) / "venv"),
                    check=False, capture=True)
        if probe.returncode:
            print("Installing Python virtual-environment support…")
            run("apt-get", "update", "-qq")
            run("apt-get", "install", "-qq", "-y", "python3-venv")


def _partial_data_is_disposable() -> bool:
    if not DATA_DIR.exists():
        return True
    if {entry.name for entry in DATA_DIR.iterdir()} - {
            "manager.db", "master.key", "installation-id", "bootstrap-token"}:
        return False
    database = DATA_DIR / "manager.db"
    if not database.exists():
        return True
    try:
        with sqlite3.connect(database) as db:
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            users = (db.execute("SELECT username, must_change_password FROM users").fetchall()
                     if "users" in tables else [])
            servers = db.execute("SELECT count(*) FROM servers").fetchone()[0] if "servers" in tables else 0
            audit = db.execute("SELECT count(*) FROM audit").fetchone()[0] if "audit" in tables else 0
            return users in ([], [("admin", 1)]) and servers == 0 and audit == 0
    except sqlite3.DatabaseError:
        return False


def initial_credential_pending() -> bool:
    try:
        with sqlite3.connect(DATA_DIR / "manager.db") as db:
            row = db.execute("SELECT must_change_password FROM users WHERE username='admin'").fetchone()
            return bool(row and row[0])
    except sqlite3.DatabaseError:
        return False


def discard_before_service() -> None:
    """Only an unstarted installer-owned directory with no operator data is disposable."""
    if UNIT_PATH.exists() or not PENDING_PLAN.exists():
        raise RuntimeError("Partial installation contains state; inspect it before retrying")
    plan = json.loads(PENDING_PLAN.read_text())
    preserved = bool(plan.get("preserve_existing_data"))
    if not preserved and not _partial_data_is_disposable():
        raise RuntimeError("Partial installation contains state; inspect it before retrying")
    if plan.get("managed_prometheus"):
        remove_prometheus_files(partial=True)
        run("systemctl", "daemon-reload")
    shutil.rmtree(APP_ROOT)
    if DATA_DIR.exists() and not preserved:
        shutil.rmtree(DATA_DIR)
    if plan.get("created_user"):
        run("userdel", SERVICE_USER, check=False)


def prepare_installation(repo: Path, plan: dict[str, object]) -> None:
    preserved = bool(plan.get("preserve_existing_data"))
    if APP_ROOT.exists() or UNIT_PATH.exists() or DATA_DIR.exists() != preserved:
        raise RuntimeError("Installation paths changed since preflight")
    if preserved and DATA_DIR.is_symlink():
        raise RuntimeError("Preserved data path must not be a symbolic link")
    APP_ROOT.mkdir(mode=0o755)
    APP_ROOT.chmod(0o755)
    if (repo / "src/c880a_manager/prometheus_runtime.py").is_file():
        plan["managed_prometheus"] = True
    plan["created_user"] = False
    PENDING_PLAN.write_text(json.dumps(plan))
    try:
        existing_user = pwd.getpwnam(SERVICE_USER)
    except KeyError:
        existing_user = None
    if existing_user:
        if existing_user.pw_dir != SERVICE_HOME or existing_user.pw_shell != "/usr/sbin/nologin":
            raise RuntimeError("An incompatible c880a-manager service account already exists")
        if preserved and DATA_DIR.stat().st_uid != existing_user.pw_uid:
            raise RuntimeError("Preserved data is not owned by the c880a-manager service account")
    else:
        if preserved:
            raise RuntimeError("Preserved data requires its original c880a-manager service account")
        run("useradd", "--system", "--user-group", "--home-dir", SERVICE_HOME,
            "--shell", "/usr/sbin/nologin", SERVICE_USER)
        plan["created_user"] = True
        PENDING_PLAN.write_text(json.dumps(plan))
    if not preserved:
        DATA_DIR.mkdir(mode=0o700)
        run("chown", f"{SERVICE_USER}:{SERVICE_USER}", str(DATA_DIR))
    install_package(repo)
    if not preserved:
        run("runuser", "-u", SERVICE_USER, "--", str(APP_ROOT / "venv/bin/python"),
            "-m", "c880a_manager.install_admin", str(DATA_DIR))


def install_package(repo: Path) -> None:
    source = APP_ROOT / "source"
    source.mkdir(mode=0o755)
    source.chmod(0o755)
    for name in ("README.md", "pyproject.toml"):
        shutil.copy2(repo / name, source / name)
    shutil.copytree(repo / "src", source / "src")
    previous_umask = os.umask(0o022)
    try:
        run(sys.executable, "-m", "venv", str(APP_ROOT / "venv"))
        command = (str(APP_ROOT / "venv/bin/python"), "-m", "pip", "install", "--quiet",
                   "--no-cache-dir", str(source))
        # Keep pip output (which may contain private index URLs) out of the terminal.
        with ThreadPoolExecutor(max_workers=1) as pool:
            task = pool.submit(run, *command, capture=True)
            elapsed = 0
            while True:
                try:
                    task.result(timeout=10)
                    break
                except FutureTimeout:
                    elapsed += 10
                    print(f"  Installing Python packages… {elapsed}s elapsed", flush=True)
                except subprocess.CalledProcessError as exc:
                    output = f"{exc.stdout or ''}\n{exc.stderr or ''}".lower()
                    if any(term in output for term in (
                            "temporary failure in name resolution", "name or service not known",
                            "could not resolve", "nodename nor servname")):
                        raise RuntimeError(
                            "Python package download failed because DNS is unavailable. "
                            "Check the VM's DNS and NAT connection, then rerun ./install.sh."
                        ) from None
                    if any(term in output for term in (
                            "network is unreachable", "no route to host", "connection timed out",
                            "connecttimeout", "max retries exceeded")):
                        raise RuntimeError(
                            "Python package download failed because the package index is unreachable. "
                            "Check the VM's Internet connection, then rerun ./install.sh."
                        ) from None
                    raise RuntimeError(
                        "Python package installation failed. Check package-index access and "
                        "dependency availability, then rerun ./install.sh."
                    ) from None
    finally:
        os.umask(previous_umask)
    if (repo / "src/c880a_manager/prometheus_runtime.py").is_file():
        provision_prometheus()


def preserved_deployment() -> dict[str, int | str]:
    """Read an uninstalled deployment without changing its users or certificate."""
    if DATA_DIR.is_symlink() or not DATA_DIR.is_dir():
        raise RuntimeError("Preserved data directory is missing or unsafe")
    path = DATA_DIR / "deployment.json"
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("Preserved deployment configuration is missing or unsafe")
    try:
        deployment = json.loads(path.read_text())
        address = str(deployment["manager_bind"])
        port = int(deployment["manager_port"])
        if any(deployment[name] != address for name in ("exporter_bind", "console_bind")):
            raise ValueError("The saved listeners use different addresses")
        start = int(deployment["port_start"])
        end = int(deployment["port_end"])
        offset = int(deployment["console_port_offset"])
        ipaddress.ip_address(address)
        port_groups(port, start, end, offset)
        certificate = deployment["certificate"]
        if not all(Path(certificate[name]).is_file() for name in ("cert", "key")):
            raise ValueError("The saved certificate or private key is missing")
    except (KeyError, TypeError, ValueError, OSError) as exc:
        raise RuntimeError(f"Cannot reinstall from preserved data: {exc}") from None
    return {"address": address, "port": port, "port_start": start,
            "port_end": end, "console_port_offset": offset}


def package_version(path: Path) -> str:
    try:
        with (path / "pyproject.toml").open("rb") as source:
            version = tomllib.load(source)["project"]["version"]
        if not isinstance(version, str) or not version.strip():
            raise ValueError("version must be a nonempty string")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise RuntimeError(f"Invalid package version in {path / 'pyproject.toml'}: {exc}") from exc
    return version


def package_digest(path: Path) -> str:
    digest = hashlib.sha256()
    for source in sorted((path / "src" / "c880a_manager").rglob("*")):
        if (source.is_file() and not source.name.startswith("._")
                and source.suffix in {".py", ".js", ".css", ".html", ".woff2", ".tsv"}):
            digest.update(str(source.relative_to(path)).encode())
            digest.update(source.read_bytes())
    digest.update((path / "pyproject.toml").read_bytes())
    return digest.hexdigest()[:8]


def managed_installation() -> bool:
    if any(path.is_symlink() for path in (APP_ROOT, DATA_DIR, UNIT_PATH, PLAN_PATH,
                                         BACKUP_ROOT, UPGRADE_PENDING)):
        raise RuntimeError("Installation and backup paths must not be symbolic links")
    if not (APP_ROOT.is_dir() and DATA_DIR.is_dir() and UNIT_PATH.is_file()
            and PLAN_PATH.is_file() and (APP_ROOT / "source/pyproject.toml").is_file()
            and (APP_ROOT / "venv/bin/python").is_file()):
        return False
    if APP_ROOT.stat().st_uid != os.geteuid() or UNIT_PATH.stat().st_uid != os.geteuid():
        raise RuntimeError("Installed application or service unit has an unexpected owner")
    unit = UNIT_PATH.read_text()
    return (f"WorkingDirectory={APP_ROOT}/source" in unit
            and f"User={SERVICE_USER}" in unit
            and f"{APP_ROOT}/venv/bin/" in unit)


def secure_backup_root(*, create: bool = False) -> None:
    if BACKUP_ROOT.is_symlink():
        raise RuntimeError("Upgrade backup path must not be a symbolic link")
    if create:
        BACKUP_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    if BACKUP_ROOT.exists():
        metadata = BACKUP_ROOT.stat()
        if not BACKUP_ROOT.is_dir() or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise RuntimeError(f"Upgrade backup directory is unsafe; check owner and mode 700: {BACKUP_ROOT}")


def _upgrade_snapshot(name: str) -> Path:
    if not re.fullmatch(r"\d{8}T\d{6}Z-[0-9a-f]{8}", name):
        raise RuntimeError("Invalid upgrade recovery marker")
    snapshot = BACKUP_ROOT / name
    if snapshot.is_symlink() or (snapshot.exists() and not snapshot.is_dir()):
        raise RuntimeError("Upgrade recovery directory is unsafe")
    return snapshot


def _write_upgrade_marker(snapshot: Path, phase: str, digest: str | None = None) -> None:
    """A durable marker separates a safe restart from a full data rollback."""
    if phase not in {"preparing", "ready", "active"}:
        raise ValueError("Invalid upgrade phase")
    if phase == "active" and (digest is None or not re.fullmatch(r"[0-9a-f]{8}", digest)):
        raise ValueError("Active upgrade marker requires a package digest")
    payload = json.dumps({"snapshot": snapshot.name, "phase": phase, "digest": digest}) + "\n"
    temporary = BACKUP_ROOT / f".upgrade-marker-{uuid.uuid4().hex}"
    try:
        with temporary.open("x") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(0o600)
        temporary.replace(UPGRADE_PENDING)
        directory_fd = os.open(BACKUP_ROOT, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def restore_upgrade(snapshot: Path) -> None:
    """Restore the saved package and database, then prove the old HTTPS service works."""
    if snapshot != _upgrade_snapshot(snapshot.name):
        raise RuntimeError("Invalid upgrade recovery path")
    if (any((snapshot / name).is_symlink() or not (snapshot / name).is_dir()
            for name in ("app", "data")) or
            (snapshot / "unit").is_symlink() or not (snapshot / "unit").is_file()):
        raise RuntimeError(f"Upgrade backup is incomplete: {snapshot}")
    # Validate ownership before stopping/removing either product service. Old
    # snapshots deliberately lack Prometheus artifacts for first-migration rollback.
    verify_prometheus_ownership(staging=True, allow_partial=True)
    saved_receipt = snapshot / "app/prometheus-owned.json"
    prior = prometheus_files()._receipt(saved_receipt)
    for name in ("prometheus-unit", "prometheus-policy"):
        saved_file = snapshot / name
        if saved_file.is_symlink() or (saved_file.exists() and not saved_file.is_file()):
            raise RuntimeError("Upgrade Prometheus service backup is unsafe")
        key = "unit" if name == "prometheus-unit" else "policy"
        if prior:
            if (not saved_file.is_file() or saved_file.stat().st_uid != os.geteuid() or
                    saved_file.stat().st_mode & 0o022 or
                    hashlib.sha256(saved_file.read_bytes()).hexdigest() != prior[key]["sha256"]):
                raise RuntimeError("Upgrade Prometheus service backup does not match its ownership receipt")
        elif saved_file.exists():
            raise RuntimeError("Upgrade Prometheus service backup has no ownership receipt")
    stop_manager()
    stop_prometheus(staging=True)
    if prometheus_installed():
        remove_prometheus_files()
    elif any(path.exists() or path.is_symlink() for path in (PROM_UNIT_PATH, PROM_POLICY_PATH)):
        remove_prometheus_files(partial=True)
    if APP_ROOT.is_symlink() or DATA_DIR.is_symlink() or UNIT_PATH.is_symlink():
        raise RuntimeError("Cannot restore over a symbolic link")
    for path in (APP_ROOT, DATA_DIR):
        if path.exists():
            shutil.rmtree(path)
    UNIT_PATH.unlink(missing_ok=True)
    run("cp", "-a", "--", str(snapshot / "app"), str(APP_ROOT))
    run("cp", "-a", "--", str(snapshot / "data"), str(DATA_DIR))
    run("cp", "-a", "--", str(snapshot / "unit"), str(UNIT_PATH))
    for name, path in (("prometheus-unit", PROM_UNIT_PATH), ("prometheus-policy", PROM_POLICY_PATH)):
        if (snapshot / name).exists():
            run("cp", "-a", "--", str(snapshot / name), str(path))
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", "--now", UNIT_PATH.name)
    saved = preserved_deployment()
    https_health(str(saved["address"]), int(saved["port"]))
    start_prometheus()
    check_prometheus()


def recover_interrupted_upgrade() -> bool:
    if not UPGRADE_PENDING.exists():
        return False
    secure_backup_root()
    if UPGRADE_PENDING.is_symlink():
        raise RuntimeError("Upgrade recovery marker is unsafe")
    try:
        marker = json.loads(UPGRADE_PENDING.read_text())
        phase = marker["phase"]
        snapshot = _upgrade_snapshot(marker["snapshot"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(f"Invalid upgrade recovery marker: {exc}") from None
    if phase == "preparing":
        verify_prometheus_ownership()
        print("Resuming interrupted preparation; checking the previous HTTPS service…")
        run("systemctl", "start", UNIT_PATH.name)
        saved = preserved_deployment()
        https_health(str(saved["address"]), int(saved["port"]))
        start_prometheus()
        check_prometheus()
        shutil.rmtree(snapshot)
    elif phase == "ready":
        print(f"Restoring the previous installation from {snapshot}…")
        restore_upgrade(snapshot)
    elif phase == "active":
        digest = marker.get("digest")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{8}", digest):
            raise RuntimeError("Invalid active upgrade marker")
        try:
            if not managed_installation() or package_digest(APP_ROOT / "source") != digest:
                raise RuntimeError("Installed package does not match the activation marker")
            saved = preserved_deployment()
            https_health(str(saved["address"]), int(saved["port"]))
            check_prometheus()
        except Exception:
            print(f"Activated upgrade is unhealthy; restoring {snapshot}…")
            restore_upgrade(snapshot)
        else:
            UPGRADE_PENDING.unlink()
            print("Upgrade already active and HTTPS healthy.")
            return True
    else:
        raise RuntimeError("Invalid upgrade recovery phase")
    UPGRADE_PENDING.unlink()
    if phase == "preparing":
        print("Previous installation is active and HTTPS healthy; no new backup retained. Rerun install.sh to retry.")
    else:
        print("Previous installation restored and HTTPS healthy. Rerun install.sh to retry.")
    return True


def upgrade_installation(repo: Path) -> None:
    if not managed_installation():
        raise RuntimeError("Existing installation is not recognized as installer-managed")
    secure_backup_root()
    lifecycle_guard()
    verify_prometheus_ownership()
    try:
        manifest = json.loads(PLAN_PATH.read_text())
        if not isinstance(manifest, dict) or not {"address", "port", "interface"} <= manifest.keys():
            raise ValueError("required fields are missing")
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Installer manifest is invalid; inspect {PLAN_PATH}: {exc}") from None
    if not (repo / "src/c880a_manager/manager.py").is_file() or not (repo / "README.md").is_file():
        raise RuntimeError("Target checkout is incomplete; manager source or README is missing")
    saved = preserved_deployment()
    address, port = str(saved["address"]), int(saved["port"])
    available = candidates(run("ip", "-j", "address", "show", "up", capture=True).stdout)
    interfaces = [name for name, value in available if value == address]
    if len(interfaces) != 1:
        raise RuntimeError(f"Saved bind address {address} must be assigned to one active interface")
    if run("systemctl", "is-active", "--quiet", UNIT_PATH.name,
           check=False).returncode:
        raise RuntimeError("Manager service is not active; inspect systemctl status before upgrading")
    old_version, new_version = package_version(APP_ROOT / "source"), package_version(repo)
    old_digest, new_digest = package_digest(APP_ROOT / "source"), package_digest(repo)
    if old_version == new_version and old_digest == new_digest:
        https_health(address, port)
        check_prometheus()
        print(f"Already installed: {new_version} ({new_digest}) · {origin(address, port)}/ · HTTPS healthy")
        return
    if old_version == new_version:
        raise RuntimeError(
            f"Different application code uses installed version {new_version}; "
            "increase the package version before upgrading")
    start, end, offset = (int(saved[name]) for name in
                          ("port_start", "port_end", "console_port_offset"))
    name = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:8]
    snapshot = _upgrade_snapshot(name)
    print(f"\nUpgrade: {old_version} ({old_digest}) → {new_version} ({new_digest})")
    print(f"HTTPS: {origin(address, port)}/ · {interfaces[0]}")
    print(f"Exporters: {start}–{end}/tcp · Consoles: {start + offset}–{end + offset}/tcp")
    firewall = firewall_state()
    if firewall not in {"none", "ufw"}:
        raise RuntimeError("Unsupported firewall state")
    https_health(address, port)
    managed_prometheus = (repo / "src/c880a_manager/prometheus_runtime.py").is_file()
    if managed_prometheus:
        prometheus_preflight(upgrade=True, repo=repo)
    elif prometheus_installed():
        raise RuntimeError("Target package has no managed Prometheus support; use verified rollback recovery")
    print("Data and certificate retained · Manager, scrapes and queries unavailable during package install/restart")
    print("Firewall changes: none")
    print(f"Safety backup and rollback: {snapshot}")
    if input("Upgrade? [y/N]: ").strip().lower() != "y":
        print("Upgrade canceled.")
        return
    ensure_venv()
    secure_backup_root(create=True)
    phase = "preparing"
    snapshot_created = False
    try:
        snapshot.mkdir(mode=0o700)
        snapshot_created = True
        _write_upgrade_marker(snapshot, phase)
        stop_manager()
        stop_prometheus()
        lifecycle_guard()
        conflicts = [(label, occupied(address, group)) for label, group in
                     port_groups(port, start, end, offset)]
        if any(ports for _, ports in conflicts):
            raise RuntimeError(f"Ports remain occupied after stopping manager: {conflicts}")
        run("cp", "-a", "--", str(APP_ROOT), str(snapshot / "app"))
        run("cp", "-a", "--", str(DATA_DIR), str(snapshot / "data"))
        run("cp", "-a", "--", str(UNIT_PATH), str(snapshot / "unit"))
        if prometheus_installed():
            run("cp", "-a", "--", str(PROM_UNIT_PATH), str(snapshot / "prometheus-unit"))
            run("cp", "-a", "--", str(PROM_POLICY_PATH), str(snapshot / "prometheus-policy"))
        _write_upgrade_marker(snapshot, "ready")
        phase = "ready"
        print(f"Backup saved: {snapshot}")
        shutil.rmtree(APP_ROOT / "source")
        shutil.rmtree(APP_ROOT / "venv")
        print("Installing package…")
        install_package(repo)
        # Regenerate the manager unit too, using the same script on both CPUs.
        UNIT_PATH.write_text(service_unit(address, port, start, end, offset))
        UNIT_PATH.chmod(0o644)
        run("systemctl", "daemon-reload")
        print("Restarting HTTPS…")
        run("systemctl", "start", UNIT_PATH.name)
        https_health(address, port)
        start_prometheus()
        check_prometheus()
        if managed_prometheus:
            manifest["managed_prometheus"] = True
            PLAN_PATH.write_text(json.dumps(manifest, indent=2) + "\n")
        _write_upgrade_marker(snapshot, "active", new_digest)
        UPGRADE_PENDING.unlink()
        print(f"Upgrade complete: {new_version} ({new_digest}) · {origin(address, port)}/ · HTTPS healthy")
    except Exception as exc:
        try:
            if phase == "ready":
                restore_upgrade(snapshot)
            else:
                run("systemctl", "start", UNIT_PATH.name)
                https_health(address, port)
                start_prometheus()
                check_prometheus()
            UPGRADE_PENDING.unlink(missing_ok=True)
            if phase == "preparing" and snapshot_created:
                shutil.rmtree(snapshot)
        except Exception as recovery_error:
            recovery_location = (f"Backup: {snapshot}." if phase == "ready" else
                                 (f"Recovery directory (possibly incomplete): {snapshot}."
                                  if snapshot_created else "No safety backup was created."))
            raise RuntimeError(f"Upgrade failed; rollback incomplete and service state unknown. "
                               f"{recovery_location} Inspect systemctl status and journal: "
                               f"{recovery_error}") from exc
        if phase == "preparing":
            raise RuntimeError(f"Upgrade failed before replacement; previous service is active "
                               f"and HTTPS healthy. No new backup retained. Cause: {exc}") from exc
        raise RuntimeError(f"Upgrade failed; previous installation restored and HTTPS healthy. "
                           f"Backup: {snapshot}. Cause: {exc}") from exc


def activate(plan: dict[str, object]) -> None:
    verify_prometheus_ownership()
    if plan.get("managed_prometheus") and not prometheus_installed():
        raise RuntimeError("Prometheus ownership receipt is missing; recover the installation before continuing")
    address, port = str(plan["address"]), int(plan["port"])
    interface, firewall = str(plan["interface"]), str(plan["firewall"])
    if (interface, address) not in candidates(run("ip", "-j", "address", "show", "up",
                                                  capture=True).stdout):
        raise RuntimeError("The selected interface address is no longer active")
    if firewall_state() != firewall:
        raise RuntimeError("Firewall state changed since preflight; inspect it before retrying")
    run("systemctl", "daemon-reload")
    owned_rules: list[list[str]] = plan.setdefault("owned_firewall_rules", [])
    try:
        if firewall == "ufw":
            if firewall_state() != "ufw":
                raise RuntimeError("UFW is no longer active; inspect the firewall before retrying")
            for rule in firewall_rules(interface, address, port,
                                       int(plan.get("port_start", EXPORTER_START)),
                                       int(plan.get("port_end", EXPORTER_END)),
                                       int(plan.get("console_port_offset", CONSOLE_OFFSET))):
                result = run(*rule, capture=True, locale_c=True)
                if "Rule added" in result.stdout:
                    owned_rules.append(rule)
                    PENDING_PLAN.write_text(json.dumps(plan))
                elif "Skipping adding existing rule" not in result.stdout:
                    raise RuntimeError("Could not confirm UFW rule ownership; inspect firewall status")
        run("systemctl", "enable", "--now", UNIT_PATH.name)
        https_health(address, port)
        if plan.get("managed_prometheus"):
            start_prometheus()
            check_prometheus()
    except Exception as activation_error:
        if plan.get("managed_prometheus") and prometheus_installed():
            run("systemctl", "disable", "--now", PROM_UNIT_PATH.name, check=False, capture=True)
        run("systemctl", "disable", "--now", UNIT_PATH.name, check=False)
        for rule in list(reversed(owned_rules)):
            result = run("ufw", "--force", "delete", *rule[1:], check=False,
                         capture=True, locale_c=True)
            if result.returncode == 0:
                owned_rules.remove(rule)
        PENDING_PLAN.write_text(json.dumps(plan))
        if owned_rules:
            raise RuntimeError("HTTPS activation failed and some installer-added UFW rules remain; "
                               "run install.sh again after inspecting UFW") from activation_error
        raise
    PLAN_PATH.write_text(json.dumps(plan, indent=2) + "\n")
    PENDING_PLAN.unlink(missing_ok=True)


def service_unit(address: str, port: int, start: int = EXPORTER_START,
                 end: int = EXPORTER_END, offset: int = CONSOLE_OFFSET) -> str:
    command = (f"{APP_ROOT}/venv/bin/c880a-manager --data-dir {DATA_DIR} "
               f"--bind {address} --port {port} --exporter-bind {address} "
               f"--exporter-advertise-host {address} --console-bind {address} "
               f"--console-advertise-host {address} --manager-origin {origin(address, port)} "
               f"--port-start {start} --port-end {end} --console-port-offset {offset}")
    return ("[Unit]\nDescription=Cisco UCS C880A Manager\n"
            "Wants=network-online.target\nAfter=network-online.target\n\n"
            f"[Service]\nType=simple\nUser={SERVICE_USER}\nGroup={SERVICE_USER}\n"
            f"WorkingDirectory={APP_ROOT}/source\n"
            f"ExecStartPre={APP_ROOT}/venv/bin/python -m c880a_manager.wait_interface {address}\n"
            f"ExecStart={command}\nTimeoutStartSec=105\n"
            "Restart=on-failure\nRestartSec=3\nNoNewPrivileges=yes\n"
            "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"
            "AmbientCapabilities=CAP_NET_BIND_SERVICE\n"
            "ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n"
            f"ReadWritePaths={DATA_DIR}\nUMask=0077\n\n"
            "[Install]\nWantedBy=multi-user.target\n")


def https_health(address: str, port: int) -> None:
    last_error: Exception | None = None
    for _ in range(30):
        try:
            deployment = json.loads((DATA_DIR / "deployment.json").read_text())
            context = ssl.create_default_context(cafile=deployment["certificate"]["cert"])
            # Pin the active leaf even when an internal CA is not in the host trust store.
            context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
            connection = HTTPSConnection(address, port, context=context, timeout=2)
            try:
                connection.request("GET", "/api/bootstrap-required")
                response = connection.getresponse()
                if response.status == 200:
                    return
            finally:
                connection.close()
        except (OSError, ValueError, KeyError, ssl.SSLError) as exc:
            last_error = exc
        time.sleep(1)
    raise RuntimeError(f"Local HTTPS health check failed: {last_error}")


def public_certificate_path() -> str:
    deployment = json.loads((DATA_DIR / "deployment.json").read_text())
    return str(deployment["certificate"]["cert"])


def main() -> None:
    os.umask(0o077)
    repo = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else None
    if not repo or not (repo / "pyproject.toml").is_file():
        raise RuntimeError("Install from a complete repository checkout")
    ensure_platform()
    if recover_interrupted_upgrade():
        return
    if PENDING_PLAN.exists():
        if UNIT_PATH.exists() and DATA_DIR.exists():
            plan = json.loads(PENDING_PLAN.read_text())
            print(f"Resuming interrupted installation at {origin(str(plan['address']), int(plan['port']))}/")
            activate(plan)
            print(f"Manager is ready: {origin(str(plan['address']), int(plan['port']))}/")
            print(f"Public certificate: {public_certificate_path()}")
            if initial_credential_pending():
                print("Sign in as admin and change the initial password before using the manager.")
            else:
                print("Sign in with the existing administrator credential.")
            return
        discard_before_service()
    if APP_ROOT.exists() or UNIT_PATH.exists():
        upgrade_installation(repo)
        return
    available = candidates(run("ip", "-j", "address", "show", "up", capture=True).stdout)
    preserved = DATA_DIR.exists()
    if preserved:
        saved = preserved_deployment()
        address, port = str(saved["address"]), int(saved["port"])
        interfaces = [name for name, value in available if value == address]
        if len(interfaces) != 1:
            raise RuntimeError(f"Saved bind address {address} must be assigned to one active interface")
        interface = interfaces[0]
        print(f"Reinstall from preserved data: {origin(address, port)}/ · {interface}")
    else:
        default_interfaces = default_route_interfaces(run("ip", "-j", "route", "show", "default",
                                                         capture=True).stdout)
        interface, address = choose_address(available, default_interfaces)
        port = choose_port(address)
        saved = {"port_start": EXPORTER_START, "port_end": EXPORTER_END,
                 "console_port_offset": CONSOLE_OFFSET}
    start, end, offset = (int(saved[name]) for name in
                          ("port_start", "port_end", "console_port_offset"))
    groups = port_groups(port, start, end, offset)
    for label, group in groups:
        conflicts = occupied(address, group)
        if conflicts:
            raise RuntimeError(f"{label} ports are occupied on {address}: {conflicts[:8]}")
    if not preserved:
        print(f"\nInstall: {origin(address, port)}/ · {interface}")
    print(f"Exporters: {start}–{end}/tcp · Consoles: "
          f"{start + offset}–{end + offset}/tcp")
    firewall = firewall_state()
    if firewall == "ufw":
        print("Firewall rules to add:")
        for rule in firewall_rules(interface, address, port, start, end, offset):
            print("  " + " ".join(rule))
    else:
        print("Firewall: no active supported firewall detected")
    print("Service: enable c880a-manager at boot; run as an unprivileged user")
    if (repo / "src/c880a_manager/prometheus_runtime.py").is_file():
        prometheus_preflight(repo=repo)
    if input(("Reinstall and reuse preserved data?" if preserved else "Install with these settings?")
             + " [y/N]: ").strip().lower() != "y":
        print("Installation canceled.")
        return
    progress(1, 4, "Checking Python environment")
    ensure_venv()
    progress(2, 4, "Installing manager and Python packages")
    plan = {"interface": interface, "address": address, "port": port, "firewall": firewall,
            "preserve_existing_data": preserved, "port_start": start,
            "port_end": end, "console_port_offset": offset}
    try:
        prepare_installation(repo, plan)
        candidate_unit = UNIT_PATH.with_suffix(".service.pending")
        candidate_unit.write_text(service_unit(address, port, start, end, offset))
        candidate_unit.replace(UNIT_PATH)
    except Exception:
        UNIT_PATH.with_suffix(".service.pending").unlink(missing_ok=True)
        if PENDING_PLAN.exists() and not UNIT_PATH.exists():
            discard_before_service()
        raise
    progress(3, 4, "Starting HTTPS service")
    activate(plan)
    progress(4, 4, "Installation complete")
    print(f"\nManager is ready: {origin(address, port)}/")
    print(f"Public certificate: {public_certificate_path()}")
    if preserved:
        print("Existing users, server data, and HTTPS certificate were retained.")
    else:
        print("The browser will warn until you trust the generated certificate.")
        print("Initial sign-in: admin / admin. Change the password before using the manager.")
    print("Test this URL from your browser host; if unreachable, check the selected IP, route/NAT forwarding, and firewall.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"Installation failed: {exc}", file=sys.stderr)
        if PENDING_PLAN.exists():
            print("Run install.sh again to resume this installation after resolving the error.", file=sys.stderr)
        raise SystemExit(1)
