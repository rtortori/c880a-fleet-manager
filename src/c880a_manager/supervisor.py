"""Small parent process supervising one manager worker and its exporter group."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time
import socket
import ssl
import sqlite3
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .deployment import read_config, atomic_config, local_addresses, url_host
from .restore import (apply_staged_restore, finish_restore, mark_restore_health_check,
                      recover_interrupted_restore)
from .restore_history import recover_file_restore, confirm_file_restore, fail_file_restore_health
from .prometheus_deployment import (JOURNAL as DEPLOYMENT_JOURNAL, begin_deployment,
                                   recover_deployment, confirm_deployment, recovery_unconfirmed)
from .prometheus_service import ManagedPrometheus, PrometheusError


def _recover_missing_interface(data_dir: Path) -> bool:
    if (data_dir / "deployment.pending.json").exists() or (data_dir / DEPLOYMENT_JOURNAL).exists():
        return False
    active = read_config(data_dir)
    available = set(local_addresses())
    if not active or all(active.get(field) in available for field in
                         ("manager_bind", "exporter_bind", "console_bind")):
        return False
    previous = read_config(data_dir, name="deployment.previous.json")
    recovery = read_config(data_dir, name="deployment.recovery.json")
    candidate = next((item for item in (previous, recovery) if item and all(
        item.get(field) in available for field in
        ("manager_bind", "exporter_bind", "console_bind"))), None)
    if candidate is None:
        return False
    if (data_dir / "prometheus" / "installation.json").exists():
        atomic_config(data_dir, "deployment.pending.json", candidate)
        return True
    atomic_config(data_dir, "deployment.json", candidate)
    atomic_config(data_dir, "deployment.last.json", {"status": "reverted", "at": time.time(),
                                                      "reason": "Selected local interface disappeared"})
    return True


def _probe_https(bind: str, port: int, advertised: str, fingerprint: str,
                 path: str) -> bool:
    with socket.create_connection((bind, port), timeout=1) as raw:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(raw, server_hostname=advertised) as connection:
            leaf = x509.load_der_x509_certificate(connection.getpeercert(binary_form=True))
            if leaf.fingerprint(hashes.SHA256()).hex() != fingerprint:
                return False
            connection.sendall(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
            return b" 200 " in connection.recv(512).split(b"\r\n", 1)[0]


def _active_exporter_ports(data_dir: Path) -> list[int]:
    database = data_dir / "manager.db"
    if not database.exists():
        return []
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        return [int(row[0]) for row in connection.execute("SELECT port FROM servers WHERE state='active'")]


def _probe_deployment(data_dir: Path, deployment: dict) -> bool:
    fingerprint = deployment["certificate"]["fingerprint"]
    if not _probe_https(deployment["manager_bind"], deployment["manager_port"],
                        deployment["manager_host"], fingerprint, "/api/bootstrap-required"):
        return False
    return all(_probe_https(deployment["exporter_bind"], port,
                            deployment["exporter_host"], fingerprint, "/healthz")
               for port in _active_exporter_ports(data_dir))


def _probe_file_restore(data_dir: Path, candidate: dict) -> bool:
    if not _probe_deployment(data_dir, candidate["deployment"]):
        return False
    if not candidate["managed"]:
        return True
    managed = ManagedPrometheus(data_dir)
    if not managed.settings()["enabled"]:
        return not managed.control.active()
    if not managed.control.active() or not managed.ready():
        return False
    # Scrape health and BMC collection success are not restore health gates.
    # The discovered stable identities must match the restored active claims.
    response = managed.request("GET", "api/v1/targets")
    if response.status_code != 200:
        return False
    targets = response.json()["data"]["activeTargets"]
    fleet_targets = [target for target in targets if target["labels"].get("job") == "c880a"]
    with sqlite3.connect(f"file:{data_dir / 'manager.db'}?mode=ro", uri=True) as db:
        expected = {row[0]:f"https://{url_host(candidate['deployment']['exporter_host'])}:{row[1]}/metrics"
                    for row in db.execute("SELECT id,port FROM servers WHERE state='active'")}
    actual = {target["labels"].get("server_id"):target["scrapeUrl"] for target in fleet_targets}
    return len(fleet_targets) == len(expected) and actual == expected


def _probe_deployment_activation(data_dir, candidate):
    if not _probe_file_restore(data_dir, candidate):
        return False
    managed = ManagedPrometheus(data_dir)
    if not managed.settings()["enabled"]:
        return True
    targets = managed.request("GET", "api/v1/targets").json()["data"]["activeTargets"]
    # Certificate activation verifies actual scraping, separately from cached
    # BMC acquisition/freshness. Never use c880a_target_up as a TLS health gate.
    return all(target.get("health") == "up" for target in targets)


RESTART_FD_ENV = "C880A_RESTART_FD"


def _terminate_group(process: subprocess.Popen[bytes], *, grace: float = 10) -> None:
    """Stop the web worker gracefully, then reap any surviving child processes."""
    if process.poll() is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    # Each worker starts a new session. Exporters and console gateways inherit
    # its process group, so a worker crash cannot leave ports occupied.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.killpg(process.pid, 0)
        except (ProcessLookupError, PermissionError):
            return
        time.sleep(0.1)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def serve(argv: list[str], data_dir: Path) -> None:
    resolved = data_dir.resolve()
    if resolved in (Path("/"), Path.home().resolve()):
        raise ValueError("Data directory must not be the filesystem root or home directory")
    resolved.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(resolved, 0o700)
    lock_fd = os.open(resolved / "manager.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("A manager supervisor already owns this data directory") from exc
        stopping = False

        def stop(_signum: int, _frame: object) -> None:
            nonlocal stopping
            stopping = True

        previous_term = signal.signal(signal.SIGTERM, stop)
        previous_int = signal.signal(signal.SIGINT, stop)
        try:
            restore_record = read_config(resolved, name="restore.transaction.json") or read_config(resolved, name="restore.pending.json")
            if restore_record.get("format") != 4:
                recover_interrupted_restore(resolved)
            failures = 0
            restore_candidate: dict | None = None
            deployment_candidate: dict | None = None
            while not stopping:
                # Admission is checked on every launch, including a worker or
                # supervisor crash. A lost pipe key never permits replay.
                restore_record = read_config(resolved, name="restore.transaction.json") or read_config(resolved, name="restore.pending.json")
                if restore_record.get("format") == 4 and restore_candidate is None:
                    try:
                        restore_candidate = recover_file_restore(resolved)
                    except Exception:
                        time.sleep(5)
                        continue  # Never launch an uncertain candidate.
                _recover_missing_interface(resolved)
                pending = read_config(resolved, pending=True)
                managed = ManagedPrometheus(resolved)
                if deployment_candidate is None and (resolved / DEPLOYMENT_JOURNAL).exists():
                    try:
                        deployment_candidate = recover_deployment(managed)
                    except Exception:
                        time.sleep(5)
                        continue
                    pending = read_config(resolved, pending=True)
                elif pending and deployment_candidate is None and (managed.root / "installation.json").exists():
                    try:
                        deployment_candidate = begin_deployment(managed, pending)
                    except Exception:
                        try:
                            deployment_candidate = recover_deployment(managed)
                        except Exception:
                            time.sleep(5)
                            continue
                    pending = read_config(resolved, pending=True)
                read_fd, write_fd = os.pipe()
                environment = os.environ.copy()
                environment[RESTART_FD_ENV] = str(write_fd)
                try:
                    process = subprocess.Popen(
                        [sys.executable, "-m", "c880a_manager.manager", "--worker", *argv],
                        env=environment, pass_fds=(write_fd,), close_fds=True,
                        start_new_session=True,
                    )
                except BaseException:
                    os.close(read_fd)
                    raise
                finally:
                    os.close(write_fd)
                started = time.monotonic()
                last_interface_check = started
                requested = False
                restore_key: bytes | None = None
                try:
                    if restore_candidate:
                        native_restore = restore_candidate.get("format") == 4
                        if not native_restore:
                            mark_restore_health_check(resolved, restore_candidate["id"])
                        ready = False
                        deadline_seconds = 90 if native_restore else 30
                        while not stopping and process.poll() is None and time.monotonic() - started < deadline_seconds:
                            try:
                                ready = (_probe_file_restore(resolved, restore_candidate) if native_restore else
                                         _probe_deployment(resolved, restore_candidate["deployment"]))
                                if ready:
                                    break
                            except (OSError, ssl.SSLError, sqlite3.Error, ValueError, KeyError, PrometheusError, httpx.HTTPError):
                                pass
                            time.sleep(0.2)
                        if ready:
                            if native_restore:
                                confirm_file_restore(resolved, restore_candidate["id"],
                                                     applied=not restore_candidate["recovering"])
                            else:
                                finish_restore(resolved, restore_candidate["id"], applied=True)
                            restore_candidate = None
                        else:
                            _terminate_group(process)
                            if native_restore:
                                if restore_candidate["recovering"]:
                                    fail_file_restore_health(resolved, restore_candidate["id"])
                                    restore_candidate = None
                                    time.sleep(5)
                                else:
                                    try:
                                        restore_candidate = recover_file_restore(resolved,
                                            reason="Restored manager, exporters or Prometheus activation did not become healthy")
                                    except Exception:
                                        restore_candidate = None
                            else:
                                finish_restore(resolved, restore_candidate["id"], applied=False,
                                               reason="Restored HTTPS manager or exporters did not become healthy")
                                restore_candidate = None
                            continue
                    if deployment_candidate:
                        ready = False
                        settings = managed.settings()
                        activation_timeout = max(90, settings["scrape_interval"] + settings["scrape_timeout"] + 20)
                        while not stopping and process.poll() is None and time.monotonic() - started < activation_timeout:
                            try:
                                ready = _probe_deployment_activation(resolved, deployment_candidate)
                                if ready:
                                    break
                            except (OSError, ssl.SSLError, sqlite3.Error, ValueError, KeyError,
                                    PrometheusError, httpx.HTTPError):
                                pass
                            time.sleep(.2)
                        if ready:
                            confirm_deployment(managed, deployment_candidate["id"],
                                               applied=not deployment_candidate["recovering"])
                            deployment_candidate = None
                            pending = {}
                        else:
                            _terminate_group(process)
                            if deployment_candidate["recovering"]:
                                recovery_unconfirmed(managed)
                                deployment_candidate = None
                                time.sleep(5)
                            else:
                                try:
                                    deployment_candidate = recover_deployment(managed)
                                except Exception:
                                    deployment_candidate = None
                            continue
                    if pending:
                        # Probe the exact local listener and leaf fingerprint.
                        # A browser's DNS path is independent of this restart
                        # health check; external scrape checks remain separate.
                        ready = False
                        while not stopping and process.poll() is None and time.monotonic() - started < 30:
                            try:
                                ready = _probe_deployment(resolved, pending)
                                if ready:
                                    break
                            except (OSError, ssl.SSLError, sqlite3.Error, ValueError, KeyError):
                                time.sleep(0.2)
                        if ready:
                            atomic_config(resolved, "deployment.previous.json", read_config(resolved))
                            recovery = read_config(resolved, name="deployment.recovery.json")
                            if recovery:
                                for field in ("manager_port", "port_start", "port_end",
                                              "console_port_offset", "bmc_ca"):
                                    recovery[field] = pending.get(field)
                                recovery["manager_origin"] = f"https://localhost:{pending['manager_port']}"
                                atomic_config(resolved, "deployment.recovery.json", recovery)
                            atomic_config(resolved, "deployment.json", pending)
                            (resolved / "deployment.pending.json").unlink(missing_ok=True)
                            atomic_config(resolved, "deployment.last.json", {"status": "applied", "at": time.time()})
                        else:
                            (resolved / "deployment.pending.json").unlink(missing_ok=True)
                            atomic_config(resolved, "deployment.last.json", {"status": "reverted", "at": time.time(),
                                                                               "reason": "Proposed HTTPS listener did not become healthy"})
                            _terminate_group(process)
                            continue
                    while not stopping and process.poll() is None:
                        readable, _, _ = select.select([read_fd], [], [], 0.2)
                        if readable:
                            message = os.read(read_fd, 33)
                            if message == b"R" or (len(message) == 33 and message.startswith(b"B")):
                                requested = True
                                restore_key = message[1:] if message.startswith(b"B") else None
                                # Let the HTTP response flush before stopping the worker.
                                time.sleep(0.5)
                                break
                        if not pending and time.monotonic() - last_interface_check >= 5:
                            last_interface_check = time.monotonic()
                            if _recover_missing_interface(resolved):
                                requested = True
                                break
                finally:
                    os.close(read_fd)
                    _terminate_group(process)
                if stopping:
                    break
                if restore_key:
                    try:
                        restore_candidate = apply_staged_restore(resolved, restore_key)
                    except Exception:
                        record = read_config(resolved, name="restore.transaction.json") or read_config(resolved, name="restore.pending.json")
                        if record.get("format") == 4:
                            try:
                                restore_candidate = recover_file_restore(resolved,
                                    reason="Restore validation or application failed before activation health check")
                            except Exception:
                                restore_candidate = None
                        else:
                            recover_interrupted_restore(resolved,
                                reason="Restore validation or application failed before HTTPS health check")
                            restore_candidate = None
                    failures = 0
                    continue
                if requested or time.monotonic() - started >= 30:
                    failures = 0
                else:
                    failures += 1
                    # Prevent a corrupt installation from spinning indefinitely.
                    time.sleep(min(30, 2 ** min(failures, 5)))
        finally:
            signal.signal(signal.SIGTERM, previous_term)
            signal.signal(signal.SIGINT, previous_int)
    finally:
        os.close(lock_fd)
