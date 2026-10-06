"""Unprivileged managed Prometheus activation with a narrow systemd boundary.

The installer grants only exact operations on the product-owned unit. Settings
never become shell arguments or root commands. Internal APIs require mutual TLS;
browser sessions and destructive-API policy remain the manager's responsibility.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import fcntl
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import time
import uuid

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .deployment import atomic_config, read_config, write_private
from .prometheus import DEFAULTS, config_bytes, scrape_config, validate_settings


UNIT = "c880a-prometheus.service"
_ID = re.compile(r"[0-9a-f]{32}\Z")
_UNIT = re.compile(r"c880a-(?:[a-z0-9]+-)*prometheus\.service\Z")


def unit_name(value: str) -> str:
    if not isinstance(value, str) or not _UNIT.fullmatch(value):
        raise ValueError("Invalid product Prometheus unit")
    return value


def startup_marker(path: Path, enabled: bool) -> None:
    """Persist intent for systemd's boot condition without unit-file privileges."""
    if path.is_symlink():
        raise PrometheusError("Prometheus startup marker is unsafe; repair the installation")
    if enabled:
        atomic_config(path.parent, path.name, {"enabled": True})
    else:
        path.unlink(missing_ok=True)
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class PrometheusError(RuntimeError):
    """An actionable, credential-free operator error."""


class Systemd:
    def __init__(self, marker: Path, *, unit: str = UNIT):
        self.marker = marker
        self.unit = unit_name(unit)

    def set_enabled(self, enabled: bool) -> None:
        startup_marker(self.marker, enabled)
        # Polkit authorizes only start/stop/restart of the installed unit. This
        # works with NoNewPrivileges; no setuid helper or password agent is used.
        command = ["/usr/bin/systemctl", "--no-ask-password",
                   "start" if enabled else "stop", self.unit]
        try:
            subprocess.run(command, check=True, capture_output=True, timeout=90)
        except (OSError, subprocess.SubprocessError):
            raise PrometheusError("Could not change Prometheus service state; repair the installation and retry") from None

    def restart(self) -> None:
        try:
            subprocess.run(["/usr/bin/systemctl", "--no-ask-password", "restart", self.unit],
                           check=True, capture_output=True, timeout=90)
        except (OSError, subprocess.SubprocessError):
            raise PrometheusError("Could not restart Prometheus; check its service and retry") from None

    def active(self) -> bool:
        try:
            result = subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", self.unit],
                                    capture_output=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            raise PrometheusError("Prometheus service state is unavailable; check the installation") from None
        if result.returncode not in (0, 3):
            raise PrometheusError("Prometheus service state is unavailable; check the installation")
        return result.returncode == 0


def _client_material(directory: Path) -> None:
    """Create a private service identity without changing any host trust store."""
    now = datetime.now(timezone.utc)
    authority_key = ec.generate_private_key(ec.SECP256R1())
    client_key = ec.generate_private_key(ec.SECP256R1())
    authority_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "C880A private service CA")])
    authority = (x509.CertificateBuilder().subject_name(authority_name).issuer_name(authority_name)
                 .public_key(authority_key.public_key()).serial_number(x509.random_serial_number())
                 .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=3650))
                 .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                 .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                             key_encipherment=False, data_encipherment=False,
                                             key_agreement=False, key_cert_sign=True, crl_sign=True,
                                             encipher_only=False, decipher_only=False), critical=True)
                 .sign(authority_key, hashes.SHA256()))
    client_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "C880A managed Prometheus client")])
    client = (x509.CertificateBuilder().subject_name(client_name).issuer_name(authority.subject)
              .public_key(client_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=3650))
              .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
              .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
              .sign(authority_key, hashes.SHA256()))
    write_private(directory / "client-ca.pem", authority.public_bytes(serialization.Encoding.PEM))
    write_private(directory / "client.pem", client.public_bytes(serialization.Encoding.PEM))
    write_private(directory / "client.key", client_key.private_bytes(serialization.Encoding.PEM,
                  serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    # The authority private key is never persisted. Each activation rotates this
    # internal identity; the product's browser-facing server certificate is kept.


class ManagedPrometheus:
    def __init__(self, data_dir: Path, *, control: Systemd | None = None):
        self.data_dir = data_dir.resolve()
        self.root = self.data_dir / "prometheus"
        self._control = control

    @property
    def control(self):
        if self._control is None:
            self._control = Systemd(self.root / "enabled", unit=self.installation().get("unit", UNIT))
        return self._control

    def installation(self) -> dict:
        value = read_config(self.root, name="installation.json")
        if not value:
            raise PrometheusError("Prometheus runtime is unavailable; re-run the installer")
        if (not {"runtime_dir", "port"} <= set(value) <= {"runtime_dir", "port", "unit"} or
                type(value["port"]) is not int or not 1024 <= value["port"] <= 65535 or
                not isinstance(value["runtime_dir"], str) or not Path(value["runtime_dir"]).is_absolute()):
            raise PrometheusError("Prometheus installation settings are invalid; re-run the installer")
        try:
            unit_name(value.get("unit", UNIT))
        except ValueError:
            raise PrometheusError("Prometheus installation unit is invalid; re-run the installer") from None
        return value

    def active(self) -> dict:
        return read_config(self.root, name="active.json")

    def settings(self) -> dict:
        pending = read_config(self.root, name="pending.json")
        # A validated generation can be provisionally active during its health
        # check. Public settings remain the previous applied values until the
        # transaction journal is cleared; status can expose desired values
        # separately without claiming successful application.
        if pending:
            return pending["previous"]["settings"]
        return self.active().get("settings", dict(DEFAULTS))

    def generation(self, value: dict | None = None) -> Path:
        identifier = (value or self.active()).get("generation", "")
        if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
            raise PrometheusError("Prometheus configuration is unavailable; re-run the installer")
        path = self.root / "generations" / identifier
        if path.is_symlink() or not path.is_dir():
            raise PrometheusError("Prometheus configuration is unavailable; re-run the installer")
        return path

    def prepare(self, settings: dict, *, deployment: dict | None = None) -> dict:
        installation = self.installation()
        settings = validate_settings(settings)
        deployment = deployment or read_config(self.data_dir)
        if not deployment:
            raise PrometheusError("Manager HTTPS configuration is not ready")
        identifier = uuid.uuid4().hex
        directory = self.root / "generations" / identifier
        directory.mkdir(parents=True, mode=0o700)
        try:
            _client_material(directory)
            scrape = scrape_config(settings, deployment, self.data_dir,
                                   internal_port=installation["port"], client_dir=directory)
            write_private(directory / "scrape.json", config_bytes(scrape))
            web = {"tls_server_config": {"cert_file": deployment["certificate"]["cert"],
                                        "key_file": deployment["certificate"]["key"],
                                        "client_auth_type": "RequireAndVerifyClientCert",
                                        "client_ca_file": str(directory / "client-ca.pem"),
                                        "min_version": "TLS13"}}
            write_private(directory / "web.json", config_bytes(web))
            for command, name in (("config", "scrape.json"), ("web-config", "web.json")):
                try:
                    subprocess.run([str(Path(installation["runtime_dir"]) / "promtool"),
                                    "check", command, str(directory / name)],
                                   check=True, capture_output=True, timeout=30)
                except (OSError, subprocess.SubprocessError):
                    raise PrometheusError("Prometheus configuration validation failed; previous settings retained") from None
            return {"generation": identifier, "settings": settings,
                    "deployment": deployment, "prepared_at": time.time()}
        except BaseException:
            shutil.rmtree(directory)
            raise

    def initialise(self) -> None:
        self.installation()
        if not self.active():
            atomic_config(self.root, "active.json", self.prepare(dict(DEFAULTS)))
        (self.root / "tsdb").mkdir(mode=0o700, exist_ok=True)
        if not read_config(self.root, name="pending.json"):
            startup_marker(self.root / "enabled", self.settings()["enabled"])

    def _client_options(self, value: dict | None, timeout) -> dict:
        active = value or self.active()
        directory = self.generation(active)
        context = ssl.create_default_context(cafile=active["deployment"]["certificate"]["cert"])
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        context.load_cert_chain(directory / "client.pem", directory / "client.key")
        return dict(base_url=f"https://127.0.0.1:{self.installation()['port']}/prometheus/",
                    verify=context, timeout=timeout, trust_env=False,
                    follow_redirects=False)

    def client(self, value: dict | None = None, *, timeout: float = 15) -> httpx.Client:
        return httpx.Client(**self._client_options(value, timeout))

    def async_client(self, value: dict | None = None, *, timeout=15) -> httpx.AsyncClient:
        return httpx.AsyncClient(**self._client_options(value, timeout))

    def request(self, method: str, path: str, *, value: dict | None = None,
                params=None) -> httpx.Response:
        active = value or self.active()
        if path.startswith("/") or ".." in path or ":" in path:
            raise ValueError("Internal Prometheus path must be relative")
        with self.client(active) as client:
            return client.request(method, path, params=params,
                                  extensions={"sni_hostname": active["deployment"]["manager_host"]})

    def ready(self, value: dict | None = None) -> bool:
        try:
            return self.request("GET", "-/ready", value=value).status_code == 200
        except (PrometheusError, OSError, ValueError, httpx.HTTPError):
            return False

    def wait_ready(self, value: dict, *, seconds: float = 30) -> bool:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                if self.control.active() and self.ready(value):
                    return True
            except PrometheusError:
                pass
            time.sleep(0.25)
        return False

    def _result(self, identifier: str, status: str, reason: str = "") -> None:
        pending = read_config(self.root, name="pending.json")
        requested = pending.get("requested_settings") or pending.get("candidate", {}).get("settings")
        atomic_config(self.root, "last.json", {"id": identifier, "status": status,
                                               "reason": reason, "at": time.time(),
                                               "requested_settings": requested})

    def change(self, settings: dict, *, operation_id: str | None = None) -> dict:
        """Synchronous private transaction; HTTP callers run it off the event loop."""
        self.installation()
        lock = os.open(self.root / "operation.lock", os.O_CREAT | os.O_RDWR |
                       getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise PrometheusError("Another Prometheus operation is in progress") from None
            self.initialise()
            if read_config(self.root, name="pending.json"):
                raise PrometheusError("An earlier Prometheus change is unconfirmed; check service recovery")
            identifier = operation_id or uuid.uuid4().hex
            if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
                raise ValueError("Invalid Prometheus operation identity")
            last = read_config(self.root, name="last.json")
            if last.get("id") == identifier:
                if settings != last.get("requested_settings"):
                    raise PrometheusError("Prometheus operation identity was already used; refresh its status")
                return last
            previous = self.active()
            # Persist identity before potentially slow validation so a lost
            # HTTP response can be resolved by checking operation status.
            atomic_config(self.root, "pending.json", {"id": identifier, "previous": previous,
                                                       "requested_settings": settings})
            self._result(identifier, "preparing")
            # Disable must work even when certificate/tool validation is broken.
            try:
                size = sum(p.stat().st_size for p in (self.root / "tsdb").rglob("*") if p.is_file())
                settings = validate_settings(settings, data_dir=self.root, existing_bytes=size,
                                             previous=previous["settings"])
                candidate = (self.prepare(settings) if settings["enabled"] else
                             {**previous, "settings": settings})
            except Exception:
                self._result(identifier, "rejected", "Configuration validation failed. Previous settings retained.")
                (self.root / "pending.json").unlink(missing_ok=True)
                raise
            atomic_config(self.root, "pending.json", {"id": identifier, "previous": previous,
                                                       "candidate": candidate})
            self._result(identifier, "applying")
            try:
                # Stop before switching immutable generations; restart reads the
                # active pointer only, never an unaccepted settings request.
                self.control.set_enabled(False)
                atomic_config(self.root, "active.json", candidate)
                if settings["enabled"]:
                    self.control.set_enabled(True)
                    if not self.wait_ready(candidate):
                        raise PrometheusError("Prometheus did not become ready")
                elif self.control.active():
                    raise PrometheusError("Prometheus did not stop")
                self._result(identifier, "applied")
            except Exception:
                try:
                    self.control.set_enabled(False)
                    atomic_config(self.root, "active.json", previous)
                    self.control.set_enabled(previous["settings"]["enabled"])
                    if previous["settings"]["enabled"]:
                        if not self.wait_ready(previous):
                            raise PrometheusError("Previous Prometheus service did not become ready")
                    elif self.control.active():
                        raise PrometheusError("Previous disabled state could not be confirmed")
                    self._result(identifier, "reverted", "Could not apply changes. Previous settings restored.")
                except Exception:
                    self._result(identifier, "unconfirmed", "Change not confirmed. Check the service before retrying.")
                    raise PrometheusError("Prometheus recovery is unconfirmed; check the service before retrying") from None
            (self.root / "pending.json").unlink(missing_ok=True)
            return read_config(self.root, name="last.json")
        finally:
            os.close(lock)

    def recover(self) -> None:
        """Recover an interrupted activation before accepting another change."""
        if not self.root.exists():
            return
        lock = os.open(self.root / "operation.lock", os.O_CREAT | os.O_RDWR |
                       getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise PrometheusError("Another Prometheus operation is in progress") from None
            pending = read_config(self.root, name="pending.json")
            if not pending:
                return
            previous = pending["previous"]
            try:
                self.control.set_enabled(False)
                atomic_config(self.root, "active.json", previous)
                self.control.set_enabled(previous["settings"]["enabled"])
                if previous["settings"]["enabled"]:
                    if not self.wait_ready(previous):
                        raise PrometheusError("Previous Prometheus service did not become ready")
                elif self.control.active():
                    raise PrometheusError("Previous disabled state could not be confirmed")
                self._result(pending["id"], "reverted", "Interrupted change. Previous settings restored.")
                (self.root / "pending.json").unlink()
            except Exception:
                self._result(pending["id"], "unconfirmed", "Recovery not confirmed. Check the service before retrying.")
                raise PrometheusError("Prometheus recovery is unconfirmed; check the service before retrying") from None
        finally:
            os.close(lock)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the private managed Prometheus service")
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--initialise", action="store_true", help="Prepare and verify installed service state")
    modes.add_argument("--check", action="store_true", help="Verify applied service state without changing it")
    parser.add_argument("--unit", default=UNIT)
    args = parser.parse_args()
    os.umask(0o077)
    managed = ManagedPrometheus(args.data_dir)
    if args.initialise:
        unit_name(args.unit)
        managed.root.mkdir(mode=0o700, exist_ok=True)
        if read_config(managed.root, name="pending.json"):
            raise PrometheusError("A Prometheus operation is pending; recover it before installing")
        if (managed.root / "installation.json").exists():
            installation = managed.installation()
            port = installation["port"]
        else:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
        atomic_config(managed.root, "installation.json", {"runtime_dir": str(args.runtime_dir.resolve()),
                                                         "port": port, "unit": args.unit})
        existed = bool(managed.active())
        managed.initialise()
        if existed and managed.settings()["enabled"]:
            atomic_config(managed.root, "active.json", managed.prepare(managed.settings()))
        managed.control.set_enabled(managed.settings()["enabled"])
        if managed.settings()["enabled"]:
            if not managed.wait_ready(managed.active()):
                raise PrometheusError("Installed Prometheus did not become ready; inspect its service")
        elif managed.control.active():
            raise PrometheusError("Disabled Prometheus remains active; inspect its service")
        return
    if args.check:
        if read_config(managed.root, name="pending.json"):
            raise PrometheusError("Prometheus change is unconfirmed; recover it before checking readiness")
        enabled = managed.settings()["enabled"]
        if enabled:
            if not managed.control.active() or not managed.ready():
                raise PrometheusError("Prometheus is unavailable; inspect its service")
        elif managed.control.active():
            raise PrometheusError("Disabled Prometheus remains active; inspect its service")
        return
    value = managed.active()
    settings = validate_settings(value["settings"])
    if not settings["enabled"]:
        return
    directory = managed.generation(value)
    deployment = value["deployment"]
    executable = args.runtime_dir / "prometheus"
    # Fixed installed executable, structured arguments, no shell/environment
    # interpolation. The entire service runs as the dedicated non-root user.
    os.execv(executable, [str(executable), f"--config.file={directory / 'scrape.json'}",
             f"--web.config.file={directory / 'web.json'}",
             f"--web.listen-address=127.0.0.1:{managed.installation()['port']}",
             f"--web.external-url={deployment['manager_origin'].rstrip('/')}/prometheus/",
             "--web.route-prefix=/prometheus", "--web.enable-admin-api",
             "--query.timeout=15s", "--query.max-concurrency=8",
             f"--storage.tsdb.path={managed.root / 'tsdb'}",
             f"--storage.tsdb.retention.time={settings['retention_hours']}h",
             f"--storage.tsdb.retention.size={settings['storage_gib']}GB",
             "--log.level=warn"])


if __name__ == "__main__":
    main()
