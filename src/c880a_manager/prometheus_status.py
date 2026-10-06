"""Public observations distinguish service readiness from exporter acquisition."""

import json
import fcntl
import os
import re
import stat
import threading
import time

from fastapi import HTTPException

from .deployment import read_config
from .prometheus_service import PrometheusError
from .prometheus_web import engine_response


def _cleanup_busy(root) -> bool:
    """Observe an existing lock without creating or changing recovery state."""
    descriptor = None
    try:
        descriptor = os.open(root / "operation.lock", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            return False
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False
    except OSError:
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)


class DiscoveryObservation:
    def __init__(self):
        self.boot_at = time.time()
        self.lock = threading.Lock()
        self.generation = None
        self.at = None
        self.expected_signature = None
        self.expected_changed_at = self.boot_at

    def record(self, managed, supplied: str) -> None:
        if not supplied:
            return
        try:
            active = managed.active()
        except (OSError, ValueError, TypeError):
            return
        if supplied != active.get("generation"):
            return
        with self.lock:
            self.generation, self.at = supplied, time.time()

    def status(self, managed, *, claimed: list, origin: str, cleanup_operation: dict | None = None) -> dict:
        now = time.time()
        result = {"enabled": None, "state": "unavailable", "discovery_state": "unavailable",
                  "claimed_exporters": len(claimed), "discovered_exporters": None,
                  "successful_scrapes": None, "checked_at": now,
                  "last_discovery_at": None, "url": origin.rstrip("/") + "/prometheus/",
                  "settings": None, "operation": None, "recovery_required": False}
        try:
            managed.installation()
            settings = managed.settings()
            active = managed.active()
            deletion = read_config(managed.root, name="delete.pending.json") or cleanup_operation
            pending = read_config(managed.root, name="pending.json")
            last = read_config(managed.root, name="last.json")
            result.update(enabled=settings["enabled"], settings=settings,
                          operation={key: last.get(key) for key in ("id", "status", "reason", "at")} if last else None)
            if deletion:
                identifier = deletion.get("id")
                if not isinstance(identifier, str) or not re.fullmatch(r"[0-9a-f]{32}", identifier):
                    return result
                busy = _cleanup_busy(managed.root)
                state = "applying" if busy else "unconfirmed"
                reason = ("Deleting target history" if busy else
                          "Target unclaimed. Prometheus history cleanup is pending.")
                result.update(state=state, recovery_required=not busy,
                              operation={"id":identifier, "status":state, "reason":reason,
                                         "at":last.get("at") if last.get("id") == identifier else deletion.get("at")})
                return result
            if pending:
                result["state"] = "unconfirmed" if last.get("status") == "unconfirmed" else "applying"
                result["recovery_required"] = last.get("status") == "unconfirmed"
                return result
            if not settings["enabled"]:
                if not managed.control.active():
                    result.update(state="disabled", discovery_state="disabled")
                return result
            if not managed.ready():
                return result
            result["state"] = "running"
            expected = {item["id"] for item in claimed}
            with self.lock:
                at = self.at if self.generation == active.get("generation") else None
                signature = (active.get("generation"), frozenset(expected))
                if signature != self.expected_signature:
                    self.expected_signature, self.expected_changed_at = signature, now
                expected_changed_at = self.expected_changed_at
            result["last_discovery_at"] = at
            if at is None:
                start = max(self.boot_at, float(active.get("prepared_at", self.boot_at)))
                result["discovery_state"] = "waiting" if now - start <= 45 else "unavailable"
                return result
            if not 0 <= now - at <= 45:
                return result
            response = engine_response(managed, "api/v1/targets", "GET", "state=active")
            if response.status_code != 200:
                return result
            payload = json.loads(response.body)
            if payload["status"] != "success":
                return result
            targets = [item for item in payload["data"]["activeTargets"] if item["labels"].get("job") == "c880a"]
            ids = [item["labels"].get("server_id") for item in targets]
            if len(set(ids)) != len(ids) or any(not isinstance(identity, str) or not identity for identity in ids):
                return result
            # A successful SD HTTP response can precede application of its
            # target set in the engine. Keep counts unknown until they agree.
            if set(ids) != expected:
                result.update(discovery_state="waiting" if now - expected_changed_at <= 45 else "incomplete",
                              discovered_exporters=len(targets),
                              successful_scrapes=sum(item.get("health") == "up" for item in targets))
                return result
            result.update(discovery_state="ready", discovered_exporters=len(targets),
                          successful_scrapes=sum(item.get("health") == "up" for item in targets))
        except (PrometheusError, HTTPException, ValueError, TypeError, KeyError, OSError):
            # No native diagnostic, configuration path, credential or TLS
            # material belongs in the public status response.
            pass
        return result
