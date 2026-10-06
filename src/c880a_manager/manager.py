"""HTTPS-only fleet manager and supervised independent exporters."""

from __future__ import annotations

import argparse
import asyncio
from concurrent.futures import Future, TimeoutError as FutureTimeoutError
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hmac
import hashlib
from http.client import HTTPResponse
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Literal
import uuid
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
import uvicorn
from starlette.datastructures import UploadFile
from starlette.background import BackgroundTask

from .redfish import RedfishAuthenticationError, RedfishClient, RedfishError, RedfishTimeoutError
from .redfish_budget import SharedGetBudget
from .redfish_actions import POWER_ACTIONS, discover_actions
from .inventory import collect_inventory, inventory_retry_sources
from .event_stream import event_records, frames
from .metric_history import MAX_SNAPSHOT_BYTES, MetricHistory
from .resource_status import ResourceSampler
from .storage import Store, _private_file
from .backup import (BackupError, MAX_ARCHIVE_BYTES, create_archive, open_archive,
                     plan_full_restore, plan_server_restore)
from .backup_jobs import BackupJobs, private_upload, opened_upload
from .prometheus_cleanup import cleanup_history
from .backup_history import plan_history_restore, history_plan_matches
from .backup_stream import Limits as BackupLimits, _space as backup_space
from .build_info import build_info
from .collection_log import CollectionLog
from .sensor_status import read_status
from .prometheus_service import ManagedPrometheus, PrometheusError
from .prometheus_status import DiscoveryObservation
from .prometheus_web import (PAGES as PROMETHEUS_PAGES, MAX_REQUEST as PROMETHEUS_MAX_REQUEST,
                             allowed_path as prometheus_path_allowed, engine_response,
                             login_location, state_page, notification_response)
from .restore import stage_restore, recover_interrupted_restore
from .restore_history import stage_file_restore, _workspace_root
from .state_operation import installation_lease
from .deployment import (atomic_config, generate_certificate, host_name, local_addresses,
                         local_interface_options,
                         read_config, stage_certificate, url_host, validate_ca_bundle,
                         validate_certificate, validate_network, write_private)


# Initial discovery crosses several BMC endpoints. Keep ordinary collection
# deadlines unchanged, but tolerate a slow remote response while onboarding.
ONBOARD_REDFISH_GET_TIMEOUT = 120
# The BMC UI's Generate Log flow has not been matched to this Redfish action.
# Keep existing job history/downloads readable, but do not allow new sends.
SUPPORT_BUNDLE_COLLECTION_ENABLED = False


COOKIE = "__Host-c880a_session"
STATIC = Path(__file__).parent / "static"


class BootstrapInput(BaseModel):
    token: str = Field(min_length=30, max_length=128)
    password: str = Field(min_length=12, max_length=256)


class LoginInput(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)


class UserCreateInput(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=12, max_length=256)
    role: str


class UserUpdateInput(BaseModel):
    role: str
    disabled: bool


class UserPasswordInput(BaseModel):
    password: str = Field(min_length=12, max_length=256)


class OnboardInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    bmc_host: str = Field(min_length=7, max_length=45)
    bmc_port: int = Field(default=443, ge=1, le=65535, strict=True)
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=4096)
    insecure_bmc: bool = False
    manager_metrics_enabled: bool = False


class ManagerMetricsInput(BaseModel):
    enabled: bool


class UnclaimInput(BaseModel):
    acknowledge_data_deletion: bool


class ServerActionInput(BaseModel):
    expected_host: str = Field(min_length=1, max_length=253)
    expected_name: str = Field(min_length=1, max_length=80)
    acknowledge_impact: bool


class InventoryIntervalInput(BaseModel):
    seconds: int | None = Field(default=None, ge=300, le=86400)


class CollectionSettingsInput(BaseModel):
    inventory_interval_seconds: int = Field(ge=300, le=86400)
    live_metrics_interval_seconds: int = Field(ge=30, le=600)
    manager_scrape_interval_seconds: int = Field(ge=60, le=3600)
    health_check_interval_seconds: int | None = Field(default=None, ge=60, le=3600)


class ConsoleSettingsInput(BaseModel):
    idle_minutes: int = Field(ge=1, le=15)
    login_idle_minutes: int = Field(default=20, ge=5, le=120)


class PrometheusOperationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation_id: str = Field(pattern=r"^[0-9a-f]{32}$")


class PrometheusToggleInput(PrometheusOperationInput):
    enabled: bool = Field(strict=True)


class PrometheusSettingsInput(PrometheusToggleInput):
    scrape_interval: int = Field(ge=15, le=3600, strict=True)
    scrape_timeout: int = Field(ge=1, le=60, strict=True)
    retention_hours: int = Field(ge=1, le=720, strict=True)
    storage_gib: int = Field(ge=1, le=128, strict=True)


class DeploymentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    bind_address: str = Field(max_length=45)
    advertised_dns_name: str = Field(default="", max_length=253)
    manager_port: int
    port_start: int
    port_end: int
    console_port_offset: int
    acknowledge_interruption: bool


class CertificateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    certificate_pem: str = Field(max_length=131072)
    chain_pem: str = Field(default="", max_length=131072)
    private_key_pem: str = Field(max_length=131072)
    acknowledge_interruption: bool


class GenerateCertificateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    additional_hosts: list[str] = Field(default_factory=list, max_length=10)


class BmcCaInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ca_pem: str = Field(max_length=131072)
    confirm_clear: bool = False


class BackupCreateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope: Literal["full", "servers"]
    passphrase: str = Field(min_length=16, max_length=1024)
    acknowledge_sensitive: bool


class WidgetInput(BaseModel):
    title: str = Field(min_length=1, max_length=80)
    series_ids: list[str] = Field(min_length=1, max_length=5)


@dataclass
class Config:
    data_dir: Path
    port_start: int = 9838
    port_end: int = 9937
    exporter_bind: str = "127.0.0.1"
    exporter_advertise_host: str = "127.0.0.1"
    exporter_tls_cert: str | None = None
    exporter_tls_key: str | None = None
    bmc_ca: str | None = None
    manager_origin: str = "https://localhost:8443"
    console_bind: str = "127.0.0.1"
    console_advertise_host: str = "localhost"
    console_port_offset: int = 2000
    console_tls_cert: str | None = None
    console_tls_key: str | None = None
    metrics_retention_days: int = 1
    live_metrics_interval: int = 60
    metrics_scrape_interval: int = 120
    bmc_actions_enabled: bool = True
    deployment: dict[str, Any] | None = None


class Runtime:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.store = Store(config.data_dir)
        self.get_budget = SharedGetBudget(config.data_dir / "redfish-get-budget.db")
        self.collection_log = None
        try:
            self.collection_log = CollectionLog(config.data_dir / "collection-log")
            for server in self.store.servers(active_only=True):
                self.collection_log.register_target(server['id'], server['name'])
                self.collection_log.interrupt_pending(server['id'], ('inventory',))
        except (OSError, ValueError):
            pass
        self.collection_log_download_slot = threading.BoundedSemaphore(1)
        self.metric_history = MetricHistory(self.store.database, retention_days=config.metrics_retention_days)
        self.resource_sampler = ResourceSampler()
        self.cleanup_orphaned_snapshots()
        self.boot_id = secrets.token_hex(16)
        self.processes: dict[str, subprocess.Popen[bytes]] = {}
        self.console_processes: dict[str, subprocess.Popen[bytes]] = {}
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.worker: threading.Thread | None = None
        self.metrics_worker: threading.Thread | None = None
        self.inventory_worker: threading.Thread | None = None
        self.health_worker: threading.Thread | None = None
        self.action_workers: dict[str, threading.Thread] = {}
        self.action_sending: set[str] = set()
        self.health_active: set[str] = set()
        self.health_next_due: dict[str, float] = {}
        self.health_slots = threading.BoundedSemaphore(4)
        self.inventory_active: set[str] = set()
        self.inventory_slots = threading.BoundedSemaphore(2)
        self.snapshot_versions: dict[str, int] = {}
        self.metrics_scraping: set[str] = set()
        self.metrics_started: dict[str, float] = {}
        self.metrics_slots = threading.BoundedSemaphore(4)
        self.live_cache: dict[str, dict[str, Any]] = {}
        self.live_locks: dict[str, threading.Lock] = {}
        self.live_slots = threading.BoundedSemaphore(4)
        self.live_active: set[str] = set()
        self.live_next_due: dict[str, float] = {}
        self.live_failures: set[str] = set()
        self.live_generation: dict[str, int] = {}
        self.live_background_slots = threading.BoundedSemaphore(2)
        self.detail_cache: dict[str, dict[str, Any]] = {}
        self.detail_cached_monotonic: dict[str, float] = {}
        self.detail_active: set[str] = set()
        self.detail_next_due: dict[str, float] = {}
        self.detail_failures: set[str] = set()
        self.detail_generation: dict[str, int] = {}
        self.detail_slots = threading.BoundedSemaphore(2)
        self.system_observations: dict[str, tuple[bytes, str, dict[str, Any], float, float]] = {}
        self.system_inflight: dict[str, tuple[bytes, str, Future[tuple[dict[str, Any], float]]]] = {}
        self.system_generation: dict[str, int] = {}
        self.login_attempts: dict[str, list[float]] = {}
        self.sse_workers: dict[str, threading.Thread] = {}
        self.sse_stops: dict[str, threading.Event] = {}
        self.sse_connections: dict[str, Any] = {}
        self.sse_connected: set[str] = set()
        self.last_log_poll: dict[str, float] = {}
        self.discovery_token_file = config.data_dir / "discovery-token"
        if not self.discovery_token_file.exists():
            _private_file(self.discovery_token_file, (secrets.token_urlsafe(32) + "\n").encode())

    def cleanup_orphaned_snapshots(self) -> None:
        """Retry private snapshot cleanup after an interrupted unclaim/restart."""
        known = {server["id"] for server in self.store.servers()}
        for pattern, expression in (
            ("metrics-*.prom", r"metrics-([0-9a-f]{32})\.prom"),
            ("metrics-*.prom.cache", r"metrics-([0-9a-f]{32})\.prom\.cache"),
            ("metrics-*.prom.catalog", r"metrics-([0-9a-f]{32})\.prom\.catalog"),
            ("metrics-*.prom.status", r"metrics-([0-9a-f]{32})\.prom\.status"),
        ):
            for path in self.config.data_dir.glob(pattern):
                match = re.fullmatch(expression, path.name)
                if match and match.group(1) not in known:
                    try:
                        path.unlink()
                    except OSError:
                        pass
    def interval(self, key: str, fallback: int) -> int:
        return self.store.setting(key, fallback)

    def action_client(self, server: Any) -> RedfishClient:
        return RedfishClient(server["bmc_host"], server["username"], self.store.decrypt(server),
                             port=server["bmc_port"],
                             ca_file=self.config.bmc_ca, insecure=bool(server["insecure_bmc"]),
                             shared_get_budget=self.get_budget, budget_priority=3)

    def start_action_monitor(self, job_id: str) -> None:
        with self.lock:
            active = self.action_workers.get(job_id)
            if active and active.is_alive():
                return
            worker = threading.Thread(target=self.monitor_action, args=(job_id,), daemon=True)
            self.action_workers[job_id] = worker
            worker.start()

    def monitor_action(self, job_id: str) -> None:
        """Observe an accepted action without ever resending its BMC command."""
        job = self.store.action_job(job_id)
        if not job:
            return
        deadline = time.monotonic() + (1800 if job["operation"] == "collect_support_bundle" else 600)
        attachment_deadline: float | None = None
        failures = 0
        saw_reboot_transition = False
        saw_bmc_disconnect = False
        while not self.stop.is_set() and time.monotonic() < deadline:
            job = self.store.action_job(job_id)
            if not job or job["state"] not in ("submitted", "running"):
                return
            server = self.store.get_server(job["server_id"])
            if not server or server["state"] != "active":
                return
            client = self.action_client(server)
            task = None
            if job["task_uri"]:
                try:
                    task = client.get(job["task_uri"])
                    failures = 0
                except RedfishError:
                    failures += 1
                    if job["operation"] == "reboot_bmc":
                        try:
                            discovered = json.loads(server["discovered_json"])
                            manager_uris = discovered.get("resources", {}).get("managers", [])
                            manager_uri = next((uri for uri in manager_uris if isinstance(uri, str)
                                                and uri.startswith("/redfish/v1/Managers/") and uri.count("/") == 4), None)
                            if manager_uri:
                                client.get(manager_uri)
                                if saw_bmc_disconnect:
                                    self.store.update_action_job(job_id, "completed")
                                    return
                        except (RedfishError, ValueError, TypeError):
                            saw_bmc_disconnect = True
                    # Manager.Reset can temporarily interrupt Redfish itself.
                    self.stop.wait(min(30, 5 * failures))
                    continue
            state = task.get("TaskState") if task else None
            status = task.get("TaskStatus") if task else None
            if state == "Completed" and status not in ("Critical", "Warning"):
                if job["operation"] == "collect_support_bundle":
                    if attachment_deadline is None:
                        attachment_deadline = time.monotonic() + 60
                    try:
                        before = set(json.loads(job["entries_before_json"]))
                        entries = client.members(job["entries_uri"], max_pages=10, max_members=1000)
                        new_uris = [item["@odata.id"] for item in entries
                                    if isinstance(item, dict) and isinstance(item.get("@odata.id"), str)
                                    and item["@odata.id"] not in before]
                        if len(new_uris) != 1 or not new_uris[0].startswith(job["entries_uri"] + "/"):
                            raise RedfishError("Diagnostic entry could not be identified uniquely")
                        entry = client.get(new_uris[0])
                        attachment = entry.get("AdditionalDataURI")
                        if not isinstance(attachment, str) or not attachment.startswith(new_uris[0] + "/"):
                            raise RedfishError("Diagnostic attachment was not advertised safely")
                        client.checked_url(attachment)
                        self.store.update_action_job(job_id, "ready", entry_uri=new_uris[0],
                                                     attachment_uri=attachment)
                    except (RedfishError, ValueError, TypeError, KeyError):
                        # Some BMCs publish the log entry after the task reaches Completed.
                        if time.monotonic() < attachment_deadline:
                            self.store.update_action_job(job_id, "running")
                            self.stop.wait(5)
                            continue
                        self.store.update_action_job(job_id, "failed", error=
                                                     "Task completed, but its diagnostic attachment could not be identified")
                    return
            if state in ("Exception", "Killed", "Cancelled", "Interrupted") or status in ("Critical", "Warning"):
                self.store.update_action_job(job_id, "failed", error="BMC reported that the task failed")
                return
            if job["operation"] in ("power_on", "power_off", "force_power_off", "reboot_server"):
                try:
                    discovered = json.loads(server["discovered_json"])
                    system_uri = discovered.get("system_uri")
                    if not isinstance(system_uri, str) or not system_uri.startswith("/redfish/v1/Systems/"):
                        raise RedfishError("System URI unavailable")
                    power = client.get(system_uri).get("PowerState")
                    if job["operation"] == "reboot_server" and power == "Off":
                        saw_reboot_transition = True
                    wanted = "Off" if job["operation"] in ("power_off", "force_power_off") else "On"
                    # A reboot needs BMC task completion; seeing the initial On state is not evidence.
                    if power == wanted and (job["operation"] != "reboot_server" or
                                            state == "Completed" or saw_reboot_transition):
                        self.store.patch_discovery(job["server_id"], {"system_power_state": power})
                        self.invalidate_system_views(job["server_id"])
                        self.store.update_action_job(job_id, "completed")
                        return
                except (RedfishError, ValueError, TypeError):
                    pass
            elif job["operation"] == "reboot_bmc":
                try:
                    discovered = json.loads(server["discovered_json"])
                    manager_uris = discovered.get("resources", {}).get("managers", [])
                    manager_uri = next((uri for uri in manager_uris if isinstance(uri, str)
                                        and uri.startswith("/redfish/v1/Managers/") and uri.count("/") == 4), None)
                    if manager_uri and (state == "Completed" or saw_bmc_disconnect):
                        client.get(manager_uri)
                        self.store.update_action_job(job_id, "completed")
                        return
                except (RedfishError, ValueError, TypeError):
                    saw_bmc_disconnect = True
            self.store.update_action_job(job_id, "running")
            self.stop.wait(5)
        if not self.stop.is_set():
            self.store.update_action_job(job_id, "uncertain",
                                         error="Outcome was not confirmed; check the BMC before retrying")

    def inventory_interval(self, server_id: str) -> int:
        override = self.store.inventory_status(server_id)["interval_override"]
        return override if override is not None else self.interval("inventory_interval_seconds", 3600)

    def shared_system_read(self, server: Any, uri: str, client: RedfishClient,
                           timeout: float) -> tuple[dict[str, Any], float]:
        """Coalesce General/Metrics System GETs without weakening action checks.

        The cache is bound to the claimed credential and exact discovered URI;
        the original response time travels with the observation. No cached
        System response is ever used to authorize a power action.
        """
        server_id = server["id"]
        credential = server["password_cipher"]
        with self.lock:
            cached = self.system_observations.get(server_id)
            if (cached and cached[0] == credential and cached[1] == uri
                    and time.monotonic() - cached[4] < 30):
                return dict(cached[2]), cached[3]
            pending = self.system_inflight.get(server_id)
            if pending and pending[0] == credential and pending[1] == uri:
                future = pending[2]
                owner = False
            else:
                future = Future()
                self.system_inflight[server_id] = (credential, uri, future)
                generation = self.system_generation.get(server_id, 0)
                owner = True
        if not owner:
            try:
                payload, observed_at = future.result(timeout=timeout + 2)
                return dict(payload), observed_at
            except (FutureTimeoutError, RedfishError) as exc:
                raise RedfishError("Shared System read unavailable") from exc
        try:
            payload = client.get(uri, timeout=timeout)
            observed_at = time.time()
        except Exception as exc:
            with self.lock:
                if self.system_inflight.get(server_id, (None, None, None))[2] is future:
                    self.system_inflight.pop(server_id, None)
            future.set_exception(RedfishError("Shared System read unavailable"))
            if isinstance(exc, RedfishError):
                raise
            raise RedfishError("Shared System read unavailable") from exc
        # Both views need only these System fields. Do not retain the BMC's
        # full response (which may contain unrelated OEM or action metadata).
        payload = {key: payload[key] for key in (
            "Model", "Manufacturer", "SerialNumber", "UUID", "BiosVersion",
            "PowerState", "Status", "MemorySummary", "ProcessorSummary", "AssetTag")
                   if key in payload}
        with self.lock:
            if (self.system_generation.get(server_id, 0) == generation and
                    self.system_inflight.get(server_id, (None, None, None))[2] is future):
                self.system_observations[server_id] = (
                    credential, uri, dict(payload), observed_at, time.monotonic())
                self.system_inflight.pop(server_id, None)
        future.set_result((payload, observed_at))
        return payload, observed_at

    def invalidate_system_views(self, server_id: str) -> None:
        """Force read-only views to refresh after an out-of-band power change."""
        with self.lock:
            self.system_observations.pop(server_id, None)
            self.system_inflight.pop(server_id, None)
            self.system_generation[server_id] = self.system_generation.get(server_id, 0) + 1
            self.detail_cached_monotonic.pop(server_id, None)
            self.detail_next_due[server_id] = 0
            self.detail_generation[server_id] = self.detail_generation.get(server_id, 0) + 1
            self.live_next_due[server_id] = 0
            self.live_generation[server_id] = self.live_generation.get(server_id, 0) + 1
            if server_id in self.live_cache:
                self.live_cache[server_id]["checked_monotonic"] = 0

    def start_inventory(self, server_id: str, *, manual: bool = False) -> bool:
        server = self.store.get_server(server_id)
        if not server or server["state"] != "active":
            return False
        if manual:
            last = self.store.inventory_status(server_id)["last_attempt_epoch"]
            if last is not None and time.time() - last < 60:
                return False
        with self.lock:
            if (server_id in self.inventory_active or server_id in self.metrics_scraping or
                    len(self.inventory_active) >= 2):
                return False
            self.inventory_active.add(server_id)
        threading.Thread(target=self.collect_inventory, args=(server_id,), daemon=True).start()
        return True

    def collect_inventory(self, server_id: str) -> None:
        try:
            with self.inventory_slots:
                if self.stop.is_set():
                    return
                server = self.store.get_server(server_id)
                if not server or server["state"] != "active":
                    return
                previous = self.store.inventory(server_id)
                retry_sources = inventory_retry_sources(previous, max_age=self.inventory_interval(server_id))
                self.store.inventory_attempt(server_id)
                if self.collection_log:
                    self.collection_log.register_target(server_id, server['name'])
                collection_started = time.monotonic()
                log_cycle = self.collection_log.begin(server_id, 'inventory') if self.collection_log else None
                collection_errors = 0
                client = None
                result = {}
                try:
                    client = RedfishClient(server["bmc_host"], server["username"], self.store.decrypt(server),
                                           port=server["bmc_port"],
                                           ca_file=self.config.bmc_ca, insecure=bool(server["insecure_bmc"]),
                                           shared_get_budget=self.get_budget, budget_priority=2,
                                           persistent_gets=True, max_get_connections=1)
                    discovered = json.loads(server["discovered_json"])
                    result = (collect_inventory(client, discovered, retry_snapshot=previous["snapshot"],
                                                retry_sources=retry_sources) if retry_sources else
                              collect_inventory(client, discovered))
                    self.store.inventory_result(server_id, result, result["failures"])
                    collection_errors = len(result["failures"])
                except (RedfishError, ValueError, OSError, TypeError) as exc:
                    self.store.inventory_result(server_id, None,
                                                [{"category": "Inventory", "source": "", "error": str(exc)[:200]}])
                    collection_errors = 1
                finally:
                    timings = client.get_statistics()['resources'].values() if client else []
                    timings = list(timings)
                    if client:
                        client.close()
                    if self.collection_log:
                        self.collection_log.record(server_id, 'inventory', 'partial' if collection_errors else 'complete',
                                                   log_cycle, errors=collection_errors,
                                                   request_count=result.get("request_count", 0),
                                                   retries=result.get("request_retries", 0),
                                                   initial_missing=result.get("initial_missing", 0),
                                                   recovered=result.get("recovered", 0),
                                                   unresolved=result.get("unresolved", 0),
                                                   recovery_seconds=result.get("recovery_seconds", 0),
                                                   request_seconds=round(sum(x["duration_seconds"] for x in timings), 3),
                                                   admission_seconds=round(sum(x["queue_wait_seconds"] for x in timings), 3),
                                                   duration_seconds=round(time.monotonic() - collection_started, 3))
        finally:
            with self.lock:
                self.inventory_active.discard(server_id)

    def inventory_loop(self) -> None:
        while not self.stop.is_set():
            for server in self.store.servers(active_only=True):
                server_id = server["id"]
                state = self.store.inventory_status(server_id)
                interval = (state["interval_override"] if state["interval_override"] is not None
                            else self.interval("inventory_interval_seconds", 3600))
                if state["state"] == "partial" and inventory_retry_sources(
                        self.store.inventory(server_id), max_age=float("inf")):
                    interval = min(interval, 60)
                # Stable per-server offset spreads first collection across a minute.
                jitter = int.from_bytes(hashlib.sha256(server_id.encode()).digest()[:2], "big") % 60
                due = (state["state"] in ("collecting", "interrupted") and server_id not in self.inventory_active and
                       state["last_attempt_epoch"] is not None and time.time() - state["last_attempt_epoch"] > 60) or (
                       state["last_attempt_epoch"] is None and
                       time.time() >= float(server["created"]) + jitter) or (
                       state["last_attempt_epoch"] is not None and
                       time.time() - state["last_attempt_epoch"] >= interval + jitter)
                if due:
                    self.start_inventory(server_id)
            self.stop.wait(15)

    def health_loop(self) -> None:
        """Check the System resource independently of inventory and metric policy."""
        while not self.stop.is_set():
            now = time.monotonic()
            for server in self.store.servers(active_only=True):
                server_id = server["id"]
                with self.lock:
                    if server_id not in self.health_next_due:
                        jitter = int.from_bytes(hashlib.sha256(server_id.encode()).digest()[:2], "big") % 60
                        self.health_next_due[server_id] = now + jitter
                    due = (now >= self.health_next_due[server_id] and server_id not in self.health_active
                           and server_id not in self.inventory_active and server_id not in self.metrics_scraping)
                    if due and self.health_slots.acquire(blocking=False):
                        self.health_active.add(server_id)
                    else:
                        due = False
                if due:
                    threading.Thread(target=self.check_health, args=(server_id,), daemon=True).start()
            self.stop.wait(15)

    def check_health(self, server_id: str) -> None:
        try:
            if self.stop.is_set():
                return
            server = self.store.get_server(server_id)
            if not server or server["state"] != "active":
                return
            discovered = json.loads(server["discovered_json"])
            checked_at = datetime.now(timezone.utc).isoformat()
            def record_problem(state: str) -> None:
                failures = min(2, int(discovered.get("health_check_failures") or 0) + 1)
                fields: dict[str, Any] = {"health_check_failures": failures,
                                          "health_last_attempt_at": checked_at}
                if failures >= 2:
                    fields["health_check_state"] = state
                self.store.patch_discovery(server_id, fields, expected_cipher=server["password_cipher"])
            try:
                system_uri = discovered.get("system_uri")
                if not isinstance(system_uri, str):
                    raise RedfishError("System resource is unavailable")
                client = RedfishClient(server["bmc_host"], server["username"], self.store.decrypt(server),
                                       port=server["bmc_port"],
                                       ca_file=self.config.bmc_ca, insecure=bool(server["insecure_bmc"]), timeout=25,
                                       shared_get_budget=self.get_budget, budget_priority=2)
                system = client.get(system_uri)
                status = system.get("Status")
                power = system.get("PowerState")
                if not isinstance(status, dict) and power is None:
                    # A successful HTTP response without either field is not a
                    # fresh health observation; retain last-known values.
                    record_problem("missing")
                    return
                self.store.patch_discovery(server_id, {
                    "system_status": status if isinstance(status, dict) else None,
                    "system_power_state": power,
                    "checked_at": checked_at,
                    "health_last_attempt_at": checked_at,
                    "health_check_state": "ok",
                    "health_check_failures": 0,
                }, expected_cipher=server["password_cipher"])
            except (RedfishError, ValueError, OSError, TypeError):
                # Keep the last successful reading, but never present it as a
                # current BMC result after a failed check. Do not expose errors
                # or credentials in the public fleet response.
                record_problem("failed")
        finally:
            with self.lock:
                self.health_active.discard(server_id)
                self.health_next_due[server_id] = time.monotonic() + self.interval(
                    "health_check_interval_seconds", 300)
            self.health_slots.release()

    def validate_host(self, host: str) -> None:
        try:
            ipaddress.ip_address(host)
        except ValueError as exc:
            raise HTTPException(400, "Enter a BMC IP address") from exc

    def start_server(self, server: Any) -> None:
        if server["state"] != "active":
            return
        with self.lock:
            current = self.store.get_server(server["id"])
            if not current or current["state"] != "active":
                return
            server = current
            if self.collection_log:
                self.collection_log.register_target(server['id'], server['name'])
            existing = self.processes.get(server["id"])
            if existing and existing.poll() is None:
                return
            password = self.store.decrypt(server)
            read_fd, write_fd = os.pipe()
            args = [sys.executable, "-m", "c880a_manager.exporter",
                    "--bmc-host", server["bmc_host"], "--bmc-port", str(server["bmc_port"]),
                    "--bmc-username", server["username"],
                    "--password-fd", str(read_fd), "--bind", self.config.exporter_bind,
                    "--port", str(server["port"]), "--snapshot-file",
                    str(self.config.data_dir / f"metrics-{server['id']}.prom"),
                    "--collection-log-dir", str(self.config.data_dir / "collection-log"),
                    "--collection-log-target", server["id"],
                    "--shared-budget-db", str(self.get_budget.database)]
            if server["insecure_bmc"]:
                args.append("--insecure-bmc")
            if self.config.bmc_ca:
                args.extend(("--bmc-ca", self.config.bmc_ca))
            if self.config.exporter_tls_cert and self.config.exporter_tls_key:
                args.extend(("--tls-cert", self.config.exporter_tls_cert,
                             "--tls-key", self.config.exporter_tls_key))
            try:
                process = subprocess.Popen(args, pass_fds=(read_fd,), close_fds=True,
                                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL)
                self.processes[server["id"]] = process
            except Exception:
                os.close(write_fd)
                raise
            finally:
                os.close(read_fd)
            try:
                os.write(write_fd, password.encode())
            finally:
                os.close(write_fd)

    def stop_server(self, server_id: str, *, purge_snapshot: bool = False) -> None:
        self.stop_sse(server_id)
        self.stop_console(server_id)
        with self.lock:
            process = self.processes.pop(server_id, None)
            self.snapshot_versions.pop(server_id, None)
            self.metrics_started.pop(server_id, None)
            self.metrics_scraping.discard(server_id)
            self.inventory_active.discard(server_id)
            self.health_active.discard(server_id)
            self.health_next_due.pop(server_id, None)
            self.live_cache.pop(server_id, None)
            self.live_locks.pop(server_id, None)
            self.live_next_due.pop(server_id, None)
            self.live_failures.discard(server_id)
            self.live_generation[server_id] = self.live_generation.get(server_id, 0) + 1
            self.detail_cache.pop(server_id, None)
            self.detail_cached_monotonic.pop(server_id, None)
            self.detail_next_due.pop(server_id, None)
            self.detail_failures.discard(server_id)
            self.detail_generation[server_id] = self.detail_generation.get(server_id, 0) + 1
            self.system_observations.pop(server_id, None)
            self.system_inflight.pop(server_id, None)
            self.system_generation[server_id] = self.system_generation.get(server_id, 0) + 1
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if purge_snapshot:
            (self.config.data_dir / f"metrics-{server_id}.prom").unlink(missing_ok=True)
            (self.config.data_dir / f"metrics-{server_id}.prom.cache").unlink(missing_ok=True)
            (self.config.data_dir / f"metrics-{server_id}.prom.catalog").unlink(missing_ok=True)
            (self.config.data_dir / f"metrics-{server_id}.prom.status").unlink(missing_ok=True)

    def metrics_loop(self) -> None:
        last_prune = 0.0
        while not self.stop.is_set():
            waiting_for_slot = False
            for server in self.store.servers(active_only=True):
                try:
                    self.start_server(server)
                except (OSError, ValueError):
                    # A transient bind or process failure must not strand a server.
                    path = self.config.data_dir / f"metrics-{server['id']}.prom"
                    try:
                        info = path.stat(follow_symlinks=False)
                        if stat.S_ISREG(info.st_mode) and info.st_mtime < time.time() - 86400:
                            path.unlink(missing_ok=True)
                    except OSError:
                        pass
                    continue
                server_id = server["id"]
                now = time.monotonic()
                with self.lock:
                    if server_id not in self.metrics_started:
                        # A recent private snapshot may be from an external
                        # scrape; avoid an immediate duplicate after restart.
                        snapshot = self.config.data_dir / f"metrics-{server_id}.prom"
                        try:
                            info = snapshot.stat(follow_symlinks=False)
                            if stat.S_ISREG(info.st_mode) and info.st_mtime >= time.time() - 600:
                                self.metrics_started[server_id] = now
                        except OSError:
                            pass
                    eligible = (bool(server["manager_metrics_enabled"]) and
                                server_id not in self.metrics_scraping and
                                server_id not in self.inventory_active and
                                now - self.metrics_started.get(server_id, 0) >=
                                self.interval("manager_scrape_interval_seconds", self.config.metrics_scrape_interval))
                    due = eligible and self.metrics_slots.acquire(blocking=False)
                    waiting_for_slot |= eligible and not due
                    if due:
                        self.metrics_scraping.add(server_id)
                        self.metrics_started[server_id] = now
                if due:
                    try:
                        threading.Thread(target=self._scrape_exporter_bounded,
                                         args=(server,), daemon=True).start()
                    except RuntimeError:
                        with self.lock:
                            self.metrics_scraping.discard(server_id)
                            self.metrics_started.pop(server_id, None)
                        self.metrics_slots.release()
                if not server["manager_metrics_enabled"]:
                    continue
                path = self.config.data_dir / f"metrics-{server['id']}.prom"
                try:
                    with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)), "rb") as source:
                        info = os.fstat(source.fileno())
                        if not stat.S_ISREG(info.st_mode):
                            continue
                        if info.st_mtime < time.time() - 86400:
                            path.unlink(missing_ok=True)
                            self.snapshot_versions.pop(server_id, None)
                            continue
                        if (info.st_size > MAX_SNAPSHOT_BYTES or
                                self.snapshot_versions.get(server["id"]) == info.st_mtime_ns):
                            continue
                        payload = source.read(MAX_SNAPSHOT_BYTES + 1)
                    self.metric_history.ingest(server["id"], payload, respect_manager_policy=True)
                    self.snapshot_versions[server["id"]] = info.st_mtime_ns
                except (OSError, UnicodeDecodeError, ValueError, sqlite3.Error):
                    # A broken snapshot must not interrupt other fleet members.
                    continue
            if time.time() - last_prune > 15:
                try:
                    self.metric_history.prune()
                    self.store.prune_metric_pauses()
                    last_prune = time.time()
                except sqlite3.Error:
                    pass
            self.stop.wait(1 if waiting_for_slot else 15)

    def _scrape_exporter_bounded(self, server: Any) -> None:
        try:
            self.scrape_exporter(server)
        finally:
            self.metrics_slots.release()

    def scrape_exporter(self, server: Any) -> None:
        """Manager-driven scrape; external Prometheus uses the same on-demand endpoint."""
        server_id = server["id"]
        opened = False
        try:
            if self.stop.is_set():
                return
            current = self.store.get_server(server_id)
            if current is None or current["state"] != "active" or not current["manager_metrics_enabled"]:
                return
            host = self.config.exporter_advertise_host
            context = ssl.create_default_context(cafile=self.config.exporter_tls_cert)
            # Connect to the actual local listener, while verifying the
            # advertised DNS/IP name via SNI and certificate SAN. DNS may
            # legitimately resolve to an external address from this host.
            with socket.create_connection((self.config.exporter_bind, server["port"]), timeout=600) as raw:
                with context.wrap_socket(raw, server_hostname=host) as encrypted:
                    encrypted.sendall((f"GET /metrics HTTP/1.1\r\nHost: {url_host(host)}:{server['port']}\r\n"
                                       "Accept: text/plain\r\nConnection: close\r\n\r\n").encode("ascii"))
                    response = HTTPResponse(encrypted)
                    response.begin()
                    if response.status == 200:
                        opened = True
                        # The exporter publishes the bounded private snapshot itself.
                        response.read(MAX_SNAPSHOT_BYTES + 1)
        except (OSError, ValueError):
            pass
        finally:
            with self.lock:
                self.metrics_scraping.discard(server_id)
                # Unclaim deletes the server under this same lock. A scrape
                # finishing afterward must not recreate its scheduler state.
                current = self.store.get_server(server_id)
                if current is not None and current["state"] == "active" and current["manager_metrics_enabled"]:
                    # Retry a listener startup race promptly; leave a full
                    # interval after a scrape that reached the exporter.
                    retry_offset = max(0, self.interval("manager_scrape_interval_seconds", self.config.metrics_scrape_interval) - 15)
                    self.metrics_started[server_id] = time.monotonic() - (0 if opened else retry_offset)

    def live_metrics(self, server: Any) -> dict[str, Any]:
        server_id = server["id"]
        with self.lock:
            lock = self.live_locks.setdefault(server_id, threading.Lock())
        with lock:
            previous = self.live_cache.get(server_id, {})
            live_interval = self.interval("live_metrics_interval_seconds", self.config.live_metrics_interval)
            if time.monotonic() - previous.get("checked_monotonic", 0) < live_interval:
                return {key: value for key, value in previous.items() if key != "checked_monotonic"}
            with self.live_slots:
                client = RedfishClient(server["bmc_host"], server["username"], self.store.decrypt(server),
                                       port=server["bmc_port"],
                                       ca_file=self.config.bmc_ca, insecure=bool(server["insecure_bmc"]),
                                       shared_get_budget=self.get_budget, budget_priority=1)
                fresh = client.live_metrics(json.loads(server["discovered_json"]))
            merged = {key: value for key, value in previous.items() if key in ("system", "power", "temperatures")}
            merged.update(fresh)
            merged["refresh_interval_seconds"] = live_interval
            merged["checked_monotonic"] = time.monotonic()
            self.live_cache[server_id] = merged
            return {key: value for key, value in merged.items() if key != "checked_monotonic"}

    def _collect_live(self, server_id: str, generation: int) -> None:
        try:
            server = self.store.get_server(server_id)
            if not server or server["state"] != "active" or not server["manager_metrics_enabled"]:
                return
            client = RedfishClient(server["bmc_host"], server["username"], self.store.decrypt(server),
                                   port=server["bmc_port"],
                                   ca_file=self.config.bmc_ca, insecure=bool(server["insecure_bmc"]),
                                   shared_get_budget=self.get_budget, budget_priority=1,
                                   system_reader=lambda uri, timeout: self.shared_system_read(
                                       server, uri, client, max(25, timeout)))
            fresh = client.live_metrics(json.loads(server["discovered_json"]))
            if self.stop.is_set():
                return
            current = self.store.get_server(server_id)
            if (not current or current["state"] != "active" or not current["manager_metrics_enabled"] or
                    current["password_cipher"] != server["password_cipher"]):
                return
            interval = self.interval("live_metrics_interval_seconds", self.config.live_metrics_interval)
            with self.lock:
                if generation != self.live_generation.get(server_id, 0):
                    return
                previous = self.live_cache.get(server_id, {})
                merged = {key: value for key, value in previous.items()
                          if key in ("system", "power", "temperatures")}
                merged.update(fresh)
                merged["refresh_interval_seconds"] = interval
                merged["checked_monotonic"] = time.monotonic()
                self.live_cache[server_id] = merged
                self.live_next_due[server_id] = merged["checked_monotonic"] + interval
                self.live_failures.discard(server_id)
        except Exception as exc:
            # Keep failures generic; a Redfish exception may contain a BMC URI.
            logging.getLogger(__name__).warning("live_refresh_failed server_id=%s error=%s",
                                                server_id, type(exc).__name__)
            with self.lock:
                if generation == self.live_generation.get(server_id, 0):
                    self.live_next_due[server_id] = time.monotonic() + 30
                    self.live_failures.add(server_id)
        finally:
            with self.lock:
                self.live_active.discard(server_id)
            self.live_background_slots.release()

    def live_view(self, server: Any) -> dict[str, Any]:
        """Serve age-stamped live readings locally while a bounded refresh runs."""
        server_id = server["id"]
        now = time.monotonic()
        interval = self.interval("live_metrics_interval_seconds", self.config.live_metrics_interval)
        start = False
        with self.lock:
            cached = self.live_cache.get(server_id, {})
            due_at = max(self.live_next_due.get(server_id, 0), cached.get("checked_monotonic", 0) + interval)
            due = now >= due_at
            if due and server_id not in self.live_active and not self.stop.is_set():
                if self.live_background_slots.acquire(blocking=False):
                    self.live_active.add(server_id)
                    start = True
                    generation = self.live_generation.get(server_id, 0)
            refreshing = server_id in self.live_active
            failed = server_id in self.live_failures
            queued = due and not refreshing and not self.stop.is_set()
            result = {key: value for key, value in cached.items() if key != "checked_monotonic"}
        if start:
            try:
                threading.Thread(target=self._collect_live, args=(server_id, generation), daemon=True).start()
            except RuntimeError:
                with self.lock:
                    self.live_active.discard(server_id)
                    self.live_next_due[server_id] = time.monotonic() + 30
                    self.live_failures.add(server_id)
                self.live_background_slots.release()
                refreshing = False
                failed = True
        result["refreshing"] = refreshing
        result["queued"] = queued
        result["refresh_error"] = failed
        return result

    def _collect_details(self, server_id: str, generation: int) -> None:
        try:
            server = self.store.get_server(server_id)
            if not server or server["state"] != "active":
                return
            client = RedfishClient(server["bmc_host"], server["username"], self.store.decrypt(server),
                                   port=server["bmc_port"],
                                   ca_file=self.config.bmc_ca, insecure=bool(server["insecure_bmc"]),
                                   shared_get_budget=self.get_budget, budget_priority=1,
                                   system_reader=lambda uri, timeout: self.shared_system_read(
                                       server, uri, client, max(25, timeout)))
            snapshot = client.detail_snapshot(json.loads(server["discovered_json"]))
            with self.lock:
                previous = self.detail_cache.get(server_id, {})
            for source in ("system", "chassis", "manager"):
                if source not in snapshot and source in previous:
                    # Keep a failed source as last known without claiming it
                    # was part of this response or moving its observation time.
                    snapshot[source] = previous[source]
            if self.stop.is_set():
                return
            current = self.store.get_server(server_id)
            if (not current or current["state"] != "active" or
                    current["password_cipher"] != server["password_cipher"]):
                return
            current_sources = snapshot.get("sources") or {}
            system = snapshot.get("system") if "system" in current_sources else {}
            manager = snapshot.get("manager") if "manager" in current_sources else {}
            system = system or {}
            manager = manager or {}
            updates: dict[str, Any] = {}
            for key, value in (("model", system.get("Model")), ("manufacturer", system.get("Manufacturer")),
                               ("serial_number", system.get("SerialNumber")),
                               ("bios_version", system.get("BiosVersion")),
                               ("firmware_version", manager.get("FirmwareVersion")),
                               ("system_status", system.get("Status")),
                               ("system_power_state", system.get("PowerState"))):
                if value is not None:
                    updates[key] = value
            if system:
                system_at = (snapshot.get("source_observed_at") or {}).get("system")
                if not isinstance(system_at, (int, float)) or isinstance(system_at, bool) or not 0 < system_at <= time.time() + 5:
                    system_at = time.time()
                updates["checked_at"] = datetime.fromtimestamp(system_at, timezone.utc).isoformat()
                updates["health_last_attempt_at"] = updates["checked_at"]
                updates["health_check_state"] = ("ok" if isinstance(system.get("Status"), dict) or
                                                 system.get("PowerState") is not None else "missing")
                updates["health_check_failures"] = 0
            with self.lock:
                if generation != self.detail_generation.get(server_id, 0):
                    return
            if updates and self.store.patch_discovery(server_id, updates,
                                                      expected_cipher=server["password_cipher"]) is None:
                return
            snapshot["checked_at"] = updates.get("checked_at") or json.loads(current["discovered_json"]).get("checked_at")
            snapshot["fetched_at"] = datetime.now(timezone.utc).isoformat()
            with self.lock:
                if generation == self.detail_generation.get(server_id, 0):
                    self.detail_cache[server_id] = snapshot
                    self.detail_cached_monotonic[server_id] = time.monotonic()
                    self.detail_next_due[server_id] = time.monotonic() + 60
                    self.detail_failures.discard(server_id)
        except Exception as exc:
            # Background work must back off on unexpected failures too. Log
            # only the error class, never BMC URLs, payloads, or credentials.
            logging.getLogger(__name__).warning("detail_refresh_failed server_id=%s error=%s",
                                                server_id, type(exc).__name__)
            with self.lock:
                if generation == self.detail_generation.get(server_id, 0):
                    self.detail_next_due[server_id] = time.monotonic() + 30
                    self.detail_failures.add(server_id)
        finally:
            with self.lock:
                self.detail_active.discard(server_id)
            self.detail_slots.release()

    def details_view(self, server: Any) -> dict[str, Any]:
        """Return local details promptly and schedule at most one bounded BMC refresh."""
        server_id = server["id"]
        now = time.monotonic()
        start = False
        with self.lock:
            cached = self.detail_cache.get(server_id)
            fresh = cached is not None and now - self.detail_cached_monotonic.get(server_id, 0) < 60
            due = now >= self.detail_next_due.get(server_id, 0)
            if due and server_id not in self.detail_active and not self.stop.is_set():
                if self.detail_slots.acquire(blocking=False):
                    self.detail_active.add(server_id)
                    start = True
                    generation = self.detail_generation.get(server_id, 0)
            refreshing = server_id in self.detail_active
            failed = server_id in self.detail_failures
            queued = due and not refreshing and not self.stop.is_set()
            result = dict(cached) if cached else {}
        if start:
            try:
                threading.Thread(target=self._collect_details, args=(server_id, generation), daemon=True).start()
            except RuntimeError:
                with self.lock:
                    self.detail_active.discard(server_id)
                    self.detail_next_due[server_id] = time.monotonic() + 30
                    self.detail_failures.add(server_id)
                self.detail_slots.release()
                refreshing = False
                failed = True
        if cached and not fresh:
            # A previous response is still useful, but no longer a current read.
            result["sources"] = {}
            result["unavailable"] = []
            result["cached"] = True
            result["checked_at"] = result.pop("fetched_at", None) or result.get("checked_at")
        result.setdefault("sources", {})
        result.setdefault("unavailable", [])
        result["refreshing"] = refreshing
        result["queued"] = queued
        result["refresh_error"] = failed
        return result

    def console_url(self, server: Any) -> str:
        scheme = "https"
        host = self.config.console_advertise_host
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"{scheme}://{host}:{server['port'] + self.config.console_port_offset}/launch"

    def start_console(self, server: Any) -> str:
        if server["state"] != "active":
            raise ValueError("Server is not active")
        port = server["port"] + self.config.console_port_offset
        if not 1 <= port <= 65535:
            raise ValueError("Console port is out of range")
        with self.lock:
            current = self.console_processes.get(server["id"])
            if current and current.poll() is None:
                process = current
            else:
                try:
                    with socket.create_connection((self.config.console_bind, port), timeout=0.2):
                        raise RuntimeError("Console port is already in use")
                except OSError:
                    pass
                args = [sys.executable, "-m", "c880a_manager.console_gateway",
                        "--data-dir", str(self.config.data_dir), "--server-id", server["id"],
                        "--manager-origin", self.config.manager_origin,
                        "--advertise-host", self.config.console_advertise_host,
                        "--bind", self.config.console_bind, "--port", str(port)]
                if self.config.bmc_ca:
                    args.extend(("--bmc-ca", self.config.bmc_ca))
                if self.config.console_tls_cert and self.config.console_tls_key:
                    args.extend(("--tls-cert", self.config.console_tls_cert,
                                 "--tls-key", self.config.console_tls_key))
                process = subprocess.Popen(args, close_fds=True, stdin=subprocess.DEVNULL,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.console_processes[server["id"]] = process
        for _ in range(30):
            if process.poll() is not None:
                break
            try:
                with socket.create_connection((self.config.console_bind, port), timeout=0.2):
                    if process.poll() is None:
                        return self.console_url(server)
            except OSError:
                time.sleep(0.1)
        self.stop_console(server["id"])
        raise RuntimeError("Console gateway did not start")

    def stop_console(self, server_id: str) -> None:
        with self.lock:
            process = self.console_processes.pop(server_id, None)
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def log_loop(self) -> None:
        while not self.stop.is_set():
            for server in self.store.servers(active_only=True):
                if self.stop.is_set():
                    break
                self.start_sse(server)
                server_id = server["id"]
                with self.lock:
                    interval = 600 if server_id in self.sse_connected else 300
                if time.monotonic() - self.last_log_poll.get(server_id, 0) < interval:
                    continue
                self.last_log_poll[server_id] = time.monotonic()
                try:
                    self.collect_logs(server)
                except (RedfishError, ValueError, TypeError, AttributeError, OSError, json.JSONDecodeError):
                    # One source must not prevent the next server from being collected.
                    continue
            self.stop.wait(30)

    def start_sse(self, server: Any) -> None:
        if not json.loads(server["discovered_json"]).get("events_sse"):
            return
        server_id = server["id"]
        with self.lock:
            existing = self.sse_workers.get(server_id)
            if existing and existing.is_alive():
                return
            stop_event = threading.Event()
            worker = threading.Thread(target=self.sse_loop, args=(server_id, stop_event), daemon=True)
            self.sse_stops[server_id] = stop_event
            self.sse_workers[server_id] = worker
            worker.start()

    def stop_sse(self, server_id: str) -> None:
        with self.lock:
            stop_event = self.sse_stops.pop(server_id, None)
            response = self.sse_connections.pop(server_id, None)
            self.sse_connected.discard(server_id)
            self.sse_workers.pop(server_id, None)
            self.last_log_poll.pop(server_id, None)
        if stop_event:
            stop_event.set()
        if response:
            # HTTPResponse.close() can wait for another thread's blocking
            # readline() (up to the stream timeout). Interrupt the socket
            # instead; the owning SSE worker closes the response in finally.
            try:
                response.fp.raw._sock.shutdown(socket.SHUT_RDWR)
            except (AttributeError, OSError, ValueError):
                pass

    def sse_loop(self, server_id: str, stop_event: threading.Event) -> None:
        last_event_id = self.store.event_cursor(server_id)
        resolved_uri: str | None = None
        event_filter = False
        failures = 0
        while not self.stop.is_set() and not stop_event.is_set():
            response = None
            try:
                server = self.store.get_server(server_id)
                if not server or server["state"] != "active":
                    return
                client = RedfishClient(server["bmc_host"], server["username"], self.store.decrypt(server),
                                       port=server["bmc_port"],
                                       ca_file=self.config.bmc_ca, insecure=bool(server["insecure_bmc"]),
                                       shared_get_budget=self.get_budget, budget_priority=0)
                discovered = json.loads(server["discovered_json"])
                if resolved_uri is None:
                    candidate = discovered.get("events_sse_uri")
                    resolved_uri = candidate if isinstance(candidate, str) and candidate else None
                    event_filter = bool(discovered.get("events_sse_event_filter"))
                if not resolved_uri:
                    root = client.get("/redfish/v1")
                    reference = root.get("EventService")
                    event_uri = reference.get("@odata.id") if isinstance(reference, dict) else None
                    if not event_uri:
                        return
                    service = client.get(event_uri)
                    resolved_uri = service.get("ServerSentEventUri")
                    if not isinstance(resolved_uri, str) or not resolved_uri:
                        return
                    filters = service.get("SSEFilterPropertiesSupported")
                    event_filter = bool(isinstance(filters, dict) and filters.get("EventFormatType"))
                response = client.open_event_stream(resolved_uri,
                    event_only=event_filter,
                    last_event_id=last_event_id)
                if self.stop.is_set() or stop_event.is_set():
                    return
                with self.lock:
                    self.sse_connections[server_id] = response
                    self.sse_connected.add(server_id)
                failures = 0
                for frame_id, payload in frames(response):
                    if self.stop.is_set() or stop_event.is_set():
                        break
                    for entry_id, entry in event_records(frame_id, payload):
                        timestamp = entry.get("EventTimestamp") or entry.get("Created")
                        self.store.insert_event(
                            server_id=server_id, source="Redfish EventService SSE",
                            source_entry_id=entry_id,
                            occurred_at=timestamp if isinstance(timestamp, str) else None,
                            severity=entry.get("Severity") if isinstance(entry.get("Severity"), str) else None,
                            message_id=entry.get("MessageId") if isinstance(entry.get("MessageId"), str) else None,
                            message=str(entry.get("Message") or entry.get("MessageId") or "Event"), raw=entry)
                    if frame_id:
                        last_event_id = frame_id
                        self.store.update_event_cursor(server_id, frame_id)
            except (RedfishError, ValueError, OSError, TimeoutError, json.JSONDecodeError):
                failures += 1
            finally:
                with self.lock:
                    if self.sse_connections.get(server_id) is response:
                        self.sse_connections.pop(server_id, None)
                        self.sse_connected.discard(server_id)
                if response:
                    try:
                        response.close()
                    except (OSError, ValueError):
                        pass
            stop_event.wait(min(300, max(15, 15 * 2 ** min(failures, 4))))

    def collect_logs(self, server: Any) -> None:
        client = RedfishClient(server["bmc_host"], server["username"], self.store.decrypt(server),
                               port=server["bmc_port"],
                               ca_file=self.config.bmc_ca, insecure=bool(server["insecure_bmc"]),
                               shared_get_budget=self.get_budget, budget_priority=0)
        discovered = json.loads(server["discovered_json"])
        for collection_uri in discovered.get("log_collections", [])[:8]:
            try:
                services = client.members(collection_uri, max_pages=3, max_members=20, warnings=[])
            except RedfishError:
                continue
            for service_ref in services[:20]:
                service_uri = service_ref["@odata.id"]
                try:
                    service = client.get(service_uri)
                    entries_uri = (service.get("Entries") or {}).get("@odata.id")
                    if not entries_uri:
                        continue
                    initial = client.get(entries_uri + "?$top=50")
                    count = initial.get("Members@odata.count")
                    if isinstance(count, int) and 50 < count <= 100_000:
                        page = client.get(entries_uri + f"?$skip={max(0, count - 50)}&$top=50")
                    else:
                        page = initial
                    entries = page.get("Members")
                    if not isinstance(entries, list):
                        continue
                    for entry in entries[-50:]:
                        if not isinstance(entry, dict):
                            continue
                        if "Message" not in entry and entry.get("@odata.id"):
                            entry = client.get(entry["@odata.id"])
                        entry_id = entry.get("@odata.id") or entry.get("Id")
                        if not isinstance(entry_id, str):
                            continue
                        self.store.insert_event(server_id=server["id"], source=service_uri,
                            source_entry_id=entry_id,
                            occurred_at=entry.get("Created") if isinstance(entry.get("Created"), str) else None,
                            severity=entry.get("Severity") if isinstance(entry.get("Severity"), str) else None,
                            message_id=entry.get("MessageId") if isinstance(entry.get("MessageId"), str) else None,
                            message=str(entry.get("Message") or ""), raw=entry)
                except RedfishError:
                    continue


def create_app(config: Config, *, start_workers: bool = True) -> FastAPI:
    runtime = Runtime(config)
    managed_prometheus = ManagedPrometheus(config.data_dir)
    backup_workspace = _workspace_root(config.data_dir)
    from .backup_stream import reap_workspaces
    reap_workspaces(backup_workspace)
    backup_jobs = BackupJobs(runtime.store, managed_prometheus, backup_workspace)
    prometheus_requests = threading.BoundedSemaphore(16)
    prometheus_notifications = threading.BoundedSemaphore(8)
    prometheus_change_guard = threading.Lock()
    prometheus_discovery = DiscoveryObservation()
    public_build = build_info()
    onboarding_progress_lock = threading.Lock()
    onboarding_progress: dict[str, dict[str, Any]] = {}
    onboarding_jobs_lock = threading.Lock()
    onboarding_jobs: dict[str, dict[str, Any]] = {}

    def public_onboarding_job(job: dict[str, Any]) -> dict[str, Any]:
        # Never expose credentials or the request body through polling.
        return {key: job[key] for key in ("id", "name", "state", "message",
                                          "started_at", "updated_at", "error", "server_id")}

    def update_onboarding_job(job_id: str, *, state: str | None = None,
                              message: str | None = None, error: str | None = None,
                              server_id: str | None = None) -> None:
        with onboarding_jobs_lock:
            job = onboarding_jobs.get(job_id)
            if not job:
                return
            if state is not None:
                job["state"] = state
            if message is not None:
                job["message"] = message
            if error is not None:
                job["error"] = error
            if server_id is not None:
                job["server_id"] = server_id
            job["updated_at"] = time.time()

    def run_onboarding_job(job_id: str, body: OnboardInput, user_id: int) -> None:
        server_id = None
        try:
            client = RedfishClient(body.bmc_host, body.username, body.password, port=body.bmc_port,
                                   ca_file=config.bmc_ca, insecure=body.insecure_bmc,
                                   timeout=ONBOARD_REDFISH_GET_TIMEOUT,
                                   shared_get_budget=runtime.get_budget, budget_priority=2,
                                   onboarding_get_retries=3)
            discovered = client.discover(progress=lambda message: update_onboarding_job(job_id, message=message))
            discovered["ui_onboarding_started"] = True
            update_onboarding_job(job_id, message="Saving the server and starting its exporter…")
            with installation_lease(config.data_dir), runtime.lock:
                previous = runtime.store.get_server_by_host(body.bmc_host, body.bmc_port)
                if previous and previous["state"] == "active":
                    raise ValueError("Server already onboarded")
                port = previous["port"] if previous else runtime.store.next_port(config.port_start, config.port_end)
                if not port:
                    raise ValueError("No exporter ports available")
                if previous:
                    server_id = previous["id"]
                    runtime.store.reactivate_server(server_id, body.name.strip(), body.username,
                                                    body.password, body.insecure_bmc, discovered,
                                                    body.manager_metrics_enabled)
                else:
                    server_id = runtime.store.add_server(body.name.strip(), body.bmc_host, body.username,
                                                         body.password, body.insecure_bmc, port, discovered,
                                                         body.manager_metrics_enabled, body.bmc_port)
            # Report the saved server even if starting its exporter subsequently fails.
            update_onboarding_job(job_id, server_id=server_id)
            server = runtime.store.get_server(server_id)
            if start_workers and server:
                runtime.start_server(server)
                runtime.start_sse(server)
            runtime.store.audit(user_id, "onboard", server_id)
            update_onboarding_job(job_id, state="succeeded", message="Server onboarded and exporter started.")
        except RedfishAuthenticationError:
            update_onboarding_job(job_id, state="failed", error="Wrong username or password")
        except RedfishTimeoutError:
            update_onboarding_job(job_id, state="failed", error="The BMC took too long to respond during validation. No server was onboarded; please retry.")
        except RedfishError as exc:
            # RedfishClient errors deliberately contain only resource classes,
            # status codes, and fixed text (never URL, response body or auth).
            update_onboarding_job(job_id, state="failed", error=f"Redfish validation failed: {exc}")
        except (TypeError, AttributeError, KeyError) as exc:
            update_onboarding_job(job_id, state="failed", error=(
                f"Redfish validation failed on {type(exc).__name__}; the BMC returned an unexpected structure."))
        except (ValueError, sqlite3.IntegrityError) as exc:
            update_onboarding_job(job_id, state="failed", error=str(exc))
        except Exception as exc:
            # Unexpected exception strings may include Redfish responses or
            # credentials; log the type only and keep the status generic.
            logging.error("Background onboarding job %s failed (%s)", job_id, type(exc).__name__)
            update_onboarding_job(job_id, state="failed", error=(
                "The server was saved but its exporter could not be started. Check the server list."
                if server_id else "Onboarding failed. No server was saved; please retry."))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if start_workers and (managed_prometheus.root / "pending.json").is_file():
            try:
                await run_in_threadpool(managed_prometheus.recover)
            except PrometheusError:
                logging.error("Managed Prometheus recovery remains unconfirmed")
        if start_workers and (runtime.store.pending_prometheus_deletions() or
                              (managed_prometheus.root / "delete.pending.json").exists()):
            try:
                await run_in_threadpool(cleanup_history, runtime.store, managed_prometheus, backup_workspace)
            except (BackupError, PrometheusError, OSError):
                logging.error("Managed target history cleanup remains pending")
        runtime.store.interrupt_inventory_jobs()
        for job in runtime.store.pending_action_jobs():
            if job["state"] == "sending" or (job["operation"] in ("reboot_server", "reboot_bmc", "collect_support_bundle") and not job["task_uri"]):
                runtime.store.update_action_job(job["id"], "uncertain",
                                                error="Manager restarted before the BMC outcome was confirmed")
            else:
                runtime.start_action_monitor(job["id"])
        if start_workers:
            for server in runtime.store.servers(active_only=True):
                runtime.start_server(server)
            runtime.worker = threading.Thread(target=runtime.log_loop, daemon=True)
            runtime.worker.start()
            runtime.metrics_worker = threading.Thread(target=runtime.metrics_loop, daemon=True)
            runtime.metrics_worker.start()
            runtime.inventory_worker = threading.Thread(target=runtime.inventory_loop, daemon=True)
            runtime.inventory_worker.start()
            runtime.health_worker = threading.Thread(target=runtime.health_loop, daemon=True)
            runtime.health_worker.start()
        yield
        backup_jobs.close()
        runtime.stop.set()
        if runtime.worker:
            runtime.worker.join(timeout=5)
        if runtime.metrics_worker:
            runtime.metrics_worker.join(timeout=5)
        if runtime.inventory_worker:
            runtime.inventory_worker.join(timeout=5)
        if runtime.health_worker:
            runtime.health_worker.join(timeout=5)
        for worker in list(runtime.action_workers.values()):
            worker.join(timeout=5)
        for server_id in list(runtime.processes):
            runtime.stop_server(server_id)
        for server_id in list(runtime.console_processes):
            runtime.stop_console(server_id)

    app = FastAPI(title="Cisco UCS C880A M8 – Fleet Operations", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.runtime = runtime
    app.state.prometheus = managed_prometheus
    app.state.backup_jobs = backup_jobs
    restore_guard = threading.Lock()

    @app.middleware("http")
    async def installation_changes(request: Request, call_next):
        path = request.url.path
        protected = (request.method not in ("GET", "HEAD") and (
            path.startswith("/api/configuration/") or path.startswith("/api/users") or
            path == "/api/runtime/restart" or
            path == "/api/servers" or
            request.method == "DELETE" and re.fullmatch(r"/api/servers/[^/]+", path)))
        if not protected:
            return await call_next(request)
        try:
            require_session(request, mutation=True)
            with installation_lease(config.data_dir):
                pending_names = ["restore.pending.json", "restore.transaction.json"]
                # A supervised restart is how a staged deployment activates or
                # recovers. It must remain available; restore keys travel via
                # their own activation pipe and cannot be replaced by a restart.
                if path != "/api/runtime/restart":
                    pending_names.append("deployment.pending.json")
                    pending_names.append("deployment.prometheus.json")
                if any((config.data_dir / name).exists() for name in pending_names):
                    raise BackupError("Installation activation or recovery is in progress; check its status before changing data")
                return await call_next(request)
        except HTTPException as error:
            return JSONResponse({"detail":error.detail}, status_code=error.status_code)
        except BackupError as error:
            return JSONResponse({"detail":str(error)}, status_code=409)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        console_host = config.console_advertise_host
        # CSP host-source cannot express an IPv6 literal (Chrome rejects the
        # bracketed address), so allow HTTPS forms for that case. The launch
        # code still checks the exact host and the gateway checks Origin/CSRF.
        console_form_source = ("https:" if ":" in console_host else
                               f"https://{console_host}:*")
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        # Cross-port console form POSTs need a real Origin header. With
        # no-referrer, browsers serialize their Origin as null for navigation.
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = getattr(request.state, "prometheus_csp", None) or ("default-src 'self'; script-src 'self'; "
            "style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
            f"form-action 'self' {console_form_source}")
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=86400"
        return response

    def require_session(request: Request, *, mutation: bool = False,
                        admin: bool | None = None, touch: bool = True,
                        allow_password_setup: bool = False) -> dict[str, Any]:
        token = request.cookies.get(COOKIE, "")
        session = runtime.store.session(token, touch=touch) if token else None
        if not session:
            raise HTTPException(401, "Sign in required")
        if mutation and not hmac.compare_digest(request.headers.get("X-CSRF-Token", ""), session["csrf"]):
            raise HTTPException(403, "Invalid CSRF token")
        if session["must_change_password"] and not allow_password_setup:
            raise HTTPException(403, "Change the initial password before using the manager")
        if (mutation if admin is None else admin) and session["role"] != "admin":
            raise HTTPException(403, "Admin role required")
        return session

    @app.get("/")
    async def index():
        return FileResponse(STATIC / "index.html", media_type="text/html")

    @app.get("/health")
    async def health():
        # Reachability only: no authentication or deployment information.
        return {"status": "ok"}

    @app.get("/api/version")
    async def version():
        return public_build

    @app.get("/app.js")
    async def javascript():
        return FileResponse(STATIC / "app.js", media_type="text/javascript")

    @app.get("/fleet-view.js")
    async def fleet_view_javascript():
        return FileResponse(STATIC / "fleet-view.js", media_type="text/javascript")

    @app.get("/app.css")
    async def stylesheet():
        return FileResponse(STATIC / "app.css", media_type="text/css")

    @app.get("/prometheus-session.js")
    async def prometheus_session_javascript():
        return FileResponse(STATIC / "prometheus-session.js", media_type="text/javascript")

    @app.get("/prometheus-return.js")
    async def prometheus_return_javascript():
        return FileResponse(STATIC / "prometheus-return.js", media_type="text/javascript")

    @app.get("/prometheus-settings.js")
    async def prometheus_settings_javascript():
        return FileResponse(STATIC / "prometheus-settings.js", media_type="text/javascript")

    @app.get("/prometheus")
    async def prometheus_root():
        return RedirectResponse("/prometheus/", status_code=307)

    @app.api_route("/prometheus/{path:path}", methods=["GET", "POST"])
    async def prometheus_browser(path: str, request: Request):
        managed_page = path in ("config", "flags", "alertmanager-discovery") and request.method == "GET"
        page = (path in PROMETHEUS_PAGES and request.method == "GET") or managed_page
        target = request.url.path + ("?" + request.url.query if request.url.query else "")
        try:
            current = require_session(request, touch=False)
        except HTTPException as exc:
            if page and exc.status_code in (401, 403):
                return RedirectResponse(login_location(target), status_code=303)
            raise
        if managed_page:
            return state_page("Managed configuration", "Prometheus settings are managed by Fleet Operations.",
                admin=current["role"] == "admin", target=target, status=200)
        if not prometheus_path_allowed(path, request.method):
            raise HTTPException(403, "This Prometheus endpoint is not available through the manager")
        if request.method == "POST":
            # These POSTs only evaluate queries. They never reach administrative
            # APIs, and must originate at this manager's authenticated origin.
            def origin(value: str):
                try:
                    parsed = urlsplit(value)
                    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or
                            parsed.password or parsed.path or parsed.query or parsed.fragment):
                        return None
                    return parsed.hostname.lower(), parsed.port or 443
                except ValueError:
                    return None
            supplied = origin(request.headers.get("Origin", ""))
            if supplied is None or supplied != origin(config.manager_origin.rstrip("/")):
                raise HTTPException(403, "Prometheus query requires the manager origin")
            if request.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/x-www-form-urlencoded":
                raise HTTPException(415, "Expected a Prometheus form query")
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > PROMETHEUS_MAX_REQUEST:
                raise HTTPException(413, "Prometheus request exceeds the limit")
            body.extend(chunk)
        try:
            installed = (managed_prometheus.root / "installation.json").is_file()
            enabled = managed_prometheus.settings()["enabled"]
        except (PrometheusError, ValueError, KeyError, OSError):
            installed, enabled = False, True
        if not installed or not enabled:
            message = ("Prometheus is disabled. Stored history is kept." if installed else
                       "Prometheus is unavailable. " + ("Check its installation in Configuration." if current["role"] == "admin" else "Retry shortly or ask an administrator to check the service."))
            if page:
                return state_page("Prometheus is disabled" if installed else "Prometheus is unavailable",
                    message, admin=current["role"] == "admin", target=target,
                    retry=not installed)
            raise HTTPException(503, message)
        if path in ("", "graph"):
            return RedirectResponse("/prometheus/query" +
                ("?" + request.url.query if request.url.query else ""), status_code=303)
        if path == "api/v1/notifications/live":
            return await notification_response(managed_prometheus, request,
                lambda: require_session(request, touch=False), prometheus_notifications)
        if not prometheus_requests.acquire(blocking=False):
            raise HTTPException(429, "Prometheus is busy; retry shortly")
        try:
            response = await run_in_threadpool(engine_response, managed_prometheus, path,
                                              request.method, request.url.query, bytes(body))
        except HTTPException as exc:
            if page and exc.status_code == 503:
                return state_page("Prometheus is unavailable", "Check its state in Configuration, then retry." if current["role"] == "admin" else "Retry shortly or ask an administrator to check the service.",
                    admin=current["role"] == "admin", target=target, retry=True)
            if exc.status_code == 503 and current["role"] != "admin":
                raise HTTPException(503, "Prometheus is unavailable. Retry shortly or ask an administrator to check the service.") from None
            raise
        finally:
            prometheus_requests.release()
        if page and response.status_code == 503:
            return state_page("Prometheus is unavailable", "Check its state in Configuration, then retry." if current["role"] == "admin" else "Retry shortly or ask an administrator to check the service.",
                admin=current["role"] == "admin", target=target, retry=True)
        # Only our fixed native-HTML transformer may relax style policy. Never
        # pass an upstream/browser-provided CSP through the manager middleware.
        if "Content-Security-Policy" in response.headers:
            request.state.prometheus_csp = response.headers["Content-Security-Policy"]
        return response

    @app.get("/fonts/InterVariable.woff2")
    async def inter_font():
        # Fixed packaged path: the browser never supplies a filesystem name.
        return FileResponse(STATIC / "fonts" / "InterVariable.woff2", media_type="font/woff2")

    @app.get("/api/bootstrap-required")
    async def bootstrap_required():
        return {"required": runtime.store.bootstrap_required()}

    @app.post("/api/bootstrap")
    async def bootstrap(body: BootstrapInput):
        if not runtime.store.bootstrap(body.token, body.password):
            raise HTTPException(400, "Invalid setup token")
        runtime.store.audit(None, "bootstrap", "admin")
        return {"ok": True}

    @app.post("/api/login")
    async def login(body: LoginInput, request: Request):
        import time
        client_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        attempts = [stamp for stamp in runtime.login_attempts.get(client_ip, []) if now - stamp < 300]
        if len(attempts) >= 10:
            raise HTTPException(429, "Too many login attempts")
        result = await run_in_threadpool(runtime.store.login, body.username, body.password)
        if not result:
            attempts.append(now)
            runtime.login_attempts[client_ip] = attempts
            raise HTTPException(401, "Invalid username or password")
        runtime.login_attempts.pop(client_ip, None)
        token, csrf = result
        user = runtime.store.session(token, touch=False)
        response = JSONResponse({"ok": True, "csrf": csrf, "username": user["username"],
                                 "role": user["role"],
                                 "password_change_required": bool(user["must_change_password"])})
        response.set_cookie(COOKIE, token, secure=True, httponly=True, samesite="strict", path="/")
        return response

    @app.get("/api/session")
    async def session(request: Request, observe: bool = False):
        current = require_session(request, touch=not observe, allow_password_setup=True)
        return {"username": current["username"], "role": current["role"], "csrf": current["csrf"],
                "password_change_required": bool(current["must_change_password"])}

    @app.put("/api/initial-password")
    async def initial_password(body: UserPasswordInput, request: Request):
        current = require_session(request, mutation=True, admin=True, allow_password_setup=True)
        if not current["must_change_password"]:
            raise HTTPException(409, "Initial password has already been changed")
        try:
            changed = await run_in_threadpool(runtime.store.set_initial_password,
                                              current["user_id"], body.password)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        if not changed:
            raise HTTPException(409, "Initial password has already been changed")
        runtime.store.audit(current["user_id"], "initial_password_changed", None)
        response = JSONResponse({"ok": True})
        response.delete_cookie(COOKIE, path="/")
        return response

    @app.get("/api/runtime")
    async def runtime_status(request: Request):
        require_session(request, touch=False)
        return {"boot_id": runtime.boot_id,
                "supervised": start_workers and bool(os.environ.get("C880A_RESTART_FD"))}

    @app.get("/api/runtime/resources")
    async def runtime_resources(request: Request):
        require_session(request, touch=False)
        return await run_in_threadpool(runtime.resource_sampler.sample)

    @app.post("/api/runtime/restart", status_code=202)
    async def restart_application(request: Request):
        current = require_session(request, mutation=True, admin=True)
        require_no_prometheus_change()
        with onboarding_jobs_lock:
            if any(job["state"] == "running" for job in onboarding_jobs.values()):
                raise HTTPException(409, "Onboarding is in progress; wait for it to finish before restarting")
        descriptor = os.environ.get("C880A_RESTART_FD") if start_workers else None
        if not descriptor or not descriptor.isdecimal():
            raise HTTPException(503, "Application restart requires the manager supervisor")
        runtime.store.audit(current["user_id"], "application_restart_requested", None)
        try:
            os.write(int(descriptor), b"R")
        except OSError as exc:
            raise HTTPException(503, "Manager supervisor is unavailable") from exc
        return {"accepted": True, "boot_id": runtime.boot_id}

    @app.post("/api/logout")
    async def logout(request: Request):
        require_session(request, mutation=True, admin=False, allow_password_setup=True)
        backup_jobs.logout(hashlib.sha256(request.cookies.get(COOKIE, "").encode()).hexdigest())
        runtime.store.logout(request.cookies.get(COOKIE, ""))
        response = JSONResponse({"ok": True})
        response.delete_cookie(COOKIE, path="/")
        return response

    @app.get("/api/users")
    async def users(request: Request):
        require_session(request, admin=True)
        return runtime.store.users()

    @app.post("/api/users")
    async def add_user(body: UserCreateInput, request: Request):
        current = require_session(request, mutation=True, admin=True)
        try:
            user = await run_in_threadpool(runtime.store.add_user, body.username, body.password, body.role)
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "Username already exists") from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        runtime.store.audit(current["user_id"], "user_create", user["id"])
        return user

    @app.patch("/api/users/{user_id}")
    async def update_user(user_id: str, body: UserUpdateInput, request: Request):
        current = require_session(request, mutation=True, admin=True)
        try:
            user = runtime.store.update_user(user_id, body.role, body.disabled)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        if not user:
            raise HTTPException(404, "User not found")
        runtime.store.audit(current["user_id"], "user_update", user_id)
        return user

    @app.put("/api/users/{user_id}/password")
    async def change_user_password(user_id: str, body: UserPasswordInput, request: Request):
        current = require_session(request, mutation=True, admin=True)
        if not await run_in_threadpool(runtime.store.set_user_password, user_id, body.password):
            raise HTTPException(404, "User not found")
        runtime.store.audit(current["user_id"], "user_password_change", user_id)
        return {"ok": True, "current_session_revoked": current["user_id"] == user_id}

    @app.delete("/api/users/{user_id}")
    async def remove_user(user_id: str, request: Request):
        current = require_session(request, mutation=True, admin=True)
        try:
            removed = runtime.store.delete_user(user_id)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        if not removed:
            raise HTTPException(404, "User not found")
        runtime.store.audit(current["user_id"], "user_delete", user_id)
        return {"ok": True}

    def fleet_onboarding(server: Any, discovered: dict[str, Any], running: bool) -> str | None:
        """UI-only readiness cache; never initiate or change BMC collection."""
        if (server["state"] != "active" or discovered.get("ui_onboarding_started") is not True or
                discovered.get("ui_initial_setup_complete") is True):
            return None
        server_id = server["id"]
        inventory = runtime.store.inventory_status(server_id)
        inventory_ready = discovered.get("ui_initial_inventory_complete") is True
        updates = {}
        if inventory["state"] == "complete" and not inventory["failures"]:
            inventory_ready = True
            if discovered.get("ui_initial_inventory_complete") is not True:
                updates["ui_initial_inventory_complete"] = True
        sensors = read_status(config.data_dir / f"metrics-{server_id}.prom.status")

        def published(suffix: str) -> bool:
            try:
                info = (config.data_dir / f"metrics-{server_id}.prom.{suffix}").stat(follow_symlinks=False)
                return (stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                        not info.st_mode & 0o077 and 0 < info.st_size <= 16 * 1024 * 1024 and
                        0 <= time.time() - info.st_mtime <= 600)
            except OSError:
                return False

        sensors_ready = (sensors.get("available") and sensors["tracked"] > 0 and
                         not sensors["paused"] and not sensors["missing"] and
                         not sensors["stale"] and not sensors["unresolved"] and
                         sensors["fresh"] == sensors["eligible"] and published("cache"))
        if inventory_ready and sensors_ready and running:
            updates["ui_initial_setup_complete"] = True
        if updates:
            # Merge only monotonic UI flags. Existing per-claim metadata already
            # survives restart and is removed/reset by unclaim/reclaim.
            saved = runtime.store.patch_discovery(server_id, updates, expected_cipher=server["password_cipher"])
            if saved is None:
                return None
            discovered.update(updates)
        if discovered.get("ui_initial_setup_complete") is True:
            return None
        if sensors.get("paused") or (inventory["state"] == "failed" and server_id not in runtime.inventory_active):
            return "incomplete"
        if not running:
            return "incomplete"
        # The saved failure list identifies the same targeted continuation plan
        # used by the inventory worker; do not call a generic partial pass recovery.
        if not inventory_ready and server_id in runtime.inventory_active and inventory["failures"]:
            previous = runtime.store.inventory(server_id)
            if inventory_retry_sources({**previous, "state": "partial"},
                                       max_age=runtime.inventory_interval(server_id)):
                return "recovering"
        if sensors.get("available") and sensors["exhausted"]:
            return "incomplete"
        if sensors.get("available") and sensors["unresolved"] and runtime.collection_log:
            try:
                journal = runtime.collection_log._state()
                alias = journal["aliases"].get(server_id)
                if alias and alias + ":sensor_recovery" in journal["pending"]:
                    return "recovering"
            except (OSError, ValueError, KeyError, TypeError):
                pass  # Missing UI evidence must not disturb collection or fleet reads.
        if not sensors_ready:
            return "sensors" if sensors.get("available") or inventory["state"] != "pending" else "initializing"
        return "inventory"

    def public_server(server: Any) -> dict[str, Any]:
        process = runtime.processes.get(server["id"])
        scheme = "https"
        discovered = json.loads(server["discovered_json"])
        running = process is not None and process.poll() is None
        onboarding = fleet_onboarding(server, discovered, running)
        discovered.pop("ui_onboarding_started", None)
        discovered.pop("ui_initial_inventory_complete", None)
        discovered.pop("ui_initial_setup_complete", None)
        discovered["warnings"] = [warning for warning in discovered.get("warnings", [])
                                  if not warning.startswith("ThermalSubsystem endpoint did not respond")]
        return {"id": server["id"], "name": server["name"], "bmc_host": server["bmc_host"],
                "bmc_port": server["bmc_port"],
                "port": server["port"], "state": server["state"],
                "manager_metrics_enabled": bool(server["manager_metrics_enabled"]),
                "bmc_actions_enabled": config.bmc_actions_enabled,
                "exporter_running": running, "onboarding_stage": onboarding,
                "scrape_url": f"{scheme}://{url_host(config.exporter_advertise_host)}:{server['port']}/metrics",
                "discovery": discovered,
                "active_action": next((public_action_job(job) for job in runtime.store.action_jobs(server["id"], 1)
                                       if job["state"] in ("sending", "submitted", "running")), None)}

    @app.get("/api/servers")
    async def servers(request: Request):
        require_session(request)
        return [public_server(server) for server in runtime.store.servers()]

    @app.get("/api/configuration/collection-log")
    async def download_collection_log(request: Request):
        require_session(request, admin=True)
        if request.query_params:
            raise HTTPException(400, "Collection log download takes no parameters")
        if runtime.collection_log is None:
            raise HTTPException(503, "Collection log unavailable")
        if not runtime.collection_log_download_slot.acquire(blocking=False):
            raise HTTPException(429, "Collection log download is busy; try again")
        try:
            try:
                payload = await run_in_threadpool(runtime.collection_log.export)
            except (OSError, ValueError, TypeError, KeyError, OverflowError):
                raise HTTPException(503, "Collection log unavailable; try again") from None
            return Response(payload, media_type="application/x-ndjson", headers={
                "Content-Disposition": 'attachment; filename="c880a-collection-log.jsonl"',
                "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
        finally:
            runtime.collection_log_download_slot.release()

    @app.get("/api/configuration")
    async def configuration(request: Request):
        require_session(request, admin=True)
        targets = [{"id": server["id"], "name": server["name"],
                    "bmc_host": server["bmc_host"], "bmc_port": server["bmc_port"],
                    "insecure_bmc": bool(server["insecure_bmc"]),
                    "manager_metrics_enabled": bool(server["manager_metrics_enabled"]),
                    "inventory_interval_override": runtime.store.inventory(server["id"])["interval_override"]}
                   for server in runtime.store.servers(active_only=True)]
        return {"collection": {
            "inventory_interval_seconds": runtime.interval("inventory_interval_seconds", 3600),
            "live_metrics_interval_seconds": runtime.interval("live_metrics_interval_seconds", config.live_metrics_interval),
            "manager_scrape_interval_seconds": runtime.interval("manager_scrape_interval_seconds", config.metrics_scrape_interval),
            "health_check_interval_seconds": runtime.interval("health_check_interval_seconds", 300)},
            "console": {"idle_minutes": runtime.store.setting("console_idle_minutes", 15),
                        "login_idle_minutes": runtime.store.setting("login_idle_minutes", 20)},
            "fixed": {"event_poll_without_sse_seconds": 300, "event_poll_with_sse_seconds": 600,
                      "metric_retention_hours": 24},
            "targets": targets,
            "deployment": ({key: value for key, value in (config.deployment or {}).items()
                            if key not in ("certificate", "bmc_ca")}),
            "local_addresses": local_addresses(),
            "local_interfaces": local_interface_options(),
            "certificate": ({key: config.deployment["certificate"].get(key) for key in
                             ("source", "expires_at", "fingerprint")}
                            if config.deployment else None),
            "bmc_ca_configured": bool(config.bmc_ca),
            "deployment_pending": ((config.data_dir / "deployment.pending.json").exists() or
                                   (config.data_dir / "deployment.prometheus.json").exists()),
            "deployment_last": (json.loads((config.data_dir / "deployment.last.json").read_text())
                                if (config.data_dir / "deployment.last.json").exists() else None),
            "restart_required": {"manager_origin": config.manager_origin,
                                 "manager_bind": (config.deployment or {}).get("manager_bind", "unknown"),
                                 "manager_port": (config.deployment or {}).get("manager_port", "unknown"),
                                 "exporter_bind": config.exporter_bind,
                                 "exporter_advertise_host": config.exporter_advertise_host,
                                 "exporter_port_range": f"{config.port_start}–{config.port_end}",
                                 "console_bind": config.console_bind,
                                 "console_advertise_host": config.console_advertise_host,
                                 "console_port_offset": config.console_port_offset}}

    def require_no_prometheus_change():
        if (prometheus_change_guard.locked() or (managed_prometheus.root / "pending.json").exists() or
                (managed_prometheus.root / "delete.pending.json").exists() or runtime.store.pending_prometheus_deletions()):
            raise HTTPException(409, "Wait for Prometheus recovery or settings application before changing the installation")

    @app.get("/api/prometheus/status")
    async def prometheus_status(request: Request):
        require_session(request, touch=False)
        return await run_in_threadpool(prometheus_discovery.status, managed_prometheus,
            claimed=runtime.store.servers(active_only=True), origin=config.manager_origin,
            cleanup_operation=runtime.store.pending_prometheus_cleanup())

    async def change_prometheus(request: Request, body: PrometheusOperationInput, settings: dict | None):
        current = require_session(request, mutation=True, admin=True)
        if not prometheus_change_guard.acquire(blocking=False):
            raise HTTPException(409, "Another Prometheus change is in progress")
        try:
            if runtime.store.pending_prometheus_deletions() or (managed_prometheus.root / "delete.pending.json").exists():
                raise HTTPException(409, "Finish target history cleanup before changing Prometheus")
            if restore_guard.locked() or any((config.data_dir / name).exists() for name in
                    ("deployment.pending.json", "deployment.prometheus.json", "restore.pending.json", "restore.transaction.json")):
                raise HTTPException(409, "Wait for installation recovery before changing Prometheus")
            if settings is None:
                settings = {**managed_prometheus.settings(), "enabled": body.enabled}
            result = await run_in_threadpool(managed_prometheus.change, settings, operation_id=body.operation_id)
            runtime.store.audit(current["user_id"], "prometheus_settings_" + result["status"], body.operation_id)
            return {key: result.get(key) for key in ("id", "status", "reason", "at")}
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        except PrometheusError as exc:
            raise HTTPException(409, str(exc)) from None
        finally:
            prometheus_change_guard.release()

    @app.put("/api/configuration/prometheus")
    async def update_prometheus(body: PrometheusSettingsInput, request: Request):
        return await change_prometheus(request, body, body.model_dump(exclude={"operation_id"}))

    @app.patch("/api/configuration/prometheus/enabled")
    async def toggle_prometheus(body: PrometheusToggleInput, request: Request):
        return await change_prometheus(request, body, None)

    @app.post("/api/configuration/prometheus/recover")
    async def recover_prometheus(body: PrometheusOperationInput, request: Request):
        current = require_session(request, mutation=True, admin=True)
        if not prometheus_change_guard.acquire(blocking=False):
            raise HTTPException(409, "Another Prometheus change is in progress")
        try:
            deletion = (read_config(managed_prometheus.root, name="delete.pending.json") or
                        runtime.store.pending_prometheus_cleanup())
            if deletion:
                if deletion["id"] != body.operation_id:
                    raise HTTPException(409, "Prometheus recovery changed; refresh its status")
                await run_in_threadpool(cleanup_history, runtime.store, managed_prometheus,
                                        backup_workspace, _lease=False)
                runtime.store.audit(current["user_id"], "prometheus_history_recovery", body.operation_id)
                last = read_config(managed_prometheus.root, name="last.json")
                return {key:last.get(key) for key in ("id", "status", "reason", "at")}
            pending = read_config(managed_prometheus.root, name="pending.json")
            if not pending or pending.get("id") != body.operation_id:
                raise HTTPException(409, "Prometheus recovery changed; refresh its status")
            await run_in_threadpool(managed_prometheus.recover)
            runtime.store.audit(current["user_id"], "prometheus_recovery", body.operation_id)
            last = read_config(managed_prometheus.root, name="last.json")
            return {key: last.get(key) for key in ("id", "status", "reason", "at")}
        except (PrometheusError, BackupError) as exc:
            raise HTTPException(409, str(exc)) from None
        finally:
            prometheus_change_guard.release()

    def backup_owner(request):
        return hashlib.sha256(request.cookies.get(COOKIE, "").encode()).hexdigest()

    async def owned_backup_task(request, function):
        cancelled = threading.Event()
        owner = backup_owner(request)
        async def observe_disconnect():
            while not cancelled.is_set():
                if await request.is_disconnected():
                    cancelled.set()
                    return
                await asyncio.sleep(.25)
        observer = asyncio.create_task(observe_disconnect())
        try:
            result = await run_in_threadpool(function,
                lambda:cancelled.is_set() or not backup_jobs._owner_valid(owner))
            return result
        finally:
            cancelled.set()
            observer.cancel()
            try:
                await observer
            except asyncio.CancelledError:
                pass

    @app.post("/api/backup/jobs", status_code=202)
    async def prepare_backup_job(body: BackupCreateInput, request: Request):
        current = require_session(request, mutation=True, admin=True)
        if not body.acknowledge_sensitive:
            raise HTTPException(400, "Acknowledge that the archive contains sensitive data")
        try:
            identifier = backup_jobs.start(backup_owner(request), body.scope, body.passphrase)
        except BackupError as error:
            raise HTTPException(409, str(error)) from None
        runtime.store.audit(current["user_id"], "backup_requested", body.scope)
        return {"id":identifier}

    @app.get("/api/backup/jobs/{identifier}")
    async def backup_job_status(identifier: str, request: Request):
        require_session(request, admin=True, touch=False)
        try:
            return backup_jobs.status(backup_owner(request), identifier)
        except BackupError as error:
            raise HTTPException(404, str(error)) from None

    @app.get("/api/backup/job")
    async def current_backup_job(request: Request):
        require_session(request, admin=True, touch=False)
        return backup_jobs.current(backup_owner(request))

    @app.delete("/api/backup/jobs/{identifier}")
    async def cancel_backup_job(identifier: str, request: Request):
        require_session(request, mutation=True, admin=True)
        try:
            backup_jobs.cancel(backup_owner(request), identifier)
            return backup_jobs.status(backup_owner(request), identifier)
        except BackupError as error:
            raise HTTPException(409, str(error)) from None

    @app.get("/api/backup/jobs/{identifier}/download")
    async def download_backup_job(identifier: str, request: Request):
        require_session(request, admin=True, touch=False)
        try:
            chunks, headers = backup_jobs.download(backup_owner(request), identifier)
        except BackupError as error:
            raise HTTPException(409, str(error)) from None
        return StreamingResponse(chunks, media_type="application/octet-stream", headers=headers,
            background=BackgroundTask(backup_jobs.finish_download, backup_owner(request), identifier))

    @app.post("/api/backup/download")
    async def download_backup(body: BackupCreateInput, request: Request):
        current = require_session(request, mutation=True, admin=True)
        if not body.acknowledge_sensitive:
            raise HTTPException(400, "Acknowledge that the archive contains sensitive data")
        try:
            owner = backup_owner(request)
            identifier = backup_jobs.start(owner, body.scope, body.passphrase)
            await owned_backup_task(request, lambda cancel:backup_jobs.wait_ready(owner, identifier, cancel=cancel))
            require_session(request, admin=True, touch=False)
            chunks, headers = backup_jobs.download(owner, identifier)
        except BackupError as exc:
            raise HTTPException(400, str(exc)) from None
        runtime.store.audit(current["user_id"], "backup_download_prepared", body.scope)
        return StreamingResponse(chunks, media_type="application/octet-stream", headers=headers,
            background=BackgroundTask(backup_jobs.finish_download, owner, identifier))

    @app.post("/api/backup/preview")
    async def preview_backup_restore(request: Request):
        require_session(request, mutation=True, admin=True)
        try:
            length = int(request.headers.get("content-length", ""))
        except ValueError:
            length = -1
        if not 0 < length <= BackupLimits().archive_bytes + 8192:
            raise HTTPException(413, "Backup upload is missing a valid size or exceeds the limit")
        if not request.headers.get("content-type", "").lower().startswith("multipart/form-data;"):
            raise HTTPException(415, "Expected multipart backup upload")
        try:
            await run_in_threadpool(backup_space, backup_workspace, 3 * length, BackupLimits())
        except BackupError as error:
            raise HTTPException(413, str(error)) from None
        async with request.form(max_files=1, max_fields=2, max_part_size=2048) as form:
            uploaded = form.get("archive")
            passphrase = form.get("passphrase")
            replacement = form.get("replacement_address")
            if not isinstance(uploaded, UploadFile) or not isinstance(passphrase, str):
                raise HTTPException(400, "Archive file and passphrase are required")
            if not 16 <= len(passphrase) <= 1024:
                raise HTTPException(400, "Passphrase must be 16–1024 characters")
            if replacement is not None and not isinstance(replacement, str):
                raise HTTPException(400, "Invalid replacement address")
            def preview(cancel):
                with private_upload(uploaded.file, backup_workspace, cancel=cancel) as path:
                    with opened_upload(path, passphrase, backup_workspace, cancel=cancel) as archive:
                        plan = plan_history_restore(runtime.store, managed_prometheus, archive,
                            backup_workspace, replacement or None, cancel=cancel)
                        return {"manifest":{**archive.metadata["manifest"], "archive_format":archive.format}, "plan":plan,
                                "archive_sha256":archive.archive_sha256}
            try:
                result = await owned_backup_task(request, preview)
                require_session(request, admin=True, touch=False)
                return result
            except BackupError as exc:
                raise HTTPException(400, str(exc)) from None

    @app.get("/api/backup/last")
    async def last_restore(request: Request):
        require_session(request, admin=True, touch=False)
        pending = read_config(config.data_dir, name="restore.pending.json")
        journal = read_config(config.data_dir, name="restore.transaction.json")
        return {"pending": ({"id": pending["id"], "scope": pending["scope"],
                             "current_url": pending["plan"].get("current_url") or config.manager_origin,
                             "result_url": pending["plan"].get("result_url") or
                                           pending["plan"].get("destination_manager_origin") or config.manager_origin,
                             "status": journal.get("phase", "applying") if journal else "queued"}
                            if pending else None),
                "last": read_config(config.data_dir, name="restore.last.json")}

    @app.post("/api/backup/restore", status_code=202)
    async def commit_backup_restore(request: Request):
        current_user = require_session(request, mutation=True, admin=True)
        descriptor = os.environ.get("C880A_RESTART_FD") if start_workers else None
        if not descriptor or not descriptor.isdecimal():
            raise HTTPException(503, "Restore requires the manager supervisor")
        if (config.data_dir / "deployment.pending.json").exists():
            raise HTTPException(409, "A deployment change is already pending")
        try:
            length = int(request.headers.get("content-length", ""))
        except ValueError:
            length = -1
        if not 0 < length <= BackupLimits().archive_bytes + 256 * 1024:
            raise HTTPException(413, "Backup upload is missing a valid size or exceeds the limit")
        if not request.headers.get("content-type", "").lower().startswith("multipart/form-data;"):
            raise HTTPException(415, "Expected multipart backup upload")
        try:
            await run_in_threadpool(backup_space, backup_workspace, 3 * length, BackupLimits())
        except BackupError as error:
            raise HTTPException(413, str(error)) from None
        async with request.form(max_files=1, max_fields=6, max_part_size=128 * 1024) as form:
            uploaded = form.get("archive")
            passphrase = form.get("passphrase")
            reviewed_json = form.get("reviewed_plan")
            digest = form.get("archive_sha256")
            replacement = form.get("replacement_address")
            if not isinstance(uploaded, UploadFile) or not isinstance(passphrase, str) or not isinstance(reviewed_json, str):
                raise HTTPException(400, "Archive, passphrase, and reviewed plan are required")
            if not 16 <= len(passphrase) <= 1024 or len(reviewed_json) > 128 * 1024:
                raise HTTPException(400, "Invalid passphrase or reviewed plan")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise HTTPException(400, "Archive identity is invalid")
            if replacement is not None and not isinstance(replacement, str):
                raise HTTPException(400, "Replacement address is invalid")
            if form.get("acknowledge_interruption") != "yes":
                raise HTTPException(400, "Confirm that restore will interrupt HTTPS and replace data")
            if form.get("confirmation") != "RESTORE":
                raise HTTPException(400, "Type RESTORE to confirm the reviewed restore")
            if not restore_guard.acquire(blocking=False):
                raise HTTPException(409, "Another restore is being prepared")
            try:
                require_no_prometheus_change()
                reviewed = json.loads(reviewed_json)
                def stage(cancel):
                    with private_upload(uploaded.file, backup_workspace, cancel=cancel) as path:
                        with opened_upload(path, passphrase, backup_workspace, cancel=cancel) as archive:
                            if archive.archive_sha256 != digest:
                                raise BackupError("Selected archive changed since preview")
                            operation, key = stage_file_restore(runtime.store, managed_prometheus,
                                archive, reviewed, backup_workspace, replacement or None, cancel=cancel)
                            return operation, key
                operation_id, one_time_key = await owned_backup_task(request, stage)
                try:
                    require_session(request, admin=True, touch=False)
                    runtime.store.audit(current_user["user_id"], "restore_requested", reviewed["scope"])
                    os.write(int(descriptor), b"B" + one_time_key)
                except (OSError, sqlite3.Error, HTTPException) as error:
                    # Staging has not altered installation data. A failed pipe
                    # notification discards only this operation's ciphertext.
                    (config.data_dir / f"restore-{operation_id}.sealed").unlink(missing_ok=True)
                    (config.data_dir / "restore.pending.json").unlink(missing_ok=True)
                    if isinstance(error, HTTPException):
                        raise
                    raise HTTPException(503, "Manager supervisor is unavailable") from None
            except (BackupError, json.JSONDecodeError) as exc:
                raise HTTPException(409, str(exc)) from None
            finally:
                restore_guard.release()
        return {"accepted": True, "operation_id": operation_id,
                "result_url": reviewed.get("result_url", config.manager_origin),
                "message": "Supervisor will stop, apply, probe HTTPS, and roll back if unhealthy"}

    @app.patch("/api/configuration/collection")
    async def update_collection(body: CollectionSettingsInput, request: Request):
        current = require_session(request, mutation=True)
        values = body.model_dump(exclude_none=True)
        runtime.store.set_settings(values)
        runtime.store.audit(current["user_id"], "collection_settings_update", json.dumps(values))
        return await configuration(request)

    @app.patch("/api/configuration/console")
    async def update_console(body: ConsoleSettingsInput, request: Request):
        current = require_session(request, mutation=True)
        runtime.store.set_settings({"console_idle_minutes": body.idle_minutes,
                                    "login_idle_minutes": body.login_idle_minutes})
        runtime.store.audit(current["user_id"], "session_settings_update", None)
        return await configuration(request)

    def stage_restart(proposal: dict, user_id: str, action: str) -> dict[str, Any]:
        require_no_prometheus_change()
        descriptor = os.environ.get("C880A_RESTART_FD") if start_workers else None
        if not descriptor or not descriptor.isdecimal():
            raise HTTPException(503, "Deployment changes require the manager supervisor")
        if (config.data_dir / "deployment.pending.json").exists():
            raise HTTPException(409, "A deployment change is already pending")
        atomic_config(config.data_dir, "deployment.pending.json", proposal)
        try:
            os.write(int(descriptor), b"R")
        except OSError as exc:
            (config.data_dir / "deployment.pending.json").unlink(missing_ok=True)
            raise HTTPException(503, "Manager supervisor is unavailable") from exc
        runtime.store.audit(user_id, action, None)
        return {"accepted": True, "message": "Restarting HTTPS listeners; reconnect to the advertised manager address"}

    @app.put("/api/configuration/deployment", status_code=202)
    async def update_deployment(body: DeploymentInput, request: Request):
        current = require_session(request, mutation=True, admin=True)
        if not body.acknowledge_interruption:
            raise HTTPException(400, "Acknowledge that listener changes interrupt scrapes and consoles")
        if not config.deployment:
            raise HTTPException(503, "Deployment settings require a supervised manager")
        selected = body.model_dump(exclude={"acknowledge_interruption"})
        bind = selected.pop("bind_address")
        dns = selected.pop("advertised_dns_name").strip()
        if dns:
            try:
                host = host_name(dns)
            except ValueError as exc:
                raise HTTPException(400, f"Invalid advertised DNS name: {exc}") from None
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass
            else:
                raise HTTPException(400, "Advertised DNS name must be a DNS name; leave it empty to use the selected IP")
        else:
            host = bind
        proposed = {**config.deployment, **selected,
                    "manager_bind": bind, "exporter_bind": bind, "console_bind": bind,
                    "manager_host": host, "exporter_host": host, "console_host": host}
        proposed.pop("manager_origin", None)
        try:
            proposed = validate_network(proposed, occupied_ports={server["port"] for server in runtime.store.servers()})
            certificate = proposed["certificate"]
            validate_certificate(Path(certificate["cert"]).read_bytes(), Path(certificate["key"]).read_bytes(),
                                 b"", [proposed["manager_host"], proposed["console_host"], proposed["exporter_host"]])
            active_ports = {server["port"] for server in runtime.store.servers(active_only=True)}
            for bind, ports in ((proposed["manager_bind"], {proposed["manager_port"]}),
                                (proposed["exporter_bind"], active_ports),
                                (proposed["console_bind"], {port + proposed["console_port_offset"] for port in active_ports})):
                for port in ports:
                    if (bind, port) in ((config.deployment["manager_bind"], config.deployment["manager_port"]),
                                        *((config.exporter_bind, p) for p in active_ports),
                                        *((config.console_bind, p + config.console_port_offset) for p in active_ports)):
                        continue
                    with socket.socket(socket.AF_INET6 if ":" in bind else socket.AF_INET) as probe:
                        probe.bind((bind, port))
        except (OSError, ValueError, KeyError) as exc:
            raise HTTPException(400, f"Invalid deployment: {exc}") from None
        return stage_restart(proposed, current["user_id"], "deployment_update")

    @app.put("/api/configuration/certificate", status_code=202)
    async def install_certificate(body: CertificateInput, request: Request):
        current = require_session(request, mutation=True, admin=True)
        if not body.acknowledge_interruption:
            raise HTTPException(400, "Acknowledge that certificate rotation interrupts HTTPS connections")
        if not config.deployment:
            raise HTTPException(503, "Certificate rotation requires a supervised manager")
        try:
            material = stage_certificate(config.data_dir, body.certificate_pem.encode(),
                                         body.private_key_pem.encode(), body.chain_pem.encode(),
                                         [config.deployment[name] for name in
                                          ("manager_host", "console_host", "exporter_host")],
                                         "operator-provided")
        except (OSError, ValueError) as exc:
            raise HTTPException(400, f"Invalid certificate: {exc}") from None
        return stage_restart({**config.deployment, "certificate": material},
                             current["user_id"], "certificate_install")

    @app.post("/api/configuration/certificate/generate", status_code=202)
    async def regenerate_certificate(body: GenerateCertificateInput, request: Request):
        current = require_session(request, mutation=True, admin=True)
        if not config.deployment:
            raise HTTPException(503, "Certificate rotation requires a supervised manager")
        hosts = [config.deployment[name] for name in ("manager_host", "console_host", "exporter_host")]
        try:
            additional = [host_name(value) for value in body.additional_hosts]
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        cert, key = generate_certificate(hosts + [config.exporter_bind, *additional])
        material = stage_certificate(config.data_dir, cert, key, b"", hosts, "installation-generated")
        return stage_restart({**config.deployment, "certificate": material},
                             current["user_id"], "certificate_regenerate")

    @app.put("/api/configuration/bmc-ca", status_code=202)
    async def update_bmc_ca(body: BmcCaInput, request: Request):
        current = require_session(request, mutation=True, admin=True)
        if not config.deployment:
            raise HTTPException(503, "CA changes require a supervised manager")
        if not body.ca_pem:
            if not config.bmc_ca:
                raise HTTPException(400, "No custom BMC CA is configured")
            if not body.confirm_clear:
                raise HTTPException(400, "Confirm removal of the custom BMC CA")
        if body.ca_pem:
            try:
                validate_ca_bundle(body.ca_pem.encode())
                path = config.data_dir / f"bmc-ca-{secrets.token_hex(12)}.pem"
                write_private(path, body.ca_pem.encode())
            except (OSError, ValueError) as exc:
                raise HTTPException(400, f"Invalid BMC CA bundle: {exc}") from None
            value = str(path)
        else:
            value = None
        return stage_restart({**config.deployment, "bmc_ca": value},
                             current["user_id"], "bmc_ca_update")

    @app.get("/api/servers/{server_id}/inventory")
    async def server_inventory(server_id: str, request: Request, since: int | None = None):
        require_session(request, touch=False)
        server = runtime.store.get_server(server_id)
        if not server or server["state"] != "active":
            raise HTTPException(404, "Server not found")
        if since is not None and since < 0:
            raise HTTPException(400, "Invalid inventory revision")
        status = runtime.store.inventory_status(server_id)
        if since is not None and since == status["revision"]:
            result = {**status, "snapshot": None, "unchanged": True}
        else:
            result = runtime.store.inventory(server_id)
            result["unchanged"] = False
        result["effective_interval_seconds"] = (result["interval_override"]
                                                if result["interval_override"] is not None
                                                else runtime.interval("inventory_interval_seconds", 3600))
        result["running"] = server_id in runtime.inventory_active
        return result

    @app.post("/api/servers/{server_id}/inventory/refresh")
    async def refresh_inventory(server_id: str, request: Request):
        current = require_session(request, mutation=True)
        server = runtime.store.get_server(server_id)
        if not server or server["state"] != "active":
            raise HTTPException(404, "Server not found")
        if not runtime.start_inventory(server_id, manual=True):
            raise HTTPException(409, "Inventory is running or was refreshed in the last minute")
        runtime.store.audit(current["user_id"], "inventory_refresh", server_id)
        return {"started": True}

    @app.patch("/api/servers/{server_id}/inventory/interval")
    async def set_inventory_interval(server_id: str, body: InventoryIntervalInput, request: Request):
        current = require_session(request, mutation=True)
        if not runtime.store.set_inventory_override(server_id, body.seconds):
            raise HTTPException(404, "Server not found")
        runtime.store.audit(current["user_id"], "inventory_interval_update", server_id)
        return {"interval_override": body.seconds, "effective_interval_seconds": runtime.inventory_interval(server_id)}

    @app.get("/api/servers/{server_id}/sensor-collection")
    async def sensor_collection_status(server_id: str, request: Request):
        require_session(request, touch=False)
        if not re.fullmatch(r'[0-9a-f]{32}', server_id) or not runtime.store.get_server(server_id):
            raise HTTPException(404, "Server not found")
        return JSONResponse(read_status(config.data_dir / f'metrics-{server_id}.prom.status'),
                            headers={"Cache-Control": "no-store"})

    @app.get("/api/servers/{server_id}/details")
    async def server_details(server_id: str, request: Request):
        current = require_session(request, touch=False)
        server = runtime.store.get_server(server_id)
        if not server or server["state"] != "active":
            raise HTTPException(404, "Server not found")
        if current["role"] != "admin":
            # Viewing a server as read-only must not initiate BMC traffic or
            # write a newly discovered value to the fleet database.
            snapshot = runtime.store.inventory(server_id)["snapshot"] or {}
            categories = snapshot.get("categories") or {}
            def first_fields(category: str) -> dict[str, Any]:
                items = categories.get(category, {}).get("items") or []
                return items[0].get("fields", {}) if items else {}
            return {"system": first_fields("System"), "chassis": first_fields("Chassis"),
                    "manager": first_fields("Management controllers"), "sources": {},
                    "unavailable": [], "cached": True,
                    "checked_at": snapshot.get("collected_at")}
        return runtime.details_view(server)

    @app.get("/api/servers/{server_id}/live-metrics")
    async def live_metrics(server_id: str, request: Request):
        # Automatic dashboard polling must not keep an idle login alive.
        current = require_session(request, touch=False)
        server = runtime.store.get_server(server_id)
        if not server or server["state"] != "active":
            raise HTTPException(404, "Server not found")
        # Enforce the operator's traffic policy on the server, not just in the UI.
        if not server["manager_metrics_enabled"]:
            return {"collection_enabled": False}
        if current["role"] != "admin":
            with runtime.lock:
                cached = runtime.live_cache.get(server_id, {}).copy()
            cached.pop("checked_monotonic", None)
            return cached
        return runtime.live_view(server)

    @app.get("/api/metrics/series")
    async def metric_series(request: Request, server_id: str | None = None,
                            search: str = "", limit: int = 100):
        # Background catalog refresh is observation, not operator activity.
        require_session(request, touch=False)
        if len(search) > 80 or not 1 <= limit <= 200:
            raise HTTPException(400, "Invalid metric search")
        if server_id is not None and not runtime.store.get_server(server_id):
            raise HTTPException(404, "Server not found")
        return runtime.metric_history.catalog(server_id, search, limit)

    @app.get("/api/metrics/series/{series_id}/history")
    async def metric_history(series_id: str, request: Request, hours: int = 24):
        # The open chart refreshes in the background; viewing alone must not
        # keep an otherwise idle management session alive.
        require_session(request, touch=False)
        if hours not in (1, 6, 24):
            raise HTTPException(400, "Choose 1, 6, or 24 hours")
        if len(series_id) != 32 or any(char not in "0123456789abcdef" for char in series_id):
            raise HTTPException(400, "Invalid metric series ID")
        series = runtime.metric_history.get_series(series_id)
        if not series:
            raise HTTPException(404, "Metric series not found")
        now = time.time()
        points = runtime.metric_history.samples(series_id, now - hours * 3600, now)
        values = [point["value"] for point in points]
        statistics = ({"last": values[-1], "minimum": min(values), "maximum": max(values),
                       "average": sum(values) / len(values)} if values else None)
        return {"series": series, "points": points, "statistics": statistics,
                "range_start": now - hours * 3600, "range_end": now,
                "expected_interval_seconds": runtime.interval(
                    "manager_scrape_interval_seconds", runtime.config.metrics_scrape_interval),
                "disabled_intervals": runtime.store.metric_disabled_intervals(
                    series["server_id"], now - hours * 3600, now)}

    @app.post("/api/metrics/series/{series_id}/track")
    async def track_metric(series_id: str, request: Request):
        require_session(request, mutation=True)
        if len(series_id) != 32 or any(char not in "0123456789abcdef" for char in series_id):
            raise HTTPException(400, "Invalid metric series ID")
        try:
            if not runtime.metric_history.track(series_id):
                raise HTTPException(404, "Metric series not found")
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"ok": True}

    @app.get("/api/dashboard/widgets")
    async def widgets(request: Request):
        require_session(request)
        return runtime.metric_history.widgets()

    @app.post("/api/dashboard/widgets")
    async def add_widget(body: WidgetInput, request: Request):
        current = require_session(request, mutation=True)
        try:
            widget = runtime.metric_history.add_widget(body.title, body.series_ids)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        runtime.store.audit(current["user_id"], "dashboard_widget_add", widget["id"])
        return widget

    @app.delete("/api/dashboard/widgets/{widget_id}")
    async def delete_widget(widget_id: str, request: Request):
        current = require_session(request, mutation=True)
        if not runtime.metric_history.delete_widget(widget_id):
            raise HTTPException(404, "Widget not found")
        runtime.store.audit(current["user_id"], "dashboard_widget_remove", widget_id)
        return {"ok": True}

    @app.get("/api/onboarding-progress/{progress_id}")
    async def get_onboarding_progress(progress_id: str, request: Request):
        current = require_session(request, touch=False)
        with onboarding_progress_lock:
            entry = onboarding_progress.get(progress_id)
            if not entry or entry["user_id"] != current["user_id"]:
                raise HTTPException(404, "Onboarding progress not found")
            message = entry["message"]
        return JSONResponse({"message": message}, headers={"Cache-Control": "no-store"})

    @app.get("/api/onboarding-jobs")
    async def list_onboarding_jobs(request: Request):
        require_session(request, admin=True, touch=False)
        with onboarding_jobs_lock:
            return [public_onboarding_job(job) for job in onboarding_jobs.values()]

    @app.post("/api/onboarding-jobs", status_code=202)
    async def start_onboarding_job(body: OnboardInput, request: Request):
        current = require_session(request, mutation=True, admin=True)
        runtime.validate_host(body.bmc_host)
        if not body.name.strip():
            raise HTTPException(400, "Display name cannot be blank")
        with onboarding_jobs_lock:
            now = time.time()
            for key, job in list(onboarding_jobs.items()):
                if job["state"] != "running" and now - job["updated_at"] > 86400:
                    del onboarding_jobs[key]
            if any(job["state"] == "running" and job["bmc_host"] == body.bmc_host
                   and job["bmc_port"] == body.bmc_port
                   for job in onboarding_jobs.values()):
                raise HTTPException(409, "This BMC is already being onboarded")
            if sum(job["state"] == "running" for job in onboarding_jobs.values()) >= 4:
                raise HTTPException(429, "Too many onboarding requests in progress")
            if len(onboarding_jobs) >= 64:
                raise HTTPException(429, "Too many onboarding results; dismiss completed jobs")
            with runtime.lock:
                previous = runtime.store.get_server_by_host(body.bmc_host, body.bmc_port)
                if previous and previous["state"] == "active":
                    raise HTTPException(409, "Server already onboarded")
            job_id = secrets.token_hex(16)
            onboarding_jobs[job_id] = {
                "id": job_id, "user_id": current["user_id"], "bmc_host": body.bmc_host,
                "bmc_port": body.bmc_port,
                "name": body.name.strip(), "state": "running", "message": "Connecting to BMC…",
                "started_at": now, "updated_at": now, "error": None, "server_id": None,
            }
        threading.Thread(target=run_onboarding_job, args=(job_id, body, current["user_id"]),
                         daemon=True, name=f"onboard-{job_id[:8]}").start()
        return public_onboarding_job(onboarding_jobs[job_id])

    @app.delete("/api/onboarding-jobs/{job_id}")
    async def dismiss_onboarding_job(job_id: str, request: Request):
        require_session(request, mutation=True, admin=True)
        with onboarding_jobs_lock:
            job = onboarding_jobs.get(job_id)
            if not job:
                raise HTTPException(404, "Onboarding job not found")
            if job["state"] == "running":
                raise HTTPException(409, "Onboarding is still in progress")
            del onboarding_jobs[job_id]
        return {"ok": True}

    @app.post("/api/servers")
    async def onboard(body: OnboardInput, request: Request):
        current = require_session(request, mutation=True)
        runtime.validate_host(body.bmc_host)
        if not body.name.strip():
            raise HTTPException(400, "Display name cannot be blank")
        progress_id = request.headers.get("X-Onboarding-Request")
        if progress_id:
            try:
                if str(uuid.UUID(progress_id)) != progress_id:
                    raise ValueError("Non-canonical UUID")
            except ValueError as exc:
                raise HTTPException(400, "Invalid onboarding request ID") from exc
            with onboarding_progress_lock:
                now = time.monotonic()
                for key, entry in list(onboarding_progress.items()):
                    if now - entry["updated_at"] > 600:
                        del onboarding_progress[key]
                if progress_id in onboarding_progress:
                    raise HTTPException(409, "Onboarding request ID already exists")
                if len(onboarding_progress) >= 64:
                    raise HTTPException(429, "Too many onboarding requests")
                onboarding_progress[progress_id] = {
                    "user_id": current["user_id"], "message": "Connecting to BMC…", "updated_at": now}

        def report_progress(message: str) -> None:
            if progress_id:
                with onboarding_progress_lock:
                    entry = onboarding_progress.get(progress_id)
                    if entry:
                        entry["message"] = message
                        entry["updated_at"] = time.monotonic()

        client = RedfishClient(body.bmc_host, body.username, body.password, port=body.bmc_port,
                               ca_file=config.bmc_ca, insecure=body.insecure_bmc,
                               timeout=ONBOARD_REDFISH_GET_TIMEOUT,
                               shared_get_budget=runtime.get_budget, budget_priority=2,
                               onboarding_get_retries=3)
        try:
            if progress_id:
                discovered = await run_in_threadpool(client.discover, progress=report_progress)
            else:
                discovered = await run_in_threadpool(client.discover)
        except RedfishAuthenticationError as exc:
            raise HTTPException(400, "Wrong username or password") from exc
        except RedfishTimeoutError as exc:
            raise HTTPException(504, "The BMC took too long to respond during validation. No server was onboarded; please retry.") from exc
        except (RedfishError, TypeError, AttributeError, KeyError) as exc:
            raise HTTPException(400, f"Redfish validation failed: {exc}") from exc
        report_progress("Saving the server and starting its exporter…")
        discovered["ui_onboarding_started"] = True
        with runtime.lock:
            previous = runtime.store.get_server_by_host(body.bmc_host, body.bmc_port)
            if previous and previous["state"] == "active":
                raise HTTPException(409, "Server already onboarded")
            port = previous["port"] if previous else runtime.store.next_port(config.port_start, config.port_end)
            if not port:
                raise HTTPException(409, "No exporter ports available")
            try:
                if previous:
                    server_id = previous["id"]
                    runtime.store.reactivate_server(server_id, body.name.strip(), body.username,
                                                    body.password, body.insecure_bmc, discovered,
                                                    body.manager_metrics_enabled)
                else:
                    server_id = runtime.store.add_server(body.name.strip(), body.bmc_host, body.username,
                                                         body.password, body.insecure_bmc, port, discovered,
                                                         body.manager_metrics_enabled, body.bmc_port)
            except sqlite3.IntegrityError as exc:
                raise HTTPException(409, "Server already onboarded or port is in use") from exc
        server = runtime.store.get_server(server_id)
        if start_workers and server:
            runtime.start_server(server)
            runtime.start_sse(server)
        runtime.store.audit(current["user_id"], "onboard", server_id)
        return public_server(server)

    @app.patch("/api/servers/{server_id}/manager-metrics")
    async def set_manager_metrics(server_id: str, body: ManagerMetricsInput, request: Request):
        current = require_session(request, mutation=True)
        if not runtime.store.set_manager_metrics_enabled(server_id, body.enabled):
            raise HTTPException(404, "Server not found")
        with runtime.lock:
            runtime.live_cache.pop(server_id, None)
            runtime.live_next_due.pop(server_id, None)
            runtime.live_failures.discard(server_id)
            runtime.live_generation[server_id] = runtime.live_generation.get(server_id, 0) + 1
            if body.enabled:
                # A snapshot left by an external scrape must not postpone the
                # first manager sample after re-enabling collection.
                runtime.metrics_started[server_id] = float("-inf")
        runtime.store.audit(current["user_id"],
                            "manager_metrics_enable" if body.enabled else "manager_metrics_disable",
                            server_id)
        return public_server(runtime.store.get_server(server_id))

    def public_action_job(job: dict[str, Any]) -> dict[str, Any]:
        return {key: job[key] for key in ("id", "server_id", "operation", "state",
                                          "created_at", "updated_at", "error")}

    @app.get("/api/servers/{server_id}/actions")
    async def server_actions(server_id: str, request: Request, operation: str | None = None):
        require_session(request, admin=True, touch=False)
        if operation is not None and operation not in (*POWER_ACTIONS, "reboot_bmc", "collect_support_bundle"):
            raise HTTPException(400, "Unsupported server action")
        if operation == "collect_support_bundle" and not SUPPORT_BUNDLE_COLLECTION_ENABLED:
            raise HTTPException(503, "Tech Support collection is temporarily unavailable")
        server = runtime.store.get_server(server_id)
        if not server or server["state"] != "active":
            raise HTTPException(404, "Server not found")
        try:
            found = await run_in_threadpool(discover_actions, runtime.action_client(server),
                                            json.loads(server["discovered_json"]), operation)
        except (RedfishError, ValueError, TypeError, KeyError):
            raise HTTPException(503, "BMC action capabilities could not be checked") from None
        return {"power_state": found["power_state"], "warnings": found["warnings"],
                "execution_enabled": config.bmc_actions_enabled,
                "actions": {key: {"label": item["label"], "impact": item["impact"]}
                            for key, item in found["actions"].items()
                            if SUPPORT_BUNDLE_COLLECTION_ENABLED or key != "collect_support_bundle"},
                "jobs": [public_action_job(job) for job in runtime.store.action_jobs(server_id)]}

    @app.get("/api/servers/{server_id}/actions/jobs")
    async def server_action_jobs(server_id: str, request: Request):
        require_session(request, admin=True, touch=False)
        if not runtime.store.get_server(server_id):
            raise HTTPException(404, "Server not found")
        return [public_action_job(job) for job in runtime.store.action_jobs(server_id)]

    @app.post("/api/servers/{server_id}/actions/{operation}", status_code=202)
    async def execute_server_action(server_id: str, operation: str,
                                    body: ServerActionInput, request: Request):
        current = require_session(request, mutation=True, admin=True)
        if not config.bmc_actions_enabled:
            raise HTTPException(403, "BMC control actions are disabled on this manager")
        if operation not in (*POWER_ACTIONS, "reboot_bmc", "collect_support_bundle"):
            raise HTTPException(404, "Unsupported server action")
        if operation == "collect_support_bundle" and not SUPPORT_BUNDLE_COLLECTION_ENABLED:
            raise HTTPException(503, "Tech Support collection is temporarily unavailable")
        if not body.acknowledge_impact:
            raise HTTPException(400, "Explicit impact acknowledgement is required")
        server = runtime.store.get_server(server_id)
        if not server or server["state"] != "active":
            raise HTTPException(404, "Server not found")
        if body.expected_host != server["bmc_host"] or body.expected_name != server["name"]:
            raise HTTPException(409, "Server identity changed; review the action again")
        client = runtime.action_client(server)
        try:
            found = await run_in_threadpool(discover_actions, client, json.loads(server["discovered_json"]), operation)
            action = found["actions"].get(operation)
            if not action:
                raise HTTPException(409, "Action is not supported in the current BMC state")
            before = []
            entries_uri = action.get("entries_uri")
            if entries_uri:
                entries = await run_in_threadpool(client.members, entries_uri,
                                                  max_pages=10, max_members=1000)
                before = [item["@odata.id"] for item in entries
                          if isinstance(item, dict) and isinstance(item.get("@odata.id"), str)]
        except RedfishError:
            raise HTTPException(503, "BMC capabilities or diagnostic entries could not be checked") from None
        with runtime.lock:
            latest = runtime.store.get_server(server_id)
            if not latest or latest["state"] != "active":
                raise HTTPException(404, "Server not found")
            if latest["name"] != body.expected_name or latest["bmc_host"] != body.expected_host:
                raise HTTPException(409, "Server identity changed; review the action again")
            try:
                job = runtime.store.create_action_job(server_id, operation, entries_uri, before)
            except ValueError as exc:
                raise HTTPException(409, str(exc)) from exc
            if not job:
                raise HTTPException(404, "Server not found")
            runtime.action_sending.add(server_id)
        try:
            runtime.store.audit(current["user_id"], f"server_action_{operation}", server_id)
            status, response, location = await run_in_threadpool(client.post_action,
                                                                  action["target"], action["payload"])
        except RedfishError:
            runtime.store.update_action_job(job["id"], "uncertain",
                                            error="BMC response was lost or rejected; check BMC before retrying")
            return public_action_job(runtime.store.action_job(job["id"]))
        finally:
            runtime.invalidate_system_views(server_id)
            with runtime.lock:
                runtime.action_sending.discard(server_id)
        task_uri = location or response.get("@odata.id")
        if isinstance(task_uri, str):
            try:
                checked = client.checked_url(task_uri)
                parsed = urlsplit(checked)
                task_uri = parsed.path if not parsed.query and parsed.path.startswith(
                    "/redfish/v1/TaskService/Tasks/") else None
            except RedfishError:
                task_uri = None
        if task_uri:
            runtime.store.update_action_job(job["id"], "submitted", task_uri=task_uri)
            runtime.start_action_monitor(job["id"])
        elif status in (200, 202, 204) and operation in (*POWER_ACTIONS, "reboot_bmc"):
            runtime.store.update_action_job(job["id"], "submitted")
            runtime.start_action_monitor(job["id"])
        else:
            runtime.store.update_action_job(job["id"], "uncertain",
                                            error="BMC accepted the request without a trackable task")
        return public_action_job(runtime.store.action_job(job["id"]))

    @app.get("/api/servers/{server_id}/actions/jobs/{job_id}/download")
    async def download_support_bundle(server_id: str, job_id: str, request: Request):
        current = require_session(request, admin=True)
        job = runtime.store.action_job(job_id)
        server = runtime.store.get_server(server_id)
        if (not job or job["server_id"] != server_id or job["operation"] != "collect_support_bundle"
                or job["state"] != "ready" or not server or server["state"] != "active"):
            raise HTTPException(404, "Support bundle not available")
        created = datetime.fromisoformat(job["created_at"])
        if (datetime.now(timezone.utc) - created).total_seconds() > 86400:
            raise HTTPException(410, "Support bundle download window expired; collect a new bundle")
        attachment = job["attachment_uri"]
        if not attachment or not job["entry_uri"] or not attachment.startswith(job["entry_uri"] + "/"):
            raise HTTPException(404, "Support bundle attachment not available")
        client = runtime.action_client(server)
        try:
            source = await run_in_threadpool(client.open_attachment, attachment)
        except RedfishError:
            raise HTTPException(502, "BMC support bundle download failed") from None
        runtime.store.audit(current["user_id"], "support_bundle_download", server_id)

        def chunks():
            remaining = 512 * 1024 * 1024
            try:
                while remaining >= 0:
                    part = source.read(min(64 * 1024, remaining + 1))
                    if not part:
                        return
                    remaining -= len(part)
                    if remaining < 0:
                        raise RuntimeError("Diagnostic attachment exceeded the download limit")
                    yield part
            finally:
                source.close()

        return StreamingResponse(chunks(), media_type="application/octet-stream", headers={
            "Content-Disposition": f'attachment; filename="c880a-support-{job_id}.bin"',
            "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})

    @app.delete("/api/servers/{server_id}")
    async def offboard(server_id: str, request: Request, body: UnclaimInput | None = None):
        require_session(request, mutation=True)
        require_no_prometheus_change()
        if body is None or not body.acknowledge_data_deletion:
            raise HTTPException(400, "Acknowledge permanent deletion of this target's local data")
        server = runtime.store.get_server(server_id)
        if not server or server["state"] not in ("active", "offboarded"):
            raise HTTPException(404, "Server not found")
        with runtime.lock:
            if server_id in runtime.action_sending:
                raise HTTPException(409, "A BMC action is being sent; wait for its outcome before unclaiming")
            runtime.store.offboard(server_id, managed_history=managed_prometheus.root.exists())
        with onboarding_jobs_lock:
            for job_id, job in list(onboarding_jobs.items()):
                if job["server_id"] == server_id:
                    del onboarding_jobs[job_id]
        try:
            runtime.stop_server(server_id, purge_snapshot=True)
        except OSError as exc:
            raise HTTPException(500, "Target unclaimed, but a local snapshot could not be removed") from exc
        if runtime.store.pending_prometheus_deletions():
            try:
                await run_in_threadpool(cleanup_history, runtime.store, managed_prometheus,
                                        backup_workspace, _lease=False)
            except (BackupError, PrometheusError, OSError):
                return JSONResponse({"ok":True, "history_cleanup":"pending",
                    "message":"Target unclaimed. Prometheus history cleanup is pending."}, status_code=202)
        return {"ok": True}

    @app.post("/api/servers/{server_id}/console/start")
    async def start_console(server_id: str, request: Request):
        current = require_session(request, mutation=True)
        server = runtime.store.get_server(server_id)
        if not server or server["state"] != "active":
            raise HTTPException(404, "Server not found")
        if not start_workers:
            raise HTTPException(503, "Console gateway is not running in this mode")
        try:
            launch_url = await run_in_threadpool(runtime.start_console, server)
        except (OSError, RuntimeError, ValueError) as exc:
            raise HTTPException(503, f"Console gateway unavailable: {exc}") from exc
        runtime.store.audit(current["user_id"], "console_gateway_start", server_id)
        return {"launch_url": launch_url}

    @app.get("/api/events")
    async def events(request: Request, server_id: str | None = None, limit: int = 100):
        # The visible timeline refreshes automatically; observation alone
        # must not extend an otherwise idle management session.
        require_session(request, touch=False)
        if limit < 1 or limit > 500:
            raise HTTPException(400, "Limit must be 1 to 500")
        return runtime.store.events(server_id, limit)

    @app.get("/api/prometheus/targets")
    async def discovery(request: Request):
        supplied = request.headers.get("Authorization", "")
        expected = "Bearer " + runtime.discovery_token_file.read_text().strip()
        if not hmac.compare_digest(supplied, expected):
            raise HTTPException(401, "Invalid discovery token")
        targets = [{"targets": [f"{url_host(config.exporter_advertise_host)}:{s['port']}"],
                 "labels": {"server_id": s["id"], "server_name": s["name"]}}
                for s in runtime.store.servers(active_only=True)]
        prometheus_discovery.record(managed_prometheus, request.headers.get("X-C880A-Managed-Discovery", ""))
        return targets

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the C880A fleet manager")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--tls-cert")
    parser.add_argument("--tls-key")
    parser.add_argument("--tls-chain", help="PEM issuer chain for a supplied first-launch certificate")
    parser.add_argument("--exporter-bind", default="127.0.0.1")
    parser.add_argument("--exporter-advertise-host", default="127.0.0.1")
    parser.add_argument("--bmc-ca")
    parser.add_argument("--port-start", type=int, default=9838)
    parser.add_argument("--port-end", type=int, default=9937)
    parser.add_argument("--console-bind", default="127.0.0.1")
    parser.add_argument("--console-advertise-host", default="localhost")
    parser.add_argument("--manager-origin")
    parser.add_argument("--console-port-offset", type=int, default=2000)
    parser.add_argument("--metrics-scrape-interval", type=int, default=120)
    parser.add_argument("--live-metrics-interval", type=int, default=60)
    action_flags = parser.add_mutually_exclusive_group()
    action_flags.add_argument("--enable-bmc-actions", action="store_true",
                              help="Allow confirmed BMC control actions (default)")
    action_flags.add_argument("--disable-bmc-actions", action="store_true",
                              help="Disable all BMC control POSTs")
    args = parser.parse_args()
    # The first launch deliberately migrates loopback HTTP to a private local
    # certificate before any network listener starts. Later launches read the
    # committed deployment or the supervisor's staged proposal.
    args.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(args.data_dir, 0o700)
    active = read_config(args.data_dir)
    if not active and not args.worker:
        origin_host = urlsplit(args.manager_origin).hostname if args.manager_origin else args.console_advertise_host
        proposal = validate_network({
            "manager_bind": args.bind, "manager_host": origin_host, "manager_port": args.port,
            "exporter_bind": args.exporter_bind, "exporter_host": args.exporter_advertise_host,
            "port_start": args.port_start, "port_end": args.port_end,
            "console_bind": args.console_bind, "console_host": args.console_advertise_host,
            "console_port_offset": args.console_port_offset,
            "manager_origin": args.manager_origin or f"https://{url_host(origin_host)}:{args.port}"})
        if bool(args.tls_cert) != bool(args.tls_key):
            parser.error("Supply both certificate and private key")
        if args.tls_chain and not args.tls_cert:
            parser.error("A certificate and private key are required with --tls-chain")
        if args.tls_cert:
            cert, key = Path(args.tls_cert).read_bytes(), Path(args.tls_key).read_bytes()
            chain = Path(args.tls_chain).read_bytes() if args.tls_chain else b""
            source = "operator-provided"
        else:
            cert, key = generate_certificate([proposal["manager_host"], proposal["exporter_host"],
                                               proposal["exporter_bind"], "127.0.0.1", "::1"])
            chain = b""
            source = "installation-generated"
        material = stage_certificate(args.data_dir, cert, key, chain,
                                     [proposal["manager_host"], proposal["console_host"],
                                      proposal["exporter_host"]], source)
        ca_path = None
        if args.bmc_ca:
            source = Path(args.bmc_ca)
            if source.stat().st_size > 128 * 1024:
                parser.error("BMC CA bundle is too large")
            ca = source.read_bytes()
            try:
                validate_ca_bundle(ca)
            except ValueError as exc:
                parser.error(f"Invalid BMC CA bundle: {exc}")
            ca_path = args.data_dir / f"bmc-ca-{secrets.token_hex(12)}.pem"
            write_private(ca_path, ca)
        active = {**proposal, "certificate": material, "bmc_ca": str(ca_path) if ca_path else None}
        recovery = {**active, "manager_bind": "127.0.0.1", "manager_host": "localhost",
                    "exporter_bind": "127.0.0.1", "exporter_host": "127.0.0.1",
                    "console_bind": "127.0.0.1", "console_host": "localhost"}
        recovery.pop("manager_origin", None)
        recovery = validate_network(recovery)
        try:
            validate_certificate(Path(material["cert"]).read_bytes(), Path(material["key"]).read_bytes(),
                                 b"", ["localhost", "127.0.0.1"])
        except ValueError:
            fallback_cert, fallback_key = generate_certificate(["localhost", "127.0.0.1", "::1"])
            recovery["certificate"] = stage_certificate(args.data_dir, fallback_cert, fallback_key,
                                                          b"", ["localhost", "127.0.0.1"],
                                                          "installation-generated")
        atomic_config(args.data_dir, "deployment.recovery.json", recovery)
        atomic_config(args.data_dir, "deployment.json", active)
        print("HTTPS deployment initialized. Update external Prometheus scrape URLs and trust stores before relying on scrapes.",
              file=sys.stderr)
    effective = read_config(args.data_dir, pending=True) if args.worker else {}
    if not effective:
        effective = active
    if not effective:
        parser.error("Deployment configuration is missing")
    try:
        effective = validate_network(effective)
        material = effective["certificate"]
        validate_certificate(Path(material["cert"]).read_bytes(), Path(material["key"]).read_bytes(), b"",
                             [effective["manager_host"], effective["console_host"], effective["exporter_host"]])
        if effective.get("bmc_ca"):
            validate_ca_bundle(Path(effective["bmc_ca"]).read_bytes())
    except (KeyError, OSError, ValueError) as exc:
        parser.error(f"Invalid HTTPS deployment: {exc}")
    args.bind, args.port = effective["manager_bind"], effective["manager_port"]
    args.exporter_bind, args.exporter_advertise_host = effective["exporter_bind"], effective["exporter_host"]
    args.port_start, args.port_end = effective["port_start"], effective["port_end"]
    args.console_bind, args.console_advertise_host = effective["console_bind"], effective["console_host"]
    args.console_port_offset, args.manager_origin = effective["console_port_offset"], effective["manager_origin"]
    args.tls_cert = args.console_tls_cert = args.exporter_tls_cert = material["cert"]
    args.tls_key = args.console_tls_key = args.exporter_tls_key = material["key"]
    args.bmc_ca = effective.get("bmc_ca")
    if not 30 <= args.metrics_scrape_interval <= 3600 or not 5 <= args.live_metrics_interval <= 60:
        parser.error("Scrape interval must be 30–3600 seconds and live interval 5–60 seconds")
    if not 1 <= args.port_start + args.console_port_offset <= args.port_end + args.console_port_offset <= 65535:
        parser.error("Invalid console port range")
    scheme = "https"
    origin_host = args.console_advertise_host
    if ":" in origin_host and not origin_host.startswith("["):
        origin_host = f"[{origin_host}]"
    manager_origin = args.manager_origin or f"{scheme}://{origin_host}:{args.port}"
    parsed_origin = urlsplit(manager_origin)
    if (parsed_origin.scheme != scheme or not parsed_origin.hostname
            or parsed_origin.hostname != args.console_advertise_host.strip("[]")
            or parsed_origin.path not in ("", "/") or parsed_origin.query
            or parsed_origin.fragment or parsed_origin.username or parsed_origin.password):
        parser.error("Manager origin must use the console hostname and configured scheme")
    if not args.worker:
        from .supervisor import serve
        serve([argument for argument in sys.argv[1:]], args.data_dir)
        return
    if not os.environ.get("C880A_RESTART_FD"):
        parser.error("Manager workers must be launched by the supervisor")
    app = create_app(Config(args.data_dir, args.port_start, args.port_end,
                            args.exporter_bind, args.exporter_advertise_host,
                            args.exporter_tls_cert, args.exporter_tls_key, args.bmc_ca,
                            manager_origin, args.console_bind, args.console_advertise_host,
                            args.console_port_offset, args.tls_cert, args.tls_key,
                            1, args.live_metrics_interval, args.metrics_scrape_interval,
                            not args.disable_bmc_actions, effective))
    uvicorn.run(app, host=args.bind, port=args.port, ssl_certfile=args.tls_cert, ssl_keyfile=args.tls_key,
                proxy_headers=False)


if __name__ == "__main__":
    main()
