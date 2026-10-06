"""Standalone, single-BMC Prometheus exporter."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import math
import os
from pathlib import Path
import re
import secrets
import ssl
import socket
import stat
import threading
import time

from .deployment import listener_address
from .metrics import COMPONENT_SOURCE_KEYS, _device_timestamp, render
from .redfish import RedfishClient, RedfishError
from .redfish_budget import SharedGetBudget


class ExporterState:
    def __init__(self, client: RedfishClient, workers: int,
                 snapshot_file: Path | None = None, *, stage_workers: int = 1,
                 sensor_page_workers: int = 1, telemetry_report_workers: int = 1,
                 component_collection_workers: int = 1) -> None:
        if stage_workers not in (1, 2, 3):
            raise ValueError("Stage workers must be 1, 2, or 3")
        if sensor_page_workers not in (1, 2, 4):
            raise ValueError("Sensor page workers must be 1, 2, or 4")
        if telemetry_report_workers not in (1, 2, 4):
            raise ValueError("Telemetry report workers must be 1, 2, or 4")
        if component_collection_workers not in (1, 2, 4):
            raise ValueError("Component collection workers must be 1, 2, or 4")
        self.client = client
        self.workers = workers
        self.stage_workers = stage_workers
        self.sensor_page_workers = sensor_page_workers
        self.telemetry_report_workers = telemetry_report_workers
        self.component_collection_workers = component_collection_workers
        self.lock = threading.Lock()
        self.collection = threading.Condition(self.lock)
        self.collecting = False
        self.request_slots = threading.BoundedSemaphore(16)
        self.payload = render([], success=False, errors=0, collected_at=0)
        self.cold_export_payload = self.payload
        self.ready = False
        self.last_success_at = 0.0
        self.last_error = "Collection has not started"
        self.snapshot_file = snapshot_file
        # The manager's snapshot remains independent: it may publish partial
        # pages for its own charts. Only /metrics uses this completed-pass cache.
        self.export_cache_file = (snapshot_file.with_name(snapshot_file.name + ".cache")
                                  if snapshot_file is not None else None)
        self.export_cache_payload: bytes | None = None
        self.export_cache_completed_at = 0.0
        self.export_cache_max_age = 600.0
        self.export_cache_last_sensor_ok = False
        self.export_cache_last_refresh_ok = False
        self.export_cache_last_refresh_errors = 0
        self.export_cache_last_refresh_completed_at = 0.0
        self.last_attempt_at = 0.0
        self.background_worker: threading.Thread | None = None
        self.refresh_interval = 300.0
        self.next_refresh_monotonic = 0.0
        self.collector_stopping = False
        self.snapshot_max_age = 180.0
        self.sensor_observations: dict[str, tuple[dict, float]] = {}
        self.sensor_expected: int | None = None
        self.sensor_identities: frozenset[str] | None = None
        self.sensor_errors = 0
        self.component_observations: dict[str, tuple[object, float]] = {}
        self.component_errors = 0
        self.telemetry_observations: dict[str, dict] = {}
        self.telemetry_errors = 0
        self.telemetry_reports_collected = 0
        self.stage_durations: dict[str, float] = {}
        self.discovery_cache: dict | None = None
        self.discovery_cached_monotonic = 0.0
        self.discovery_ttl = 3600.0
        self._load_export_cache()

    def current(self) -> bytes:
        """Serve the completed cache; scrapes never duplicate scheduled Redfish work."""
        with self.collection:
            self._start_collector_locked()
        return self._serve_export_cache()

    def start_collector(self) -> None:
        """Start the background collector even when nothing scrapes /metrics."""
        with self.collection:
            self._start_collector_locked()

    def _start_collector_locked(self) -> None:
        if not self.collector_stopping and (self.background_worker is None
                                            or not self.background_worker.is_alive()):
            now = time.time()
            if self._snapshot_usable(now):
                age = now - self.export_cache_completed_at
                self.next_refresh_monotonic = time.monotonic() + max(0.0, self.refresh_interval - age)
            else:
                self.next_refresh_monotonic = time.monotonic()
            self.background_worker = threading.Thread(
                target=self._background_collect, name="redfish-collector", daemon=True)
            self.background_worker.start()

    def stop_collector(self) -> None:
        with self.collection:
            self.collector_stopping = True
            self.collection.notify_all()

    def _snapshot_usable(self, now: float) -> bool:
        return (self.export_cache_payload is not None
                and 0 <= now - self.export_cache_completed_at <= self.export_cache_max_age)

    def _serve_export_cache(self) -> bytes:
        """Return one complete exposition while a later Redfish pass runs."""
        now = time.time()
        with self.lock:
            usable = self._snapshot_usable(now)
            # The manager handoff can contain partial pages; never expose
            # those as the external exporter's cold/warming response.
            payload = self.export_cache_payload if usable else self.cold_export_payload
            completed = self.export_cache_completed_at if usable else 0.0
            collecting = self.collecting
            sensor_ok = self.export_cache_last_sensor_ok
            refresh_ok = self.export_cache_last_refresh_ok
            refresh_errors = self.export_cache_last_refresh_errors
            refresh_completed = self.export_cache_last_refresh_completed_at
        if usable and not sensor_ok:
            # The measurements are last-known, but the latest pass failed.
            # Preserve the measurements while reporting target health honestly.
            payload = payload.replace(b"\nc880a_target_up 1\n", b"\nc880a_target_up 0\n", 1)
        age = max(0.0, now - completed) if usable else -1.0
        status = (
            "# HELP c880a_exporter_cache_available A completed cached exposition is available.\n"
            "# TYPE c880a_exporter_cache_available gauge\n"
            f"c880a_exporter_cache_available {int(usable)}\n"
            "# HELP c880a_exporter_cache_completed_timestamp_seconds Time the cached exposition completed.\n"
            "# TYPE c880a_exporter_cache_completed_timestamp_seconds gauge\n"
            f"c880a_exporter_cache_completed_timestamp_seconds {completed:.3f}\n"
            "# HELP c880a_exporter_cache_age_seconds Age of the completed exposition, or -1 if unavailable.\n"
            "# TYPE c880a_exporter_cache_age_seconds gauge\n"
            f"c880a_exporter_cache_age_seconds {age:.3f}\n"
            "# HELP c880a_exporter_refresh_in_progress A background Redfish collection is in progress.\n"
            "# TYPE c880a_exporter_refresh_in_progress gauge\n"
            f"c880a_exporter_refresh_in_progress {int(collecting)}\n"
            "# HELP c880a_exporter_last_refresh_success The last completed pass had no collection errors.\n"
            "# TYPE c880a_exporter_last_refresh_success gauge\n"
            f"c880a_exporter_last_refresh_success {int(refresh_ok)}\n"
            "# HELP c880a_exporter_last_refresh_errors Errors in the last completed pass.\n"
            "# TYPE c880a_exporter_last_refresh_errors gauge\n"
            f"c880a_exporter_last_refresh_errors {refresh_errors}\n"
            "# HELP c880a_exporter_last_refresh_timestamp_seconds Time the last pass ended.\n"
            "# TYPE c880a_exporter_last_refresh_timestamp_seconds gauge\n"
            f"c880a_exporter_last_refresh_timestamp_seconds {refresh_completed:.3f}\n"
        )
        return payload + status.encode("ascii")

    def _load_export_cache(self) -> None:
        """Restore only a bounded, private, recently completed exposition."""
        path = self.export_cache_file
        if path is None:
            return
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as source:
                info = os.fstat(source.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                        or not 0 < info.st_size <= 12_000_000
                        or not 0 <= time.time() - info.st_mtime <= self.export_cache_max_age):
                    return
                payload = source.read(12_000_001)
            discovered = re.search(rb"(?m)^c880a_sensor_discovered ([1-9][0-9]{0,3})$", payload)
            collected = re.search(rb"(?m)^c880a_sensor_collected ([1-9][0-9]{0,3})$", payload)
            if (len(payload) != info.st_size or not payload.endswith(b"\n")
                    or b"\nc880a_target_up 1\n" not in payload
                    or discovered is None or collected is None
                    or discovered.group(1) != collected.group(1)
                    or int(discovered.group(1)) > 3000):
                return
            payload.decode("utf-8")
            error_total = 0
            for name in (b"c880a_sensor_collection_errors",
                         b"c880a_component_collection_errors",
                         b"c880a_telemetry_collection_errors"):
                match = re.search(rb"(?m)^" + name + rb" ([0-9]{1,9})$", payload)
                if match is None:
                    return
                error_total += int(match.group(1))
            self.export_cache_payload = payload
            self.export_cache_completed_at = info.st_mtime
            self.export_cache_last_sensor_ok = True
            self.export_cache_last_refresh_errors = error_total
            self.export_cache_last_refresh_ok = error_total == 0
            self.export_cache_last_refresh_completed_at = info.st_mtime
        except (OSError, UnicodeDecodeError):
            return

    def _publish_export_cache(self, payload: bytes, completed_at: float,
                              refresh_errors: int) -> None:
        """Swap a complete /metrics body; keep the prior one on disk failure."""
        if len(payload) > 12_000_000:
            with self.lock:
                self.export_cache_last_sensor_ok = False
                self.export_cache_last_refresh_ok = False
                self.export_cache_last_refresh_errors = refresh_errors + 1
                self.export_cache_last_refresh_completed_at = completed_at
            return
        with self.lock:
            self.export_cache_payload = payload
            self.export_cache_completed_at = completed_at
            self.export_cache_last_sensor_ok = True
            self.export_cache_last_refresh_ok = refresh_errors == 0
            self.export_cache_last_refresh_errors = refresh_errors
            self.export_cache_last_refresh_completed_at = completed_at
        path = self.export_cache_file
        if path is None:
            return
        temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(payload)
            os.replace(temporary, path)
        except OSError:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def _cache_completed_pass(self, readings: list[dict],
                              observed_sensors: dict[str, tuple[dict, float]],
                              expected: int, component_errors: int,
                              telemetry_errors: int, stage_durations: dict[str, float]) -> None:
        """Build the external cache from one finished, full sensor pass only."""
        completed_at = time.time()
        with self.lock:
            components = {key: value for key, (value, _) in self.component_observations.items()}
            component_times = {key: observed for key, (_, observed) in
                               self.component_observations.items()}
            reports = list(self.telemetry_observations.values())
            report_count = self.telemetry_reports_collected
            attempted_at = self.last_attempt_at
            last_success_at = self.last_success_at
        # Preserve the pre-R18 value scope. Redfish observation/device times
        # remain explicit; only the cache's age determines when these last-
        # known samples stop being served to Prometheus.
        payload = render(readings, success=True, errors=0,
                         collected_at=attempted_at, expected=expected,
                         last_success_at=last_success_at, components=components,
                         component_errors=component_errors,
                         component_observed_at=min(component_times.values()) if component_times else None,
                         component_source_observed_at=component_times,
                         telemetry=reports, telemetry_errors=telemetry_errors,
                         telemetry_reports_collected=report_count,
                         stage_durations=stage_durations,
                         get_statistics=self._get_statistics(),
                         sensor_observed_at={uri: observed for uri, (_, observed) in
                                             observed_sensors.items()},
                         telemetry_max_age_seconds=None, as_of=completed_at)
        self._publish_export_cache(payload, completed_at,
                                   component_errors + telemetry_errors)

    def _render_observations(self, *, sensor_max_age: float | None = None) -> bytes:
        """Assemble a point-in-time exposition without touching the BMC."""
        now = time.time()
        with self.lock:
            fresh = {uri: (sensor, observed) for uri, (sensor, observed) in
                     self.sensor_observations.items()
                     if 0 <= now - observed <= (self.snapshot_max_age if sensor_max_age is None else sensor_max_age)}
            expected = self.sensor_expected
            success = (self.ready and expected is not None and len(fresh) == expected)
            errors = self.sensor_errors + max(0, (expected or 0) - len(fresh))
            component_sources = {key: (value, observed) for key, (value, observed) in
                                 self.component_observations.items()
                                 if 0 <= now - observed <= self.snapshot_max_age}
            components = {key: value for key, (value, _) in component_sources.items()}
            component_times = {key: observed for key, (_, observed) in component_sources.items()}
            component_observed_at = min(component_times.values()) if component_times else None
            reports = list(self.telemetry_observations.values())
            component_errors = self.component_errors
            telemetry_errors = self.telemetry_errors
            telemetry_reports_collected = self.telemetry_reports_collected
            last_attempt_at = self.last_attempt_at
            last_success_at = self.last_success_at
            stage_durations = self.stage_durations.copy()
        return render([sensor for sensor, _ in fresh.values()], success=success, errors=errors,
                      collected_at=last_attempt_at, expected=expected, last_success_at=last_success_at,
                      components=components, component_errors=component_errors,
                      component_observed_at=component_observed_at,
                      component_source_observed_at=component_times,
                      telemetry=reports, telemetry_errors=telemetry_errors,
                      telemetry_reports_collected=telemetry_reports_collected,
                      stage_durations=stage_durations, get_statistics=self._get_statistics(),
                      sensor_observed_at={uri: observed for uri, (_, observed) in fresh.items()},
                      telemetry_max_age_seconds=self.snapshot_max_age, as_of=now)

    def _background_collect(self) -> None:
        while True:
            with self.collection:
                while not self.collector_stopping:
                    remaining = self.next_refresh_monotonic - time.monotonic()
                    if remaining <= 0:
                        break
                    self.collection.wait(timeout=remaining)
                if self.collector_stopping:
                    self.background_worker = None
                    return
            started = time.monotonic()
            try:
                self.collect()
            except Exception:
                # Keep the HTTP endpoint available even if an unexpected parser
                # failure escapes the normal per-request Redfish error handling.
                with self.collection:
                    self.ready = False
                    self.export_cache_last_sensor_ok = False
                    self.export_cache_last_refresh_ok = False
                    self.export_cache_last_refresh_errors = 1
                    self.export_cache_last_refresh_completed_at = time.time()
                    self.last_error = "Unexpected collector failure"
            with self.collection:
                # Usually start every five minutes, measured from the prior
                # start. Never overlap; an overlong pass gets a short cooldown
                # so a struggling BMC is not hammered back-to-back.
                self.next_refresh_monotonic = max(
                    started + self.refresh_interval,
                    time.monotonic() + min(30.0, self.refresh_interval * 0.1))

    def _get_statistics(self) -> dict:
        measure = getattr(self.client, "get_statistics", None)
        return measure() if callable(measure) else {}

    def _discover_for_collection(self) -> tuple[dict, bool]:
        """Reconcile topology hourly; refresh dynamic System fields every pass."""
        now = time.monotonic()
        with self.lock:
            cached = self.discovery_cache
            cache_age = now - self.discovery_cached_monotonic
        system_get = getattr(self.client, "get", None)
        if cached is None or cache_age >= self.discovery_ttl or not callable(system_get):
            discovered = self.client.discover(metrics_only=True)
            discovered.setdefault("system_observed_at", time.time())
            with self.lock:
                self.discovery_cache = discovered
                self.discovery_cached_monotonic = time.monotonic()
            return discovered, True
        discovered = dict(cached)
        try:
            system = system_get(cached["system_uri"], timeout=25)
            system_observed_at = time.time()
        except (KeyError, RedfishError):
            # Keep the validated sensor/report links for this pass, but never
            # present cached System health as if it came from this response.
            with self.lock:
                self.discovery_cache = None
            discovered.update({"system_status": None, "system_power_state": None,
                               "memory_summary": None, "processor_summary": None,
                               "system_refresh_error": True})
            return discovered, False
        links = cached.get("component_links") or {}
        changed_links = any(
            ((system.get(name) or {}).get("@odata.id") if isinstance(system.get(name), dict) else None)
            != links.get(name)
            for name in ("Processors", "Memory", "Storage", "NetworkInterfaces")
        ) if isinstance(links, dict) and links else False
        if (system.get("BiosVersion") != cached.get("bios_version") or
                system.get("PowerState") != cached.get("system_power_state") or
                system.get("Model") != cached.get("model") or
                system.get("SerialNumber") != cached.get("serial_number") or changed_links):
            with self.lock:
                self.discovery_cache = None
        discovered.update({"system_status": system.get("Status"),
                           "system_power_state": system.get("PowerState"),
                           "system_observed_at": system_observed_at,
                           "memory_summary": system.get("MemorySummary"),
                           "processor_summary": system.get("ProcessorSummary"),
                           "bios_version": system.get("BiosVersion")})
        return discovered, False

    @staticmethod
    def _merge_report(previous: dict | None, current: dict) -> dict:
        """Keep each property's newest device-stamped value across report refreshes."""
        if previous is None or previous.get("uri") != current.get("uri"):
            return current
        values: dict[str, dict] = {}
        for report in (previous, current):
            report_values = report.get("values")
            if not isinstance(report_values, list):
                continue
            for item in report_values:
                if not isinstance(item, dict):
                    continue
                prop = item.get("MetricProperty")
                if not isinstance(prop, str) or not prop:
                    continue
                old = values.get(prop)
                old_time = _device_timestamp(old.get("Timestamp")) if old else None
                new_time = _device_timestamp(item.get("Timestamp"))
                if old is None or (new_time is not None and
                                   (old_time is None or new_time >= old_time)):
                    values[prop] = item
        if len(values) > 20000:
            # Never let a changing report create unbounded retained state.
            return current
        current_values = current.get("values")
        return {**current, "values": list(values.values()),
                "raw_count": len(current_values) if isinstance(current_values, list) else 0}

    def publish_snapshot(self, payload: bytes) -> None:
        """Optional manager handoff; a standalone exporter needs no shared file."""
        if self.snapshot_file is None or len(payload) > 12_000_000:
            return
        temporary = self.snapshot_file.with_name(self.snapshot_file.name + "." + secrets.token_hex(8) + ".tmp")
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(payload)
            os.replace(temporary, self.snapshot_file)
        except OSError:
            # A full manager disk must not take down external /metrics scraping.
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def collect(self) -> bytes:
        """Run one Redfish pass; concurrent callers share the same in-flight pass."""
        with self.collection:
            if self.collecting:
                while self.collecting:
                    self.collection.wait()
                return self.payload
            self.collecting = True
        try:
            self._collect_once()
        finally:
            with self.collection:
                self.collecting = False
                self.collection.notify_all()
        with self.lock:
            return self.payload

    def _collect_once(self) -> None:
        now = time.time()
        with self.lock:
            self.last_attempt_at = now
        stage_started = time.monotonic()
        stage_durations: dict[str, float] = {}
        stage_pool: ThreadPoolExecutor | None = None
        try:
            discovered, fully_discovered = self._discover_for_collection()
            stage_durations["discovery" if fully_discovered else "system_refresh"] = time.monotonic() - stage_started
            expected = discovered.get("sensor_count")
            if not isinstance(expected, int) or expected < 1:
                expected = None
            reports_uri = discovered.get("telemetry_reports_uri")

            def component_job():
                started = time.monotonic()
                observed = time.time()
                if self.component_collection_workers > 1:
                    values, failures = self.client.component_snapshot(
                        discovered, collection_workers=self.component_collection_workers)
                else:
                    values, failures = self.client.component_snapshot(discovered)
                return values, failures, time.monotonic() - started, observed

            def telemetry_job(uri: str):
                started = time.monotonic()
                try:
                    if self.telemetry_report_workers > 1:
                        values, failures = self.client.telemetry_snapshot(
                            uri, report_workers=self.telemetry_report_workers)
                    else:
                        values, failures = self.client.telemetry_snapshot(uri)
                except RedfishError:
                    values, failures = [], 1
                return values, failures, time.monotonic() - started

            component_future = telemetry_future = None
            if self.stage_workers > 1:
                # Probe-only candidate: stages may overlap, but one client GET
                # semaphore still caps total outstanding BMC requests.
                stage_pool = ThreadPoolExecutor(max_workers=self.stage_workers - 1,
                                                thread_name_prefix="redfish-stage")
                component_future = stage_pool.submit(component_job)
                if self.stage_workers == 3 and isinstance(reports_uri, str):
                    telemetry_future = stage_pool.submit(telemetry_job, reports_uri)
            stage_started = time.monotonic()
            page_observed_at: dict[str, float] = {}

            def observed_page(items: list[dict], page_count: int | None) -> None:
                observed = time.time()
                refreshed: dict[str, tuple[dict, float]] = {}
                for item in items:
                    uri = item.get("@odata.id")
                    if isinstance(uri, str) and isinstance(item.get("Id"), str):
                        page_observed_at[uri] = observed
                        refreshed[uri] = (item, observed)

                # A long sensor walk must not hold newly read, known values
                # until its final page. Stream only identities from a prior
                # complete pass and only when the BMC's count still agrees;
                # candidate parallel pages remain tentative until validated.
                if self.sensor_page_workers != 1 or not refreshed:
                    return
                with self.lock:
                    known = self.sensor_identities
                    if (known is None or page_count != self.sensor_expected
                            or len(known) != page_count):
                        return
                    updates = {uri: value for uri, value in refreshed.items() if uri in known}
                    self.sensor_observations.update(updates)
                if updates:
                    payload = self._render_observations()
                    with self.lock:
                        self.payload = payload
                    self.publish_snapshot(payload)

            if self.sensor_page_workers > 1:
                readings, errors, count = self.client.sensor_snapshot_parallel(
                    discovered["sensor_uri"], page_workers=self.sensor_page_workers,
                    workers=self.workers, on_page=observed_page)
            else:
                readings, errors, count = self.client.sensor_snapshot(
                    discovered["sensor_uri"], workers=self.workers, on_page=observed_page)
            sensor_finished_at = time.time()
            stage_durations["sensors"] = time.monotonic() - stage_started
            count = count or expected
            observed_sensors = {}
            for sensor in readings:
                uri = sensor.get("@odata.id") or sensor.get("Id")
                if isinstance(uri, str):
                    observed_sensors[uri] = (sensor, page_observed_at.get(uri, sensor_finished_at))
            complete_pass = (errors == 0 and count is not None
                             and len(readings) == count and len(observed_sensors) == count)
            observed_ids = frozenset(observed_sensors)
            with self.lock:
                previous_ids = self.sensor_identities
                topology_changed = (previous_ids is not None and
                                    (count != len(previous_ids) or
                                     (complete_pass and observed_ids != previous_ids)))
                if topology_changed or (previous_ids is not None and
                                        bool(observed_ids - previous_ids)):
                    self.discovery_cache = None
                if complete_pass:
                    # A changed membership, even at the same count, needs one
                    # complete follow-up before being called healthy.
                    self.sensor_identities = observed_ids
            success = complete_pass and not topology_changed
            if component_future is not None:
                components, component_errors, component_duration, component_started_at = component_future.result()
            else:
                components, component_errors, component_duration, component_started_at = component_job()
            if discovered.get("system_refresh_error"):
                component_errors += 1
            stage_durations["components"] = component_duration
            with self.lock:
                if complete_pass:
                    # Drop removed identities on a fully read topology pass;
                    # otherwise their old readings would linger beside new IDs.
                    self.sensor_observations = observed_sensors
                if success:
                    self.last_success_at = sensor_finished_at
                else:
                    if not complete_pass:
                        self.sensor_observations.update(observed_sensors)
                self.sensor_expected = count
                self.sensor_errors = errors if count else errors + 1
                source_times = components.get("_source_observed_at")
                if not isinstance(source_times, dict):
                    source_times = {}
                for source in COMPONENT_SOURCE_KEYS:
                    if source not in components or (source == "system" and discovered.get("system_refresh_error")):
                        continue
                    observed = source_times.get(source)
                    if source == "system" and observed is None:
                        observed = discovered.get("system_observed_at")
                    if (not isinstance(observed, (int, float)) or isinstance(observed, bool)
                            or not math.isfinite(observed) or observed <= 0):
                        observed = component_started_at
                    self.component_observations[source] = (components[source], observed)
                self.component_errors = component_errors
                self.stage_durations = stage_durations.copy()
                self.ready = success
                self.last_error = ("" if success else
                                   "Sensor topology changed; reconciling" if topology_changed else
                                   f"{errors or 1} sensors missing or collection errors")
            payload = self._render_observations()
            with self.lock:
                self.payload = payload
            # Publish the completed sensor/component pass before optional telemetry,
            # which can take substantially longer on this BMC.
            self.publish_snapshot(payload)
            telemetry_errors = 0
            if isinstance(reports_uri, str):
                if telemetry_future is not None:
                    telemetry, telemetry_errors, telemetry_duration = telemetry_future.result()
                else:
                    telemetry, telemetry_errors, telemetry_duration = telemetry_job(reports_uri)
                stage_durations["telemetry"] = telemetry_duration
                with self.lock:
                    for report in telemetry:
                        report_uri = report.get("uri")
                        if isinstance(report_uri, str):
                            self.telemetry_observations[report_uri] = self._merge_report(
                                self.telemetry_observations.get(report_uri), report)
                    self.telemetry_reports_collected = len(telemetry)
                    self.telemetry_errors = telemetry_errors
                    self.stage_durations = stage_durations.copy()
                payload = self._render_observations()
                with self.lock:
                    self.payload = payload
            self.publish_snapshot(payload)
            if success and count is not None:
                self._cache_completed_pass(readings, observed_sensors, count,
                                           component_errors, telemetry_errors, stage_durations)
            else:
                with self.lock:
                    self.export_cache_last_sensor_ok = False
                    self.export_cache_last_refresh_ok = False
                    self.export_cache_last_refresh_errors = max(1, errors) + component_errors + telemetry_errors
                    self.export_cache_last_refresh_completed_at = time.time()
        except (RedfishError, ValueError) as exc:
            with self.lock:
                self.discovery_cache = None
                self.ready = False
                self.export_cache_last_sensor_ok = False
                self.export_cache_last_refresh_ok = False
                self.export_cache_last_refresh_errors = 1
                self.export_cache_last_refresh_completed_at = time.time()
                self.sensor_errors += 1
                self.last_error = str(exc)
                self.stage_durations = stage_durations.copy()
            payload = self._render_observations()
            with self.lock:
                self.payload = payload
            self.publish_snapshot(payload)
        finally:
            if stage_pool is not None:
                stage_pool.shutdown(wait=True, cancel_futures=True)


def serve(state: ExporterState, bind: str, port: int, cert: str | None, key: str | None) -> None:
    bind = listener_address(bind)
    if not cert or not key:
        raise ValueError("An HTTPS certificate and key are required for every exporter")

    class ExporterHTTPServer(ThreadingHTTPServer):
        # The stdlib default backlog is five. A modest scrape burst can be
        # reset at accept() before the per-request concurrency limit applies.
        request_queue_size = 32
        address_family = socket.AF_INET6 if ":" in bind else socket.AF_INET

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/metrics":
                if not state.request_slots.acquire(blocking=False):
                    status, body, mime = 503, b"scrape busy\n", "text/plain; charset=utf-8"
                else:
                    try:
                        body = state.current()
                        status, mime = 200, "text/plain; version=0.0.4; charset=utf-8"
                    finally:
                        state.request_slots.release()
            elif self.path in ("/healthz", "/readyz"):
                with state.lock:
                    ready = state._snapshot_usable(time.time())
                status = 200 if self.path == "/healthz" or ready else 503
                body, mime = (b"ok\n" if status == 200 else b"not ready\n"), "text/plain; charset=utf-8"
            else:
                status, body, mime = 404, b"not found\n", "text/plain; charset=utf-8"
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            # Avoid logging arbitrary request paths, which can contain secrets.
            return

    server = ExporterHTTPServer((bind, port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=cert, keyfile=key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    try:
        # Bind/TLS must be ready before asynchronous collection. Scrapes share
        # this one five-minute collector and never start a duplicate BMC pass.
        state.start_collector()
        server.serve_forever(poll_interval=0.5)
    finally:
        state.stop_collector()
        server.server_close()
        state.client.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Export C880A Redfish metrics")
    parser.add_argument("--bmc-host", required=True)
    parser.add_argument("--bmc-port", type=int, default=443)
    parser.add_argument("--bmc-username", required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--password-env", help="Environment variable containing the BMC password")
    source.add_argument("--password-fd", type=int, help="Inherited file descriptor containing the BMC password")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9838)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--snapshot-file", type=Path, help="Optional private manager snapshot handoff")
    parser.add_argument("--shared-budget-db", type=Path,
                        help="Private manager-owned GET budget; omit for standalone operation")
    parser.add_argument("--collection-log-dir", type=Path,
                        help="Private anonymous collection-summary directory")
    parser.add_argument("--collection-log-target", default="standalone", help=argparse.SUPPRESS)
    parser.add_argument("--bmc-ca")
    parser.add_argument("--insecure-bmc", action="store_true", help="Only for an explicitly approved BMC certificate exception")
    parser.add_argument("--persistent-gets", action="store_true",
                        help="Compatibility option; exporter GETs use persistent HTTPS by default")
    parser.add_argument("--tls-cert")
    parser.add_argument("--tls-key")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 1 <= args.bmc_port <= 65535 or not 1 <= args.workers <= 16:
        parser.error("Invalid port or worker count")
    if args.password_fd is not None:
        with os.fdopen(args.password_fd, "rb", closefd=True) as source_file:
            password = source_file.read(4097).decode("utf-8").rstrip("\n")
    else:
        password = os.environ.get(args.password_env, "")
    if not password or len(password) > 4096:
        parser.error("BMC password is missing or too long")
    client = RedfishClient(args.bmc_host, args.bmc_username, password,
                           port=args.bmc_port,
                           ca_file=args.bmc_ca, insecure=args.insecure_bmc,
                           persistent_gets=True,
                           shared_get_budget=(SharedGetBudget(args.shared_budget_db)
                                              if args.shared_budget_db else None))
    from .rolling_exporter import RollingExporterState
    serve(RollingExporterState(client, args.workers, args.snapshot_file,
                              log_dir=args.collection_log_dir, target_id=args.collection_log_target),
          args.bind, args.port, args.tls_cert, args.tls_key)


if __name__ == "__main__":
    main()
