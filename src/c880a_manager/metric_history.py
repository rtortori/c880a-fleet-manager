"""Bounded, local history from the manager's own exporter snapshots.

The exporter remains a normal standalone Prometheus endpoint. This module only
reads the optional private snapshot handoff when the fleet manager runs it.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import re
import secrets
import sqlite3
import time
from typing import Any


MAX_SNAPSHOT_BYTES = 12_000_000
MAX_SERIES = 30_000
MAX_POINTS_PER_SERVER = 500_000
_SAMPLE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+([^\s]+)(?:\s+\S+)?$')
_LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"(?:,|$)')
_DEFAULT_HISTORY = (
    "c880a_sensor_temperature_celsius", "c880a_sensor_power_watts",
    "c880a_sensor_fan_speed_rpm", "c880a_chassis_power_average_watts",
    "c880a_chassis_power_max_watts", "c880a_chassis_power_min_watts",
    "c880a_system_power_on",
)
_COMPONENT_TYPE_SOURCE = {
    "processor": "processors", "memory": "memory", "power_supply": "power_supplies",
    "storage": "storage", "storage_controller": "storage_controllers", "drive": "drives",
    "volume": "volumes", "network_interface": "network_interfaces",
}
_COMPONENT_METRIC_SOURCE = (
    ("c880a_storage_controller_", "storage_controllers"),
    ("c880a_power_subsystem_", "power_subsystem"),
    ("c880a_power_supply_", "power_supplies"),
    ("c880a_chassis_power_", "power"),
    ("c880a_network_interface_", "network_interfaces"),
    ("c880a_processor_", "processors"),
    ("c880a_memory_", "memory"),
    ("c880a_storage_", "storage"),
    ("c880a_drive_", "drives"),
    ("c880a_volume_", "volumes"),
    ("c880a_system_", "system"),
)


def _component_source(name: str, labels: dict[str, str]) -> str | None:
    if name in ("c880a_component_present", "c880a_component_discovered"):
        return _COMPONENT_TYPE_SOURCE.get(labels.get("component_type", ""))
    return next((source for prefix, source in _COMPONENT_METRIC_SOURCE
                 if name.startswith(prefix)), None)


def _labels(raw: str | None) -> dict[str, str] | None:
    if not raw:
        return {}
    labels: dict[str, str] = {}
    position = 0
    for match in _LABEL.finditer(raw):
        if match.start() != position or match.group(1) in labels:
            return None
        try:
            value = json.loads('"' + match.group(2) + '"')
        except json.JSONDecodeError:
            return None
        if len(value) > 512:
            return None
        labels[match.group(1)] = value
        position = match.end()
    return labels if position == len(raw) and len(labels) <= 16 else None


def parse_exposition(payload: bytes) -> tuple[float, list[tuple[str, dict[str, str], float]]]:
    """Parse only finite numeric samples from our bounded Prometheus text."""
    if len(payload) > MAX_SNAPSHOT_BYTES:
        raise ValueError("Exporter snapshot is too large")
    text = payload.decode("utf-8")
    captured_at = 0.0
    snapshot_at = 0.0
    series: list[tuple[str, dict[str, str], float]] = []
    for line in text.splitlines():
        if not line or line.startswith("#") or len(line) > 2048:
            continue
        match = _SAMPLE.fullmatch(line)
        if not match or not match.group(1).startswith("c880a_"):
            continue
        try:
            number = float(match.group(3))
        except ValueError:
            continue
        if not math.isfinite(number):
            continue
        name = match.group(1)
        if name == "c880a_last_collection_timestamp_seconds":
            captured_at = number
        if name == "c880a_snapshot_timestamp_seconds":
            snapshot_at = number
        labels = _labels(match.group(2))
        if labels is not None:
            series.append((name, labels, number))
        if len(series) >= MAX_SERIES:
            break
    return snapshot_at or captured_at, series


def _unit(name: str) -> str:
    for suffix, unit in (("_celsius", "°C"), ("_watts", "W"), ("_rpm", "RPM"),
                         ("_volts", "V"), ("_amperes", "A"), ("_gib", "GiB"),
                         ("_bytes", "bytes"), ("_seconds", "s")):
        if name.endswith(suffix):
            return unit
    return ""


class MetricHistory:
    def __init__(self, database: Path, *, retention_days: int = 1) -> None:
        if retention_days != 1:
            raise ValueError("Metric history is limited to 24 hours")
        self.database = database
        self.retention_days = retention_days
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS metric_series (
                  id TEXT PRIMARY KEY, server_id TEXT NOT NULL, name TEXT NOT NULL,
                  labels_json TEXT NOT NULL, unit TEXT NOT NULL,
                  value REAL NOT NULL, updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS metric_series_server_idx
                  ON metric_series(server_id, name);
                CREATE TABLE IF NOT EXISTS metric_points (
                  server_id TEXT NOT NULL, series_id TEXT NOT NULL,
                  sampled_at REAL NOT NULL, value REAL NOT NULL,
                  PRIMARY KEY(series_id, sampled_at)
                );
                CREATE INDEX IF NOT EXISTS metric_points_server_time_idx
                  ON metric_points(server_id, sampled_at);
                CREATE TABLE IF NOT EXISTS dashboard_widgets (
                  id TEXT PRIMARY KEY, title TEXT NOT NULL, series_json TEXT NOT NULL,
                  created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tracked_series (
                  id TEXT PRIMARY KEY, server_id TEXT NOT NULL, created_at REAL NOT NULL
                );
            """)
        self.prune()

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.database, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA secure_delete=ON")
        return db

    def ingest(self, server_id: str, payload: bytes, *, respect_manager_policy: bool = False) -> int:
        captured_at, parsed = parse_exposition(payload)
        now = time.time()
        if not now - 86400 <= captured_at <= now + 300:
            return 0
        sensor_times: dict[tuple[str, str], float] = {}
        telemetry_times: dict[tuple[tuple[str, str], ...], float] = {}
        component_time: float | None = None
        component_source_times: dict[str, float] = {}
        for name, labels, number in parsed:
            if name == "c880a_sensor_observed_timestamp_seconds":
                sensor_times[(labels.get("sensor_id", ""), labels.get("sensor_uri", ""))] = number
            elif name == "c880a_telemetry_value_device_timestamp_seconds":
                telemetry_times[tuple(sorted(labels.items()))] = number
            elif name == "c880a_component_observed_timestamp_seconds":
                component_time = number
            elif name == "c880a_component_source_observed_timestamp_seconds":
                source = labels.get("source", "")
                if source in _COMPONENT_TYPE_SOURCE.values() or source in ("system", "power", "power_subsystem"):
                    component_source_times[source] = number
        with self.connect() as db:
            if respect_manager_policy:
                # Serialize with policy transitions so an in-flight exporter
                # scrape cannot write local history after collection is off.
                db.execute("BEGIN IMMEDIATE")
                server = db.execute("SELECT manager_metrics_enabled FROM servers WHERE id=? AND state='active'",
                                    (server_id,)).fetchone()
                if server is None or not server[0]:
                    return 0
                latest = db.execute("""SELECT enabled_at FROM manager_metric_pauses
                                      WHERE server_id=? AND enabled_at IS NOT NULL
                                      ORDER BY enabled_at DESC LIMIT 1""", (server_id,)).fetchone()
                if latest is not None and captured_at < latest[0]:
                    return 0
            # Widget IDs are stored in JSON arrays; do not interpolate them into SQL.
            chosen = set()
            for row in db.execute("SELECT series_json FROM dashboard_widgets"):
                chosen.update(json.loads(row[0]))
            chosen.update(row[0] for row in db.execute("SELECT id FROM tracked_series WHERE server_id=?", (server_id,)))
            catalog = []
            history = []
            for name, labels, number in parsed:
                if name in ("c880a_sensor_info", "c880a_sensor_observed_timestamp_seconds",
                            "c880a_component_observed_timestamp_seconds",
                            "c880a_component_source_observed_timestamp_seconds",
                            "c880a_telemetry_value_device_timestamp_seconds"):
                    continue
                sampled_at = captured_at
                if name.startswith("c880a_sensor_") and name != "c880a_sensor_observed_timestamp_seconds":
                    sampled_at = sensor_times.get(
                        (labels.get("sensor_id", ""), labels.get("sensor_uri", "")), captured_at)
                elif name == "c880a_telemetry_value":
                    # Device time is authoritative; an untimed telemetry
                    # value must not enter local history as a new sample.
                    sampled_at = telemetry_times.get(tuple(sorted(labels.items())), 0)
                elif name == "c880a_telemetry_report_latest_sample_timestamp_seconds":
                    sampled_at = number
                else:
                    source = _component_source(name, labels)
                    if source is not None:
                        sampled_at = component_source_times.get(
                            source, component_time if component_time is not None else captured_at)
                if not now - 86400 <= sampled_at <= now + 300:
                    continue
                labels_json = json.dumps(labels, sort_keys=True, separators=(",", ":"))
                identifier = hashlib.sha256(
                    f"{server_id}\0{name}\0{labels_json}".encode("utf-8")
                ).hexdigest()[:32]
                catalog.append((identifier, server_id, name, labels_json, _unit(name), number, sampled_at))
                if name in _DEFAULT_HISTORY or identifier in chosen:
                    history.append((server_id, identifier, sampled_at, number))
            db.executemany("""INSERT INTO metric_series
                (id, server_id, name, labels_json, unit, value, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET value=excluded.value,
                updated_at=excluded.updated_at
                WHERE excluded.updated_at >= metric_series.updated_at""", catalog)
            db.executemany("INSERT OR IGNORE INTO metric_points VALUES (?, ?, ?, ?)", history)
        self.prune()
        return len(history)

    def prune(self) -> None:
        cutoff = time.time() - self.retention_days * 86400
        with self.connect() as db:
            db.execute("DELETE FROM metric_points WHERE sampled_at < ?", (cutoff,))
            for row in db.execute("SELECT DISTINCT server_id FROM metric_points"):
                db.execute("""DELETE FROM metric_points WHERE rowid IN (
                  SELECT rowid FROM metric_points WHERE server_id=?
                  ORDER BY sampled_at DESC LIMIT -1 OFFSET ?)""",
                           (row[0], MAX_POINTS_PER_SERVER))
            db.execute("DELETE FROM metric_series WHERE updated_at < ?", (cutoff,))

    def catalog(self, server_id: str | None, search: str, limit: int = 100) -> list[dict[str, Any]]:
        escaped = search[:80].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        with self.connect() as db:
            rows = db.execute("""SELECT * FROM metric_series
                WHERE updated_at >= ? AND (? IS NULL OR server_id=?) AND
                  (name LIKE ? ESCAPE '\\' OR labels_json LIKE ? ESCAPE '\\')
                ORDER BY CASE name
                  WHEN 'c880a_chassis_power_average_watts' THEN 0
                  WHEN 'c880a_sensor_temperature_celsius' THEN 1
                  WHEN 'c880a_sensor_fan_speed_rpm' THEN 2
                  WHEN 'c880a_sensor_power_watts' THEN 3
                  ELSE 4 END, name, labels_json LIMIT ?""",
                (time.time() - 86400, server_id, server_id, f"%{escaped}%", f"%{escaped}%", min(200, max(1, limit)))).fetchall()
        return [{**dict(row), "labels": json.loads(row["labels_json"])} for row in rows]

    def get_series(self, identifier: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM metric_series WHERE id=? AND updated_at >= ?",
                             (identifier, time.time() - 86400)).fetchone()
        return {**dict(row), "labels": json.loads(row["labels_json"])} if row else None

    def samples(self, identifier: str, since: float, until: float) -> list[dict[str, float]]:
        with self.connect() as db:
            rows = db.execute("""SELECT sampled_at, value FROM metric_points
                WHERE series_id=? AND sampled_at BETWEEN ? AND ?
                ORDER BY sampled_at LIMIT 5000""", (identifier, max(since, time.time() - 86400), until)).fetchall()
        return [dict(row) for row in rows]

    def track(self, identifier: str) -> bool:
        """Begin bounded per-server history for a series selected in the explorer."""
        with self.connect() as db:
            row = db.execute("SELECT server_id, updated_at, value FROM metric_series WHERE id=? AND updated_at >= ?",
                             (identifier, time.time() - 86400)).fetchone()
            if row is None:
                return False
            if not db.execute("SELECT 1 FROM tracked_series WHERE id=?", (identifier,)).fetchone():
                count = db.execute("SELECT count(*) FROM tracked_series WHERE server_id=?", (row["server_id"],)).fetchone()[0]
                if count >= 100:
                    raise ValueError("At most 100 charted series per server are supported")
                db.execute("INSERT INTO tracked_series VALUES (?, ?, ?)",
                           (identifier, row["server_id"], time.time()))
            db.execute("INSERT OR IGNORE INTO metric_points VALUES (?, ?, ?, ?)",
                       (row["server_id"], identifier, row["updated_at"], row["value"]))
        return True

    def widgets(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM dashboard_widgets ORDER BY created_at, id").fetchall()
        return [{"id": row["id"], "title": row["title"],
                 "series_ids": json.loads(row["series_json"])} for row in rows]

    def add_widget(self, title: str, series_ids: list[str]) -> dict[str, Any]:
        if not 1 <= len(series_ids) <= 5 or len(set(series_ids)) != len(series_ids):
            raise ValueError("Select 1 to 5 distinct metric series")
        if any(not re.fullmatch(r"[0-9a-f]{32}", identifier) for identifier in series_ids):
            raise ValueError("Invalid metric series ID")
        title = title.strip()
        if not 1 <= len(title) <= 80:
            raise ValueError("Widget title must be 1 to 80 characters")
        with self.connect() as db:
            if db.execute("SELECT count(*) FROM dashboard_widgets").fetchone()[0] >= 24:
                raise ValueError("Dashboard is limited to 24 saved charts")
            series = [db.execute("SELECT unit, name FROM metric_series WHERE id=?", (identifier,)).fetchone()
                      for identifier in series_ids]
            if any(row is None for row in series):
                raise ValueError("Metric series is unavailable")
            if len({row["unit"] for row in series if row}) != 1:
                raise ValueError("A chart cannot mix different units")
            if len({row["name"] for row in series if row}) != 1:
                raise ValueError("A comparison chart must use the same metric")
            identifier = secrets.token_hex(16)
            db.execute("INSERT INTO dashboard_widgets VALUES (?, ?, ?, ?)",
                       (identifier, title, json.dumps(series_ids), time.time()))
        return {"id": identifier, "title": title, "series_ids": series_ids}

    def delete_widget(self, identifier: str) -> bool:
        with self.connect() as db:
            cursor = db.execute("DELETE FROM dashboard_widgets WHERE id=?", (identifier,))
            return cursor.rowcount > 0
