"""Synthetic, bounded Redfish C880A fleet for demos and functional tests.

This is deliberately a model of resources consumed by this project, not a
general-purpose Redfish implementation or a source of real hardware data.
"""

from __future__ import annotations

import argparse
import base64
import csv
from datetime import datetime, timedelta, timezone
from functools import lru_cache
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import stat
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit


ROOT = "/redfish/v1"
MAX_FLEET = 50
MAX_BODY = 2_000_000
COUNTS = {"cpus": (1, 8), "gpus": (0, 16), "dimms": (1, 128),
          "network_adapters": (0, 32), "network_interfaces": (0, 64),
          "storage": (0, 16), "drives": (0, 64), "power_supplies": (0, 32),
          "fans": (0, 128)}
DEFAULT_COUNTS = {"cpus": 2, "gpus": 8, "dimms": 32,
                  "network_adapters": 2, "network_interfaces": 4,
                  "storage": 1, "drives": 2, "power_supplies": 6, "fans": 8}
LAB_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in
                     ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                      "::1/128", "fc00::/7"))


def link(path: str) -> dict[str, str]:
    return {"@odata.id": path}


def _integer(value: Any, label: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{label} must be an integer from {low} to {high}")
    return value


def _name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}", value):
        raise ValueError(f"{label} has invalid characters or length")
    return value


def _profile(raw: dict[str, Any]) -> dict[str, Any]:
    allowed = {"name", "model", "gpu_model", "gpu_vendor", "gpu_firmware", "cpu_model",
               "network_model", "network_firmware", "bios_version", "bmc_firmware",
               "counts", "sensor_page_size"}
    if set(raw) - allowed:
        raise ValueError(f"Unknown profile settings: {sorted(set(raw) - allowed)}")
    result = {
        "name": _name(raw.get("name", "Standard C880A"), "profile name"),
        "model": _name(raw.get("model", "UCSAI-880A-M8"), "model"),
        "gpu_model": _name(raw.get("gpu_model", "Synthetic accelerator"), "GPU model"),
        "gpu_vendor": _name(raw.get("gpu_vendor", "Synthetic vendor"), "GPU vendor"),
        "gpu_firmware": _name(raw.get("gpu_firmware", "1.0.0"), "GPU firmware"),
        "cpu_model": _name(raw.get("cpu_model", "Synthetic 64-core processor"), "CPU model"),
        "network_model": _name(raw.get("network_model", "Synthetic 200G adapter"), "network model"),
        "network_firmware": _name(raw.get("network_firmware", "2.0.0"), "network firmware"),
        "bios_version": _name(raw.get("bios_version", "1.0.0"), "BIOS version"),
        "bmc_firmware": _name(raw.get("bmc_firmware", "1.0.0"), "BMC firmware"),
        "sensor_page_size": _integer(raw.get("sensor_page_size", 24), "sensor_page_size", 1, 256),
    }
    counts = raw.get("counts", {})
    if not isinstance(counts, dict) or set(counts) - set(COUNTS):
        raise ValueError("counts must contain only known component names")
    result["counts"] = {key: _integer(counts.get(key, default), key, *COUNTS[key])
                        for key, default in DEFAULT_COUNTS.items()}
    if not result["counts"]["storage"] and result["counts"]["drives"]:
        raise ValueError("drives require at least one storage unit")
    sensor_count = (result["counts"]["cpus"] * 3 + result["counts"]["gpus"] * 5
                    + result["counts"]["fans"] + 6 + int(result["counts"]["gpus"] == 0))
    if sensor_count > result["sensor_page_size"] * 12:
        raise ValueError("sensor_page_size would exceed the exporter's 12-page collection limit")
    if "880A" not in result["model"].upper():
        raise ValueError("model must identify a C880A for manager onboarding")
    return result


def validate_latency(latency: Any) -> dict[str, Any]:
    if not isinstance(latency, dict) or set(latency) - {"base_ms", "jitter_ms", "tail_every", "tail_ms", "paths", "periods"}:
        raise ValueError("latency has unknown settings")
    checked_latency: dict[str, Any] = {
        "base_ms": _integer(latency.get("base_ms", 0), "base_ms", 0, 30_000),
        "jitter_ms": _integer(latency.get("jitter_ms", 0), "jitter_ms", 0, 30_000),
        "tail_every": _integer(latency.get("tail_every", 0), "tail_every", 0, 1000),
        "tail_ms": _integer(latency.get("tail_ms", 0), "tail_ms", 0, 120_000),
        "paths": {},
        "periods": [],
    }
    paths = latency.get("paths", {})
    if not isinstance(paths, dict) or len(paths) > 32:
        raise ValueError("latency.paths must be an object of at most 32 entries")
    for prefix, delay in paths.items():
        if not isinstance(prefix, str) or not (prefix == ROOT or prefix.startswith(ROOT + "/")) or len(prefix) > 180:
            raise ValueError("latency path prefixes must be Redfish paths")
        checked_latency["paths"][prefix] = _integer(delay, "path delay", 0, 120_000)
    periods = latency.get("periods", [])
    if not isinstance(periods, list) or len(periods) > 16:
        raise ValueError("latency.periods must be an array of at most 16 entries")
    for period in periods:
        if not isinstance(period, dict) or set(period) != {"start_seconds", "duration_seconds", "delay_ms"}:
            raise ValueError("each latency period requires start_seconds, duration_seconds, and delay_ms")
        checked_latency["periods"].append({
            "start_seconds": _integer(period["start_seconds"], "period start", 0, 86400),
            "duration_seconds": _integer(period["duration_seconds"], "period duration", 1, 86400),
            "delay_ms": _integer(period["delay_ms"], "period delay", 0, 120_000),
        })
    return checked_latency


def load_config(path: Path) -> dict[str, Any]:
    """Validate a small JSON configuration; never deserialize arbitrary objects."""
    if path.stat().st_size > 64_000:
        raise ValueError("Simulator configuration is too large")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Simulator configuration must be an object")
    allowed = {"fleet_size", "address_start", "port", "seed", "tick_seconds", "profiles",
               "latency", "faults", "observed_sensors"}
    if set(raw) - allowed:
        raise ValueError(f"Unknown simulator settings: {sorted(set(raw) - allowed)}")
    size = _integer(raw.get("fleet_size", 1), "fleet_size", 1, MAX_FLEET)
    address = ipaddress.ip_address(raw.get("address_start", "127.0.0.2"))
    if address.is_multicast or address.is_unspecified or address.is_link_local:
        raise ValueError("address_start must be a non-link-local unicast IP address")
    if isinstance(address, ipaddress.IPv6Address):
        if size != 1:
            raise ValueError("IPv6 supports one BMC per simulator process")
        addresses = [str(address)]
    else:
        if int(address) + size - 1 >= 2**32:
            raise ValueError("fleet address range overflows IPv4")
        addresses = [str(ipaddress.IPv4Address(int(address) + index)) for index in range(size)]
    if any(not any(ipaddress.ip_address(item) in network for network in LAB_NETWORKS)
           for item in addresses):
        raise ValueError("fleet address range must stay on private or loopback addresses")
    profiles = raw.get("profiles", [{}])
    if not isinstance(profiles, list) or not 1 <= len(profiles) <= 16 or not all(isinstance(p, dict) for p in profiles):
        raise ValueError("profiles must be a nonempty array of objects")
    checked_latency = validate_latency(raw.get("latency", {}))
    observed_sensors = raw.get("observed_sensors", False)
    if not isinstance(observed_sensors, bool):
        raise ValueError("observed_sensors must be true or false")
    if observed_sensors and any(profile["sensor_page_size"] * 12 < 336
                                for profile in [_profile(item) for item in profiles]):
        raise ValueError("Observed sensors need sensor_page_size of at least 28")
    faults = raw.get("faults", [])
    if not isinstance(faults, list) or len(faults) > 32:
        raise ValueError("faults must be an array of at most 32 entries")
    checked_faults = []
    for fault in faults:
        if not isinstance(fault, dict) or set(fault) - {"server", "path", "start_seconds", "duration_seconds",
                                                    "mode", "delay_ms", "status"}:
            raise ValueError("fault has unknown settings")
        server = _integer(fault.get("server", 0), "fault server", 0, size - 1)
        prefix = fault.get("path", ROOT)
        if not isinstance(prefix, str) or not (prefix == ROOT or prefix.startswith(ROOT + "/")) or len(prefix) > 180:
            raise ValueError("fault path must be a Redfish path")
        mode = fault.get("mode", "http_error")
        if mode not in {"http_error", "disconnect", "delay", "malformed_pagination"}:
            raise ValueError("unknown fault mode")
        checked_faults.append({"server": server, "path": prefix,
                               "start_seconds": _integer(fault.get("start_seconds", 0), "start_seconds", 0, 86400),
                               "duration_seconds": _integer(fault.get("duration_seconds", 30), "duration_seconds", 1, 86400),
                               "mode": mode, "delay_ms": _integer(fault.get("delay_ms", 0), "delay_ms", 0, 120_000),
                               "status": _integer(fault.get("status", 503), "status", 400, 599)})
    return {"fleet_size": size, "addresses": addresses,
            "port": _integer(raw.get("port", 443), "port", 1, 65535),
            "seed": _integer(raw.get("seed", 880), "seed", 0, 2**31 - 1),
            "tick_seconds": _integer(raw.get("tick_seconds", 15), "tick_seconds", 1, 3600),
            "profiles": [_profile(item) for item in profiles], "latency": checked_latency,
            "observed_sensors": observed_sensors,
            "faults": checked_faults}


@lru_cache(maxsize=1)
def observed_sensor_rows() -> tuple[tuple[str, str, str], ...]:
    """Public, value-free identities extracted from the reviewed C880A matrix."""
    path = Path(__file__).with_name("c880a_sensors.tsv")
    with path.open(newline="", encoding="utf-8") as stream:
        rows = tuple((row["id"], row["metric_family"], row["baseline_reading"])
                     for row in csv.DictReader(stream, delimiter="\t"))
    if len(rows) != 336 or len({row[0] for row in rows}) != 336:
        raise ValueError("Packaged C880A sensor profile is incomplete")
    return rows


class VirtualBMC:
    def __init__(self, config: dict[str, Any], index: int, *, clock=time.monotonic) -> None:
        self.config = config
        self.index = index
        self.address = config["addresses"][index]
        self.profile = config["profiles"][index % len(config["profiles"])]
        self.seed = config["seed"] + index * 1009
        self.clock = clock
        self.started = clock()
        self._lock = threading.Lock()
        self._requests: dict[str, int] = {}
        self._power_state = "On"
        self._tasks: dict[str, dict[str, Any]] = {}

    @property
    def serial(self) -> str:
        return f"SIM{self.seed:010d}"

    def tick(self) -> int:
        return max(0, int((self.clock() - self.started) // self.config["tick_seconds"]))

    def _variation(self, key: str, span: int = 10) -> int:
        digest = hashlib.sha256(f"{self.seed}:{key}:{self.tick()}".encode()).digest()
        return int.from_bytes(digest[:4], "big") % (span * 2 + 1) - span

    def _status(self, key: str) -> dict[str, str]:
        # Deterministic fault-like health transitions; never pretend to model
        # the exact physical behavior of a particular customer's hardware.
        health = "Warning" if self.tick() > 0 and self._variation(key, 40) == 40 else "OK"
        return {"Health": health, "State": "Enabled"}

    def _collection(self, path: str, items: list[dict[str, Any]], query: dict[str, list[str]]) -> dict[str, Any]:
        page_size = self.profile["sensor_page_size"] if path.endswith("/Sensors") else 256
        raw_skip = query.get("$skip", ["0"])[0]
        skip = int(raw_skip) if len(raw_skip) <= 8 and raw_skip.isdigit() else 0
        skip = min(skip, len(items))
        selected = items[skip:skip + page_size]
        expanded = "$expand" in query
        members = selected if expanded else [link(item["@odata.id"]) for item in selected]
        body: dict[str, Any] = {"@odata.id": path, "Members@odata.count": len(items), "Members": members}
        if skip + page_size < len(items):
            body["Members@odata.nextLink"] = f"{path}?$skip={skip + page_size}"
        return body

    def _sensor(self, path: str, name: str, reading_type: str, unit: str,
                nominal: int) -> dict[str, Any]:
        reading = nominal + self._variation(name, 3)
        return {"@odata.id": path, "Id": name, "Name": name.replace("_", " "),
                "ReadingType": reading_type, "ReadingUnits": unit,
                "Reading": reading, "PhysicalContext": "Chassis" if "PWR" in name else "CPU",
                "Status": self._status(name), "ReadingRangeMin": 0,
                "ReadingRangeMax": max(nominal * 2, 100)}

    def _observed_sensor(self, chassis: str, sensor_id: str, family: str,
                         baseline: str) -> dict[str, Any]:
        types = {
            "c880a_sensor_temperature_celsius": ("Temperature", "Cel"),
            "c880a_sensor_fan_speed_rpm": ("Rotational", "RPM"),
            "c880a_sensor_power_watts": ("Power", "W"),
            "c880a_sensor_voltage_volts": ("Voltage", "V"),
            "c880a_sensor_current_amperes": ("Current", "A"),
            "c880a_sensor_energy_joules": ("EnergyJoules", "J"),
            "c880a_sensor_reading": ("Numeric", ""),
        }
        reading_type, unit = types[family]
        result = {"@odata.id": f"{chassis}/Sensors/{sensor_id}", "Id": sensor_id,
                  "Name": sensor_id.replace("_", " "), "ReadingType": reading_type,
                  "ReadingUnits": unit, "PhysicalContext": "Chassis",
                  "Status": self._status(sensor_id)}
        if baseline == "unavailable":
            return result
        noise = self._variation(sensor_id, 5)
        if reading_type == "Temperature":
            nominal = (24 if "AMBIENT" in sensor_id or "INLET" in sensor_id else
                       53 if "GPU" in sensor_id or "GB_" in sensor_id else 43)
            reading = nominal + noise
        elif reading_type == "Rotational":
            reading = 8500 + noise * 25
        elif reading_type == "Power":
            nominal = (3200 if "TOT" in sensor_id else 550 if "GPU" in sensor_id or "SXM" in sensor_id
                       else 350 if "CPU" in sensor_id else 500 if "PSU" in sensor_id else 220)
            reading = nominal + noise * 3
        elif reading_type == "Voltage":
            match = re.search(r"(\d+)V(\d*)", sensor_id)
            nominal = float(f"{match.group(1)}.{match.group(2)}") if match else 3.3
            reading = round(nominal * (1 + noise / 1000), 3)
        elif reading_type == "Current":
            reading = round(8 + noise / 25, 2)
        elif reading_type == "EnergyJoules":
            reading = 2500 + self.tick() * 20 + noise
        else:
            reading = 1 if noise >= -4 else 0
        result["Reading"] = reading
        result["ReadingRangeMin"] = 0
        result["ReadingRangeMax"] = max(reading * 2, 1)
        return result

    def _resources(self) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
        """Create one internally consistent resource graph per request/tick."""
        p, c = self.profile, self.profile["counts"]
        with self._lock:
            power_state = self._power_state
            tasks = dict(self._tasks)
        sys, hgx, chassis, manager = (ROOT + suffix for suffix in
                                      ("/Systems/DGX", "/Systems/HGX", "/Chassis/DGX", "/Managers/BMC"))
        diagnostic = manager + "/LogServices/DiagnosticLog"
        root: dict[str, dict[str, Any]] = {
            ROOT: {"@odata.id": ROOT, "RedfishVersion": "1.17.0", "Systems": link(ROOT + "/Systems"),
                   "Chassis": link(ROOT + "/Chassis"), "Managers": link(ROOT + "/Managers"),
                   "TelemetryService": link(ROOT + "/TelemetryService"),
                   "EventService": link(ROOT + "/EventService"),
                   "TaskService": link(ROOT + "/TaskService")},
            sys: {"@odata.id": sys, "Id": "DGX", "Name": "Synthetic C880A system",
                  "Model": p["model"], "Manufacturer": "Synthetic lab", "SerialNumber": self.serial,
                  "UUID": f"00000000-0000-4000-8000-{self.seed:012x}",
                  "BiosVersion": p["bios_version"], "PowerState": power_state, "Status": self._status("system"),
                  "Actions": {"#ComputerSystem.Reset": {
                      "target": sys + "/Actions/ComputerSystem.Reset",
                      "@Redfish.ActionInfo": sys + "/ResetActionInfo"}},
                  "ProcessorSummary": {"Count": c["cpus"], "Status": self._status("processors")},
                  "MemorySummary": {"TotalSystemMemoryGiB": c["dimms"] * 96,
                                    "Status": self._status("memory")},
                  "Processors": link(sys + "/Processors"), "Memory": link(sys + "/Memory"),
                  "Storage": link(sys + "/Storage"),
                  "NetworkInterfaces": link(sys + "/NetworkInterfaces"),
                  "NetworkAdapters": link(chassis + "/NetworkAdapters"),
                  "Boot": {"BootOrder": ["Boot0000", "Boot0001"]}},
            hgx: {"@odata.id": hgx, "Id": "HGX", "Name": "Synthetic accelerator subsystem",
                  "Model": "Synthetic HGX baseboard", "SerialNumber": f"{self.serial}-H",
                  "Status": self._status("hgx"), "Processors": link(hgx + "/Processors")},
            chassis: {"@odata.id": chassis, "Id": "DGX", "Name": "Synthetic chassis",
                      "Model": p["model"], "SerialNumber": f"{self.serial}-C",
                      "Status": self._status("chassis"), "Sensors": link(chassis + "/Sensors"),
                      "Power": link(chassis + "/Power"), "Thermal": link(chassis + "/Thermal"),
                      "PowerSubsystem": link(chassis + "/PowerSubsystem"),
                      "NetworkAdapters": link(chassis + "/NetworkAdapters")},
            manager: {"@odata.id": manager, "Id": "BMC", "Name": "Synthetic management controller",
                      "FirmwareVersion": p["bmc_firmware"], "Status": self._status("bmc"),
                      "LogServices": link(manager + "/LogServices"),
                      "Actions": {"#Manager.Reset": {
                          "target": manager + "/Actions/Manager.Reset",
                          "ResetType@Redfish.AllowableValues": ["ForceRestart"]}}},
            sys + "/ResetActionInfo": {"Parameters": [{"Name": "ResetType", "AllowableValues":
                ["On", "GracefulShutdown", "ForceOff", "GracefulRestart", "ForceRestart"]}]},
            diagnostic: {"@odata.id": diagnostic, "Id": "DiagnosticLog",
                         "Entries": link(diagnostic + "/Entries"),
                         "Actions": {"#LogService.CollectDiagnosticData": {
                             "target": diagnostic + "/Actions/LogService.CollectDiagnosticData",
                             "@Redfish.ActionInfo": diagnostic + "/CollectDiagnosticDataActionInfo"}}},
            diagnostic + "/CollectDiagnosticDataActionInfo": {"Parameters": [
                {"Name": "DiagnosticDataType", "AllowableValues": ["OEM"]},
                {"Name": "OEMDiagnosticDataType", "AllowableValues": ["ALL"]}]},
            ROOT + "/TaskService": {"@odata.id": ROOT + "/TaskService",
                                      "Tasks": link(ROOT + "/TaskService/Tasks")},
            ROOT + "/TelemetryService": {"@odata.id": ROOT + "/TelemetryService",
                                           "MetricReports": link(ROOT + "/TelemetryService/MetricReports")},
            ROOT + "/EventService": {"@odata.id": ROOT + "/EventService", "ServiceEnabled": False},
        }
        for count_key, resource_key in (("storage", "Storage"),
                                        ("network_interfaces", "NetworkInterfaces"),
                                        ("network_adapters", "NetworkAdapters")):
            if not c[count_key]:
                root[sys].pop(resource_key, None)
        if not c["network_adapters"]:
            root[chassis].pop("NetworkAdapters", None)
        collections: dict[str, list[dict[str, Any]]] = {
            ROOT + "/Systems": [link(sys), link(hgx)],
            ROOT + "/Chassis": [link(chassis)],
            ROOT + "/Managers": [link(manager)],
            manager + "/LogServices": [link(diagnostic)],
            diagnostic + "/Entries": [],
            ROOT + "/TaskService/Tasks": [],
        }
        for task_id, task in tasks.items():
            task_uri = ROOT + "/TaskService/Tasks/" + task_id
            completed = self.clock() - task["started"] >= 0.3
            root[task_uri] = {"@odata.id": task_uri, "Id": task_id,
                              "TaskState": "Completed" if completed else "Running",
                              "TaskStatus": "OK", "PercentComplete": 100 if completed else 25}
            collections[ROOT + "/TaskService/Tasks"].append(link(task_uri))
            if completed and task["operation"] == "collect_support_bundle":
                entry_uri = diagnostic + "/Entries/bundle-" + task_id
                content = self.attachment(entry_uri + "/attachment")
                root[entry_uri] = {"@odata.id": entry_uri, "Id": "bundle-" + task_id,
                                   "DiagnosticDataType": "Manager", "AdditionalDataURI": entry_uri + "/attachment",
                                   "AdditionalDataSizeBytes": len(content) if content else 0}
                collections[diagnostic + "/Entries"].append(link(entry_uri))
        for path in (sys + "/Processors", hgx + "/Processors", sys + "/Memory",
                     sys + "/Storage", sys + "/NetworkInterfaces",
                     chassis + "/NetworkAdapters", chassis + "/PowerSubsystem/PowerSupplies"):
            collections[path] = []

        def add(path: str, payload: dict[str, Any], collection: str | None = None) -> None:
            root[path] = {"@odata.id": path, **payload}
            if collection:
                collections.setdefault(collection, []).append(root[path])

        for i in range(c["cpus"]):
            path = f"{sys}/Processors/CPU{i}"
            add(path, {"Id": f"CPU{i}", "Name": f"Processor {i}", "ProcessorType": "CPU",
                       "Model": p["cpu_model"], "Manufacturer": "Synthetic lab", "TotalCores": 64,
                       "TotalThreads": 128, "Status": self._status(path)}, sys + "/Processors")
        for i in range(c["gpus"]):
            path = f"{hgx}/Processors/GPU{i}"
            add(path, {"Id": f"GPU{i}", "Name": f"GPU {i}", "ProcessorType": "GPU",
                       "Model": p["gpu_model"], "Manufacturer": p["gpu_vendor"],
                       "FirmwareVersion": p["gpu_firmware"], "SerialNumber": f"{self.serial}-G{i:02d}",
                       "Location": {"PartLocation": {"ServiceLabel": f"GPU{i}"}},
                       "Status": self._status(path)}, hgx + "/Processors")
        for i in range(c["dimms"]):
            path = f"{sys}/Memory/DIMM{i}"
            add(path, {"Id": f"DIMM{i}", "Name": f"DIMM{i}", "CapacityMiB": 98304,
                       "MemoryDeviceType": "DDR5", "OperatingSpeedMhz": 5200,
                       "Manufacturer": "Synthetic lab", "SerialNumber": f"{self.serial}-M{i:03d}",
                       "Location": {"PartLocation": {"ServiceLabel": f"CPU{i % c['cpus']}_DIMM_{i}"}},
                       "Status": self._status(path)}, sys + "/Memory")
        for i in range(c["network_adapters"]):
            path = f"{chassis}/NetworkAdapters/NIC{i}"
            add(path, {"Id": f"NIC{i}", "Name": f"Adapter {i}", "Model": p["network_model"],
                       "Manufacturer": "Synthetic lab", "SerialNumber": f"{self.serial}-N{i:02d}",
                       "FirmwareVersion": p["network_firmware"], "Status": self._status(path)},
                chassis + "/NetworkAdapters")
        for i in range(c["network_interfaces"]):
            path = f"{sys}/NetworkInterfaces/Eth{i}"
            adapter = f"{chassis}/NetworkAdapters/NIC{i % c['network_adapters']}" if c["network_adapters"] else None
            payload = {"Id": f"Eth{i}", "Name": f"Ethernet {i}",
                       "MACAddress": f"02:88:{self.index:02x}:{i:02x}:00:01",
                       "CurrentLinkSpeedMbps": 200000, "Status": self._status(path)}
            if adapter:
                payload["Links"] = {"NetworkAdapter": link(adapter)}
            add(path, payload, sys + "/NetworkInterfaces")
        for i in range(c["storage"]):
            path = f"{sys}/Storage/Storage{i}"
            drives = [link(f"{sys}/Storage/Storage{i}/Drives/Drive{n}")
                      for n in range(c["drives"]) if n % max(c["storage"], 1) == i]
            add(path, {"Id": f"Storage{i}", "Name": f"Storage {i}",
                       "Status": self._status(path), "Drives": drives,
                       "StorageControllers": [{"MemberId": "Controller0", "Name": "Controller 0",
                                               "FirmwareVersion": "1.0.0", "Status": self._status(path + "/Controller0")}]},
                sys + "/Storage")
            for ref in drives:
                drive_path = ref["@odata.id"]
                drive_id = drive_path.rsplit("/", 1)[-1]
                add(drive_path, {"Id": drive_id, "Name": drive_id, "Model": "Synthetic NVMe drive",
                                 "CapacityBytes": 2_000_000_000_000,
                                 "SerialNumber": f"{self.serial}-{drive_id}",
                                 "Status": self._status(drive_path)})
        supply_collection = chassis + "/PowerSubsystem/PowerSupplies"
        subsystem = {"Id": "PowerSubsystem", "Status": self._status("power")}
        if c["power_supplies"]:
            subsystem["PowerSupplies"] = link(supply_collection)
        add(chassis + "/PowerSubsystem", subsystem)
        supplies = []
        for i in range(c["power_supplies"]):
            path = f"{supply_collection}/PSU{i}"
            item = {"Id": f"PSU{i}", "Name": f"Power supply {i}", "Model": "Synthetic 3000W PSU",
                    "PowerCapacityWatts": 3000, "SerialNumber": f"{self.serial}-P{i:02d}",
                    "Status": self._status(path)}
            add(path, item, supply_collection)
            supplies.append(item)
        fans = [{"MemberId": f"FAN{i}", "Name": f"Fan {i}", "ReadingRPM": 8500 + self._variation(f"fan{i}", 150),
                 "Status": self._status(f"fan{i}")} for i in range(c["fans"])]
        power = 3200 + self._variation("power", 75)
        add(chassis + "/Power", {"Id": "Power", "PowerControl": [{"PowerConsumedWatts": power,
            "PowerMetrics": {"AverageConsumedWatts": power - 10,
                             "MinConsumedWatts": power - 100, "MaxConsumedWatts": power + 100}}],
            "PowerSupplies": supplies})
        temperatures = [{"MemberId": f"TEMP_CPU{i}", "Name": f"CPU {i} temperature",
                         "ReadingCelsius": 42 + self._variation(f"cpu-temp{i}", 4),
                         "Status": self._status(f"cpu-temp{i}")} for i in range(c["cpus"])]
        temperatures.append({"MemberId": "TEMP_AMBIENT", "Name": "Ambient temperature",
                             "ReadingCelsius": 24 + self._variation("ambient", 2),
                             "Status": self._status("ambient")})
        add(chassis + "/Thermal", {"Id": "Thermal", "Temperatures": temperatures, "Fans": fans})
        if self.config.get("observed_sensors"):
            sensors = [self._observed_sensor(chassis, *row) for row in observed_sensor_rows()]
        else:
            sensors = [self._sensor(f"{chassis}/Sensors/TEMP_{i}", f"TEMP_{i}", "Temperature", "Cel",
                                    35 + i % 25) for i in range(c["cpus"] * 3 + c["gpus"] * 4 + 6)]
            sensors += [self._sensor(f"{chassis}/Sensors/PWR_{i}", f"PWR_{i}", "Power", "W",
                                     300 + i * 10) for i in range(max(1, c["gpus"]))]
            sensors += [self._sensor(f"{chassis}/Sensors/FAN_{i}", f"FAN_{i}", "Rotational", "RPM",
                                     8500) for i in range(c["fans"])]
        for item in sensors:
            root[item["@odata.id"]] = item
        collections[chassis + "/Sensors"] = sensors
        report_path = ROOT + "/TelemetryService/MetricReports/Host"
        add(report_path, {"Id": "Host", "MetricValues": [
            {"MetricProperty": f"{chassis}/Power#/PowerControl/0/PowerConsumedWatts",
             "MetricValue": str(power), "Timestamp": datetime.now(timezone.utc).isoformat()},
            {"MetricProperty": f"{sys}#/ProcessorSummary/Count",
             "MetricValue": str(c["cpus"]), "Timestamp": datetime.now(timezone.utc).isoformat()}]},
            ROOT + "/TelemetryService/MetricReports")
        for path, items in collections.items():
            root[path] = {"@odata.id": path, "Members@odata.count": len(items),
                          "Members": [link(item["@odata.id"]) for item in items]}
        return root, collections

    def fault(self, path: str) -> dict[str, Any] | None:
        elapsed = self.clock() - self.started
        for entry in self.config["faults"]:
            if (entry["server"] == self.index and path.startswith(entry["path"])
                    and entry["start_seconds"] <= elapsed < entry["start_seconds"] + entry["duration_seconds"]):
                return entry
        return None

    def delay(self, path: str, fault: dict[str, Any] | None) -> float:
        profile = self.config["latency"]
        with self._lock:
            count = self._requests.get(path, 0) + 1
            self._requests[path] = count
        digest = hashlib.sha256(f"{self.seed}:{path}:{count}".encode()).digest()
        jitter = int.from_bytes(digest[:4], "big") % (profile["jitter_ms"] + 1)
        tail = profile["tail_ms"] if profile["tail_every"] and count % profile["tail_every"] == 0 else 0
        specific = max((delay for prefix, delay in profile["paths"].items() if path.startswith(prefix)), default=0)
        elapsed = self.clock() - self.started
        shared = max((period["delay_ms"] for period in profile["periods"]
                      if period["start_seconds"] <= elapsed
                      < period["start_seconds"] + period["duration_seconds"]), default=0)
        added = fault["delay_ms"] if fault and fault["mode"] == "delay" else 0
        return (profile["base_ms"] + jitter + tail + specific + shared + added) / 1000

    def response(self, target: str) -> tuple[int, dict[str, Any]]:
        parsed = urlsplit(target)
        path = parsed.path.rstrip("/") or ROOT
        if not (path == ROOT or path.startswith(ROOT + "/")) or ".." in path:
            return 404, {"error": "Not found"}
        resources, collections = self._resources()
        if path not in resources:
            return 404, {"error": "Not found"}
        payload = resources[path]
        if path in collections:
            payload = self._collection(path, collections[path], parse_qs(parsed.query, keep_blank_values=True))
        return 200, payload

    def action(self, path: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any], str | None]:
        """Simulate only three deliberately allowlisted Redfish action routes."""
        system_reset = ROOT + "/Systems/DGX/Actions/ComputerSystem.Reset"
        manager_reset = ROOT + "/Managers/BMC/Actions/Manager.Reset"
        diagnostic = ROOT + "/Managers/BMC/LogServices/DiagnosticLog/Actions/LogService.CollectDiagnosticData"
        if path == system_reset:
            if set(payload) != {"ResetType"}:
                return 400, {"error": "Invalid reset payload"}, None
            reset_type = payload["ResetType"]
            with self._lock:
                if reset_type == "On" and self._power_state == "Off":
                    self._power_state = "On"
                elif reset_type in ("GracefulShutdown", "ForceOff") and self._power_state == "On":
                    self._power_state = "Off"
                elif reset_type in ("GracefulRestart", "ForceRestart") and self._power_state == "On":
                    self._power_state = "On"
                else:
                    return 409, {"error": "Reset type does not apply to current power state"}, None
        elif path == manager_reset:
            if payload != {"ResetType": "ForceRestart"}:
                return 400, {"error": "Invalid manager reset payload"}, None
        elif path == diagnostic:
            if payload != {"DiagnosticDataType": "OEM", "OEMDiagnosticDataType": "ALL"}:
                return 400, {"error": "Invalid diagnostic payload"}, None
        else:
            return 404, {"error": "Action not found"}, None
        operation = "collect_support_bundle" if path == diagnostic else "reboot_bmc" if path == manager_reset else reset_type
        with self._lock:
            if len(self._tasks) >= 100:
                self._tasks.pop(next(iter(self._tasks)))
            task_id = f"task-{len(self._tasks) + 1}-{secrets.token_hex(4)}"
            self._tasks[task_id] = {"operation": operation, "started": self.clock()}
        task_uri = ROOT + "/TaskService/Tasks/" + task_id
        return 202, {"@odata.id": task_uri, "Id": task_id, "TaskState": "New"}, task_uri

    def attachment(self, path: str) -> bytes | None:
        prefix = ROOT + "/Managers/BMC/LogServices/DiagnosticLog/Entries/bundle-"
        if not path.startswith(prefix) or not path.endswith("/attachment"):
            return None
        task_id = path[len(prefix):-len("/attachment")]
        with self._lock:
            task = self._tasks.get(task_id)
        if not task or task["operation"] != "collect_support_bundle" or self.clock() - task["started"] < 0.3:
            return None
        return f"Synthetic support data for {self.serial}; task {task_id}\n".encode()


class SimulatorServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, address: tuple[str, int], bmc: VirtualBMC, username: str,
                 password: str, context: ssl.SSLContext) -> None:
        if isinstance(ipaddress.ip_address(address[0]), ipaddress.IPv6Address):
            self.address_family = socket.AF_INET6
        self.bmc = bmc
        self.expected_auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        self._request_slots = threading.BoundedSemaphore(16)
        self.accepted_connections = 0
        super().__init__(address, SimulatorHandler)
        self.socket = context.wrap_socket(self.socket, server_side=True)

    def process_request(self, request, client_address) -> None:
        if not self._request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            self.accepted_connections += 1
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


class SimulatorHandler(BaseHTTPRequestHandler):
    server: SimulatorServer
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        if self.headers.get("Authorization") is None or not secrets.compare_digest(
                self.headers["Authorization"], self.server.expected_auth):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Synthetic Redfish lab"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        path = urlsplit(self.path).path
        fault = self.server.bmc.fault(path)
        time.sleep(self.server.bmc.delay(path, fault))
        if fault and fault["mode"] == "disconnect":
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            return
        if fault and fault["mode"] == "http_error":
            status, payload = fault["status"], {"error": "Synthetic Redfish fault"}
        else:
            attachment = self.server.bmc.attachment(path)
            if attachment is not None:
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(attachment)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                try:
                    self.wfile.write(attachment)
                except OSError:
                    pass
                return
            status, payload = self.server.bmc.response(self.path)
            if fault and fault["mode"] == "malformed_pagination" and "Members" in payload:
                payload["Members@odata.nextLink"] = path + "?$skip=0"
                payload["Members@odata.count"] = max(payload["Members@odata.count"], len(payload["Members"]) + 1)
        body = json.dumps(payload, separators=(",", ":")).encode()
        if len(body) > MAX_BODY:
            status, body = 503, b'{"error":"Synthetic response too large"}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def do_POST(self) -> None:
        if self.headers.get("Authorization") is None or not secrets.compare_digest(
                self.headers["Authorization"], self.server.expected_auth):
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        length = self.headers.get("Content-Length", "")
        if not length.isdigit() or not 0 < int(length) <= 4096:
            self.send_response(413)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        try:
            payload = json.loads(self.rfile.read(int(length)))
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = None
        if not isinstance(payload, dict):
            status, result, location = 400, {"error": "Invalid action body"}, None
        else:
            path = urlsplit(self.path).path
            fault = self.server.bmc.fault(path)
            time.sleep(self.server.bmc.delay(path, fault))
            if fault and fault["mode"] == "disconnect":
                self.close_connection = True
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                return
            if fault and fault["mode"] == "http_error":
                status, result, location = fault["status"], {"error": "Synthetic Redfish fault"}, None
            else:
                status, result, location = self.server.bmc.action(path, payload)
        body = json.dumps(result, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if location:
            self.send_header("Location", location)
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def log_message(self, format: str, *args: object) -> None:
        # Authorization headers and arbitrary paths must not reach logs.
        return


def create_lab_certificate(path: Path, addresses: list[str]) -> tuple[Path, Path]:
    """Generate a short-lived lab certificate without committing key material."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.stat().st_mode & 0o077:
        raise ValueError("Certificate directory must be private and not a symlink")
    cert_path, key_path = path / "simulator.crt", path / "simulator.key"
    if cert_path.exists() or key_path.exists():
        raise ValueError("Lab certificate paths already exist; choose a fresh private directory")
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    # Distinct subjects allow several self-signed simulator roots in one BMC
    # CA bundle. OpenSSL otherwise selects only the first matching issuer.
    identity = x509.Name([x509.NameAttribute(
        NameOID.COMMON_NAME, f"Synthetic C880A Lab {secrets.token_hex(8)}")])
    cert = (x509.CertificateBuilder()
            .subject_name(identity)
            .issuer_name(identity)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(item))
                                                         for item in addresses]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256()))
    for target, data in ((key_path, key.private_bytes(serialization.Encoding.PEM,
                                                     serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption())),
                         (cert_path, cert.public_bytes(serialization.Encoding.PEM))):
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
    return cert_path, key_path


def verify_lab_certificate(path: Path, addresses: list[str]) -> None:
    """Fail closed on expired, weak, or incorrectly addressed lab certificates."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    certificate = x509.load_pem_x509_certificate(path.read_bytes())
    now = datetime.now(timezone.utc)
    before = certificate.not_valid_before_utc
    after = certificate.not_valid_after_utc
    if not before <= now <= after:
        raise ValueError("Lab certificate is not currently valid")
    public_key = certificate.public_key()
    if not ((isinstance(public_key, ec.EllipticCurvePublicKey) and public_key.key_size >= 256)
            or (isinstance(public_key, rsa.RSAPublicKey) and public_key.key_size >= 2048)):
        raise ValueError("Lab certificate uses a weak or unsupported key")
    if certificate.signature_hash_algorithm is None or certificate.signature_hash_algorithm.name not in {
            "sha256", "sha384", "sha512"}:
        raise ValueError("Lab certificate uses an unsupported signature hash")
    try:
        sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("Lab certificate needs IP Subject Alternative Names") from exc
    covered = set(sans.get_values_for_type(x509.IPAddress))
    if not all(ipaddress.ip_address(address) in covered for address in addresses):
        raise ValueError("Lab certificate must cover every virtual BMC IP")


def serve(config: dict[str, Any], username: str, password: str, cert: Path, key: Path,
          ready=None) -> None:
    verify_lab_certificate(cert, config["addresses"])
    if key.is_symlink() or not stat.S_ISREG(key.stat().st_mode) or key.stat().st_mode & 0o077:
        raise ValueError("Lab TLS private key must be a private regular file")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert, key)
    servers: list[SimulatorServer] = []
    threads: list[threading.Thread] = []
    try:
        for index, address in enumerate(config["addresses"]):
            server = SimulatorServer((address, config["port"]), VirtualBMC(config, index),
                                     username, password, context)
            servers.append(server)
            thread = threading.Thread(target=server.serve_forever, name=f"synthetic-bmc-{index}", daemon=True)
            thread.start()
            threads.append(thread)
        urls = ", ".join(f"https://{'[' + address + ']' if ':' in address else address}:{config['port']}"
                         for address in config["addresses"])
        print(f"Synthetic Redfish fleet ready: {len(servers)} BMCs at {urls} (PID {os.getpid()})", flush=True)
        if ready:
            ready()
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        stop.wait()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a synthetic C880A Redfish lab fleet")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--username", default="simulator")
    parser.add_argument("--password-env", required=True, help="Environment variable with a synthetic lab password")
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--generate-cert-dir", type=Path)
    parser.add_argument("--latency-profile", type=Path,
                        help="JSON latency object overriding the fleet configuration")
    parser.add_argument("--allow-nonloopback", action="store_true",
                        help="Explicitly permit binding to isolated private lab addresses")
    args = parser.parse_args()
    if bool(args.cert) != bool(args.key) or (args.generate_cert_dir and args.cert):
        parser.error("Provide cert and key together, or a fresh generate-cert-dir")
    password = os.environ.get(args.password_env, "")
    if not password or len(password) > 4096:
        parser.error("Synthetic lab password is missing or too long")
    try:
        config = load_config(args.config)
        if not args.allow_nonloopback and any(not ipaddress.ip_address(address).is_loopback
                                              for address in config["addresses"]):
            parser.error("Non-loopback lab addresses require --allow-nonloopback")
        if args.latency_profile:
            if args.latency_profile.stat().st_size > 8_000:
                raise ValueError("Latency profile is too large")
            config["latency"] = validate_latency(json.loads(args.latency_profile.read_text(encoding="utf-8")))
        cert, key = (create_lab_certificate(args.generate_cert_dir, config["addresses"])
                     if args.generate_cert_dir else (args.cert, args.key))
        if not cert or not key:
            parser.error("HTTPS certificate and key are required")
        serve(config, _name(args.username, "username"), password, cert, key)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
