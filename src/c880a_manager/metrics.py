"""Prometheus text format for immutable Redfish snapshots."""

from __future__ import annotations

import hashlib
import math
import re
import time
from datetime import datetime
from typing import Any


READING_METRICS = {
    "Temperature": ("c880a_sensor_temperature_celsius", "Temperature in Celsius", "Cel"),
    "Rotational": ("c880a_sensor_fan_speed_rpm", "Fan speed in RPM", "RPM"),
    "Voltage": ("c880a_sensor_voltage_volts", "Voltage in volts", "V"),
    "Current": ("c880a_sensor_current_amperes", "Current in amperes", "A"),
    "Power": ("c880a_sensor_power_watts", "Power in watts", "W"),
    "EnergyJoules": ("c880a_sensor_energy_joules", "Energy in joules", "J"),
}

THRESHOLD_NAMES = ("LowerCaution", "LowerCritical", "LowerFatal",
                   "UpperCaution", "UpperCritical", "UpperFatal")
COMPONENT_SOURCE_KEYS = ("system", "processors", "memory", "storage", "storage_controllers",
                         "drives", "volumes", "network_interfaces", "power", "power_subsystem",
                         "power_supplies")

# Exact eight-GPU properties observed in the R18 baseline, not an assumption
# that every firmware supplies them. Missing/old values stay visible as a
# coverage shortfall; they are never synthesized or re-stamped.
GPU_BASELINE_PROPERTIES = frozenset({
    ("HGX_PlatformEnvironmentMetrics_0", path)
    for path in (
        "/redfish/v1/Chassis/HGX_GPU_N/Sensors/HGX_GPU_N_Power_0",
        "/redfish/v1/Chassis/HGX_GPU_N/Sensors/HGX_GPU_N_Energy_0",
        "/redfish/v1/Chassis/HGX_GPU_N/Sensors/HGX_GPU_N_DRAM_0_Power_0",
        "/redfish/v1/Chassis/HGX_GPU_N/Sensors/HGX_GPU_N_DRAM_0_Temp_0",
        "/redfish/v1/Chassis/HGX_GPU_N/Sensors/HGX_GPU_N_TEMP_0",
        "/redfish/v1/Chassis/HGX_GPU_N/Sensors/HGX_GPU_N_TEMP_1",
    )
} | {
    ("HGX_ProcessorMetrics_0", path)
    for path in (
        "/redfish/v1/Systems/HGX_Baseboard_0/Processors/GPU_N/ProcessorMetrics#/Oem/Nvidia/SMUtilizationPercent",
        "/redfish/v1/Systems/HGX_Baseboard_0/Processors/GPU_N/ProcessorMetrics#/BandwidthPercent",
    )
} | {
    ("HGX_MemoryMetrics_0", path)
    for path in (
        "/redfish/v1/Systems/HGX_Baseboard_0/Memory/GPU_N_DRAM_0/MemoryMetrics#/CapacityUtilizationPercent",
        "/redfish/v1/Systems/HGX_Baseboard_0/Memory/GPU_N_DRAM_0/MemoryMetrics#/BandwidthPercent",
    )
})
GPU_ID_PATTERN = re.compile(r"GPU_([0-7])(?![0-9])")


def _gpu_baseline_key(report_id: str, property_uri: str) -> tuple[int, str] | None:
    gpu_ids = GPU_ID_PATTERN.findall(property_uri)
    if not gpu_ids or len(set(gpu_ids)) != 1:
        return None
    template = GPU_ID_PATTERN.sub("GPU_N", property_uri)
    if (report_id, template) not in GPU_BASELINE_PROPERTIES:
        return None
    return int(gpu_ids[0]), template


def _escape(value: object) -> str:
    cleaned = "".join(" " if ord(char) < 32 and char != "\n" else char for char in str(value))
    return cleaned.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _number(value: object) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        if not math.isfinite(value):
            return None
    except OverflowError:
        return None
    return str(value)


def _telemetry_number(value: object) -> tuple[float, str] | None:
    if isinstance(value, bool):
        return float(value), "boolean"
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("true", "false"):
            return float(normalized == "true"), "boolean"
        duration = re.fullmatch(
            r"P(?:(?P<days>\d+(?:\.\d+)?)D)?(?:T(?:(?P<hours>\d+(?:\.\d+)?)H)?"
            r"(?:(?P<minutes>\d+(?:\.\d+)?)M)?(?:(?P<seconds>\d+(?:\.\d+)?)S)?)?",
            value,
        )
        if duration and any(part is not None for part in duration.groupdict().values()):
            seconds = sum(float(duration.group(name) or 0) * factor for name, factor in
                          (("days", 86400), ("hours", 3600), ("minutes", 60), ("seconds", 1)))
            return (seconds, "duration_seconds") if math.isfinite(seconds) else None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return (number, "number") if math.isfinite(number) else None


def _device_timestamp(value: object) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        timestamp = parsed.timestamp()
    except (ValueError, OverflowError):
        return None
    return timestamp if math.isfinite(timestamp) else None


def render(readings: list[dict[str, Any]], *, success: bool, errors: int,
           collected_at: float, expected: int | None = None,
           last_success_at: float = 0, components: dict[str, Any] | None = None,
           component_errors: int = 0, telemetry: list[dict[str, Any]] | None = None,
           telemetry_errors: int = 0, stage_durations: dict[str, float] | None = None,
           get_statistics: dict[str, Any] | None = None,
           sensor_observed_at: dict[str, float] | None = None,
           component_observed_at: float | None = None,
           component_source_observed_at: dict[str, float] | None = None,
           telemetry_max_age_seconds: float | None = None,
           telemetry_reports_collected: int | None = None,
           as_of: float | None = None) -> bytes:
    render_started = time.monotonic()
    lines = [
        "# HELP c880a_target_up Last Redfish sensor collection succeeded.",
        "# TYPE c880a_target_up gauge",
        f"c880a_target_up {int(success)}",
        "# HELP c880a_sensor_collection_errors Missing sensors or collection errors in the last attempt.",
        "# TYPE c880a_sensor_collection_errors gauge",
        f"c880a_sensor_collection_errors {errors}",
        "# HELP c880a_last_collection_timestamp_seconds Unix timestamp of the last collection attempt.",
        "# TYPE c880a_last_collection_timestamp_seconds gauge",
        f"c880a_last_collection_timestamp_seconds {collected_at:.3f}",
        "# HELP c880a_last_success_timestamp_seconds Unix timestamp of the last complete collection.",
        "# TYPE c880a_last_success_timestamp_seconds gauge",
        f"c880a_last_success_timestamp_seconds {last_success_at:.3f}",
        "# HELP c880a_sensor_discovered Number of sensors reported by the Redfish collection.",
        "# TYPE c880a_sensor_discovered gauge",
        f"c880a_sensor_discovered {expected if expected is not None else 0}",
        "# HELP c880a_sensor_collected Number of distinct sensors in the current snapshot.",
        "# TYPE c880a_sensor_collected gauge",
        f"c880a_sensor_collected {len(readings)}",
        "# HELP c880a_component_collection_errors Optional hardware summary collection errors.",
        "# TYPE c880a_component_collection_errors gauge",
        f"c880a_component_collection_errors {component_errors}",
        "# HELP c880a_collection_stage_duration_seconds Duration of a completed Redfish collection stage.",
        "# TYPE c880a_collection_stage_duration_seconds gauge",
    ]
    for stage in ("discovery", "system_refresh", "sensors", "components", "telemetry"):
        duration = (stage_durations or {}).get(stage)
        if isinstance(duration, (int, float)) and math.isfinite(duration) and duration >= 0:
            lines.append(f'c880a_collection_stage_duration_seconds{{stage="{stage}"}} {duration:.3f}')
    # Profiling labels are fixed resource classes, never a Redfish URI or query.
    classes = ("service_root", "topology_collection", "topology_member", "telemetry_service",
               "sensors_collection", "sensors_member", "metric_reports_collection",
               "metric_reports_member", "component_collection", "component_member",
               "aggregate", "other")
    for name, description in (
        ("c880a_redfish_get_requests_total", "Completed Redfish GET requests"),
        ("c880a_redfish_get_errors_total", "Failed Redfish GET requests"),
        ("c880a_redfish_get_duration_seconds_total", "Cumulative Redfish GET duration"),
        ("c880a_redfish_get_queue_wait_seconds_total", "Cumulative time waiting for a per-BMC GET slot"),
        ("c880a_redfish_get_response_bytes_total", "Cumulative Redfish GET response bytes"),
    ):
        lines.extend((f"# HELP {name} {description}.", f"# TYPE {name} counter"))
    resources = (get_statistics or {}).get("resources", {})
    if isinstance(resources, dict):
        for kind in classes:
            values = resources.get(kind)
            if not isinstance(values, dict):
                continue
            label = f'{{resource_class="{kind}"}}'
            for name, key in (("c880a_redfish_get_requests_total", "requests"),
                              ("c880a_redfish_get_errors_total", "errors"),
                              ("c880a_redfish_get_duration_seconds_total", "duration_seconds"),
                              ("c880a_redfish_get_queue_wait_seconds_total", "queue_wait_seconds"),
                              ("c880a_redfish_get_response_bytes_total", "response_bytes")):
                raw_value = values.get(key)
                value = _number(raw_value)
                if value is not None and raw_value >= 0:
                    lines.append(f"{name}{label} {value}")
    lines.extend((
        "# HELP c880a_redfish_get_inflight Current Redfish GET requests.",
        "# TYPE c880a_redfish_get_inflight gauge",
        f"c880a_redfish_get_inflight {max(0, int((get_statistics or {}).get('inflight', 0)))}",
        "# HELP c880a_redfish_get_peak_inflight Maximum concurrent Redfish GET requests in this process.",
        "# TYPE c880a_redfish_get_peak_inflight gauge",
        f"c880a_redfish_get_peak_inflight {max(0, int((get_statistics or {}).get('peak_inflight', 0)))}",
    ))
    for metric, help_text, _ in READING_METRICS.values():
        lines.extend((f"# HELP {metric} {help_text}.", f"# TYPE {metric} gauge"))
    other_metrics = {
        "c880a_sensor_info": "Redfish sensor identity, type, context, unit, and state",
        "c880a_sensor_reading": "Raw numeric Redfish Sensor.Reading; see sensor_info for its type and unit",
        "c880a_sensor_reading_available": "Whether Sensor.Reading is numeric and finite",
        "c880a_sensor_health": "Health of a Redfish sensor: 0 OK, 1 Warning, 2 Critical",
        "c880a_sensor_threshold": "Redfish sensor threshold reading",
        "c880a_sensor_range_min": "Minimum Redfish sensor reading range",
        "c880a_sensor_range_max": "Maximum Redfish sensor reading range",
        "c880a_sensor_observed_timestamp_seconds": "Time the exporter observed this Redfish sensor response",
        "c880a_sensor_measurement_timestamp_known": "Whether the BMC supplied a parseable sensor ReadingTime",
        "c880a_sensor_measurement_timestamp_seconds": "BMC supplied sensor ReadingTime; not the exporter observation time",
    }
    for metric, help_text in other_metrics.items():
        lines.extend((f"# HELP {metric} {help_text}.", f"# TYPE {metric} gauge"))
    for sensor in sorted(readings, key=lambda item: str(item.get("Id", ""))):
        sensor_id = sensor.get("Id")
        if not isinstance(sensor_id, str) or len(sensor_id) > 160:
            continue
        resource_uri = sensor.get("@odata.id")
        if not isinstance(resource_uri, str):
            resource_uri = sensor_id
        observed = (sensor_observed_at or {}).get(resource_uri)
        if len(resource_uri) > 512:
            resource_uri = "sha256:" + hashlib.sha256(resource_uri.encode("utf-8")).hexdigest()
        label_body = f'sensor_id="{_escape(sensor_id)}",sensor_uri="{_escape(resource_uri)}"'
        label = "{" + label_body + "}"
        if isinstance(observed, (int, float)) and math.isfinite(observed) and observed > 0:
            lines.append(f"c880a_sensor_observed_timestamp_seconds{label} {observed:.3f}")
        measured = _device_timestamp(sensor.get('ReadingTime'))
        lines.append(f'c880a_sensor_measurement_timestamp_known{label} {int(measured is not None)}')
        if measured is not None:
            lines.append(f'c880a_sensor_measurement_timestamp_seconds{label} {measured:.3f}')
        reading_type = sensor.get("ReadingType") if isinstance(sensor.get("ReadingType"), str) else ""
        metric = READING_METRICS.get(reading_type)
        unit = sensor.get("ReadingUnits") if isinstance(sensor.get("ReadingUnits"), str) else (metric[2] if metric else "")
        status = sensor.get("Status") if isinstance(sensor.get("Status"), dict) else {}
        name = sensor.get("Name") if isinstance(sensor.get("Name"), str) else ""
        context = sensor.get("PhysicalContext") if isinstance(sensor.get("PhysicalContext"), str) else ""
        state = status.get("State") if isinstance(status.get("State"), str) else ""
        info = (f'{{{label_body},name="{_escape(name[:160])}",'
                f'reading_type="{_escape(reading_type[:80])}",unit="{_escape(unit[:40])}",'
                f'physical_context="{_escape(context[:80])}",state="{_escape(state[:40])}"}}')
        lines.append(f"c880a_sensor_info{info} 1")
        value = _number(sensor.get("Reading"))
        lines.append(f"c880a_sensor_reading_available{label} {int(value is not None)}")
        if value is not None:
            lines.append(f"c880a_sensor_reading{label} {value}")
            if metric:
                lines.append(f"{metric[0]}{label} {value}")
        for field, metric_name in (("ReadingRangeMin", "c880a_sensor_range_min"),
                                   ("ReadingRangeMax", "c880a_sensor_range_max")):
            bound = _number(sensor.get(field))
            if bound is not None:
                lines.append(f"{metric_name}{label} {bound}")
        thresholds = sensor.get("Thresholds") if isinstance(sensor.get("Thresholds"), dict) else {}
        for threshold in THRESHOLD_NAMES:
            raw = thresholds.get(threshold)
            threshold_value = _number(raw.get("Reading")) if isinstance(raw, dict) else None
            if threshold_value is not None:
                threshold_label = f'{{{label_body},threshold="{threshold}"}}'
                lines.append(f"c880a_sensor_threshold{threshold_label} {threshold_value}")
        health = status.get("Health")
        if health in ("OK", "Warning", "Critical"):
            score = {"OK": 0, "Warning": 1, "Critical": 2}[health]
            lines.append(f"c880a_sensor_health{label} {score}")
    _render_components(lines, components or {})
    lines.extend(("# HELP c880a_component_observed_timestamp_seconds Oldest observation time among currently exposed component sources.",
                  "# TYPE c880a_component_observed_timestamp_seconds gauge"))
    if (component_observed_at is not None and math.isfinite(component_observed_at)
            and component_observed_at > 0):
        lines.append(f"c880a_component_observed_timestamp_seconds {component_observed_at:.3f}")
    lines.extend(("# HELP c880a_component_source_observed_timestamp_seconds Time one component source was observed by the exporter.",
                  "# TYPE c880a_component_source_observed_timestamp_seconds gauge"))
    for source in COMPONENT_SOURCE_KEYS:
        observed = (component_source_observed_at or {}).get(source)
        if isinstance(observed, (int, float)) and not isinstance(observed, bool) and math.isfinite(observed) and observed > 0:
            lines.append(f'c880a_component_source_observed_timestamp_seconds{{source="{source}"}} {observed:.3f}')
    _render_telemetry(lines, telemetry or [], telemetry_errors,
                      collected_count=telemetry_reports_collected,
                      max_age_seconds=telemetry_max_age_seconds,
                      as_of=as_of if as_of is not None else time.time())
    lines.extend(("# HELP c880a_collection_render_duration_seconds Time to assemble the current exposition.",
                  "# TYPE c880a_collection_render_duration_seconds gauge",
                  f"c880a_collection_render_duration_seconds {time.monotonic() - render_started:.6f}"))
    return ("\n".join(lines) + "\n").encode("utf-8")


def _render_telemetry(lines: list[str], reports: list[dict[str, Any]], errors: int,
                      *, collected_count: int | None, max_age_seconds: float | None,
                      as_of: float) -> None:
    families = {
        "c880a_telemetry_collection_errors": "Telemetry report collection errors",
        "c880a_telemetry_reports_collected": "Telemetry reports collected",
        "c880a_telemetry_reports_retained": "Last-good telemetry reports retained for freshness evaluation",
        "c880a_telemetry_values_exported": "Numeric, boolean, and duration telemetry values exposed",
        "c880a_telemetry_report_values": "Values returned by a telemetry report",
        "c880a_telemetry_report_latest_sample_timestamp_seconds": "Latest device timestamp in a telemetry report",
        "c880a_telemetry_value": "Redfish TelemetryService MetricValue; value_kind identifies numeric, boolean, or duration seconds",
        "c880a_telemetry_value_device_timestamp_seconds": "Device timestamp of an exported telemetry value",
        "c880a_telemetry_values_expired": "Telemetry values omitted because their device timestamps expired",
        "c880a_telemetry_values_unverified_time": "Telemetry values omitted because device time was missing, invalid, or implausibly future-dated",
    }
    for metric, help_text in families.items():
        lines.extend((f"# HELP {metric} {help_text}.", f"# TYPE {metric} gauge"))
    lines.append(f"c880a_telemetry_collection_errors {errors}")
    lines.append(f"c880a_telemetry_reports_collected {len(reports) if collected_count is None else collected_count}")
    lines.append(f"c880a_telemetry_reports_retained {len(reports)}")
    exported_total = 0
    expired_total = 0
    unverified_total = 0
    gpu_baseline_exposed: set[tuple[int, str]] = set()
    for report in reports:
        report_id = report.get("id")
        report_uri = report.get("uri")
        values = report.get("values")
        if not isinstance(report_id, str) or not isinstance(report_uri, str) or not isinstance(values, list):
            continue
        if len(report_uri) > 512:
            report_uri = "sha256:" + hashlib.sha256(report_uri.encode("utf-8")).hexdigest()
        report_label = (f'{{report_id="{_escape(report_id[:160])}",'
                        f'report_uri="{_escape(report_uri)}"}}')
        raw_count = report.get("raw_count")
        lines.append(f"c880a_telemetry_report_values{report_label} "
                     f"{raw_count if isinstance(raw_count, int) and raw_count >= 0 else len(values)}")
        latest: float | None = None
        unique: dict[str, tuple[float, str, float | None]] = {}
        for item in values:
            if not isinstance(item, dict):
                continue
            property_uri = item.get("MetricProperty")
            if not isinstance(property_uri, str) or not property_uri:
                continue
            if len(property_uri) > 1024:
                property_uri = "sha256:" + hashlib.sha256(property_uri.encode("utf-8")).hexdigest()
            parsed_value = _telemetry_number(item.get("MetricValue"))
            if parsed_value is None:
                continue
            timestamp = _device_timestamp(item.get("Timestamp"))
            if timestamp is not None:
                latest = timestamp if latest is None else max(latest, timestamp)
            previous = unique.get(property_uri)
            if previous is None or (timestamp is not None and
                                    (previous[2] is None or timestamp >= previous[2])):
                unique[property_uri] = (*parsed_value, timestamp)
        for property_uri, (value, kind, timestamp) in sorted(unique.items()):
            if max_age_seconds is not None:
                if timestamp is None or timestamp > as_of + 60:
                    unverified_total += 1
                    continue
                if as_of - timestamp > max_age_seconds:
                    expired_total += 1
                    continue
            value_label = (report_label[:-1] + f',metric_property="{_escape(property_uri)}",'
                           f'value_kind="{kind}"}}')
            lines.append(f"c880a_telemetry_value{value_label} {value}")
            if timestamp is not None:
                lines.append(f"c880a_telemetry_value_device_timestamp_seconds{value_label} {timestamp:.3f}")
            if max_age_seconds is not None:
                gpu_key = _gpu_baseline_key(report_id, property_uri)
                if gpu_key is not None:
                    gpu_baseline_exposed.add(gpu_key)
            exported_total += 1
        if latest is not None:
            lines.append(f"c880a_telemetry_report_latest_sample_timestamp_seconds{report_label} {latest}")
    lines.append(f"c880a_telemetry_values_exported {exported_total}")
    lines.append(f"c880a_telemetry_values_expired {expired_total}")
    lines.append(f"c880a_telemetry_values_unverified_time {unverified_total}")
    if max_age_seconds is not None:
        lines.extend((
            "# HELP c880a_gpu_baseline_values_expected Eight-GPU R18 baseline telemetry properties expected in this exposition.",
            "# TYPE c880a_gpu_baseline_values_expected gauge",
            f"c880a_gpu_baseline_values_expected {8 * len(GPU_BASELINE_PROPERTIES)}",
            "# HELP c880a_gpu_baseline_values_exposed Eight-GPU R18 baseline properties with valid, unexpired values.",
            "# TYPE c880a_gpu_baseline_values_exposed gauge",
            f"c880a_gpu_baseline_values_exposed {len(gpu_baseline_exposed)}",
            "# HELP c880a_gpu_baseline_values_exposed_per_gpu R18 baseline properties with valid, unexpired values for one GPU.",
            "# TYPE c880a_gpu_baseline_values_exposed_per_gpu gauge",
        ))
        for gpu in range(8):
            count = sum(1 for identity, _ in gpu_baseline_exposed if identity == gpu)
            lines.append(f'c880a_gpu_baseline_values_exposed_per_gpu{{gpu="{gpu}"}} {count}')


def _render_components(lines: list[str], data: dict[str, Any]) -> None:
    families = {
        "c880a_component_present": "Redfish component exists in its collection",
        "c880a_component_discovered": "Number of components returned by a Redfish collection",
        "c880a_system_health": "System health: 0 OK, 1 Warning, 2 Critical",
        "c880a_system_power_on": "Whether Redfish reports system power On",
        "c880a_system_memory_gib": "Total system memory in GiB",
        "c880a_system_processor_count": "System processor count",
        "c880a_processor_health": "Processor health: 0 OK, 1 Warning, 2 Critical",
        "c880a_processor_cores": "Processor core count",
        "c880a_processor_threads": "Processor thread count",
        "c880a_processor_max_speed_mhz": "Processor maximum speed in MHz",
        "c880a_memory_health": "Memory module health: 0 OK, 1 Warning, 2 Critical",
        "c880a_memory_capacity_mib": "Memory module capacity in MiB",
        "c880a_memory_operating_speed_mhz": "Memory module operating speed in MHz",
        "c880a_power_supply_health": "Power supply health: 0 OK, 1 Warning, 2 Critical",
        "c880a_power_supply_capacity_watts": "Power supply rated capacity in watts",
        "c880a_storage_health": "Storage unit health: 0 OK, 1 Warning, 2 Critical",
        "c880a_storage_drive_count": "Drives in a storage unit",
        "c880a_storage_controller_count": "Controllers in a storage unit",
        "c880a_storage_controller_health": "Storage controller health: 0 OK, 1 Warning, 2 Critical",
        "c880a_storage_controller_speed_gbps": "Storage controller speed in Gbps",
        "c880a_drive_health": "Drive health: 0 OK, 1 Warning, 2 Critical",
        "c880a_drive_capacity_bytes": "Drive capacity in bytes",
        "c880a_drive_block_size_bytes": "Drive block size in bytes",
        "c880a_drive_negotiated_speed_gbps": "Drive negotiated speed in Gbps",
        "c880a_drive_media_life_left_percent": "Predicted drive media life left in percent",
        "c880a_volume_health": "Volume health: 0 OK, 1 Warning, 2 Critical",
        "c880a_volume_capacity_bytes": "Volume capacity in bytes",
        "c880a_network_interface_health": "Network interface health: 0 OK, 1 Warning, 2 Critical",
        "c880a_power_subsystem_health": "Power subsystem health: 0 OK, 1 Warning, 2 Critical",
        "c880a_chassis_power_average_watts": "Average consumed chassis power in watts",
        "c880a_chassis_power_max_watts": "Maximum consumed chassis power in watts",
        "c880a_chassis_power_min_watts": "Minimum consumed chassis power in watts",
        "c880a_chassis_power_limit_watts": "Configured chassis power limit in watts",
    }
    for metric, help_text in families.items():
        lines.extend((f"# HELP {metric} {help_text}.", f"# TYPE {metric} gauge"))

    def emit(metric: str, value: object, label: str = "") -> None:
        number = _number(value)
        if number is not None:
            lines.append(f"{metric}{label} {number}")

    def health(metric: str, resource: Any, label: str = "") -> None:
        if not isinstance(resource, dict):
            return
        status = resource.get("Status")
        if not isinstance(status, dict):
            return
        value = status.get("Health")
        score = {"OK": 0, "Warning": 1, "Critical": 2}.get(value) if isinstance(value, str) else None
        if score is not None:
            emit(metric, score, label)

    system = data.get("system")
    if isinstance(system, dict):
        health("c880a_system_health", system)
        if system.get("PowerState") in ("On", "Off"):
            emit("c880a_system_power_on", int(system["PowerState"] == "On"))
        memory_summary = system.get("MemorySummary")
        if isinstance(memory_summary, dict):
            emit("c880a_system_memory_gib", memory_summary.get("TotalSystemMemoryGiB"))
        processor_summary = system.get("ProcessorSummary")
        if isinstance(processor_summary, dict):
            emit("c880a_system_processor_count", processor_summary.get("Count"))
    for collection, component_type, fields, health_metric in (
        ("processors", "processor", (("TotalCores", "c880a_processor_cores"),
                        ("TotalThreads", "c880a_processor_threads"),
                        ("MaxSpeedMHz", "c880a_processor_max_speed_mhz")), "c880a_processor_health"),
        ("memory", "memory", (("CapacityMiB", "c880a_memory_capacity_mib"),
                    ("OperatingSpeedMhz", "c880a_memory_operating_speed_mhz")), "c880a_memory_health"),
        ("power_supplies", "power_supply", (("PowerCapacityWatts", "c880a_power_supply_capacity_watts"),),
         "c880a_power_supply_health"),
        ("storage", "storage", (("Drives@odata.count", "c880a_storage_drive_count"),
                                 ("StorageControllers@odata.count", "c880a_storage_controller_count")),
         "c880a_storage_health"),
        ("storage_controllers", "storage_controller", (("SpeedGbps", "c880a_storage_controller_speed_gbps"),),
         "c880a_storage_controller_health"),
        ("drives", "drive", (("CapacityBytes", "c880a_drive_capacity_bytes"),
                             ("BlockSizeBytes", "c880a_drive_block_size_bytes"),
                             ("NegotiatedSpeedGbs", "c880a_drive_negotiated_speed_gbps"),
                             ("PredictedMediaLifeLeftPercent", "c880a_drive_media_life_left_percent")),
         "c880a_drive_health"),
        ("volumes", "volume", (("CapacityBytes", "c880a_volume_capacity_bytes"),),
         "c880a_volume_health"),
        ("network_interfaces", "network_interface", (), "c880a_network_interface_health"),
    ):
        items = data.get(collection)
        if not isinstance(items, list):
            continue
        emit("c880a_component_discovered", len(items), f'{{component_type="{component_type}"}}')
        for item in items:
            if not isinstance(item, dict):
                continue
            item_id = item.get("Id")
            if not isinstance(item_id, str) or len(item_id) > 160:
                continue
            resource_uri = item.get("@odata.id")
            if not isinstance(resource_uri, str):
                resource_uri = item_id
            if len(resource_uri) > 512:
                resource_uri = "sha256:" + hashlib.sha256(resource_uri.encode("utf-8")).hexdigest()
            label = f'{{component_id="{_escape(item_id)}",component_uri="{_escape(resource_uri)}"}}'
            present_label = (f'{{component_type="{component_type}",component_id="{_escape(item_id)}",'
                             f'component_uri="{_escape(resource_uri)}"}}')
            emit("c880a_component_present", 1, present_label)
            health(health_metric, item, label)
            for field, metric in fields:
                emit(metric, item.get(field), label)
    health("c880a_power_subsystem_health", data.get("power_subsystem"))
    power = data.get("power")
    if isinstance(power, dict):
        controls = power.get("PowerControl")
        if isinstance(controls, list) and controls and isinstance(controls[0], dict):
            control = controls[0]
            metrics = control.get("PowerMetrics")
            if isinstance(metrics, dict):
                for field, metric in (("AverageConsumedWatts", "c880a_chassis_power_average_watts"),
                                      ("MaxConsumedWatts", "c880a_chassis_power_max_watts"),
                                      ("MinConsumedWatts", "c880a_chassis_power_min_watts")):
                    emit(metric, metrics.get(field))
            limit = control.get("PowerLimit")
            if isinstance(limit, dict):
                emit("c880a_chassis_power_limit_watts", limit.get("LimitInWatts"))
