"""Private configuration for one global, independently supervised Prometheus."""

from __future__ import annotations

import json
from pathlib import Path
import shutil

from .deployment import host_name, url_host


DEFAULTS = {"enabled": True, "scrape_interval": 30, "scrape_timeout": 10,
            "retention_hours": 24, "storage_gib": 1}
DISCOVERY_INTERVAL = 15
GIB = 1024 ** 3


def validate_settings(value: dict, *, data_dir: Path | None = None,
                      existing_bytes: int = 0, previous: dict | None = None) -> dict:
    if not isinstance(value, dict) or set(value) != set(DEFAULTS):
        raise ValueError("Provide enabled state, scrape interval, timeout, retention, and storage limit")
    if type(value["enabled"]) is not bool:
        raise ValueError("Enabled must be true or false")
    bounds = {"scrape_interval": (15, 3600), "scrape_timeout": (1, 60),
              "retention_hours": (1, 720), "storage_gib": (1, 128)}
    labels = {"scrape_interval": "Scrape interval", "scrape_timeout": "Scrape timeout",
              "retention_hours": "Retention", "storage_gib": "Storage limit"}
    for name, (minimum, maximum) in bounds.items():
        if type(value[name]) is not int or not minimum <= value[name] <= maximum:
            raise ValueError(f"{labels[name]} must be an integer between {minimum} and {maximum}")
    if value["scrape_timeout"] > value["scrape_interval"]:
        raise ValueError("Scrape timeout must not exceed the scrape interval")
    # Low disk must not prevent stopping scrapes or reducing allocation.
    # Enabling or increasing allocation still requires reserved headroom.
    reducing = bool(previous and previous.get("enabled") is True and
                    type(previous.get("storage_gib")) is int and
                    value["storage_gib"] < previous["storage_gib"])
    if data_dir is not None and value["enabled"] and not reducing:
        cap = value["storage_gib"] * GIB
        reserve = max(GIB, cap // 5)
        needed = max(0, cap - existing_bytes) + reserve
        if shutil.disk_usage(data_dir).free < needed:
            raise ValueError("Insufficient disk headroom; free disk space or choose a smaller storage limit")
    return dict(value)


def scrape_config(settings: dict, deployment: dict, data_dir: Path,
                  *, internal_port: int, client_dir: Path | None = None) -> dict:
    """JSON is valid YAML; no user-provided text is interpreted as YAML syntax."""
    settings = validate_settings(settings)
    if type(internal_port) is not int or not 1024 <= internal_port <= 65535:
        raise ValueError("Invalid private Prometheus port")
    manager = host_name(deployment["manager_host"])
    exporter = host_name(deployment["exporter_host"])
    certificate = str(Path(deployment["certificate"]["cert"]).resolve())
    private = client_dir or data_dir.resolve() / "prometheus" / "auth"
    tls = {"ca_file": certificate, "server_name": manager, "min_version": "TLS13"}
    origin = f"https://{url_host(manager)}:{int(deployment['manager_port'])}"
    return {
        "global": {"scrape_interval": f"{settings['scrape_interval']}s",
                   "scrape_timeout": f"{settings['scrape_timeout']}s"},
        "scrape_configs": [
            {"job_name": "c880a", "scheme": "https", "metrics_path": "/metrics",
             "tls_config": {**tls, "server_name": exporter},
             "http_sd_configs": [{"url": origin + "/api/prometheus/targets",
                                  "refresh_interval": f"{DISCOVERY_INTERVAL}s",
                                  "authorization": {"type": "Bearer", "credentials_file":
                                                    str(data_dir.resolve() / "discovery-token")},
                                  "http_headers": {"X-C880A-Managed-Discovery": {"values": [private.name]}},
                                  "tls_config": tls}]},
            {"job_name": "prometheus", "scheme": "https",
             "metrics_path": "/prometheus/metrics",
             "tls_config": {**tls, "cert_file": str(private / "client.pem"),
                            "key_file": str(private / "client.key")},
             "static_configs": [{"targets": [f"127.0.0.1:{internal_port}"]}]},
        ],
    }


def config_bytes(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
