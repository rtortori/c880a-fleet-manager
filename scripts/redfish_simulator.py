#!/usr/bin/env python3
"""Start one synthetic HTTPS C880A BMC without installing the manager."""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from c880a_manager.simulator import create_lab_certificate, load_config, serve


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one synthetic C880A Redfish BMC over HTTPS")
    parser.add_argument("--ip", default="127.0.0.1", help="Local loopback or explicitly allowed private IP")
    parser.add_argument("--port", required=True, type=int, help="HTTPS listener port (1–65535)")
    parser.add_argument("--allow-nonloopback", action="store_true",
                        help="Explicitly bind a private lab interface")
    parser.add_argument("--cert", type=Path, help="Optional existing PEM certificate")
    parser.add_argument("--key", type=Path, help="Matching private PEM key")
    parser.add_argument("--scenario", type=Path,
                        help="Optional JSON profile, latency, and fault settings")
    args = parser.parse_args()
    if isinstance(args.port, bool) or not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if bool(args.cert) != bool(args.key):
        parser.error("--cert and --key must be supplied together")
    try:
        address = ipaddress.ip_address(args.ip)
        if address.is_link_local or address.is_multicast or address.is_unspecified:
            raise ValueError("--ip must be a non-link-local unicast address")
        if not address.is_loopback and not args.allow_nonloopback:
            raise ValueError("Non-loopback IPs require --allow-nonloopback")
        raw = {"fleet_size": 1, "address_start": str(address), "port": args.port,
               "observed_sensors": True, "profiles": [{"sensor_page_size": 64}],
               "seed": 880 + args.port}
        if args.scenario:
            if args.scenario.stat().st_size > 64_000:
                raise ValueError("Scenario file is too large")
            scenario = json.loads(args.scenario.read_text(encoding="utf-8"))
            if not isinstance(scenario, dict) or set(scenario) - {
                    "profiles", "latency", "faults", "seed", "tick_seconds"}:
                raise ValueError("Scenario may contain only profiles, latency, faults, seed, and tick_seconds")
            raw.update(scenario)
        with tempfile.TemporaryDirectory(prefix="c880a-simulator-") as private_dir:
            root = Path(private_dir)
            config_file = root / "config.json"
            config_file.write_text(json.dumps(raw), encoding="utf-8")
            config = load_config(config_file)
            config_file.unlink()
            cert, key = ((args.cert, args.key) if args.cert else
                         create_lab_certificate(root, config["addresses"]))
            def ready():
                if not args.cert:
                    print(f"Public certificate: {cert} (copy it while this process runs)", flush=True)
                print("Synthetic BMC credentials: admin/admin (lab use only)", flush=True)
            serve(config, "admin", "admin", cert, key, ready=ready)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
