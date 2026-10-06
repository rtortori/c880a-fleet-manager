"""Net-SNMP snmptrapd traphandle: authenticated traps into the event timeline.

snmptrapd performs SNMPv3 authentication and BER parsing. This helper only
consumes its documented line-oriented handler input from stdin.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import re
import sys
import time
from pathlib import Path

from .storage import Store


MAX_TRAP_BYTES = 64 * 1024


def _source_address(value: str) -> str | None:
    candidates = re.findall(r"\[([0-9a-fA-F:.]+)\]|((?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]))", value)
    for match in candidates:
        candidate = next((part for part in match if part), "")
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def ingest(store: Store, raw: bytes) -> bool:
    if len(raw) > MAX_TRAP_BYTES:
        return False
    lines = raw.decode("utf-8", "replace").splitlines()
    if len(lines) < 3:
        return False
    source_ip = _source_address(lines[1])
    if not source_ip:
        return False
    # Traps carry a source IP but no HTTPS port. Ambiguous same-IP simulators
    # must not have their events attributed to an arbitrary target.
    matches = [item for item in store.servers(active_only=True) if item["bmc_host"] == source_ip]
    server = matches[0] if len(matches) == 1 else None
    if server is None:
        # Unknown or unclaimed BMCs must not rebuild an orphaned event log.
        return False
    varbinds = [line[:1024] for line in lines[2:66]]
    trap_oid = next((line.split(" ", 1)[1] for line in varbinds
                     if "snmpTrapOID.0 " in line or line.startswith(".1.3.6.1.6.3.1.1.4.1.0 ")), "")
    digest = hashlib.sha256(raw + str(time.time_ns()).encode()).hexdigest()
    store.insert_event(server_id=server["id"], source=f"snmp:{source_ip}",
                       source_entry_id=digest, occurred_at=None, severity="Unknown",
                       message_id=trap_oid, message=" | ".join(varbinds)[:4096],
                       raw={"source_ip": source_ip, "hostname": lines[0][:255], "varbinds": varbinds})
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest one snmptrapd traphandle event")
    parser.add_argument("--data-dir", type=Path, required=True)
    args = parser.parse_args()
    raw = sys.stdin.buffer.read(MAX_TRAP_BYTES + 1)
    if not ingest(Store(args.data_dir), raw):
        raise SystemExit("Invalid or oversized trap handler input")


if __name__ == "__main__":
    main()
