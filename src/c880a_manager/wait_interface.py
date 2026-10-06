"""Wait for the selected local bind address during Linux boot."""

from __future__ import annotations

import argparse
import ipaddress
import socket
import sys
import time

import psutil


def assigned(address: str) -> bool:
    target = ipaddress.ip_address(address)
    family = socket.AF_INET6 if target.version == 6 else socket.AF_INET
    for entries in psutil.net_if_addrs().values():
        for entry in entries:
            if entry.family == family:
                try:
                    if ipaddress.ip_address(entry.address.split("%", 1)[0]) == target:
                        return True
                except ValueError:
                    continue
    return False


def wait(address: str, timeout: int = 90) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if assigned(address):
            return True
        time.sleep(1)
    return assigned(address)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("address", type=ipaddress.ip_address)
    args = parser.parse_args()
    if not wait(str(args.address)):
        print(f"Selected bind address {args.address} is not assigned yet", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
