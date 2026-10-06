"""Bounded parser for Redfish Server-Sent Event messages."""

from __future__ import annotations

import hashlib
import json
from typing import Any, BinaryIO, Iterator


MAX_LINE = 64 * 1024
MAX_FRAME = 256 * 1024
MAX_EVENTS = 100


def frames(stream: BinaryIO) -> Iterator[tuple[str | None, dict[str, Any]]]:
    """Yield JSON SSE frames, ignoring comments and non-JSON keepalives.

    A malformed or oversized frame closes the connection so its memory use is
    bounded; the caller reconnects and continues LogService reconciliation.
    """
    data: list[bytes] = []
    event_id: str | None = None
    size = 0
    while True:
        line = stream.readline(MAX_LINE + 1)
        if not line:
            return
        if len(line) > MAX_LINE or not line.endswith(b"\n"):
            raise ValueError("SSE line exceeds configured limit")
        line = line.rstrip(b"\r\n")
        if not line:
            if data:
                try:
                    payload = json.loads(b"\n".join(data))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    payload = None
                if isinstance(payload, dict):
                    yield event_id, payload
            data, event_id, size = [], None, 0
            continue
        if line.startswith(b":"):
            continue
        field, separator, value = line.partition(b":")
        if not separator:
            value = b""
        elif value.startswith(b" "):
            value = value[1:]
        if field == b"data":
            size += len(value) + 1
            if size > MAX_FRAME:
                raise ValueError("SSE frame exceeds configured limit")
            data.append(value)
        elif field == b"id" and len(value) <= 256 and all(32 <= byte < 127 for byte in value):
            event_id = value.decode("ascii")


def event_records(frame_id: str | None, payload: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Return deduplicatable Event records; MetricReports are not log events."""
    entries = payload.get("Events")
    if not isinstance(entries, list):
        return []
    records = []
    for index, entry in enumerate(entries[:MAX_EVENTS]):
        if not isinstance(entry, dict):
            continue
        identity = (f"{frame_id}:{index}" if frame_id else
                    f"{entry.get('EventId', '')}:{entry.get('EventTimestamp', '')}:"
                    f"{json.dumps(entry, sort_keys=True, default=str)}")
        records.append((hashlib.sha256(identity.encode("utf-8")).hexdigest(), entry))
    return records
