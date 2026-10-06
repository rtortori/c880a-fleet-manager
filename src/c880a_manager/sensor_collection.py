"""Bounded sensor observations, independent of optional inventory/telemetry work.

Catalog files are private runtime state. No URI, payload or exception is emitted
as a diagnostic: consumers receive numeric aggregates and fixed state codes.
"""
from __future__ import annotations

from copy import deepcopy
from collections import deque
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
from typing import Callable

from .metrics import READING_METRICS

CATALOG_TTL = 86400.0
# Start renewing with enough headroom for catalog page bursts, optional reads
# and bounded transient recovery under the unchanged three-request BMC cap.
OBSERVATION_INTERVAL = 60.0
MAX_OBSERVATION_AGE = 300.0
MAX_SENSORS = 3000
MAX_CATALOG_BYTES = 2_000_000
_ERRORS = frozenset({'timeout', 'transport', 'budget', 'authentication', 'certificate', 'metadata', 'internal'})
_FATAL = frozenset({'authentication', 'certificate', 'metadata', 'internal'})


def checked_uri(value: object) -> str:
    # The advertised C880A catalog contains a literal space in one sensor path.
    # httpx percent-encodes it for HTTPS; retain the original catalog identity.
    # Queries, fragments, encoded separators and other whitespace remain rejected.
    if (not isinstance(value, str) or len(value) > 512 or
            not value.startswith('/redfish/v1/') or '/Sensors/' not in value or
            not re.fullmatch(r'/[A-Za-z0-9_./~: -]+', value) or
            any(part in ('', '.', '..') for part in value.split('/')[1:])):
        raise ValueError('Invalid sensor identity')
    return value


def _metadata(row: dict) -> dict:
    uri = checked_uri(row.get('@odata.id'))
    identifier = row.get('Id')
    if (not isinstance(identifier, str) or not 0 < len(identifier) <= 160 or
            any(ord(c) < 32 for c in identifier)):
        raise ValueError('Invalid sensor identity')
    result = {'@odata.id': uri, 'Id': identifier}
    for key, limit in [('ReadingType', 80), ('ReadingUnits', 40), ('Name', 160),
                       ('PhysicalContext', 80), ('SerialNumber', 160), ('PartNumber', 160)]:
        value = row.get(key)
        if value is not None and (not isinstance(value, str) or len(value) > limit or
                                  any(ord(c) < 32 for c in value)):
            raise ValueError('Invalid sensor metadata')
        result[key] = value or ''
    metric = READING_METRICS.get(result['ReadingType'])
    result['ReadingUnits'] = result['ReadingUnits'] or (metric[2] if metric else '')
    related = row.get('RelatedItem', [])
    if not isinstance(related, list) or len(related) > 32:
        raise ValueError('Invalid sensor metadata')
    links = []
    for link in related:
        value = link.get('@odata.id') if isinstance(link, dict) else None
        if (not isinstance(value, str) or len(value) > 512 or
                not re.fullmatch(r'/redfish/v1/[A-Za-z0-9_./~: -]+', value) or
                any(x in ('', '.', '..') for x in value.split('/')[1:])):
            raise ValueError('Invalid sensor metadata')
        links.append(value)
    result['RelatedItem'] = sorted(set(links))
    for value in result.values():
        if isinstance(value, str):
            value.encode('utf-8')
    return result


def checked_catalog(rows: list[dict]) -> dict[str, dict]:
    if not isinstance(rows, list) or not 0 < len(rows) <= MAX_SENSORS:
        raise ValueError('Invalid sensor catalog')
    result = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('Invalid sensor catalog')
        metadata = _metadata(row)
        uri = metadata['@odata.id']
        if uri in result:
            raise ValueError('Duplicate sensor identity')
        result[uri] = metadata
    return result


def _finite(value: object) -> bool:
    try:
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
    except OverflowError:
        return False


def _reading(row: dict) -> dict:
    # Retain the renderer's fields, without holding arbitrary OEM payloads in memory.
    keys = ('@odata.id', 'Id', 'Name', 'ReadingType', 'ReadingUnits', 'PhysicalContext',
            'Status', 'Reading', 'ReadingTime', 'Thresholds', 'ReadingRangeMin', 'ReadingRangeMax')
    value = deepcopy({key: row[key] for key in keys if key in row})
    if not _finite(value.get('Reading')):
        value['Reading'] = None
    encoded = json.dumps(value, allow_nan=False, ensure_ascii=False, separators=(',', ':')).encode()
    if len(encoded) > 16_384:
        raise ValueError('Sensor observation exceeds its bound')
    return value


@dataclass(frozen=True)
class SensorTask:
    uri: str
    generation: int
    token: int
    timeout: float
    started: float


@dataclass(frozen=True)
class SensorResult:
    status: int = 200
    payload: dict | None = None
    error: str | None = None
    retry_after: float | None = None
    observed_wall: float | None = None
    observed_monotonic: float | None = None


@dataclass
class _Resource:
    metadata: dict
    due: float
    value: dict | None = None
    observed_wall: float = 0.0
    observed_monotonic: float = 0.0
    attempt: int = 0
    consecutive_404: int = 0
    last_404: float = -math.inf
    excluded: bool = False
    token: int | None = None
    last_error: str = ''
    failure_sequence: int = 0
    failure_code: str = ''
    exhausted: bool = False


class SensorLedger:
    """Thread-safe rolling deadlines; callbacks never run under the state lock."""

    def __init__(self, *, interval: float = OBSERVATION_INTERVAL,
                 max_age: float = MAX_OBSERVATION_AGE, workers: int = 3,
                 monotonic: Callable[[], float] = time.monotonic,
                 wall: Callable[[], float] = time.time) -> None:
        if not 0 < interval < max_age <= 600 or workers not in (1, 2, 3):
            raise ValueError('Invalid sensor observation budget')
        self.interval, self.max_age, self.workers = interval, max_age, workers
        self.monotonic, self.wall = monotonic, wall
        self.lock = threading.RLock()
        self.changed = threading.Condition(self.lock)
        self.rows: dict[str, _Resource] = {}
        self.generation = 0
        self.sequence = 0
        self.catalog_revision = 0
        self.failure_history = deque(maxlen=6000)
        self.last_attempt_wall = 0.0
        self.last_completion_wall = 0.0
        self.discovered_at = 0.0
        self.paused = ''
        self.stopping = False
        self.threads: list[threading.Thread] = []
        self.counters = dict(attempts=0, successes=0, errors=0, retries=0,
                             recovered_retries=0, excluded_404=0, exhausted_cycles=0)

    def reconcile(self, rows: list[dict], *, observed: dict[str, SensorResult] | None = None,
                  discovered_at: float | None = None) -> None:
        catalog = checked_catalog(rows)
        now, wall = self.monotonic(), self.wall()
        stamp = wall if discovered_at is None else discovered_at
        if not _finite(stamp) or not 0 < stamp <= wall:
            raise ValueError('Invalid catalog time')
        seeds = {}
        for uri, result in (observed or {}).items():
            if uri not in catalog or result.status != 200 or result.error:
                raise ValueError('Invalid catalog observation')
            seeds[uri] = self._checked_observation(catalog[uri], result, now, wall)
        with self.changed:
            new_rows = {}
            for uri, metadata in catalog.items():
                old = self.rows.get(uri)
                resource = _Resource(metadata, now)
                if old is not None and old.metadata == metadata:
                    resource.value = old.value
                    resource.observed_wall = old.observed_wall
                    resource.observed_monotonic = old.observed_monotonic
                    resource.due = min(old.due, now) if old.excluded else old.due
                    resource.failure_sequence, resource.failure_code = old.failure_sequence, old.failure_code
                if uri in seeds and seeds[uri][1] >= resource.observed_wall:
                    value, observed_wall, observed_monotonic = seeds[uri]
                    resource.value, resource.observed_wall, resource.observed_monotonic = value, observed_wall, observed_monotonic
                    due = observed_monotonic + self.interval
                    # Daily page responses must not recreate simultaneous
                    # renewal bursts in an already established reader cadence.
                    resource.due = (min(resource.due, due) if old is not None and
                                    old.metadata == metadata and old.value is not None and
                                    not old.excluded else due)
                new_rows[uri] = resource
            self.rows = new_rows
            self.discovered_at = stamp
            self.generation += 1
            self.catalog_revision += 1
            self.paused = ''
            self.changed.notify_all()

    @staticmethod
    def _checked_observation(metadata: dict, result: SensorResult, now: float, wall: float):
        if not isinstance(result.payload, dict) or _metadata(result.payload) != metadata:
            raise ValueError('Sensor metadata changed')
        source_wall = wall if result.observed_wall is None else result.observed_wall
        source_mono = now if result.observed_monotonic is None else result.observed_monotonic
        if (not _finite(source_wall) or not _finite(source_mono) or not 0 < source_wall <= wall or
                source_mono > now or source_mono < 0 or
                abs((wall - source_wall) - (now - source_mono)) > 5):
            raise ValueError('Invalid sensor observation time')
        return _reading(result.payload), source_wall, source_mono

    def reserve(self) -> SensorTask | None:
        with self.lock:
            now = self.monotonic()
            if self.stopping or self.paused or sum(row.token is not None for row in self.rows.values()) >= self.workers:
                return None
            candidates = [(row.observed_monotonic + self.max_age if row.value else -math.inf,
                           row.due, uri, row) for uri, row in self.rows.items()
                          if not row.excluded and row.token is None and row.due <= now]
            if not candidates:
                return None
            _, _, uri, row = min(candidates)
            remaining = row.observed_monotonic + self.max_age - now if row.value else 10.0
            timeout = min(10.0, remaining) if remaining > 0 else 10.0
            self.sequence += 1
            row.token = self.sequence
            row.exhausted = False
            self.counters['attempts'] += 1
            self.last_attempt_wall = self.wall()
            self.counters['retries'] += int(row.attempt > 0)
            return SensorTask(uri, self.generation, row.token, max(0.01, timeout), now)

    def request_priority(self, uri: str) -> int:
        """Keep the qualified 90-second urgent admission threshold.

        Receipt age, rather than retry/backoff time, determines urgency. Rank
        two keeps the action slot reserved and leaves optional queue aging intact.
        """
        with self.lock:
            row = self.rows.get(uri)
            return (2 if row is None or row.value is None or
                    self.monotonic() - row.observed_monotonic >= min(90.0, self.max_age / 2) else 1)

    def complete(self, task: SensorTask, result: SensorResult) -> None:
        with self.changed:
            row = self.rows.get(task.uri)
            if not row or task.generation != self.generation or row.token != task.token:
                return  # A late reply cannot repopulate replaced identities.
            row.token = None
            now, wall = self.monotonic(), self.wall()
            self.last_completion_wall = wall
            error = result.error if result.error in _ERRORS else ('internal' if result.error else '')
            if error not in _FATAL and now - task.started > task.timeout + 0.05:
                error = 'timeout'
            if not error and result.status == 200:
                try:
                    value, source_wall, source_mono = self._checked_observation(row.metadata, result, now, wall)
                except (ValueError, TypeError, OverflowError):
                    error = 'metadata'
                else:
                    if source_wall < row.observed_wall:
                        error = 'metadata'
                    else:
                        self.counters['recovered_retries'] += int(row.attempt > 0)
                        self.counters['successes'] += 1
                        if row.consecutive_404:
                            self.catalog_revision += 1
                        row.value, row.observed_wall, row.observed_monotonic = value, source_wall, source_mono
                        row.due = source_mono + self.interval
                        row.attempt = row.consecutive_404 = 0
                        row.last_error = ''
                        self.changed.notify_all()
                        return
            self.counters['errors'] += 1
            row.attempt += 1
            row.last_error = error or ('not_found' if result.status == 404 else 'throttled' if result.status == 429 else 'http')
            row.failure_sequence = self.counters['errors']
            row.failure_code = row.last_error
            self.failure_history.append((row.failure_sequence, task.uri, row.failure_code, now))
            if error in _FATAL or result.status in (401, 403):
                self.paused = error or 'authentication'
            elif not error and result.status == 404:
                if now - row.last_404 >= 10:
                    self.catalog_revision += 1
                    row.consecutive_404 += 1
                    row.last_404 = now
                if row.consecutive_404 >= 3:
                    row.excluded = True
                    self.counters['excluded_404'] += 1
                row.due = now + 10
            else:
                if row.consecutive_404:
                    self.catalog_revision += 1
                row.consecutive_404 = 0
                if not error and result.status not in (429, 500, 502, 503, 504):
                    self.paused = 'metadata'
                delay = (1.0, 3.0, 8.0)[min(row.attempt - 1, 2)]
                if result.status == 429 and _finite(result.retry_after):
                    delay = max(delay, min(3600.0, max(0.0, result.retry_after)))
                if row.attempt >= 4:
                    self.counters['exhausted_cycles'] += 1
                    row.exhausted = True
                    row.attempt = 0
                    delay = max(delay, self.interval)
                row.due = now + delay
            self.changed.notify_all()

    def snapshot(self) -> dict:
        with self.lock:
            now, wall = self.monotonic(), self.wall()
            eligible = [r for r in self.rows.values() if not r.excluded]
            fresh = [r for r in eligible if r.value is not None and
                     0 <= now - r.observed_monotonic <= self.max_age and
                     0 <= wall - r.observed_wall <= self.max_age]
            never = sum(r.value is None for r in eligible)
            numeric = sum(_finite(r.value.get('Reading')) for r in fresh)
            ages = [max(now - r.observed_monotonic, wall - r.observed_wall) for r in eligible if r.value]
            fresh_ids = {id(r) for r in fresh}
            unresolved = sum(id(r) not in fresh_ids or bool(r.last_error) for r in eligible)
            return {**self.counters, 'tracked': len(self.rows), 'eligible': len(eligible),
                    'fresh': len(fresh), 'missing': never, 'stale': len(eligible) - len(fresh) - never,
                    'numeric_unavailable': len(fresh) - numeric, 'numeric_available': numeric,
                    'excluded_404': len(self.rows) - len(eligible),
                    'max_source_age_seconds': max(ages, default=-1.0),
                    'inflight': sum(r.token is not None for r in self.rows.values()),
                    'unresolved': unresolved,
                    'exhausted': sum(r.exhausted for r in eligible),
                    'catalog_revision': self.catalog_revision,
                    'last_attempt_wall': self.last_attempt_wall,
                    'last_completion_wall': self.last_completion_wall,
                    'error_codes': sorted({r.last_error for r in self.rows.values() if r.last_error}),
                    # Private coordinator inputs. Publishers use explicit numeric allowlists.
                    'failure_events': list(self.failure_history),
                    '_resources': {uri: {'eligible': not row.excluded,
                                         'id': row.metadata['Id'], 'observed': row.value is not None,
                                         'unresolved': not row.excluded and
                                                       (id(row) not in fresh_ids or bool(row.last_error)),
                                         'fresh': id(row) in fresh_ids}
                                   for uri, row in self.rows.items()},
                    'paused': self.paused, 'discovered_at': self.discovered_at,
                    'complete': bool(self.rows) and not self.paused and len(fresh) == len(eligible)}

    def publication(self) -> tuple[list[dict], dict[str, float]]:
        with self.lock:
            now, wall = self.monotonic(), self.wall()
            values, stamps = [], {}
            for uri, row in self.rows.items():
                if row.excluded or row.value is None:
                    continue  # Never create a history sample for an unobserved identity.
                value = deepcopy(row.value)
                if not (0 <= now - row.observed_monotonic <= self.max_age and
                        0 <= wall - row.observed_wall <= self.max_age):
                    value['Reading'] = None
                values.append(value)
                stamps[uri] = row.observed_wall
            return values, stamps

    def catalog(self) -> list[dict]:
        with self.lock:
            return deepcopy([row.metadata for row in self.rows.values()])

    def start(self, fetch: Callable[[str, float], SensorResult],
              on_change: Callable[[], None] | None = None) -> None:
        with self.changed:
            if self.threads:
                return
            self.stopping = False
            def worker():
                while True:
                    with self.changed:
                        if self.stopping:
                            return
                        task = self.reserve()
                        if task is None:
                            self.changed.wait(timeout=0.25)
                            continue
                    try:
                        result = fetch(task.uri, task.timeout)
                        if not isinstance(result, SensorResult):
                            result = SensorResult(error='internal')
                    except Exception:
                        result = SensorResult(error='internal')
                    self.complete(task, result)
                    if on_change is not None:
                        try:
                            on_change()
                        except Exception:
                            # A handoff/log write failure must not stop acquisition.
                            pass
            self.threads = [threading.Thread(target=worker, name='sensor-observer', daemon=True)
                            for _ in range(self.workers)]
            for thread in self.threads:
                thread.start()

    def stop(self, timeout: float = 15) -> bool:
        with self.changed:
            self.stopping = True
            self.changed.notify_all()
        deadline = time.monotonic() + timeout
        for thread in self.threads:
            thread.join(timeout=max(0, deadline - time.monotonic()))
        stopped = all(not t.is_alive() for t in self.threads)
        if stopped:
            self.threads = []
        return stopped


def save_catalog(path: Path, ledger: SensorLedger, binding: str) -> int:
    parent = path.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o077 or
            parent.st_uid != os.geteuid()):
        raise ValueError('Invalid private catalog directory')
    with ledger.lock:
        now, wall = ledger.monotonic(), ledger.wall()
        not_found = {uri: {'count': row.consecutive_404, 'last_at': wall - (now - row.last_404)}
                     for uri, row in ledger.rows.items() if row.consecutive_404}
        revision = ledger.catalog_revision
        payload = json.dumps({'version': 1, 'binding': binding,
                              'discovered_at': ledger.discovered_at, 'rows': ledger.catalog(),
                              'not_found': not_found},
                             allow_nan=False, separators=(',', ':')).encode()
    if len(payload) > MAX_CATALOG_BYTES or path.is_symlink():
        raise ValueError('Invalid private catalog destination')
    temporary = path.with_name(path.name + '.' + secrets.token_hex(8) + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return revision


def load_catalog(path: Path, ledger: SensorLedger, binding: str) -> bool:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or
                    info.st_uid != os.geteuid() or info.st_size > MAX_CATALOG_BYTES):
                return False
            raw = json.loads(stream.read(MAX_CATALOG_BYTES + 1))
        if not isinstance(raw, dict) or raw.get('version') != 1 or raw.get('binding') != binding:
            return False
        # Persistence contains identities, never an invented fresh observation.
        rows = []
        for row in raw['rows']:
            item = dict(row)
            item['RelatedItem'] = [{'@odata.id': uri} for uri in item.get('RelatedItem', [])]
            rows.append(item)
        not_found = raw.get('not_found', {})
        catalog = checked_catalog(rows)
        if not isinstance(not_found, dict) or len(not_found) > len(catalog):
            return False
        for uri, item in not_found.items():
            if (uri not in catalog or not isinstance(item, dict) or set(item) != {'count', 'last_at'} or
                    type(item['count']) is not int or not 1 <= item['count'] <= 3 or
                    not _finite(item['last_at']) or not 0 < item['last_at'] <= ledger.wall()):
                return False
        ledger.reconcile(rows, discovered_at=raw['discovered_at'])
        with ledger.lock:
            for uri, item in not_found.items():
                row = ledger.rows[uri]
                row.consecutive_404 = item['count']
                row.excluded = item['count'] == 3
                row.last_error = 'not_found'
                row.last_404 = ledger.monotonic() - (ledger.wall() - item['last_at'])
                row.due = max(ledger.monotonic(), row.last_404 + 10)
        return True
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        return False
