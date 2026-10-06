"""Allowlisted named collection summaries, never general application logs."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time

from .build_info import build_info

RETENTION_SECONDS = 14 * 86400
SIZE_LIMIT = 50 * 1024 * 1024
SEGMENT_BYTES = 1024 * 1024
STATE_LIMIT = 2 * 1024 * 1024
ENTRY_LIMIT = 4096
OPERATIONS = frozenset(('sensors', 'sensor_recovery', 'catalog', 'inventory', 'components', 'telemetry', 'logging'))
OUTCOMES = frozenset(('started', 'complete', 'partial', 'failed', 'recovered', 'exhausted', 'interrupted', 'gap'))
ERROR_CODES = frozenset(('timeout', 'transport', 'budget', 'authentication', 'certificate', 'metadata',
                         'internal', 'not_found', 'throttled', 'http', 'storage', 'restart'))
COUNTS = frozenset(('tracked', 'eligible', 'fresh', 'missing', 'stale', 'numeric_unavailable', 'excluded_404',
                   'retries', 'errors', 'initial_missing', 'recovered', 'unresolved', 'new_exclusions',
                   'dropped_records', 'request_count', 'catalog_errors'))
COUNTS |= frozenset(('additional_missing', 'original_exclusions', 'original_unresolved', 'catalog_removed'))
DURATIONS = frozenset(('duration_seconds', 'recovery_seconds', 'total_seconds', 'max_source_age_seconds',
                       'request_seconds', 'admission_seconds'))
BASE_KEYS = frozenset(('schema', 'timestamp', 'version', 'target', 'operation', 'outcome', 'cycle_id', 'error_codes'))


def display_name(value: object) -> str | None:
    """Accept concise configured names, excluding addresses and structured secrets."""
    if (not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_. -]{0,79}', value) or
            re.search(r'(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])', value)):
        return None
    return value


def _utc(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def _validate(record: dict) -> bytes:
    """Reject unknown fields before writing; no text redaction heuristic is used."""
    if isinstance(record, dict) and record.get('schema') == 2:
        # Retain earlier timings/names while removing the retired public field.
        # Validate its old shape before normalizing; arbitrary fields remain
        # rejected by the same strict allowlist below.
        if not re.fullmatch(r'server-[0-9]{2,10}', str(record.get('target_alias', ''))):
            raise ValueError('Invalid legacy collection summary')
        record = {key: value for key, value in record.items() if key != 'target_alias'}
        record['schema'] = 3
    if not isinstance(record, dict) or set(record) - (BASE_KEYS | COUNTS | DURATIONS):
        raise ValueError('Invalid collection summary')
    if (record.get('schema') != 3 or record.get('operation') not in OPERATIONS or
            record.get('outcome') not in OUTCOMES or
            display_name(record.get('target')) is None or
            not re.fullmatch(r'[0-9a-f]{32}', str(record.get('cycle_id', ''))) or
            not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', str(record.get('version', ''))) or
            not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z',
                             str(record.get('timestamp', '')))):
        raise ValueError('Invalid collection summary')
    datetime.fromisoformat(record['timestamp'].replace('Z', '+00:00'))
    for key in COUNTS & record.keys():
        if type(record[key]) is not int or not 0 <= record[key] <= 1_000_000_000:
            raise ValueError('Invalid summary count')
    for key in DURATIONS & record.keys():
        if (type(record[key]) not in (int, float) or not math.isfinite(record[key]) or
                not 0 <= record[key] <= 1_000_000_000):
            raise ValueError('Invalid summary duration')
    codes = record.get('error_codes', [])
    if not isinstance(codes, list) or len(codes) > len(ERROR_CODES) or any(x not in ERROR_CODES for x in codes):
        raise ValueError('Invalid summary error category')
    payload = json.dumps(record, separators=(',', ':'), allow_nan=False).encode() + b'\n'
    if len(payload) > ENTRY_LIMIT:
        raise ValueError('Collection summary exceeds its bound')
    return payload


class CollectionLog:
    def __init__(self, directory: Path, *, version: str | None = None,
                 retention: int = RETENTION_SECONDS, size_limit: int = SIZE_LIMIT,
                 segment_bytes: int = SEGMENT_BYTES, wall=time.time) -> None:
        if not 60 <= retention <= RETENTION_SECONDS or not 8192 <= size_limit <= SIZE_LIMIT:
            raise ValueError('Invalid collection log limits')
        self.directory, self.wall = directory, wall
        self.retention, self.size_limit = retention, size_limit
        self.segment_bytes = min(segment_bytes, size_limit // 4)
        if self.segment_bytes < ENTRY_LIMIT:
            raise ValueError('Invalid collection segment limit')
        directory.mkdir(mode=0o700, parents=False, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
            raise ValueError('Collection log directory must be private')
        self.version = version or build_info()['version']
        if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', self.version):
            raise ValueError('Invalid collection log version')
        self.lock = threading.RLock()
        self.dropped = 0
        self.owner = secrets.token_hex(16)

    def _open(self, name: str, flags: int):
        fd = os.open(self.directory / name, flags | os.O_NOFOLLOW, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
            os.close(fd)
            raise OSError('Invalid private collection file')
        return fd

    @contextmanager
    def _locked(self):
        with self.lock:
            fd = self._open('writer.lock', os.O_RDWR | os.O_CREAT)
            try:
                deadline = time.monotonic() + 1
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise OSError('Collection log writer busy')
                        time.sleep(.01)
                yield
            finally:
                os.close(fd)

    def _state(self) -> dict:
        try:
            with os.fdopen(self._open('state.json', os.O_RDONLY), 'rb') as stream:
                data = stream.read(STATE_LIMIT + 1)
            if len(data) > STATE_LIMIT:
                raise ValueError('Invalid collection state')
            state = json.loads(data)
        except FileNotFoundError:
            if self._files():
                raise ValueError('Missing private alias state')
            return {'schema': 1, 'record_schema': 3, 'aliases': {}, 'names': {}, 'next_alias': 1, 'segment': 1,
                    'pending': {}, 'dropped': 0, 'pruned_at': 0}
        if (not isinstance(state, dict) or state.get('schema') != 1 or
                not isinstance(state.get('aliases'), dict) or not isinstance(state.get('pending'), dict) or
                type(state.get('next_alias')) is not int or not 1 <= state['next_alias'] < 10**10 or
                type(state.get('segment')) is not int or not 1 <= state['segment'] < 10**10 or
                type(state.get('dropped')) is not int or state['dropped'] < 0):
            # Do not reset/reassign aliases when private state becomes unreadable.
            raise ValueError('Invalid collection state')
        aliases = state['aliases']
        names = state.setdefault('names', {})
        if (not isinstance(names, dict) or len(names) > 20000 or
                any(key not in aliases or not isinstance(value, str) or value != '' and display_name(value) != value
                    for key, value in names.items())):
            raise ValueError('Invalid private target names')
        if (len(aliases) > 20000 or len(set(aliases.values())) != len(aliases) or
                any((key != 'standalone' and not re.fullmatch(r'[0-9a-f]{32}', key)) or
                    not isinstance(value, str) or not re.fullmatch(r'server-[0-9]{2,10}', value)
                    for key, value in aliases.items()) or
                any(int(value[7:]) >= state['next_alias'] for value in aliases.values())):
            raise ValueError('Invalid private alias state')
        if state.get('record_schema') != 3:
            state['record_schema'] = 3
            state['pruned_at'] = 0  # Normalize retained records on the first write/export.
        return state

    def _replace_file(self, name, data):
        temporary = 'write-' + secrets.token_hex(8) + '.tmp'
        try:
            with os.fdopen(self._open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL), 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(self.directory / temporary, self.directory / name)
        finally:
            (self.directory / temporary).unlink(missing_ok=True)

    def _save(self, state):
        data = json.dumps(state, allow_nan=False, separators=(',', ':')).encode()
        if len(data) > STATE_LIMIT:
            raise ValueError('Collection state exceeds its bound')
        self._replace_file('state.json', data)

    @staticmethod
    def _alias(state, target_id):
        if target_id != 'standalone' and not re.fullmatch(r'[0-9a-f]{32}', target_id):
            raise ValueError('Invalid private claim identity')
        value = state['aliases'].get(target_id)
        if value is None:
            value = f'server-{state["next_alias"]:02d}'
            state['next_alias'] += 1
            state['aliases'][target_id] = value
        if not re.fullmatch(r'server-[0-9]{2,10}', value):
            raise ValueError('Invalid private alias')
        return value

    def register_target(self, target_id: str, name: str) -> bool:
        """Update only saved display metadata; never contact a BMC."""
        try:
            with self._locked():
                state = self._state()
                self._alias(state, target_id)
                state['names'][target_id] = display_name(name) or ''
                self._save(state)
            return True
        except (OSError, ValueError, TypeError, KeyError, OverflowError):
            self.dropped += 1
            return False

    def _files(self):
        return sorted(path for path in self.directory.iterdir()
                      if re.fullmatch(r'collection-[0-9]{10}\.jsonl', path.name))

    def _append(self, state, record):
        payload = _validate(record)
        name = f'collection-{state["segment"]:010d}.jsonl'
        path = self.directory / name
        if path.exists() and path.lstat().st_size + len(payload) > self.segment_bytes:
            state['segment'] += 1
            name = f'collection-{state["segment"]:010d}.jsonl'
        with os.fdopen(self._open(name, os.O_WRONLY | os.O_CREAT | os.O_APPEND), 'ab') as stream:
            stream.write(payload)
        self._prune(state)

    def _prune(self, state):
        now = self.wall()
        cutoff = _utc(now - self.retention)
        files = self._files()
        if now - state.get('pruned_at', 0) >= 60 or now < state.get('pruned_at', 0):
            for path in files:
                with os.fdopen(self._open(path.name, os.O_RDONLY), 'rb') as stream:
                    data = stream.read(self.segment_bytes + ENTRY_LIMIT + 1)
                if len(data) > self.segment_bytes + ENTRY_LIMIT:
                    raise ValueError('Collection segment exceeds its bound')
                kept = []
                for line in data.splitlines():
                    try:
                        record = json.loads(line)
                        clean = _validate(record)
                        if record['timestamp'] >= cutoff:
                            kept.append(clean)
                    except (ValueError, TypeError, OverflowError):
                        state['dropped'] += 1
                filtered = b''.join(kept)
                if not filtered:
                    path.unlink()
                elif filtered != data:
                    # Coordinated writers/export hold the same private file lock.
                    self._replace_file(path.name, filtered)
            state['pruned_at'] = now
            files = self._files()
        total = sum(path.lstat().st_size for path in files)
        # Reserve private mapping/state overhead as part of the total disk cap.
        reserve = min(STATE_LIMIT, self.size_limit // 4)
        for path in files:
            if total <= self.size_limit - reserve:
                break
            total -= path.lstat().st_size
            path.unlink()

    def _record(self, alias, operation, outcome, cycle_id, values, *, name=None):
        if set(values) - (COUNTS | DURATIONS | {'error_codes'}):
            raise ValueError('Invalid summary fields')
        return {'schema': 3, 'timestamp': _utc(self.wall()), 'version': self.version,
                'target': display_name(name) or alias,
                'operation': operation, 'outcome': outcome,
                'cycle_id': cycle_id, **values}

    def begin(self, target_id: str, operation: str, *, cycle_id: str | None = None, **values) -> str | None:
        identifier = cycle_id or secrets.token_hex(16)
        try:
            with self._locked():
                state = self._state()
                allocation = target_id not in state['aliases']
                alias = self._alias(state, target_id)
                record = self._record(alias, operation, 'started', identifier, values, name=state['names'].get(target_id))
                _validate(record)
                # Commit alias allocation before any exported record can use it.
                if allocation:
                    self._save(state)
                key = alias + ':' + operation
                previous = state['pending'].get(key)
                if previous:
                    old = self._record(alias, operation, 'interrupted', previous['cycle_id'],
                                       {'error_codes': ['restart'], **previous.get('counts', {})}, name=state['names'].get(target_id))
                    self._append(state, old)
                self._append(state, record)
                state['pending'][key] = {'cycle_id': identifier, 'owner': self.owner,
                                         'counts': {k: v for k, v in values.items() if k in COUNTS}}
                state['dropped'] += self.dropped
                self._save(state)
                self.dropped = 0
            return identifier
        except (OSError, ValueError, TypeError, KeyError, OverflowError):
            self.dropped += 1
            return None

    def interrupt_pending(self, target_id: str, operations: tuple[str, ...]) -> None:
        try:
            if any(operation not in OPERATIONS for operation in operations):
                raise ValueError('Invalid collection operation')
            with self._locked():
                state = self._state()
                allocation = target_id not in state['aliases']
                alias = self._alias(state, target_id)
                if allocation:
                    self._save(state)
                for operation in operations:
                    pending = state['pending'].pop(alias + ':' + operation, None)
                    if pending:
                        self._append(state, self._record(alias, operation, 'interrupted', pending['cycle_id'],
                            {'error_codes': ['restart'], **pending.get('counts', {})}, name=state['names'].get(target_id)))
                state['dropped'] += self.dropped
                self._save(state)
                self.dropped = 0
        except (OSError, ValueError, TypeError, KeyError, OverflowError):
            self.dropped += 1

    def record(self, target_id: str, operation: str, outcome: str, cycle_id: str | None,
               *, terminal: bool = True, **values) -> bool:
        if cycle_id is None:
            return False
        try:
            with self._locked():
                state = self._state()
                allocation = target_id not in state['aliases']
                alias = self._alias(state, target_id)
                record = self._record(alias, operation, outcome, cycle_id, values, name=state['names'].get(target_id))
                _validate(record)
                if allocation:
                    self._save(state)
                self._append(state, record)
                key = alias + ':' + operation
                pending = state['pending'].get(key)
                if pending and pending['cycle_id'] == cycle_id:
                    if terminal:
                        del state['pending'][key]
                    else:
                        pending['counts'] = {k: v for k, v in values.items() if k in COUNTS}
                state['dropped'] += self.dropped
                self._save(state)
                self.dropped = 0
            return True
        except (OSError, ValueError, TypeError, KeyError, OverflowError):
            self.dropped += 1
            return False

    def export(self) -> bytes:
        """Fixed files only; revalidate every record before returning an attachment."""
        with self._locked():
            state = self._state()
            self._prune(state)
            self._save(state)
            parts = []
            size = 0
            for path in self._files():
                with os.fdopen(self._open(path.name, os.O_RDONLY), 'rb') as stream:
                    data = stream.read(self.segment_bytes + ENTRY_LIMIT + 1)
                size += len(data)
                if len(data) > self.segment_bytes + ENTRY_LIMIT or size > self.size_limit:
                    raise ValueError('Collection download exceeds its bound')
                parts.append(data)
            drops = state['dropped'] + self.dropped
        cutoff = _utc(self.wall() - self.retention)
        records = []
        for data in parts:
            for line in data.splitlines():
                try:
                    item = json.loads(line)
                    clean = _validate(item)
                    if item['timestamp'] >= cutoff:
                        records.append((item['timestamp'], clean))
                except (ValueError, TypeError, OverflowError):
                    drops += 1
        records.sort(key=lambda pair: pair[0])
        header = {'schema': 1, 'record_type': 'coverage', 'version': self.version,
                  'available_from': records[0][0] if records else None,
                  'available_until': records[-1][0] if records else None,
                  'retention_days': self.retention / 86400, 'size_limit_bytes': self.size_limit,
                  'known_dropped_records': drops, 'unrecorded_gaps_possible': True,
                  'records': len(records)}
        return json.dumps(header, separators=(',', ':')).encode() + b'\n' + b''.join(pair[1] for pair in records)
