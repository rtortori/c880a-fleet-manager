"""Small saved collection status; UI reads never initiate Redfish work."""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import secrets
import stat
import time

COUNT_KEYS = ('tracked', 'eligible', 'fresh', 'missing', 'stale', 'numeric_unavailable', 'excluded_404', 'unresolved', 'exhausted')
PAUSED = ('', 'authentication', 'certificate', 'metadata', 'internal')


def write_status(path: Path, state: dict) -> None:
    data = {'schema': 1, 'captured_at': time.time(), 'paused': state['paused'],
            **{key: state[key] for key in COUNT_KEYS}}
    payload = json.dumps(data, allow_nan=False, separators=(',', ':')).encode()
    temporary = path.with_name(path.name + '.' + secrets.token_hex(8) + '.tmp')
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_status(path: Path) -> dict:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or
                    info.st_uid != os.geteuid() or not 0 < info.st_size <= 4096):
                return {'available': False}
            data = json.loads(stream.read(4097))
        if (not isinstance(data, dict) or set(data) != {'schema', 'captured_at', 'paused', *COUNT_KEYS} or
                data['schema'] != 1 or data['paused'] not in PAUSED or
                type(data['captured_at']) not in (int, float) or not math.isfinite(data['captured_at']) or
                any(type(data[key]) is not int or not 0 <= data[key] <= 3000 for key in COUNT_KEYS)):
            return {'available': False}
        age = time.time() - data['captured_at']
        if (data['eligible'] + data['excluded_404'] != data['tracked'] or
                data['fresh'] + data['missing'] + data['stale'] != data['eligible'] or
                data['numeric_unavailable'] > data['fresh'] or
                data['unresolved'] > data['eligible'] or data['exhausted'] > data['unresolved']):
            return {'available': False}
        if not 0 <= age <= 10:
            return {'available': False, 'captured_at': data['captured_at']}
        return {'available': True, **{key: data[key] for key in ('captured_at', 'paused', *COUNT_KEYS)}}
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        return {'available': False}
