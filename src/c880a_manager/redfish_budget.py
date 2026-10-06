"""Process-shared, bounded Redfish GET admission for a managed fleet.

SQLite is used only for short admission transactions. No BMC response, URL,
credential, or request payload is written to this database. Standalone
exporters do not need the database and retain their local GET limit.
"""

from __future__ import annotations

from contextlib import closing
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import threading
import time


class BudgetUnavailable(Exception):
    """Admission failed closed; callers must not issue an unbudgeted GET."""


class SharedGetBudget:
    def __init__(self, database: Path, *, fleet_limit: int = 24,
                 target_limit: int = 4, wait_limit: float = 900) -> None:
        if not 1 <= target_limit <= fleet_limit <= 64 or wait_limit <= 0:
            raise ValueError("Invalid Redfish GET budget")
        self.database = database
        self.fleet_limit = fleet_limit
        self.target_limit = target_limit
        self.wait_limit = wait_limit
        self._renewers_lock = threading.Lock()
        self._renewers: dict[str, threading.Event] = {}
        # The manager owns a private (0700) data directory. Create this file
        # privately too, and reject symlinks or unexpected file types.
        try:
            fd = os.open(database, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        info = database.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("Redfish budget database must be a private regular file")
        try:
            with closing(self._connect()) as db:
                db.execute("PRAGMA journal_mode=WAL")
                db.executescript("""
                    CREATE TABLE IF NOT EXISTS waiters (
                      token TEXT PRIMARY KEY, target TEXT NOT NULL,
                      priority INTEGER NOT NULL, created REAL NOT NULL,
                      last_seen REAL NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS leases (
                      token TEXT PRIMARY KEY, target TEXT NOT NULL,
                      expires REAL NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS budget_waiters_target ON waiters(target);
                    CREATE INDEX IF NOT EXISTS budget_leases_target ON leases(target);
                """)
        except sqlite3.Error as exc:
            raise BudgetUnavailable("Redfish request budget is unavailable") from exc

    def _connect(self, wait_timeout: float = 3) -> sqlite3.Connection:
        db = sqlite3.connect(self.database, timeout=wait_timeout, isolation_level=None)
        db.execute(f"PRAGMA busy_timeout={max(1, int(wait_timeout * 1000))}")
        return db

    def acquire(self, target: str, *, priority: int = 0,
                request_timeout: float = 10, wait_timeout: float | None = None) -> str:
        """Wait for one GET slot; priority ages so slow lanes cannot starve."""
        if not target or len(target) > 253 or priority not in (0, 1, 2, 3):
            raise ValueError("Invalid Redfish budget target or priority")
        if wait_timeout is not None and not 0 < wait_timeout <= self.wait_limit:
            raise ValueError("Invalid Redfish admission timeout")
        token = secrets.token_hex(16)
        # The database is local to one host, so monotonic clock values are
        # comparable across its processes and immune to NTP/wall-time jumps.
        # Entries from a prior boot are pruned as expired or implausibly future.
        created = time.monotonic()
        deadline = created + (self.wait_limit if wait_timeout is None else wait_timeout)
        # Renew short leases only while this process owns the GET. A crashed
        # process relinquishes capacity within 15 seconds. The total deadline
        # is also enforced by RedfishClient while reading the response.
        max_lease_seconds = min(150.0, max(30.0, request_timeout + 30.0)) + 5
        granted = False
        try:
            with closing(self._connect(min(3, deadline - created))) as db:
                # A bounded reader can leave before best-effort cleanup acquires
                # SQLite's write lock. Expire its queue position at its deadline,
                # rather than blocking every other target for ten more seconds.
                heartbeat = min(created, deadline - 10)
                db.execute("INSERT INTO waiters VALUES (?, ?, ?, ?, ?)",
                           (token, target, priority, created, heartbeat))
                while True:
                    if time.monotonic() >= deadline:
                        raise BudgetUnavailable("Redfish request budget wait timed out")
                    now = time.monotonic()
                    db.execute(f"PRAGMA busy_timeout={max(1, min(3000, int((deadline - now) * 1000)))}")
                    db.execute("BEGIN IMMEDIATE")
                    try:
                        db.execute("DELETE FROM leases WHERE expires < ? OR expires > ?",
                                   (now, now + 155))
                        db.execute("DELETE FROM waiters WHERE last_seen < ? OR last_seen > ?",
                                   (now - 10, now + 60))
                        db.execute("UPDATE waiters SET last_seen=? WHERE token=?",
                                   (min(now, deadline - 10), token))
                        active = db.execute("SELECT target, count(*) FROM leases GROUP BY target").fetchall()
                        active_by_target = dict(active)
                        active_total = sum(active_by_target.values())
                        waiting = db.execute(
                            "SELECT token, target, priority, created FROM waiters"
                        ).fetchall()
                        # Ordinary collection leaves one slot across the
                        # fleet and on each BMC for fresh action confirmation.
                        # A request gains one rank every 30 seconds, up
                        # to four ranks. FIFO resolves equal scores.
                        ordered = sorted(waiting, key=lambda row: (
                            -(row[2] + min(4, max(0, int((now - row[3]) / 30)))),
                            row[3], row[0]))
                        # Reserve free positions for earlier eligible waiters,
                        # rather than waiting for just the first poller to wake.
                        # Every admission is still serialized by this write
                        # transaction; virtual reservations preserve priority,
                        # FIFO and the fleet/BMC action-confirmation slots.
                        admitted = False
                        for queued_token, queued_target, queued_priority, _ in ordered:
                            if (active_total >= max(1, self.fleet_limit - (queued_priority < 3)) or
                                    active_by_target.get(queued_target, 0) >=
                                    max(1, self.target_limit - (queued_priority < 3))):
                                continue
                            if queued_token == token:
                                admitted = True
                                break
                            active_total += 1
                            active_by_target[queued_target] = active_by_target.get(queued_target, 0) + 1
                        if admitted:
                            max_lease_until = now + max_lease_seconds
                            db.execute("DELETE FROM waiters WHERE token=?", (token,))
                            db.execute("INSERT INTO leases VALUES (?, ?, ?)",
                                       (token, target, min(now + 15, max_lease_until)))
                            db.execute("COMMIT")
                            self._start_renewer(token, max_lease_until)
                            granted = True
                            return token
                        db.execute("COMMIT")
                    except Exception:
                        db.execute("ROLLBACK")
                        raise
                    time.sleep(min(0.1, max(0, deadline - time.monotonic())))
        except sqlite3.Error as exc:
            raise BudgetUnavailable("Redfish request budget is unavailable") from exc
        finally:
            # This is harmless after admission and avoids a stale waiter after
            # timeout, cancellation, or an unexpected exception.
            try:
                if not granted:
                    with closing(self._connect(min(.1, max(.001, deadline - time.monotonic())))) as db:
                        db.execute("DELETE FROM waiters WHERE token=?", (token,))
            except sqlite3.Error:
                pass

    def _start_renewer(self, token: str, max_until: float) -> None:
        stop = threading.Event()
        with self._renewers_lock:
            self._renewers[token] = stop
        try:
            threading.Thread(target=self._renew_loop, args=(token, stop, max_until),
                             name="redfish-budget-lease", daemon=True).start()
        except RuntimeError as exc:
            with self._renewers_lock:
                self._renewers.pop(token, None)
            self.release(token)
            raise BudgetUnavailable("Redfish request budget is unavailable") from exc

    def _renew_loop(self, token: str, stop: threading.Event, max_until: float) -> None:
        while not stop.wait(5):
            now = time.monotonic()
            if now >= max_until:
                return
            try:
                with closing(self._connect()) as db:
                    changed = db.execute("UPDATE leases SET expires=? WHERE token=? AND expires>=?",
                                         (min(now + 15, max_until), token, now))
                    if not changed.rowcount:
                        return
            except sqlite3.Error:
                # A transient lock can recover on the next renewal. If not,
                # the lease expires and release() reports the lost admission.
                continue

    def release(self, token: str, *, wait_timeout: float = 3) -> None:
        with self._renewers_lock:
            stop = self._renewers.pop(token, None)
        if stop is not None:
            stop.set()
        try:
            with closing(self._connect(wait_timeout)) as db:
                changed = db.execute("DELETE FROM leases WHERE token=?", (token,))
                if not changed.rowcount:
                    raise BudgetUnavailable("Redfish GET exceeded its shared admission lease")
        except sqlite3.Error as exc:
            raise BudgetUnavailable("Redfish request budget is unavailable") from exc

    def active_counts(self) -> tuple[int, dict[str, int]]:
        """Secret-free diagnostic counts for tests and capacity checks."""
        try:
            with closing(self._connect()) as db:
                now = time.monotonic()
                rows = db.execute("SELECT target, count(*) FROM leases WHERE expires >= ? GROUP BY target",
                                  (now,)).fetchall()
                counts = dict(rows)
                return sum(counts.values()), counts
        except sqlite3.Error as exc:
            raise BudgetUnavailable("Redfish request budget is unavailable") from exc
