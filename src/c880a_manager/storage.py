"""Local prototype state, encrypted BMC credentials, and event history."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _private_file(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)


def _password_hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**17, r=8, p=1,
                          dklen=32, maxmem=256 * 1024 * 1024)


class Store:
    def __init__(self, data_dir: Path) -> None:
        if data_dir.resolve() in (Path("/"), Path.home().resolve()):
            raise ValueError("Data directory must not be the filesystem root or home directory")
        data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(data_dir, 0o700)
        self.data_dir = data_dir
        self.database = data_dir / "manager.db"
        self.key_file = data_dir / "master.key"
        self.installation_id_file = data_dir / "installation-id"
        self.bootstrap_file = data_dir / "bootstrap-token"
        if not self.key_file.exists():
            _private_file(self.key_file, AESGCM.generate_key(bit_length=256))
        self.key = self.key_file.read_bytes()
        if len(self.key) != 32:
            raise ValueError("Invalid credential encryption key")
        if not self.installation_id_file.exists():
            try:
                _private_file(self.installation_id_file, (secrets.token_hex(16) + "\n").encode())
            except FileExistsError:
                pass  # Another process initialized the same owner-only directory.
        if self.installation_id_file.is_symlink() or not self.installation_id_file.is_file():
            raise ValueError("Invalid installation identity file")
        self.installation_id = self.installation_id_file.read_text().strip()
        if not re.fullmatch(r"[0-9a-f]{32}", self.installation_id):
            raise ValueError("Invalid installation identity")
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                  id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                  salt BLOB NOT NULL, password_hash BLOB NOT NULL,
                  role TEXT NOT NULL DEFAULT 'admin', disabled INTEGER NOT NULL DEFAULT 0,
                  must_change_password INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS sessions (
                  token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL,
                  csrf TEXT NOT NULL, created REAL NOT NULL, last_seen REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS servers (
                  id TEXT PRIMARY KEY, name TEXT NOT NULL, bmc_host TEXT NOT NULL,
                  bmc_port INTEGER NOT NULL DEFAULT 443 CHECK(bmc_port BETWEEN 1 AND 65535),
                  username TEXT NOT NULL, password_cipher BLOB,
                  insecure_bmc INTEGER NOT NULL, port INTEGER UNIQUE NOT NULL,
                  state TEXT NOT NULL, discovered_json TEXT NOT NULL,
                  created REAL NOT NULL,
                  manager_metrics_enabled INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS events (
                  id INTEGER PRIMARY KEY AUTOINCREMENT, server_id TEXT,
                  source TEXT NOT NULL, source_entry_id TEXT NOT NULL,
                  occurred_at TEXT, observed_at TEXT NOT NULL, time_quality TEXT NOT NULL,
                  severity TEXT, message_id TEXT, message TEXT NOT NULL,
                  raw_json TEXT NOT NULL,
                  UNIQUE(server_id, source, source_entry_id)
                );
                CREATE INDEX IF NOT EXISTS events_observed_idx ON events(observed_at DESC);
                CREATE INDEX IF NOT EXISTS events_server_idx ON events(server_id, observed_at DESC);
                CREATE TABLE IF NOT EXISTS event_cursors (
                  server_id TEXT PRIMARY KEY, last_event_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit (
                  id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL,
                  user_id TEXT, action TEXT NOT NULL, subject TEXT
                );
                CREATE TABLE IF NOT EXISTS settings (
                  key TEXT PRIMARY KEY, value INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS inventory_snapshots (
                  server_id TEXT PRIMARY KEY, snapshot_json TEXT,
                  last_success_at TEXT, last_attempt_at TEXT,
                  last_attempt_epoch REAL, state TEXT NOT NULL DEFAULT 'pending',
                  failures_json TEXT NOT NULL DEFAULT '[]',
                  interval_override INTEGER,
                  revision INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS manager_metric_pauses (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  server_id TEXT NOT NULL,
                  disabled_at REAL NOT NULL,
                  enabled_at REAL
                );
                CREATE INDEX IF NOT EXISTS manager_metric_pauses_range_idx
                  ON manager_metric_pauses(server_id, disabled_at, enabled_at);
                CREATE UNIQUE INDEX IF NOT EXISTS manager_metric_pauses_open_idx
                  ON manager_metric_pauses(server_id) WHERE enabled_at IS NULL;
                CREATE TABLE IF NOT EXISTS server_action_jobs (
                  id TEXT PRIMARY KEY, server_id TEXT NOT NULL, operation TEXT NOT NULL,
                  state TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                  task_uri TEXT, entries_uri TEXT, entries_before_json TEXT NOT NULL DEFAULT '[]',
                  entry_uri TEXT, attachment_uri TEXT, error TEXT
                );
                CREATE INDEX IF NOT EXISTS server_action_jobs_server_idx
                  ON server_action_jobs(server_id, created_at DESC);
                CREATE TABLE IF NOT EXISTS prometheus_deletions (
                  server_id TEXT PRIMARY KEY, created_at REAL NOT NULL,
                  operation_id TEXT NOT NULL
                );
            """)
            deletion_columns = {row["name"] for row in db.execute("PRAGMA table_info(prometheus_deletions)")}
            if "operation_id" not in deletion_columns:
                db.execute("ALTER TABLE prometheus_deletions ADD COLUMN operation_id TEXT")
                db.execute("UPDATE prometheus_deletions SET operation_id=?", (secrets.token_hex(16),))
            # Existing installations retain their prior collection behavior;
            # newly onboarded servers require an explicit opt-in.
            columns = {row["name"] for row in db.execute("PRAGMA table_info(servers)")}
            if "manager_metrics_enabled" not in columns:
                db.execute("ALTER TABLE servers ADD COLUMN manager_metrics_enabled INTEGER NOT NULL DEFAULT 1")
            if "bmc_port" not in columns:
                # SQLite cannot drop the old single-host UNIQUE constraint in
                # place. Rebuild once, retaining IDs, credentials and history.
                db.executescript("""
                    BEGIN IMMEDIATE;
                    CREATE TABLE servers_r20 (
                      id TEXT PRIMARY KEY, name TEXT NOT NULL, bmc_host TEXT NOT NULL,
                      bmc_port INTEGER NOT NULL DEFAULT 443 CHECK(bmc_port BETWEEN 1 AND 65535),
                      username TEXT NOT NULL, password_cipher BLOB,
                      insecure_bmc INTEGER NOT NULL, port INTEGER UNIQUE NOT NULL,
                      state TEXT NOT NULL, discovered_json TEXT NOT NULL,
                      created REAL NOT NULL, manager_metrics_enabled INTEGER NOT NULL DEFAULT 0
                    );
                    INSERT INTO servers_r20
                      (id, name, bmc_host, username, password_cipher, insecure_bmc,
                       port, state, discovered_json, created, manager_metrics_enabled)
                      SELECT id, name, bmc_host, username, password_cipher, insecure_bmc,
                             port, state, discovered_json, created, manager_metrics_enabled
                      FROM servers;
                    DROP TABLE servers;
                    ALTER TABLE servers_r20 RENAME TO servers;
                    CREATE UNIQUE INDEX servers_bmc_target_idx ON servers(bmc_host, bmc_port);
                    COMMIT;
                """)
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS servers_bmc_target_idx ON servers(bmc_host, bmc_port)")
            db.execute("""UPDATE manager_metric_pauses SET enabled_at=? WHERE enabled_at IS NULL
                          AND server_id IN (SELECT id FROM servers WHERE manager_metrics_enabled=1
                          OR state!='active')""", (time.time(),))
            # Existing disabled servers have no trustworthy transition time. Begin
            # recording from this migration rather than inventing past outages.
            db.execute("""INSERT OR IGNORE INTO manager_metric_pauses(server_id, disabled_at)
                          SELECT id, ? FROM servers WHERE state='active'
                          AND manager_metrics_enabled=0 AND id NOT IN
                          (SELECT server_id FROM manager_metric_pauses WHERE enabled_at IS NULL)""", (time.time(),))
            db.execute("DELETE FROM manager_metric_pauses WHERE enabled_at < ?", (time.time() - 86400,))
            user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
            if "role" not in user_columns:
                db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'")
            if "disabled" not in user_columns:
                db.execute("ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0")
            if "must_change_password" not in user_columns:
                db.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")
            inventory_columns = {row["name"] for row in db.execute("PRAGMA table_info(inventory_snapshots)")}
            if "revision" not in inventory_columns:
                db.execute("ALTER TABLE inventory_snapshots ADD COLUMN revision INTEGER NOT NULL DEFAULT 0")
            count = db.execute("SELECT count(*) FROM users").fetchone()[0]
        os.chmod(self.database, 0o600)
        if count == 0 and not self.bootstrap_file.exists():
            _private_file(self.bootstrap_file, (secrets.token_urlsafe(32) + "\n").encode())

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.database, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA secure_delete=ON")
        return db

    def bootstrap_required(self) -> bool:
        with self.connect() as db:
            return db.execute("SELECT count(*) FROM users").fetchone()[0] == 0

    def bootstrap(self, token: str, password: str) -> bool:
        if not self.bootstrap_required() or not self.bootstrap_file.exists():
            return False
        expected = self.bootstrap_file.read_text().strip()
        if not hmac.compare_digest(token, expected):
            return False
        salt = secrets.token_bytes(16)
        with self.connect() as db:
            db.execute("INSERT INTO users (id, username, salt, password_hash, role, disabled) VALUES (?, ?, ?, ?, 'admin', 0)",
                       (secrets.token_hex(16), "admin", salt, _password_hash(password, salt)))
        self.bootstrap_file.unlink()
        return True

    def provision_installer_admin(self) -> None:
        """Fresh installer deployments alone use the agreed temporary credential."""
        with self.connect() as db:
            if (db.execute("SELECT count(*) FROM users").fetchone()[0] or
                    db.execute("SELECT count(*) FROM servers").fetchone()[0] or
                    db.execute("SELECT count(*) FROM audit").fetchone()[0]):
                raise ValueError("Installer admin can only be provisioned on an empty installation")
            salt = secrets.token_bytes(16)
            db.execute("""INSERT INTO users
                       (id, username, salt, password_hash, role, disabled, must_change_password)
                       VALUES (?, 'admin', ?, ?, 'admin', 0, 1)""",
                       (secrets.token_hex(16), salt, _password_hash("admin", salt)))
        self.bootstrap_file.unlink(missing_ok=True)

    def set_initial_password(self, user_id: str, password: str) -> bool:
        if password == "admin":
            raise ValueError("Choose a password other than the initial password")
        salt = secrets.token_bytes(16)
        digest = _password_hash(password, salt)
        with self.connect() as db:
            changed = db.execute("""UPDATE users SET salt=?, password_hash=?, must_change_password=0
                                   WHERE id=? AND username='admin' AND must_change_password=1""",
                                 (salt, digest, user_id))
            if changed.rowcount:
                db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
            return changed.rowcount == 1

    def login(self, username: str, password: str) -> tuple[str, str] | None:
        with self.connect() as db:
            user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            # A dummy scrypt invocation keeps failed usernames on the expensive path.
            salt = user["salt"] if user else b"\x00" * 16
            expected = user["password_hash"] if user else b"\x00" * 32
            if not hmac.compare_digest(_password_hash(password, salt), expected) or not user or user["disabled"]:
                return None
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            now = time.time()
            db.execute("INSERT INTO sessions VALUES (?, ?, ?, ?, ?)",
                       (hashlib.sha256(token.encode()).hexdigest(), user["id"], csrf, now, now))
            return token, csrf

    def session(self, token: str, *, touch: bool = True) -> dict[str, Any] | None:
        digest = hashlib.sha256(token.encode()).hexdigest()
        return self.session_by_hash(digest, touch=touch)

    def session_by_hash(self, digest: str, *, touch: bool = False) -> dict[str, Any] | None:
        """Check a gateway lease without retaining a raw manager cookie token."""
        now = time.time()
        with self.connect() as db:
            row = db.execute("""SELECT sessions.*, users.username, users.role, users.disabled,
                              users.must_change_password
                              FROM sessions LEFT JOIN users ON users.id=sessions.user_id
                              WHERE token_hash=?""", (digest,)).fetchone()
            if (not row or row["username"] is None or row["disabled"]
                    or now - row["created"] > 8 * 3600
                    or now - row["last_seen"] > self.setting("login_idle_minutes", 20) * 60):
                if row:
                    db.execute("DELETE FROM sessions WHERE token_hash=?", (digest,))
                return None
            if touch:
                db.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (now, digest))
            return dict(row)

    def logout(self, token: str) -> None:
        with self.connect() as db:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))

    def users(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            return [dict(row) for row in db.execute(
                "SELECT id, username, role, disabled FROM users ORDER BY username")]

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT id, username, role, disabled FROM users WHERE id=?", (user_id,)).fetchone()
            return dict(row) if row else None

    def add_user(self, username: str, password: str, role: str) -> dict[str, Any]:
        username = username.strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", username):
            raise ValueError("Username must be 1–80 letters, numbers, dots, underscores or hyphens")
        if role not in ("admin", "read-only"):
            raise ValueError("Invalid role")
        salt, user_id = secrets.token_bytes(16), secrets.token_hex(16)
        digest = _password_hash(password, salt)
        with self.connect() as db:
            db.execute("""INSERT INTO users (id, username, salt, password_hash, role, disabled)
                          VALUES (?, ?, ?, ?, ?, 0)""", (user_id, username, salt, digest, role))
        return self.get_user(user_id)

    def update_user(self, user_id: str, role: str, disabled: bool) -> dict[str, Any] | None:
        if role not in ("admin", "read-only"):
            raise ValueError("Invalid role")
        with self.connect() as db:
            row = db.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
            if not row:
                return None
            if row["username"] == "admin" and (role != "admin" or disabled):
                raise ValueError("The bootstrap admin account must remain active with the admin role")
            db.execute("UPDATE users SET role=?, disabled=? WHERE id=?", (role, int(disabled), user_id))
            db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        return self.get_user(user_id)

    def set_user_password(self, user_id: str, password: str) -> bool:
        salt = secrets.token_bytes(16)
        digest = _password_hash(password, salt)
        with self.connect() as db:
            result = db.execute("UPDATE users SET salt=?, password_hash=? WHERE id=?", (salt, digest, user_id))
            if result.rowcount:
                db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
            return result.rowcount == 1

    def delete_user(self, user_id: str) -> bool:
        with self.connect() as db:
            row = db.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
            if not row:
                return False
            if row["username"] == "admin":
                raise ValueError("The bootstrap admin account cannot be deleted")
            db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
            db.execute("DELETE FROM users WHERE id=?", (user_id,))
            return True

    def encrypt(self, server_id: str, password: str) -> bytes:
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(self.key).encrypt(nonce, password.encode(), server_id.encode())
        return nonce + ciphertext

    def decrypt(self, server: sqlite3.Row | dict[str, Any]) -> str:
        blob = server["password_cipher"]
        if blob is None:
            raise ValueError("Server credential has been removed")
        return AESGCM(self.key).decrypt(blob[:12], blob[12:], server["id"].encode()).decode()

    def add_server(self, name: str, host: str, username: str, password: str,
                   insecure: bool, port: int, discovered: dict[str, Any],
                   manager_metrics_enabled: bool = False, bmc_port: int = 443) -> str:
        server_id = secrets.token_hex(16)
        with self.connect() as db:
            db.execute("""INSERT INTO servers
                       (id, name, bmc_host, bmc_port, username, password_cipher, insecure_bmc, port,
                        state, discovered_json, created, manager_metrics_enabled)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                       (server_id, name, host, bmc_port, username, self.encrypt(server_id, password),
                        int(insecure), port, "active", json.dumps(discovered), time.time(),
                        int(manager_metrics_enabled)))
            if not manager_metrics_enabled:
                db.execute("INSERT INTO manager_metric_pauses(server_id, disabled_at) VALUES (?, ?)",
                           (server_id, time.time()))
        return server_id

    def get_server(self, server_id: str) -> sqlite3.Row | None:
        with self.connect() as db:
            return db.execute("SELECT * FROM servers WHERE id=?", (server_id,)).fetchone()

    def get_server_by_host(self, host: str, bmc_port: int = 443) -> sqlite3.Row | None:
        with self.connect() as db:
            return db.execute("SELECT * FROM servers WHERE bmc_host=? AND bmc_port=?",
                              (host, bmc_port)).fetchone()

    def patch_discovery(self, server_id: str, fields: dict[str, Any],
                        *, expected_cipher: bytes | None = None) -> dict[str, Any] | None:
        """Merge a small Redfish result without losing concurrent inventory/details updates."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT discovered_json FROM servers WHERE id=? AND state='active'
                                AND (? IS NULL OR password_cipher=?)""",
                             (server_id, expected_cipher, expected_cipher)).fetchone()
            if row is None:
                return None
            discovered = json.loads(row["discovered_json"])
            updates = fields.copy()
            attempt = updates.get("health_last_attempt_at")
            previous = discovered.get("health_last_attempt_at")
            if isinstance(attempt, str) and isinstance(previous, str):
                try:
                    older = datetime.fromisoformat(attempt) < datetime.fromisoformat(previous)
                except ValueError:
                    older = False
                if older:
                    for key in ("health_last_attempt_at", "health_check_state", "health_check_failures", "checked_at",
                                "system_status", "system_power_state"):
                        updates.pop(key, None)
            discovered.update(updates)
            db.execute("UPDATE servers SET discovered_json=? WHERE id=? AND state='active'",
                       (json.dumps(discovered), server_id))
            return discovered

    def reactivate_server(self, server_id: str, name: str, username: str, password: str,
                          insecure: bool, discovered: dict[str, Any],
                          manager_metrics_enabled: bool = False) -> None:
        with self.connect() as db:
            db.execute("""UPDATE servers SET name=?, username=?, password_cipher=?, insecure_bmc=?,
                          state='active', discovered_json=?, manager_metrics_enabled=?
                          WHERE id=? AND state='offboarded'""",
                       (name, username, self.encrypt(server_id, password), int(insecure),
                        json.dumps(discovered), int(manager_metrics_enabled), server_id))
            if not manager_metrics_enabled:
                db.execute("INSERT OR IGNORE INTO manager_metric_pauses(server_id, disabled_at) VALUES (?, ?)",
                           (server_id, time.time()))

    def set_manager_metrics_enabled(self, server_id: str, enabled: bool) -> bool:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT manager_metrics_enabled FROM servers WHERE id=? AND state='active'",
                                 (server_id,)).fetchone()
            if current is None:
                return False
            if bool(current[0]) == enabled:
                return True
            now = time.time()
            if enabled:
                db.execute("UPDATE manager_metric_pauses SET enabled_at=? WHERE server_id=? AND enabled_at IS NULL",
                           (now, server_id))
            else:
                db.execute("INSERT INTO manager_metric_pauses(server_id, disabled_at) VALUES (?, ?)",
                           (server_id, now))
            db.execute("UPDATE servers SET manager_metrics_enabled=? WHERE id=?", (int(enabled), server_id))
            return True

    def metric_disabled_intervals(self, server_id: str, since: float, until: float) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("""SELECT disabled_at, enabled_at FROM manager_metric_pauses
                                WHERE server_id=? AND disabled_at < ?
                                AND (enabled_at IS NULL OR enabled_at > ?)
                                ORDER BY disabled_at""", (server_id, until, since)).fetchall()
        return [{"start": max(since, row["disabled_at"]),
                 "end": min(until, row["enabled_at"] if row["enabled_at"] is not None else until),
                 "ongoing": row["enabled_at"] is None} for row in rows]

    def prune_metric_pauses(self) -> None:
        with self.connect() as db:
            db.execute("DELETE FROM manager_metric_pauses WHERE enabled_at < ?", (time.time() - 86400,))

    def servers(self, active_only: bool = False) -> list[sqlite3.Row]:
        query = "SELECT * FROM servers WHERE state='active' ORDER BY name" if active_only else "SELECT * FROM servers ORDER BY name"
        with self.connect() as db:
            return db.execute(query).fetchall()

    def next_port(self, start: int, end: int) -> int:
        with self.connect() as db:
            used = {row[0] for row in db.execute("SELECT port FROM servers")}
        return next((port for port in range(start, end + 1) if port not in used), 0)

    def pending_prometheus_deletions(self) -> list[str]:
        with self.connect() as db:
            return [row[0] for row in db.execute("SELECT server_id FROM prometheus_deletions ORDER BY server_id")]

    def pending_prometheus_cleanup(self) -> dict | None:
        """Read the recovery identity committed atomically with claim removal."""
        with self.connect() as db:
            row = db.execute("SELECT operation_id, created_at FROM prometheus_deletions ORDER BY created_at LIMIT 1").fetchone()
        return {"id": row["operation_id"], "at": row["created_at"]} if row else None

    def finish_prometheus_deletions(self, identities: list[str]) -> None:
        with self.connect() as db:
            db.executemany("DELETE FROM prometheus_deletions WHERE server_id=?", [(identity,) for identity in identities])

    def offboard(self, server_id: str, *, managed_history: bool = False) -> None:
        """Irreversibly remove a target and its locally collected data.

        A later claim of the same BMC creates a new target ID and fresh history.
        Audit rows linked to the target are erased too; unrelated audit remains.
        """
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if managed_history:
                existing = db.execute("SELECT operation_id FROM prometheus_deletions ORDER BY created_at LIMIT 1").fetchone()
                identifier = existing[0] if existing else secrets.token_hex(16)
                db.execute("INSERT OR IGNORE INTO prometheus_deletions(server_id,created_at,operation_id) VALUES (?,?,?)",
                           (server_id, time.time(), identifier))
            db.execute("DELETE FROM servers WHERE id=?", (server_id,))
            db.execute("DELETE FROM event_cursors WHERE server_id=?", (server_id,))
            db.execute("DELETE FROM inventory_snapshots WHERE server_id=?", (server_id,))
            db.execute("DELETE FROM events WHERE server_id=?", (server_id,))
            db.execute("DELETE FROM manager_metric_pauses WHERE server_id=?", (server_id,))
            db.execute("DELETE FROM server_action_jobs WHERE server_id=?", (server_id,))
            db.execute("DELETE FROM audit WHERE subject=?", (server_id,))
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "metric_points" in tables:
                db.execute("DELETE FROM metric_points WHERE server_id=?", (server_id,))
            if "tracked_series" in tables:
                db.execute("DELETE FROM tracked_series WHERE server_id=?", (server_id,))
            if "metric_series" in tables:
                series_ids = {row[0] for row in db.execute("SELECT id FROM metric_series WHERE server_id=?", (server_id,))}
                db.execute("DELETE FROM metric_series WHERE server_id=?", (server_id,))
                if series_ids and "dashboard_widgets" in tables:
                    for widget in db.execute("SELECT id, series_json FROM dashboard_widgets"):
                        remaining = [item for item in json.loads(widget["series_json"]) if item not in series_ids]
                        if remaining:
                            db.execute("UPDATE dashboard_widgets SET series_json=? WHERE id=?",
                                       (json.dumps(remaining), widget["id"]))
                        else:
                            db.execute("DELETE FROM audit WHERE subject=?", (widget["id"],))
                            db.execute("DELETE FROM dashboard_widgets WHERE id=?", (widget["id"],))

    def setting(self, key: str, default: int) -> int:
        with self.connect() as db:
            row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return int(row["value"]) if row else default

    def set_setting(self, key: str, value: int) -> None:
        with self.connect() as db:
            db.execute("INSERT INTO settings (key, value) VALUES (?, ?) "
                       "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def set_settings(self, values: dict[str, int]) -> None:
        with self.connect() as db:
            db.executemany("INSERT INTO settings (key, value) VALUES (?, ?) "
                           "ON CONFLICT(key) DO UPDATE SET value=excluded.value", values.items())

    def inventory(self, server_id: str) -> dict[str, Any]:
        with self.connect() as db:
            row = db.execute("SELECT * FROM inventory_snapshots WHERE server_id=?", (server_id,)).fetchone()
        if not row:
            return {"snapshot": None, "last_success_at": None, "last_attempt_at": None,
                    "last_attempt_epoch": None, "state": "pending", "failures": [],
                    "interval_override": None, "revision": 0}
        result = dict(row)
        result["snapshot"] = json.loads(result.pop("snapshot_json")) if result["snapshot_json"] else None
        result["failures"] = json.loads(result.pop("failures_json"))
        return result

    def inventory_status(self, server_id: str) -> dict[str, Any]:
        """Read polling metadata without fetching or decoding the large snapshot."""
        with self.connect() as db:
            row = db.execute("SELECT last_success_at, last_attempt_at, last_attempt_epoch, "
                             "state, failures_json, interval_override, revision "
                             "FROM inventory_snapshots WHERE server_id=?", (server_id,)).fetchone()
        if not row:
            return {"last_success_at": None, "last_attempt_at": None,
                    "last_attempt_epoch": None, "state": "pending", "failures": [],
                    "interval_override": None, "revision": 0}
        result = dict(row)
        result["failures"] = json.loads(result.pop("failures_json"))
        return result

    def set_inventory_override(self, server_id: str, interval: int | None) -> bool:
        with self.connect() as db:
            if not db.execute("SELECT 1 FROM servers WHERE id=? AND state='active'", (server_id,)).fetchone():
                return False
            db.execute("INSERT INTO inventory_snapshots (server_id, interval_override) VALUES (?, ?) "
                       "ON CONFLICT(server_id) DO UPDATE SET interval_override=excluded.interval_override",
                       (server_id, interval))
        return True

    def inventory_attempt(self, server_id: str) -> None:
        with self.connect() as db:
            db.execute("INSERT INTO inventory_snapshots (server_id, last_attempt_at, last_attempt_epoch, state) "
                       "SELECT id, ?, ?, 'collecting' FROM servers WHERE id=? AND state='active' "
                       "ON CONFLICT(server_id) DO UPDATE SET "
                       "last_attempt_at=excluded.last_attempt_at, last_attempt_epoch=excluded.last_attempt_epoch, "
                       "state='collecting'", (datetime.now(timezone.utc).isoformat(), time.time(), server_id))

    def interrupt_inventory_jobs(self) -> None:
        """A collecting marker belongs to a worker that did not finish before restart."""
        with self.connect() as db:
            db.execute("UPDATE inventory_snapshots SET state='interrupted' WHERE state='collecting'")

    def inventory_result(self, server_id: str, collected: dict[str, Any] | None,
                         failures: list[dict[str, str]]) -> None:
        previous = self.inventory(server_id)
        old = previous["snapshot"] or {"categories": {}}
        prior_categories = old.get("categories") or {}
        new_categories = (collected or {}).get("categories") or {}
        if collected:
            for category in new_categories.values():
                for item in category.get("items", []):
                    item.setdefault("collected_at", collected["collected_at"])
        failed = {item["category"] for item in failures}
        failed_sources = {item["source"] for item in failures if item.get("source")}
        failed_subsystems = {item["source"] for item in failures
                             if item["category"] == "Subsystems" and item.get("source")}
        def beneath_failed_subsystem(item):
            return any(item["source"] == source or item["source"].startswith(source.rstrip("/") + "/")
                       for source in failed_subsystems)
        # Preserve only failed resources from a previous snapshot. Successful
        # categories still reflect removals rather than becoming immortal.
        merged = dict(new_categories)
        for category in failed:
            old_category = prior_categories.get(category)
            if not old_category:
                continue
            if category not in merged:
                if category == "Subsystems" and failed_subsystems:
                    retained = [item for item in old_category.get("items", []) if beneath_failed_subsystem(item)]
                    if retained:
                        merged[category] = {**old_category, "items": retained}
                else:
                    merged[category] = old_category
                continue
            current_items = merged[category]["items"]
            current_sources = {item["source"] for item in current_items}
            for item in old_category.get("items", []):
                if (item["source"] in failed_sources or
                        any(item["source"].startswith(source.rstrip("/") + "/") for source in failed_sources)):
                    if item["source"] not in current_sources:
                        current_items.append(item)
        if failed.intersection({"System", "Subsystems", "Chassis", "Management controllers"}):
            for category, old_category in prior_categories.items():
                if category not in merged:
                    if failed.intersection({"System", "Chassis", "Management controllers"}):
                        merged[category] = old_category
                    else:
                        retained = [item for item in old_category.get("items", []) if beneath_failed_subsystem(item)]
                        if retained:
                            merged[category] = {**old_category, "items": retained}
                    continue
                current_items = merged[category]["items"]
                current_sources = {item["source"] for item in current_items}
                for item in old_category.get("items", []):
                    if item["source"] not in current_sources and any(
                            item["source"].startswith(source.rstrip("/") + "/") for source in failed_sources):
                        current_items.append(item)
                        current_sources.add(item["source"])
        snapshot = dict(collected or old)
        snapshot["categories"] = merged or prior_categories
        state = "partial" if failures and new_categories else "failed" if failures else "complete"
        success_at = collected["collected_at"] if new_categories else previous["last_success_at"]
        with self.connect() as db:
            db.execute("UPDATE inventory_snapshots SET snapshot_json=?, last_success_at=?, state=?, failures_json=?, "
                       "revision=revision+1 "
                       "WHERE server_id=?", (json.dumps(snapshot) if snapshot["categories"] else None,
                       success_at, state, json.dumps(failures[:100]), server_id))

    def event_cursor(self, server_id: str) -> str | None:
        with self.connect() as db:
            row = db.execute("SELECT last_event_id FROM event_cursors WHERE server_id=?",
                             (server_id,)).fetchone()
        return row["last_event_id"] if row else None

    def update_event_cursor(self, server_id: str, last_event_id: str) -> None:
        if not last_event_id or len(last_event_id) > 256:
            return
        with self.connect() as db:
            db.execute("""INSERT INTO event_cursors (server_id, last_event_id)
                          SELECT id, ? FROM servers WHERE id=? AND state='active'
                          ON CONFLICT(server_id) DO UPDATE SET last_event_id=excluded.last_event_id""",
                       (last_event_id, server_id))

    def insert_event(self, *, server_id: str | None, source: str, source_entry_id: str,
                     occurred_at: str | None, severity: str | None, message_id: str | None,
                     message: str, raw: dict[str, Any]) -> None:
        observed = datetime.now(timezone.utc).isoformat()
        quality = "unknown"
        if occurred_at:
            try:
                event_time = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
                if event_time.tzinfo and 2020 <= event_time.year <= datetime.now(timezone.utc).year and event_time.timestamp() <= time.time() + 86400:
                    quality = "plausible"
                else:
                    quality = "implausible"
            except ValueError:
                quality = "implausible"
        with self.connect() as db:
            if server_id is not None:
                db.execute("BEGIN IMMEDIATE")
                if not db.execute("SELECT 1 FROM servers WHERE id=? AND state='active'",
                                  (server_id,)).fetchone():
                    return
            db.execute("""INSERT OR IGNORE INTO events
                (server_id, source, source_entry_id, occurred_at, observed_at, time_quality,
                 severity, message_id, message, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                       (server_id, source[:240], source_entry_id[:240], occurred_at, observed, quality,
                        (severity or "Unknown")[:40], (message_id or "")[:160], message[:4096],
                        json.dumps(raw, ensure_ascii=False)[:16000]))

    def events(self, server_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as db:
            if server_id:
                rows = db.execute("SELECT * FROM events WHERE server_id=? ORDER BY observed_at DESC LIMIT ?",
                                  (server_id, limit)).fetchall()
            else:
                rows = db.execute("SELECT * FROM events ORDER BY observed_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def audit(self, user_id: str | None, action: str, subject: str | None) -> None:
        with self.connect() as db:
            db.execute("INSERT INTO audit (occurred_at,user_id,action,subject) VALUES (?,?,?,?)",
                       (datetime.now(timezone.utc).isoformat(), user_id, action, subject))

    def create_action_job(self, server_id: str, operation: str, entries_uri: str | None = None,
                          entries_before: list[str] | None = None) -> dict[str, Any] | None:
        """Reserve one in-flight action per target before sending a BMC POST."""
        job_id = secrets.token_hex(16)
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("""DELETE FROM server_action_jobs WHERE state NOT IN ('sending','submitted','running')
                         AND created_at < ?""",
                       ((datetime.now(timezone.utc) - timedelta(days=7)).isoformat(),))
            if not db.execute("SELECT 1 FROM servers WHERE id=? AND state='active'", (server_id,)).fetchone():
                return None
            if db.execute("""SELECT 1 FROM server_action_jobs WHERE server_id=?
                             AND state IN ('sending','submitted','running')""", (server_id,)).fetchone():
                raise ValueError("Another server action is still in progress")
            db.execute("""INSERT INTO server_action_jobs
                (id,server_id,operation,state,created_at,updated_at,entries_uri,entries_before_json)
                VALUES (?,?,?,?,?,?,?,?)""", (job_id, server_id, operation, "sending", now, now, entries_uri,
                                             json.dumps(entries_before or [])))
        return self.action_job(job_id)

    def action_job(self, job_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM server_action_jobs WHERE id=?", (job_id,)).fetchone()
        return dict(row) if row else None

    def action_jobs(self, server_id: str, limit: int = 20) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("""SELECT * FROM server_action_jobs WHERE server_id=?
                                 ORDER BY created_at DESC LIMIT ?""", (server_id, limit)).fetchall()
        return [dict(row) for row in rows]

    def pending_action_jobs(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("""SELECT * FROM server_action_jobs
                                 WHERE state IN ('sending','submitted','running')""").fetchall()
        return [dict(row) for row in rows]

    def update_action_job(self, job_id: str, state: str, *, task_uri: str | None = None,
                          entry_uri: str | None = None, attachment_uri: str | None = None,
                          error: str | None = None) -> None:
        if state not in {"submitted", "running", "completed", "ready", "failed", "uncertain", "accepted"}:
            raise ValueError("Invalid server action state")
        with self.connect() as db:
            db.execute("""UPDATE server_action_jobs SET state=?, updated_at=?,
                task_uri=COALESCE(?,task_uri), entry_uri=COALESCE(?,entry_uri),
                attachment_uri=COALESCE(?,attachment_uri), error=? WHERE id=?""",
                       (state, datetime.now(timezone.utc).isoformat(), task_uri, entry_uri,
                        attachment_uri, error, job_id))
