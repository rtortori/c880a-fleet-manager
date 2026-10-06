"""Small, cross-platform, on-demand resource sample for the manager UI."""

from __future__ import annotations

from datetime import datetime, timezone
import os
import threading
import time
from typing import Any

try:
    import psutil
except ImportError:  # A source checkout may not have installed project dependencies yet.
    psutil = None


class ResourceSampler:
    """Cache one sample for all viewers; never inspect process arguments or users."""

    def __init__(self, *, minimum_interval: float = 5.0) -> None:
        self.minimum_interval = minimum_interval
        self.lock = threading.Lock()
        self.last_monotonic: float | None = None
        self.last_process_times: dict[tuple[int, float], float] = {}
        self.cached: dict[str, Any] = {"available": False}

    def sample(self) -> dict[str, Any]:
        if psutil is None:
            return {"available": False}
        with self.lock:
            now = time.monotonic()
            if self.last_monotonic is not None and now - self.last_monotonic < self.minimum_interval:
                return dict(self.cached)
            try:
                # The first nonblocking CPU read only establishes a baseline.
                host_cpu = psutil.cpu_percent(interval=None)
                memory = psutil.virtual_memory()
                parent = psutil.Process(os.getpid())
                try:
                    processes = [parent, *parent.children(recursive=True)]
                    process_scope = "manager_and_children"
                except (OSError, psutil.Error):
                    # Restricted hosts may hide the process table; own-process
                    # figures remain useful, but must not be labeled aggregate.
                    processes = [parent]
                    process_scope = "manager_only"
                process_times: dict[tuple[int, float], float] = {}
                process_rss = 0
                incomplete_processes = False
                for process in processes:
                    try:
                        with process.oneshot():
                            key = (process.pid, process.create_time())
                            cpu = process.cpu_times()
                            process_times[key] = cpu.user + cpu.system
                            process_rss += process.memory_info().rss
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        incomplete_processes = True
                        continue
                if not process_times:
                    raise RuntimeError("Manager process unavailable")
                if incomplete_processes and process_scope == "manager_and_children":
                    process_scope = "accessible_children"
                elapsed = now - self.last_monotonic if self.last_monotonic is not None else 0
                cpu_delta = sum(max(0.0, used - self.last_process_times[key])
                                for key, used in process_times.items()
                                if key in self.last_process_times)
                count = psutil.cpu_count(logical=True) or 1
                process_cpu = min(100.0, cpu_delta / elapsed / count * 100) if elapsed > 0 else None
                self.cached = {
                    "available": True,
                    "sampled_at": datetime.now(timezone.utc).isoformat(),
                    "host": {
                        "cpu_percent": round(host_cpu, 1) if elapsed > 0 else None,
                        "memory_percent": round(memory.percent, 1),
                        "memory_used_bytes": memory.total - memory.available,
                        "memory_total_bytes": memory.total,
                    },
                    "app": {
                        "cpu_percent_of_host": round(process_cpu, 1) if process_cpu is not None else None,
                        "rss_bytes": process_rss,
                        "process_count": len(process_times),
                        "scope": process_scope,
                    },
                }
                self.last_monotonic = now
                self.last_process_times = process_times
            except (OSError, RuntimeError, ValueError, psutil.Error):
                self.cached = {"available": False}
                self.last_monotonic = now
            return dict(self.cached)
