"""Bounded, read-only Redfish access for a single BMC."""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
from http.client import HTTPException
import httpx
import json
import ipaddress
import math
import re
import ssl
import threading
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

from .redfish_budget import BudgetUnavailable, SharedGetBudget


class RedfishError(Exception):
    pass


class RedfishAuthenticationError(RedfishError):
    """The BMC rejected credentials; never include them in this exception."""


class RedfishTimeoutError(RedfishError):
    """A bounded BMC read timed out; do not expose its URL or credentials."""


class RedfishUnavailableError(RedfishError):
    """A transient BMC gateway/service failure on an idempotent GET."""


class RedfishHTTPError(RedfishError):
    """Structured status for bounded recovery; no response body or URL."""

    def __init__(self, status: int, retry_after: float | None = None) -> None:
        super().__init__(f"BMC read failed: HTTP {status}")
        self.status = status
        self.retry_after = retry_after


class RedfishCertificateError(RedfishError):
    """Certificate failures stop recovery rather than retrying without trust."""


class RedfishTransportError(RedfishError):
    """An idempotent read can be retried within its observation budget."""


def _retry_after(value: str | None) -> float | None:
    try:
        seconds = float(value) if value is not None else None
        if seconds is None:
            return None
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
            if parsed.tzinfo is None:
                return None
            seconds = parsed.timestamp() - time.time()
        except (ValueError, TypeError, OverflowError):
            return None
    return min(3600.0, max(0.0, seconds)) if math.isfinite(seconds) else None


def _certificate_failure(error: BaseException) -> bool:
    seen = set()
    pending = [error]
    while pending and len(seen) < 64:
        error = pending.pop()
        if not isinstance(error, BaseException) or id(error) in seen:
            continue
        seen.add(id(error))
        if isinstance(error, ssl.SSLCertVerificationError):
            return True
        pending.extend((getattr(error, "reason", None), error.__cause__, error.__context__))
    return False


EXCLUDED_PORT_REPORT_IDS = frozenset({
    "HGX_NVSwitchPortMetrics_0", "HGX_NetworkAdapterPortMetrics_0",
    "HGX_ProcessorPortGPMMetrics_0", "HGX_ProcessorPortMetrics_0",
})
EXCLUDED_UNAVAILABLE_REPORT_IDS = frozenset({
    # Operator-approved exact exclusion: the tested BMC advertises this report
    # but both its report and definition return HTTP 500. The saved pre-R18
    # exposition contains no values from it; never generalize this by prefix.
    "NvidiaNMMetrics_0",
})


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise RedfishError("Redfish redirects are disabled")


class RedfishClient:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        port: int = 443,
        ca_file: str | None = None,
        insecure: bool = False,
        timeout: float = 10,
        persistent_gets: bool = False,
        max_get_connections: int = 4,
        system_reader: Callable[[str, float], tuple[dict[str, Any], float]] | None = None,
        shared_get_budget: SharedGetBudget | None = None,
        budget_priority: int = 1,
        onboarding_get_retries: int = 0,
    ) -> None:
        if not (re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host) or self._ipv6(host)):
            raise ValueError("BMC host must be a hostname or IP address")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("BMC port must be between 1 and 65535")
        if not 1 <= max_get_connections <= 4:
            raise ValueError("BMC GET connection limit must be between 1 and 4")
        if budget_priority not in (0, 1, 2, 3):
            raise ValueError("Invalid Redfish GET priority")
        if not 0 <= onboarding_get_retries <= 3:
            raise ValueError("Onboarding GET retries must be between 0 and 3")
        authority = f"[{host}]" if ":" in host else host
        self.base = f"https://{authority}" + (f":{port}" if port != 443 else "")
        self.username = username
        self.password = password
        self.timeout = timeout
        # Manager-only observation sharing; action checks never use this hook.
        self.system_reader = system_reader
        self.shared_get_budget = shared_get_budget
        self.budget_priority = budget_priority
        self.onboarding_get_retries = onboarding_get_retries
        if insecure:
            context = ssl._create_unverified_context()
        else:
            context = ssl.create_default_context(cafile=ca_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._opener = build_opener(_NoRedirect(), HTTPSHandler(context=context))
        self._get_client = (httpx.Client(
            verify=context, auth=httpx.BasicAuth(username, password), trust_env=False,
            follow_redirects=False, http2=False,
            limits=httpx.Limits(max_connections=max_get_connections,
                                max_keepalive_connections=max_get_connections,
                                keepalive_expiry=120),
        ) if persistent_gets else None)
        self._get_stats_lock = threading.Lock()
        # One bound applies across expanded pages, fallback members, and any
        # concurrent exporter stages, including the legacy HTTPS transport.
        self._get_slots = threading.BoundedSemaphore(max_get_connections)
        self._get_stats: dict[str, dict[str, float]] = {}
        self._get_inflight = 0
        self._get_peak_inflight = 0
        self._sensor_page_attempts = 0
        self._sensor_page_fallbacks = 0

    @staticmethod
    def _get_resource_class(path: str) -> str:
        """Use fixed labels; never expose a BMC path or query in profiling data."""
        if path == "/redfish/v1":
            return "service_root"
        parts = path.strip("/").split("/")
        for segment, name in (("Sensors", "sensors"), ("MetricReports", "metric_reports")):
            if segment in parts:
                return name + ("_collection" if parts[-1] == segment else "_member")
        if parts[-1] in ("Systems", "Chassis", "Managers"):
            return "topology_collection"
        for segment in ("Processors", "Memory", "Storage", "NetworkInterfaces",
                        "PowerSupplies", "Volumes", "Drives"):
            if segment in parts:
                return "component_collection" if parts[-1] == segment else "component_member"
        if parts[-1] in ("Power", "Thermal", "PowerSubsystem", "ThermalSubsystem"):
            return "aggregate"
        if parts[-1] == "TelemetryService":
            return "telemetry_service"
        if len(parts) >= 4 and parts[2] in ("Systems", "Chassis", "Managers"):
            return "topology_member"
        return "other"

    def get_statistics(self) -> dict[str, Any]:
        """Return cumulative, bounded GET measurements without resource identifiers."""
        with self._get_stats_lock:
            return {"resources": {kind: values.copy() for kind, values in self._get_stats.items()},
                    "inflight": self._get_inflight, "peak_inflight": self._get_peak_inflight,
                    "sensor_page_attempts": self._sensor_page_attempts,
                    "sensor_page_fallbacks": self._sensor_page_fallbacks}

    def close(self) -> None:
        """Release persistent GET connections when this single-BMC client exits."""
        if self._get_client is not None:
            self._get_client.close()

    def read_system(self, uri: str, *, timeout: float) -> tuple[dict[str, Any], float]:
        if self.system_reader is not None:
            return self.system_reader(uri, timeout)
        payload = self.get(uri, timeout=timeout)
        return payload, time.time()

    @staticmethod
    def _ipv6(host: str) -> bool:
        try:
            return isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address)
        except ValueError:
            return False

    def checked_url(self, uri: str) -> str:
        """Resolve only same-BMC Redfish paths; redirects remain disabled."""
        try:
            url = urljoin(self.base, uri)
            parsed = urlsplit(url)
        except ValueError as exc:
            raise RedfishError("Redfish link is malformed") from exc
        if (not self._same_origin(parsed)
                or not (parsed.path == "/redfish/v1" or parsed.path.startswith("/redfish/v1/"))
                or parsed.fragment):
            raise RedfishError("Redfish link leaves the configured BMC service")
        return url

    def _same_origin(self, parsed) -> bool:
        base = urlsplit(self.base)
        try:
            return (parsed.scheme == "https" and parsed.username is None and parsed.password is None
                    and parsed.hostname == base.hostname
                    and (443 if parsed.port is None else parsed.port) ==
                    (443 if base.port is None else base.port))
        except ValueError:  # Malformed port in an untrusted Redfish link.
            return False

    def get(self, uri: str, *, timeout: float | None = None,
            deadline: float | None = None) -> dict[str, Any]:
        if deadline is not None and (type(deadline) not in (int, float) or not math.isfinite(deadline)):
            raise ValueError("Invalid Redfish GET deadline")
        # Validation tolerates brief BMC service outages. Exporter reads keep
        # their existing single-attempt behavior and scraping cadence.
        for attempt in range(self.onboarding_get_retries + 1):
            try:
                return self._get_once(uri, timeout=timeout, deadline=deadline)
            except RedfishUnavailableError:
                if attempt == self.onboarding_get_retries:
                    raise
                delay = 2 ** attempt
                if deadline is not None and time.monotonic() + delay >= deadline:
                    raise
                time.sleep(delay)
        raise AssertionError("Unreachable Redfish retry state")

    def read_sensor(self, uri: str, *, timeout: float = 10,
                    priority: int | None = None) -> tuple[dict[str, Any], float, float]:
        """One read with a total budget including admission, and actual receipt times."""
        received = []
        if priority is not None and (type(priority) is not int or priority not in (1, 2)):
            raise ValueError("Invalid ordinary sensor priority")
        payload = self._get_once(uri, timeout=timeout, deadline=time.monotonic() + timeout,
                                 observed=received, priority=priority)
        return payload, *received[0]

    def _get_once(self, uri: str, *, timeout: float | None = None,
                  deadline: float | None = None, observed: list | None = None,
                  priority: int | None = None) -> dict[str, Any]:
        url = self.checked_url(uri)
        parsed = urlsplit(url)
        resource_class = self._get_resource_class(parsed.path)
        request_timeout = self.timeout if timeout is None else timeout
        if not 0 < request_timeout <= 120:
            raise ValueError("Redfish GET timeout must be between 0 and 120 seconds")
        queued_at = time.monotonic()
        ticket = None
        slot_acquired = False
        try:
            # Managed priority must be resolved before a connection waiter
            # can hide an urgent reader behind optional, lower-priority work.
            # The shared lease still bounds every managed GET, including the
            # local connection wait. Standalone clients retain their cap.
            if self.shared_get_budget is not None:
                options = ({"wait_timeout": min(self.shared_get_budget.wait_limit,
                            max(0.001, deadline - time.monotonic()))} if deadline is not None else {})
                ticket = self.shared_get_budget.acquire(
                    hashlib.sha256(parsed.netloc.lower().encode("ascii")).hexdigest(),
                    priority=self.budget_priority if priority is None else priority,
                    request_timeout=request_timeout, **options)
            if deadline is None:
                slot_acquired = self._get_slots.acquire()
            else:
                slot_acquired = self._get_slots.acquire(timeout=max(0.0, deadline - time.monotonic()))
            if not slot_acquired:
                raise RedfishTimeoutError("BMC read admission timed out")
        except BaseException as exc:
            if ticket is not None and self.shared_get_budget is not None:
                try:
                    release_options = ({"wait_timeout": min(3, max(.001, deadline - time.monotonic()))}
                                       if deadline is not None else {})
                    self.shared_get_budget.release(ticket, **release_options)
                except BudgetUnavailable:
                    pass  # The failed-closed lease expires without an HTTP GET.
            if slot_acquired:
                self._get_slots.release()
            if isinstance(exc, BudgetUnavailable):
                raise RedfishTransportError("Redfish request budget is unavailable") from exc
            raise
        queue_wait = time.monotonic() - queued_at
        with self._get_stats_lock:
            self._get_inflight += 1
            self._get_peak_inflight = max(self._get_peak_inflight, self._get_inflight)
        started = time.monotonic()
        total_deadline = deadline if deadline is not None else started + min(150.0, max(30.0, request_timeout + 30.0))
        response_bytes = 0
        succeeded = False
        try:
            if deadline is not None:
                request_timeout = min(request_timeout, deadline - started)
                if request_timeout <= 0:
                    raise RedfishTimeoutError("BMC read admission timed out")
            if self._get_client is not None:
                try:
                    with self._get_client.stream(
                        "GET", url, headers={"Accept": "application/json"},
                        timeout=request_timeout,
                    ) as response:
                        if not 200 <= response.status_code < 300:
                            if response.status_code in (401, 403):
                                raise RedfishAuthenticationError("BMC authentication failed")
                            if response.status_code in (502, 503, 504):
                                raise RedfishUnavailableError(
                                    f"GET {resource_class} failed: HTTP {response.status_code}")
                            raise RedfishHTTPError(response.status_code,
                                                   _retry_after(response.headers.get("Retry-After")))
                        chunks = []
                        for chunk in response.iter_bytes():
                            if time.monotonic() > total_deadline:
                                raise RedfishTimeoutError("Redfish GET exceeded total time budget")
                            response_bytes += len(chunk)
                            if response_bytes > 2_000_000:
                                raise RedfishError("Redfish response exceeds 2 MB")
                            chunks.append(chunk)
                    payload = json.loads(b"".join(chunks))
                    if not isinstance(payload, dict):
                        raise RedfishError("Redfish response must be an object")
                    if deadline is not None and time.monotonic() > deadline:
                        raise RedfishTimeoutError("BMC read exceeded its observation budget")
                    succeeded = True
                    if observed is not None:
                        observed.append((time.time(), time.monotonic()))
                    return payload
                except httpx.HTTPError as exc:
                    # Never surface a URL/query or credentials from an HTTP
                    # library exception in manager diagnostics or metrics.
                    if isinstance(exc, httpx.TimeoutException):
                        raise RedfishTimeoutError("BMC read timed out") from exc
                    if _certificate_failure(exc):
                        raise RedfishCertificateError("BMC certificate verification failed") from exc
                    raise RedfishTransportError("BMC read connection failed") from exc
            token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode("ascii")
            request = Request(url, headers={"Authorization": f"Basic {token}", "Accept": "application/json"}, method="GET")
            with self._opener.open(request, timeout=request_timeout) as response:
                chunks = []
                while True:
                    if time.monotonic() > total_deadline:
                        raise RedfishTimeoutError("Redfish GET exceeded total time budget")
                    chunk = response.read(min(64 * 1024, 2_000_001 - response_bytes))
                    if not chunk:
                        break
                    response_bytes += len(chunk)
                    if response_bytes > 2_000_000:
                        raise RedfishError("Redfish response exceeds 2 MB")
                    chunks.append(chunk)
                raw = b"".join(chunks)
                payload = json.loads(raw)
                if not isinstance(payload, dict):
                    raise RedfishError("Redfish response must be an object")
                if deadline is not None and time.monotonic() > deadline:
                    raise RedfishTimeoutError("BMC read exceeded its observation budget")
                succeeded = True
                if observed is not None:
                    observed.append((time.time(), time.monotonic()))
                return payload
        except (HTTPError, URLError, TimeoutError, OSError, HTTPException, json.JSONDecodeError) as exc:
            status = getattr(exc, "code", None)
            if status in (401, 403):
                raise RedfishAuthenticationError("BMC authentication failed") from exc
            if status in (502, 503, 504):
                raise RedfishUnavailableError(f"GET {resource_class} failed: HTTP {status}") from exc
            if isinstance(exc, TimeoutError) or (
                isinstance(exc, URLError) and isinstance(exc.reason, TimeoutError)
            ):
                raise RedfishTimeoutError("BMC read timed out") from exc
            if isinstance(status, int):
                raise RedfishHTTPError(status, _retry_after(exc.headers.get("Retry-After"))) from exc
            if _certificate_failure(exc):
                raise RedfishCertificateError("BMC certificate verification failed") from exc
            if isinstance(exc, (URLError, OSError, HTTPException)):
                raise RedfishTransportError("BMC read connection failed") from exc
            detail = f": HTTP {status}" if isinstance(status, int) else ""
            raise RedfishError(f"GET {resource_class} failed: {type(exc).__name__}{detail}") from exc
        finally:
            elapsed = time.monotonic() - started
            with self._get_stats_lock:
                self._get_inflight -= 1
                values = self._get_stats.setdefault(resource_class, {
                    "requests": 0, "errors": 0, "duration_seconds": 0.0,
                    "queue_wait_seconds": 0.0, "response_bytes": 0})
                values["requests"] += 1
                values["errors"] += int(not succeeded)
                values["duration_seconds"] += elapsed
                values["queue_wait_seconds"] += queue_wait
                values["response_bytes"] += response_bytes
            try:
                if ticket is not None and self.shared_get_budget is not None:
                    try:
                        release_options = ({"wait_timeout": min(3, max(.001, deadline - time.monotonic()))}
                                           if deadline is not None else {})
                        self.shared_get_budget.release(ticket, **release_options)
                    except BudgetUnavailable as exc:
                        raise RedfishTransportError("Redfish GET lost its shared admission lease") from exc
            finally:
                self._get_slots.release()

    def post_action(self, uri: str, payload: dict[str, str]) -> tuple[int, dict[str, Any], str | None]:
        """Send one already-allowlisted action; never retry an uncertain POST."""
        url = self.checked_url(uri)
        if not isinstance(payload, dict) or any(not isinstance(key, str) or not isinstance(value, str)
                                               for key, value in payload.items()):
            raise RedfishError("Invalid Redfish action payload")
        body = json.dumps(payload, separators=(",", ":")).encode()
        if len(body) > 4096:
            raise RedfishError("Redfish action payload exceeds limit")
        token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode("ascii")
        request = Request(url, data=body, method="POST", headers={
            "Authorization": f"Basic {token}", "Accept": "application/json",
            "Content-Type": "application/json"})
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                raw = response.read(2_000_001)
                if len(raw) > 2_000_000:
                    raise RedfishError("Redfish action response exceeds 2 MB")
                result = json.loads(raw) if raw else {}
                if not isinstance(result, dict):
                    raise RedfishError("Redfish action response must be an object")
                location = response.headers.get("Location")
                if location:
                    self.checked_url(location)
                return response.status, result, location
        except (HTTPError, URLError, TimeoutError, OSError, HTTPException, json.JSONDecodeError) as exc:
            raise RedfishError(f"Action response uncertain or failed: {type(exc).__name__}: "
                               f"{getattr(exc, 'code', '')}; do not retry automatically") from exc

    def open_attachment(self, uri: str, *, max_bytes: int = 512 * 1024 * 1024):
        """Open a same-BMC attachment for bounded streaming; caller closes it."""
        url = self.checked_url(uri)
        token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode("ascii")
        request = Request(url, headers={"Authorization": f"Basic {token}",
                                        "Accept": "application/octet-stream"}, method="GET")
        try:
            response = self._opener.open(request, timeout=self.timeout)
            length = response.headers.get("Content-Length")
            if length and (not length.isdigit() or int(length) > max_bytes):
                response.close()
                raise RedfishError("Diagnostic attachment exceeds the download limit")
            return response
        except (HTTPError, URLError, TimeoutError, OSError, HTTPException) as exc:
            raise RedfishError(f"Diagnostic attachment unavailable: {type(exc).__name__}") from exc

    def open_event_stream(self, uri: str, *, event_only: bool, last_event_id: str | None = None,
                          timeout: float = 300):
        """Open a same-BMC, read-only SSE connection; the caller must close it."""
        try:
            url = urljoin(self.base, uri)
            parsed = urlsplit(url)
        except ValueError as exc:
            raise RedfishError("Event stream link is malformed") from exc
        if (not self._same_origin(parsed) or not parsed.path.startswith("/redfish/v1/")
                or parsed.fragment):
            raise RedfishError("Event stream link leaves the configured BMC service")
        if event_only:
            query = parsed.query + ("&" if parsed.query else "") + "$filter=EventFormatType%20eq%20Event"
            url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))
        token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode("ascii")
        headers = {"Authorization": f"Basic {token}", "Accept": "text/event-stream"}
        if last_event_id and len(last_event_id) <= 256 and not any(char in last_event_id for char in "\r\n\x00"):
            headers["Last-Event-ID"] = last_event_id
        try:
            response = self._opener.open(Request(url, headers=headers, method="GET"), timeout=timeout)
            if response.headers.get_content_type() != "text/event-stream":
                response.close()
                raise RedfishError("Event stream did not return text/event-stream")
            return response
        except (HTTPError, URLError, TimeoutError, OSError, HTTPException) as exc:
            raise RedfishError(f"Event stream failed: {type(exc).__name__}: {getattr(exc, 'code', '')}") from exc

    def members(self, uri: str, *, max_pages: int = 12, max_members: int = 3000,
                warnings: list[str] | None = None) -> list[dict[str, Any]]:
        """Deduplicate pages; opt-in partial results flag broken BMC pagination."""
        next_uri: str | None = uri
        seen_pages: set[str] = set()
        members: dict[str, dict[str, Any]] = {}
        expected: int | None = None
        while next_uri and len(seen_pages) < max_pages:
            if next_uri in seen_pages:
                if expected is not None and len(members) >= expected:
                    next_uri = None
                    break
                if warnings is not None and members:
                    warnings.append("Repeated Redfish pagination link; collection may be incomplete")
                    next_uri = None
                    break
                raise RedfishError("Redfish pagination cycle")
            seen_pages.add(next_uri)
            page = self.get(next_uri)
            page_members = page.get("Members")
            if not isinstance(page_members, list):
                raise RedfishError("Redfish collection has no Members array")
            count = page.get("Members@odata.count")
            if isinstance(count, int) and not isinstance(count, bool) and 0 <= count <= max_members:
                expected = count
            for item in page_members:
                if isinstance(item, dict) and isinstance(item.get("@odata.id"), str):
                    members[item["@odata.id"]] = item
                    if len(members) > max_members:
                        raise RedfishError("Redfish collection exceeds configured limit")
            next_uri = page.get("Members@odata.nextLink") or page.get("@odata.nextLink")
            if expected is not None and len(members) >= expected:
                next_uri = None
        if next_uri:
            raise RedfishError("Redfish collection exceeded page limit")
        return list(members.values())

    def discover(self, *, metrics_only: bool = False,
                 progress: Callable[[str], None] | None = None) -> dict[str, Any]:
        if progress:
            progress("Connecting to BMC and checking credentials…")
        root = self.get("/redfish/v1")
        if progress:
            progress("Reading system and chassis endpoints…")
        discovered: dict[str, Any] = {"redfish_version": root.get("RedfishVersion"), "resources": {}, "warnings": []}
        # Full onboarding inspects optional inventory and event capabilities;
        # every metrics scrape needs only the paths feeding metric samples.
        collections = ("Systems", "Chassis") if metrics_only else ("Systems", "Chassis", "Managers")
        for collection in collections:
            link = (root.get(collection) or {}).get("@odata.id")
            if not link:
                raise RedfishError(f"Missing required {collection} link")
            collection_warnings: list[str] = []
            discovered["resources"][collection.lower()] = [m["@odata.id"] for m in self.members(link, warnings=collection_warnings)]
            discovered["warnings"].extend(f"{collection}: {warning}" for warning in collection_warnings)
        systems = discovered["resources"]["systems"]
        chassis = discovered["resources"]["chassis"]
        system_uri = next((u for u in systems if u.rsplit("/", 1)[-1] == "DGX"), systems[0] if systems else None)
        chassis_uri = next((u for u in chassis if u.rsplit("/", 1)[-1] == "DGX"), chassis[0] if chassis else None)
        if not system_uri or not chassis_uri:
            raise RedfishError("No system or chassis member was found")
        system = self.get(system_uri)
        system_observed_at = time.time()
        main_chassis = self.get(chassis_uri)
        sensor_uri = (main_chassis.get("Sensors") or {}).get("@odata.id")
        if not sensor_uri:
            raise RedfishError("Main chassis has no Sensors link")
        sensor_count = None
        if not metrics_only:
            if progress:
                progress("Checking sensor collection…")
            sensor_page = self.get(sensor_uri)
            if "Members" not in sensor_page:
                raise RedfishError("Sensor collection is unreadable")
            sensor_count = sensor_page.get("Members@odata.count")
        discovered.update({"system_uri": system_uri, "chassis_uri": chassis_uri, "sensor_uri": sensor_uri,
                           "model": system.get("Model"), "manufacturer": system.get("Manufacturer"),
                           "serial_number": system.get("SerialNumber"), "bios_version": system.get("BiosVersion"),
                           "system_status": system.get("Status"),
                           "system_power_state": system.get("PowerState"),
                           "system_observed_at": system_observed_at,
                           "memory_summary": system.get("MemorySummary"),
                           "processor_summary": system.get("ProcessorSummary"),
                           "sensor_count": sensor_count,
                           "checked_at": datetime.now(timezone.utc).isoformat()})
        def resource_link(resource: dict[str, Any], name: str) -> str | None:
            value = resource.get(name)
            if not isinstance(value, dict):
                return None
            link = value.get("@odata.id")
            return link if isinstance(link, str) else None

        discovered["component_links"] = {
            name: resource_link(resource, name)
            for resource, names in ((system, ("Processors", "Memory", "Storage", "NetworkInterfaces")),
                                    (main_chassis, ("Power", "PowerSubsystem")))
            for name in names
        }
        if "880A" not in str(system.get("Model", "")).upper():
            raise RedfishError("System model does not identify a C880A")
        if progress:
            progress("Checking optional Redfish capabilities…")
        telemetry_ref = root.get("TelemetryService")
        telemetry_uri = telemetry_ref.get("@odata.id") if isinstance(telemetry_ref, dict) else None
        if isinstance(telemetry_uri, str):
            try:
                telemetry = self.get(telemetry_uri)
                report_link = telemetry.get("MetricReports")
                if isinstance(report_link, dict) and isinstance(report_link.get("@odata.id"), str):
                    discovered["telemetry_reports_uri"] = report_link["@odata.id"]
            except RedfishError:
                discovered["warnings"].append("TelemetryService did not respond")
        if metrics_only:
            return discovered
        log_collections = []
        for uri in [*systems, chassis_uri, *discovered["resources"]["managers"]]:
            try:
                resource = system if uri == system_uri else main_chassis if uri == chassis_uri else self.get(uri)
                link = (resource.get("LogServices") or {}).get("@odata.id")
                if link:
                    log_collections.append(link)
            except RedfishError:
                discovered["warnings"].append(f"Could not inspect {uri}")
        discovered["log_collections"] = log_collections
        for name in ("PowerSubsystem",):
            link = (main_chassis.get(name) or {}).get("@odata.id")
            if link:
                try:
                    self.get(link)
                    discovered["resources"][name.lower()] = link
                except RedfishError:
                    discovered["warnings"].append(f"{name} endpoint did not respond; child collections may still work")
        # This platform's parent ThermalSubsystem may return HTTP 500 even while
        # its legacy Thermal resource and sensor collection are usable.
        thermal_uri = resource_link(main_chassis, "Thermal")
        if thermal_uri:
            try:
                thermal = self.get(thermal_uri)
                discovered["resources"]["thermal"] = thermal_uri
                discovered["thermal_counts"] = {
                    "temperatures": len(thermal.get("Temperatures", [])) if isinstance(thermal.get("Temperatures"), list) else None,
                    "fans": len(thermal.get("Fans", [])) if isinstance(thermal.get("Fans"), list) else None,
                }
            except RedfishError:
                pass
        manager_uri = next((u for u in discovered["resources"]["managers"]
                            if u.rsplit("/", 1)[-1] == "BMC"), None)
        if manager_uri:
            try:
                discovered["firmware_version"] = self.get(manager_uri).get("FirmwareVersion")
            except RedfishError:
                pass
        discovered["events_sse"] = False
        event_ref = root.get("EventService")
        event_uri = event_ref.get("@odata.id") if isinstance(event_ref, dict) else None
        if event_uri:
            try:
                event = self.get(event_uri)
                stream_uri = event.get("ServerSentEventUri")
                discovered["events_sse"] = bool(event.get("ServiceEnabled", True) and
                                                isinstance(stream_uri, str) and stream_uri)
                if discovered["events_sse"]:
                    discovered["events_sse_uri"] = stream_uri
                    filters = event.get("SSEFilterPropertiesSupported")
                    if not isinstance(filters, dict):
                        filters = {}
                    discovered["events_sse_event_filter"] = bool(filters.get("EventFormatType"))
            except RedfishError:
                discovered["warnings"].append("EventService did not respond")
        return discovered

    def live_metrics(self, discovered: dict[str, Any]) -> dict[str, Any]:
        """Read only the already-discovered system, power, and thermal resources."""
        result: dict[str, Any] = {"errors": []}
        resources = discovered.get("resources") or {}
        links = discovered.get("component_links") or {}

        def finite_number(value: Any) -> float | None:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return None
            try:
                number = float(value)
            except OverflowError:
                return None
            return number if math.isfinite(number) else None

        system_uri = discovered.get("system_uri")
        if isinstance(system_uri, str):
            try:
                system, observed_at = self.read_system(system_uri, timeout=10)
                result["system"] = {"power_state": system.get("PowerState"), "fetched_at": observed_at}
            except RedfishError:
                result["errors"].append("System power state unavailable")

        power_uri = links.get("Power")
        chassis_uri = discovered.get("chassis_uri")
        thermal_uri = resources.get("thermal") or (
            chassis_uri.rstrip("/") + "/Thermal" if isinstance(chassis_uri, str) else None)

        # Keep the sometimes-fragile System GET alone. Power and Thermal are
        # independent, so overlap only these two bounded, read-only requests.
        def read_observed(uri: str) -> tuple[dict[str, Any], float]:
            payload = self.get(uri, timeout=10)
            return payload, time.time()

        with ThreadPoolExecutor(max_workers=2) as pool:
            power_future = pool.submit(read_observed, power_uri) if isinstance(power_uri, str) else None
            thermal_future = pool.submit(read_observed, thermal_uri) if isinstance(thermal_uri, str) else None

            if power_future is not None:
                try:
                    power, power_at = power_future.result()
                    controls = power.get("PowerControl")
                    control = next((item for item in controls if isinstance(item, dict)), None) if isinstance(controls, list) else None
                    if control:
                        metrics = control.get("PowerMetrics")
                        if not isinstance(metrics, dict):
                            metrics = {}
                        result["power"] = {
                            "current_watts": finite_number(control.get("PowerConsumedWatts")),
                            "average_watts": finite_number(metrics.get("AverageConsumedWatts")),
                            "minimum_watts": finite_number(metrics.get("MinConsumedWatts")),
                            "maximum_watts": finite_number(metrics.get("MaxConsumedWatts")),
                            "fetched_at": power_at,
                        }
                    else:
                        result["errors"].append("Chassis power reading unavailable")
                except RedfishError:
                    result["errors"].append("Chassis power resource unavailable")
            else:
                result["errors"].append("Chassis power resource not advertised")

            if thermal_future is None:
                result["errors"].append("Chassis thermal resource not advertised")
                return result
            try:
                thermal, thermal_at = thermal_future.result()
            except RedfishError:
                result["errors"].append("Chassis thermal resource unavailable")
                return result
            readings = thermal.get("Temperatures")
            items = []
            if isinstance(readings, list):
                for item in readings[:256]:
                    if not isinstance(item, dict):
                        continue
                    reading = finite_number(item.get("ReadingCelsius"))
                    if reading is None:
                        continue
                    items.append({"id": str(item.get("MemberId") or item.get("@odata.id") or
                                             item.get("Name") or "")[:160],
                                  "name": str(item.get("Name") or "Temperature")[:160],
                                  "celsius": reading})
            result["temperatures"] = {"items": items, "fetched_at": thermal_at}
        return result

    def detail_snapshot(self, discovered: dict[str, Any]) -> dict[str, Any]:
        """Small General-view snapshot; detailed thermal readings belong to Metrics."""
        resources = discovered.get("resources") or {}
        system_uri = discovered.get("system_uri")
        chassis_uri = discovered.get("chassis_uri")
        manager_uris = resources.get("managers") or []
        manager_uri = next((u for u in manager_uris if isinstance(u, str) and u.rsplit("/", 1)[-1] == "BMC"), None)
        targets = {"system": system_uri, "chassis": chassis_uri, "manager": manager_uri}
        result: dict[str, Any] = {"sources": {}, "source_observed_at": {}, "unavailable": []}
        def record(kind: str, uri: str, payload: dict[str, Any], observed_at: float | None = None) -> None:
            result["sources"][kind] = uri
            result["source_observed_at"][kind] = observed_at if observed_at is not None else time.time()
            if kind == "system":
                result[kind] = {key: payload.get(key) for key in (
                    "Model", "Manufacturer", "SerialNumber", "UUID", "BiosVersion", "PowerState",
                    "Status", "MemorySummary", "ProcessorSummary", "AssetTag")}
            elif kind == "chassis":
                result[kind] = {key: payload.get(key) for key in ("Model", "PowerState", "Status")}
            elif kind == "manager":
                result[kind] = {key: payload.get(key) for key in ("FirmwareVersion", "Status")}

        # Prioritize the system read: this BMC sometimes fails it while serving
        # several concurrent requests. Its observed response time can also exceed
        # the normal 10-second polling timeout. Optional resources run afterward.
        if isinstance(system_uri, str):
            try:
                system, observed_at = self.read_system(system_uri, timeout=25)
                record("system", system_uri, system, observed_at)
            except RedfishError:
                try:
                    system, observed_at = self.read_system(system_uri, timeout=25)
                    record("system", system_uri, system, observed_at)
                except RedfishError:
                    result["unavailable"].append("system")
        else:
            result["unavailable"].append("system")

        with ThreadPoolExecutor(max_workers=3) as pool:
            pending = {kind: pool.submit(self.get, uri, timeout=25) for kind, uri in targets.items()
                       if kind != "system" and isinstance(uri, str)}
            for kind, uri in targets.items():
                if kind == "system":
                    continue
                if not isinstance(uri, str):
                    result["unavailable"].append(kind)
                    continue
                try:
                    record(kind, uri, pending[kind].result())
                except RedfishError:
                    result["unavailable"].append(kind)
        return result

    def telemetry_snapshot(self, reports_uri: str, *, max_reports: int = 32,
                           max_values: int = 20000, max_duration: float = 180,
                           report_workers: int = 1) -> tuple[list[dict[str, Any]], int]:
        """Read numeric values from advertised telemetry reports with hard size/time bounds."""
        if report_workers not in (1, 2, 4):
            raise ValueError("Telemetry report workers must be 1, 2, or 4")
        if max_reports < 1 or max_values < 1 or max_duration <= 0:
            raise ValueError("Telemetry report budget must be positive")
        warnings: list[str] = []
        references = self.members(reports_uri, max_pages=4, max_members=max_reports, warnings=warnings)
        # Exact operator-approved IDs: omit their BMC GETs, not merely their
        # Prometheus lines. All other reports stay in scope.
        references = [reference for reference in references
                      if urlsplit(reference["@odata.id"]).path.rsplit("/", 1)[-1]
                      not in EXCLUDED_PORT_REPORT_IDS | EXCLUDED_UNAVAILABLE_REPORT_IDS]
        reports: list[dict[str, Any]] = []
        errors = len(warnings)
        total_values = 0
        deadline = time.monotonic() + max_duration
        def read_report(reference: dict[str, Any]) -> dict[str, Any]:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RedfishError("Telemetry report deadline expired")
            return self.get(reference["@odata.id"], timeout=min(45, remaining))

        # Probe-only fan-out keeps the same advertised order and value budget.
        # The client-wide GET semaphore and shared fleet budget still apply.
        pool = ThreadPoolExecutor(max_workers=report_workers) if report_workers > 1 else None
        try:
            pending = ({index: pool.submit(read_report, references[index])
                        for index in range(min(report_workers, len(references)))}
                       if pool is not None else {})
            next_index = len(pending)
            for index, reference in enumerate(references):
                if time.monotonic() >= deadline:
                    errors += len(references) - index
                    break
                report_uri = reference["@odata.id"]
                try:
                    report = pending.pop(index).result() if pool is not None else read_report(reference)
                    values = report.get("MetricValues")
                    if not isinstance(values, list):
                        raise RedfishError("Telemetry report has no MetricValues array")
                    if total_values + len(values) > max_values:
                        errors += len(references) - index
                        break
                    total_values += len(values)
                    report_id = report.get("Id")
                    if not isinstance(report_id, str) or len(report_id) > 160:
                        report_id = report_uri.rsplit("/", 1)[-1][:160]
                    reports.append({"id": report_id, "uri": report_uri, "values": values})
                except RedfishError:
                    errors += 1
                if pool is not None and next_index < len(references) and time.monotonic() < deadline:
                    pending[next_index] = pool.submit(read_report, references[next_index])
                    next_index += 1
        finally:
            if pool is not None:
                for future in pending.values():
                    future.cancel()
                pool.shutdown(wait=True, cancel_futures=True)
        return reports, errors

    def component_snapshot(self, discovered: dict[str, Any], *,
                           collection_workers: int = 1) -> tuple[dict[str, Any], int]:
        """Collect optional hardware summaries without degrading sensor readiness."""
        if collection_workers not in (1, 2, 4):
            raise ValueError("Component collection workers must be 1, 2, or 4")
        links = discovered.get("component_links") or {}
        data: dict[str, Any] = {"system": {
            "Status": discovered.get("system_status"),
            "PowerState": discovered.get("system_power_state"),
            "MemorySummary": discovered.get("memory_summary"),
            "ProcessorSummary": discovered.get("processor_summary"),
        }}
        # Source timestamps are internal metadata, not Redfish payload values.
        # Never stamp the earlier System GET as though it happened after the
        # potentially long sensor walk.
        observed: dict[str, float] = {}
        system_observed_at = discovered.get("system_observed_at")
        if (isinstance(system_observed_at, (int, float)) and not isinstance(system_observed_at, bool)
                and math.isfinite(system_observed_at) and system_observed_at > 0):
            observed["system"] = system_observed_at
        data["_source_observed_at"] = observed
        errors = 0

        def read_collection(link: str, name: str) -> tuple[list[dict[str, Any]] | None, float | None]:
            try:
                page = self.get(self._with_expand(link), timeout=30)
                members = page.get("Members")
                if not isinstance(members, list):
                    raise RedfishError(f"{name} collection has no Members array")
                expected = page.get("Members@odata.count")
                expanded = [item for item in members if isinstance(item, dict) and isinstance(item.get("Id"), str)]
                if isinstance(expected, int) and not isinstance(expected, bool) and len(expanded) != expected:
                    raise RedfishError(f"{name} collection count changed")
                return expanded, time.time()
            except RedfishError:
                return None, None

        jobs = [(name, key, links[name]) for name, key in
                (("Processors", "processors"), ("Memory", "memory"),
                 ("Storage", "storage"), ("NetworkInterfaces", "network_interfaces"))
                if isinstance(links.get(name), str)]
        if collection_workers == 1:
            results = [(name, key, read_collection(link, name))
                       for name, key, link in jobs]
        else:
            # Probe-only candidate. The Redfish client's own GET semaphore
            # remains the shared per-BMC limit across concurrent stages.
            with ThreadPoolExecutor(max_workers=collection_workers) as pool:
                futures = [(name, key, pool.submit(read_collection, link, name))
                           for name, key, link in jobs]
                results = [(name, key, future) for name, key, future in futures]
        for _name, key, result in results:
            expanded, observed_at = result.result() if collection_workers > 1 else result
            if expanded is not None and observed_at is not None:
                data[key] = expanded
                observed[key] = observed_at
            else:
                errors += 1
        storage = data.get("storage")
        if isinstance(storage, list):
            drive_links: set[str] = set()
            volume_links: set[str] = set()
            data["storage_controllers"] = []
            for item in storage:
                drives = item.get("Drives")
                if isinstance(drives, list):
                    drive_links.update(ref["@odata.id"] for ref in drives
                                       if isinstance(ref, dict) and isinstance(ref.get("@odata.id"), str))
                volumes = item.get("Volumes")
                if isinstance(volumes, dict) and isinstance(volumes.get("@odata.id"), str):
                    volume_links.add(volumes["@odata.id"])
                controllers = item.get("StorageControllers")
                if isinstance(controllers, list):
                    for controller in controllers[:16]:
                        if isinstance(controller, dict):
                            copy = dict(controller)
                            copy["Id"] = str(controller.get("Name") or controller.get("MemberId") or "")
                            data["storage_controllers"].append(copy)
            observed["storage_controllers"] = observed["storage"]
            data["drives"] = []
            data["volumes"] = []
            drive_errors = errors
            for uri in sorted(drive_links)[:64]:
                try:
                    drive = self.get(uri, timeout=30)
                    if isinstance(drive.get("Id"), str):
                        data["drives"].append(drive)
                except RedfishError:
                    errors += 1
            if len(drive_links) > 64:
                errors += len(drive_links) - 64
            if errors == drive_errors:
                observed["drives"] = time.time()
            else:
                data.pop("drives")
            volume_errors = errors
            for uri in sorted(volume_links)[:32]:
                try:
                    page = self.get(self._with_expand(uri), timeout=30)
                    members = page.get("Members")
                    if not isinstance(members, list):
                        raise RedfishError("Volumes collection has no Members array")
                    expected = page.get("Members@odata.count")
                    expanded = [item for item in members if isinstance(item, dict) and isinstance(item.get("Id"), str)]
                    if isinstance(expected, int) and not isinstance(expected, bool) and len(expanded) != expected:
                        errors += 1
                        continue
                    data["volumes"].extend(expanded)
                except RedfishError:
                    errors += 1
            if len(volume_links) > 32:
                errors += len(volume_links) - 32
            if errors == volume_errors:
                observed["volumes"] = time.time()
            else:
                data.pop("volumes")
        power_link = links.get("Power")
        if isinstance(power_link, str):
            try:
                data["power"] = self.get(power_link, timeout=30)
                observed["power"] = time.time()
            except RedfishError:
                errors += 1
        subsystem_link = links.get("PowerSubsystem")
        if isinstance(subsystem_link, str):
            try:
                subsystem = self.get(subsystem_link, timeout=30)
                data["power_subsystem"] = subsystem
                observed["power_subsystem"] = time.time()
                supplies = subsystem.get("PowerSupplies")
                supply_link = supplies.get("@odata.id") if isinstance(supplies, dict) else None
                if isinstance(supply_link, str):
                    page = self.get(self._with_expand(supply_link), timeout=30)
                    members = page.get("Members")
                    if not isinstance(members, list):
                        raise RedfishError("PowerSupplies collection has no Members array")
                    expected = page.get("Members@odata.count")
                    expanded = [item for item in members if isinstance(item, dict) and isinstance(item.get("Id"), str)]
                    if isinstance(expected, int) and not isinstance(expected, bool) and len(expanded) != expected:
                        errors += 1
                    else:
                        data["power_supplies"] = expanded
                        observed["power_supplies"] = time.time()
            except RedfishError:
                errors += 1
        return data, errors

    @staticmethod
    def _with_expand(uri: str) -> str:
        parts = urlsplit(uri)
        if any(key == "$expand" for key, _ in parse_qsl(parts.query, keep_blank_values=True)):
            return uri
        query = parts.query + ("&" if parts.query else "") + "$expand=."
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))

    def sensor_snapshot_parallel(self, sensor_uri: str, *, page_workers: int,
                                 workers: int = 4,
                                 on_page: Callable[[list[dict[str, Any]], int | None], None] | None = None,
                                 max_pages: int = 12,
                                 max_duration: float = 240) -> tuple[list[dict[str, Any]], int, int | None]:
        """Probe-only numeric-$skip page fan-out; verify complete IDs or walk serially.

        Never infer that a BMC supports random page access merely from a
        nextLink. This candidate stays opt-in until a live parity benchmark.
        """
        if page_workers not in (2, 4):
            raise ValueError("Page workers must be 2 or 4")
        if max_pages < 1 or max_duration <= 0:
            raise ValueError("Sensor page budget must be positive")
        with self._get_stats_lock:
            self._sensor_page_attempts += 1
        started = time.monotonic()
        candidate: dict[str, dict[str, Any]] = {}
        expected: int | None = None
        try:
            first = self.get(self._with_expand(sensor_uri), timeout=min(90, max_duration))
            members = first.get("Members")
            expected = first.get("Members@odata.count")
            if (not isinstance(members, list) or not members
                    or not isinstance(expected, int) or isinstance(expected, bool)
                    or not 0 < expected <= 3000):
                raise RedfishError("Sensor page candidate has no bounded membership")
            if expected <= len(members):
                if expected != len(members):
                    raise RedfishError("Sensor page membership mismatch")
                pages = [first]
            else:
                link = first.get("Members@odata.nextLink") or first.get("@odata.nextLink")
                if not isinstance(link, str):
                    raise RedfishError("Sensor page candidate has no next link")
                # Accept only a same-collection numeric skip cursor. Other
                # firmware pagination schemes must use the proven serial walk.
                full = urlsplit(self.checked_url(link))
                collection = urlsplit(self.checked_url(sensor_uri))
                query = parse_qsl(full.query, keep_blank_values=True)
                if (full.path != collection.path or len(query) != 1
                        or query[0][0] != "$skip" or not query[0][1].isdigit()):
                    raise RedfishError("Sensor pages do not use a numeric skip cursor")
                stride = int(query[0][1])
                if not 0 < stride <= len(members):
                    raise RedfishError("Sensor page stride is not bounded")
                offsets = list(range(stride, expected, stride))
                if len(offsets) + 1 > max_pages:
                    raise RedfishError("Sensor page candidate exceeds page budget")
                pages = [first]
                if on_page:
                    on_page(members, expected)
                deadline = started + max_duration

                def fetch_offset(offset: int) -> dict[str, Any]:
                    # Queued tasks must not inherit a timeout calculated at
                    # submission; later waves may start after the budget.
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RedfishError("Sensor page candidate exceeded time budget")
                    uri = self._with_expand(urlunsplit(
                        (full.scheme, full.netloc, full.path, f"$skip={offset}", "")))
                    return self.get(uri, timeout=min(90, remaining))

                with ThreadPoolExecutor(max_workers=page_workers) as pool:
                    futures = [pool.submit(fetch_offset, offset) for offset in offsets]
                    for future in as_completed(futures):
                        page = future.result()
                        pages.append(page)
                        if on_page and isinstance(page.get("Members"), list):
                            on_page(page["Members"], expected)
            for page in pages:
                page_members = page.get("Members")
                if (page.get("Members@odata.count") != expected
                        or not isinstance(page_members, list)):
                    raise RedfishError("Sensor page count changed during candidate")
                for item in page_members:
                    if (not isinstance(item, dict) or not isinstance(item.get("@odata.id"), str)
                            or not isinstance(item.get("Id"), str)):
                        raise RedfishError("Sensor page was not expanded")
                    candidate[item["@odata.id"]] = item
            if len(candidate) != expected or time.monotonic() - started > max_duration:
                raise RedfishError("Sensor page candidate did not cover every identity")
            if on_page and len(pages) == 1:
                on_page(members, expected)
            return list(candidate.values()), 0, expected
        except RedfishError:
            with self._get_stats_lock:
                self._sensor_page_fallbacks += 1
            # The serial result alone determines success; a failed candidate
            # never publishes a partial set or changes target_up semantics.
            remaining = max(0, max_duration - (time.monotonic() - started))
            return self.sensor_snapshot(sensor_uri, workers=workers, on_page=on_page,
                                        max_pages=max_pages, max_duration=remaining)

    def sensor_snapshot(self, sensor_uri: str, *, workers: int = 4,
                        on_page: Callable[[list[dict[str, Any]], int | None], None] | None = None,
                        max_pages: int = 12, max_duration: float = 240) -> tuple[list[dict[str, Any]], int, int | None]:
        """Read expanded pages, preserving partial data but reporting incomplete coverage.

        This BMC drops $expand from nextLink and overlaps pages. Following its links
        while reapplying $expand avoids hundreds of expensive per-sensor requests.
        """
        next_uri: str | None = self._with_expand(sensor_uri)
        seen_pages: set[str] = set()
        sensors: dict[str, dict[str, Any]] = {}
        expected: int | None = None
        errors = 0
        deadline = time.monotonic() + max_duration
        while next_uri and len(seen_pages) < max_pages and time.monotonic() < deadline:
            if next_uri in seen_pages:
                errors += 1
                break
            seen_pages.add(next_uri)
            try:
                page = self.get(next_uri, timeout=min(90, max(1, deadline - time.monotonic())))
            except RedfishError:
                if not sensors:
                    raise
                errors += 1
                break
            page_members = page.get("Members")
            if not isinstance(page_members, list):
                raise RedfishError("Sensor collection has no Members array")
            count = page.get("Members@odata.count")
            if isinstance(count, int) and not isinstance(count, bool) and 0 < count <= 3000:
                if expected is not None and count != expected:
                    # A shifting collection total can truncate an expanded walk;
                    # never replace the original completeness target mid-pass.
                    errors += 1
                    break
                expected = count
            for item in page_members:
                if not isinstance(item, dict):
                    continue
                uri = item.get("@odata.id")
                if isinstance(uri, str):
                    sensors[uri] = item
                    if len(sensors) > 3000:
                        raise RedfishError("Sensor collection exceeds configured limit")
            if on_page:
                # Report only items from this response so callers can retain
                # each sensor's actual observed time across overlapping pages.
                on_page([item for item in page_members if isinstance(item, dict)], expected)
            if expected is not None and len(sensors) >= expected:
                next_uri = None
                break
            link = page.get("Members@odata.nextLink") or page.get("@odata.nextLink")
            next_uri = self._with_expand(link) if isinstance(link, str) and link else None
        if next_uri:
            errors += 1
        # A count mismatch must not be presented as a successful full collection.
        if expected is not None and len(sensors) != expected:
            errors += abs(expected - len(sensors))
        link_only = [item["@odata.id"] for item in sensors.values() if "Id" not in item]
        if link_only:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(self.get, uri): uri for uri in link_only}
                for future in as_completed(futures):
                    try:
                        resolved = future.result()
                        sensors[futures[future]] = resolved
                        if on_page:
                            on_page([resolved], expected)
                    except RedfishError:
                        errors += 1
        return list(sensors.values()), errors, expected
