"""Bounded, read-only asset collection from advertised Redfish resources."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timezone
import threading
import re
import time
from typing import Any
from urllib.parse import unquote_plus, urlsplit, urlunsplit

from .redfish import (RedfishClient, RedfishError, RedfishAuthenticationError,
                      RedfishCertificateError, RedfishHTTPError, RedfishTimeoutError,
                      RedfishTransportError, RedfishUnavailableError)


# These are resource link names, not presumed hardware. Empty/unadvertised links
# never become categories. Sensors belong to metrics, not the asset inventory.
ROOT_LINKS = {
    "system": ("Processors", "Memory", "Storage", "NetworkInterfaces", "NetworkAdapters",
               "PCIeDevices", "PCIeFunctions", "Drives", "TrustedModules"),
    "chassis": ("PowerSubsystem", "ThermalSubsystem", "PowerSupplies", "Fans", "Drives",
                "NetworkAdapters", "PCIeDevices"),
    "manager": ("EthernetInterfaces",),
}
CHILD_LINKS = {
    "Storage": ("Controllers", "StorageControllers", "Drives", "Volumes"),
    "PowerSubsystem": ("PowerSupplies",),
    "ThermalSubsystem": ("Fans",),
    "NetworkAdapters": ("NetworkPorts", "NetworkDeviceFunctions"),
}
FIELDS = (
    "Id", "Name", "Description", "Model", "Manufacturer", "SerialNumber", "PartNumber",
    "SKU", "UUID", "AssetTag", "FirmwareVersion", "BiosVersion", "ProcessorType",
    "ProcessorArchitecture", "InstructionSet", "TotalCores", "TotalThreads", "MaxSpeedMHz",
    "OperatingSpeedMHz", "CapacityMiB", "MemoryDeviceType", "MemoryType", "OperatingSpeedMhz",
    "OperatingSpeedMHz", "AllowedSpeedsMHz", "DeviceLocator", "Socket", "Slot", "Location",
    "PhysicalLocation", "PowerCapacityWatts", "LineInputVoltage", "PowerState", "Status",
    "SpeedRPM", "ReadingRPM", "PCIeInterface", "Identifiers", "Protocol",
    "MediaType", "RotationSpeedRPM", "BlockSizeBytes", "CapacityBytes", "EncryptionStatus",
    "MACAddress", "PermanentMACAddress", "LinkStatus", "InterfaceEnabled", "CurrentLinkSpeedMbps",
    "BootOptionReference", "DisplayName", "BootOptionEnabled", "TrustedModules",
)
MAX_ITEMS = 700
MAX_PER_CATEGORY = 256
MAX_REQUESTS = 760
MAX_DURATION_SECONDS = 600


def _link(value: Any) -> str | None:
    if isinstance(value, dict) and isinstance(value.get("@odata.id"), str):
        return value["@odata.id"]
    return None


def _bounded_value(value: Any, depth: int = 0) -> Any:
    if isinstance(value, str):
        return value[:512]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if depth >= 2:
        return None
    if isinstance(value, dict):
        return {str(k)[:80]: item for k, v in list(value.items())[:16]
                if (item := _bounded_value(v, depth + 1)) is not None and not str(k).startswith("@")} or None
    if isinstance(value, list):
        return [item for v in value[:16] if (item := _bounded_value(v, depth + 1)) is not None] or None
    return None


def _component(payload: dict[str, Any], uri: str) -> dict[str, Any]:
    fields = {key: item for key in FIELDS if (item := _bounded_value(payload.get(key))) is not None}
    if isinstance(modules := payload.get("TrustedModules"), list):
        fields["TrustedModules"] = [item for module in modules[:16]
                                     if isinstance(module, dict) and (item := _bounded_value(module)) is not None]
    boot = payload.get("Boot")
    if isinstance(boot, dict):
        # Expose configured order and current override, not Redfish schema
        # metadata or every allowable value in the BMC's Boot object.
        boot_fields = ("BootOrder", "BootNext", "BootSourceOverrideEnabled",
                       "BootSourceOverrideTarget", "BootSourceOverrideMode")
        selected = {key: item for key in boot_fields if (item := _bounded_value(boot.get(key))) is not None}
        if selected:
            fields["Boot"] = selected
    controllers = payload.get("Controllers")
    if isinstance(controllers, list):
        versions = list(dict.fromkeys(
            version.strip() for controller in controllers[:16] if isinstance(controller, dict)
            if isinstance(version := controller.get("FirmwarePackageVersion"), str)
            and version.strip().lower() not in {"", "nil", "na", "n/a", "unknown"}
        ))
        if versions:
            fields["FirmwarePackageVersion"] = ", ".join(versions)
    return {"source": uri, "fields": fields, "collected_at": datetime.now(timezone.utc).isoformat()}


def inventory_retry_sources(previous: dict[str, Any], *, max_age: float = 3600) -> list[tuple[str, str]]:
    """Resume only unambiguous failed leaf collections; roots need a full scan."""
    if previous.get("state") != "partial" or not previous.get("snapshot") or not previous.get("failures"):
        return []
    try:
        stamp = previous["snapshot"].get("full_collected_at") or previous["snapshot"]["collected_at"]
        age = time.time() - datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
        if not 0 <= age < max_age:
            return []
    except (KeyError, ValueError, TypeError, OverflowError):
        return []
    categories = previous["snapshot"].get("categories") or {}
    targets = set()
    for issue in previous["failures"]:
        category, uri = issue.get("category"), issue.get("source")
        error = issue.get("error", "")
        status = re.search(r"HTTP ([0-9]{3})$", error)
        if error not in {"BMC read timed out", "BMC read connection failed", "BMC read admission timed out",
                         "BMC read exceeded its observation budget", "Redfish GET exceeded total time budget",
                         "Redfish request budget is unavailable", "Inventory collection may be incomplete",
                         "Inventory collection budget reached"} and not (
                         status and (int(status[1]) == 429 or int(status[1]) >= 500)):
            return []
        if category in {"System", "Subsystems", "Chassis", "Management controllers", "Inventory"} or category in CHILD_LINKS:
            return []
        if not isinstance(uri, str) or not uri.startswith("/redfish/v1/"):
            return []
        parts = urlsplit(uri)
        if parts.fragment or parts.scheme or parts.netloc:
            return []
        bucket = categories.get(category) or {}
        if uri in bucket.get("advertised_members", []):
            targets.add((category, uri))
            continue
        items = {item["source"] for item in bucket.get("items", [])}
        parents = [source for source in bucket.get("sources", []) if source not in items and "?" not in source
                   and (uri.split("?", 1)[0] == source or uri.startswith(source.rstrip("/") + "/"))]
        if parents:
            targets.add((category, max(parents, key=len)))
        else:
            # A cold scan may reach its budget before a leaf collection's
            # first response, or fail on a singleton. Resume that advertised
            # resource without inventing a parent or rereading successes.
            leaves = {name for links in (*ROOT_LINKS.values(), *CHILD_LINKS.values()) for name in links}
            if (category not in leaves | {"GPUs", "FPGAs", "BootOptions"} or parts.query or
                    parts.fragment or parts.scheme or parts.netloc):
                return []
            targets.add((category, uri))
    return sorted(targets)


def collect_inventory(client: RedfishClient, discovered: dict[str, Any], *,
                      retry_snapshot: dict[str, Any] | None = None,
                      retry_sources: list[tuple[str, str]] | None = None) -> dict[str, Any]:
    """Collect present categories, retaining resource-level failures for merging."""
    roots: list[tuple[str, str]] = []
    primary_system = discovered.get("system_uri")
    if isinstance(primary_system, str):
        roots.append(("system", primary_system))
    # The C880A advertises the HGX baseboard as another ComputerSystem. Walk
    # every advertised system, but only its processors, to discover actual GPU
    # and FPGA resources without assuming a fixed GPU count or model.
    systems = (discovered.get("resources") or {}).get("systems") or []
    roots.extend(("secondary_system", uri) for uri in systems[:8]
                 if isinstance(uri, str) and uri != primary_system)
    if isinstance(discovered.get("chassis_uri"), str):
        roots.append(("chassis", discovered["chassis_uri"]))
    managers = (discovered.get("resources") or {}).get("managers") or []
    roots.extend(("manager", uri) for uri in managers[:4] if isinstance(uri, str))
    categories: dict[str, dict[str, Any]] = deepcopy((retry_snapshot or {}).get("categories") or {})
    if retry_sources:
        roots = []
        for category, uri in retry_sources:
            bucket = categories.setdefault(category, {"items": [], "sources": []})
            bucket["items"] = [item for item in bucket["items"] if not (
                item["source"] == uri or item["source"].startswith(uri.rstrip("/") + "/"))]
            bucket["sources"] = [source for source in bucket.get("sources", []) if not (
                source == uri or source.startswith(uri.rstrip("/") + "/"))]
    failures: list[dict[str, str]] = []
    requests = 0
    total = sum(len(bucket.get("items", [])) for bucket in categories.values())
    visited: set[str] = set()
    cycle_started = time.monotonic()
    deadline = cycle_started + MAX_DURATION_SECONDS
    budget_lock = threading.Lock()
    # One inventory GET shares the three ordinary BMC slots with rolling
    # sensors. Do not acquire a shared lease while waiting for this lane.
    read_slot = threading.BoundedSemaphore(1)
    responses: dict[str, dict[str, Any]] = {}
    receipt_times: dict[str, str] = {}
    failed_reads: dict[str, RedfishError] = {}
    retries = 0
    fatal: RedfishError | None = None

    def read(uri: str) -> dict[str, Any]:
        nonlocal requests, retries, fatal
        if not read_slot.acquire(timeout=max(0, deadline - time.monotonic())):
            raise RedfishError("Inventory collection budget reached")
        try:
            if fatal is not None:
                raise fatal
            if uri in responses:
                return responses[uri]
            if uri in failed_reads:
                raise failed_reads[uri]
            read_timeout = client.timeout
            for attempt in range(3):
                with budget_lock:
                    if requests >= MAX_REQUESTS or time.monotonic() >= deadline:
                        raise RedfishError("Inventory collection budget reached")
                    requests += 1
                try:
                    payload = client.get(uri, timeout=min(read_timeout, max(0.1, deadline - time.monotonic())),
                                         deadline=deadline)
                    responses[uri] = payload
                    receipt_times[uri] = datetime.now(timezone.utc).isoformat()
                    return payload
                except (RedfishAuthenticationError, RedfishCertificateError) as exc:
                    fatal = exc
                    raise
                except RedfishError as exc:
                    transient = isinstance(exc, (RedfishTimeoutError, RedfishTransportError, RedfishUnavailableError)) or (
                        isinstance(exc, RedfishHTTPError) and (exc.status == 429 or exc.status >= 500))
                    if not transient or attempt == 2:
                        failed_reads[uri] = exc
                        raise
                    delay = (exc.retry_after if isinstance(exc, RedfishHTTPError) and exc.retry_after is not None
                             else .5 * 2 ** attempt)
                    if time.monotonic() + delay >= deadline:
                        raise
                    if isinstance(exc, RedfishTimeoutError):
                        read_timeout = min(30, read_timeout + 10)
                    retries += 1
                    time.sleep(delay)
            raise AssertionError("Unreachable inventory retry state")
        finally:
            read_slot.release()

    def record(category: str, uri: str, payload: dict[str, Any], observed_at: str | None = None) -> None:
        nonlocal total
        if category == "Processors":
            processor_type = payload.get("ProcessorType")
            if processor_type == "GPU":
                category = "GPUs"
            elif processor_type == "FPGA":
                category = "FPGAs"
        bucket = categories.setdefault(category, {"items": [], "sources": []})
        if any(item["source"] == uri for item in bucket["items"]):
            return
        if uri not in bucket["sources"]:
            bucket["sources"].append(uri)
        if len(bucket["items"]) >= MAX_PER_CATEGORY or total >= MAX_ITEMS:
            failures.append({"category": category, "source": uri, "error": "Inventory item limit reached"})
            return
        component = _component(payload, uri)
        component["collected_at"] = observed_at or receipt_times.get(uri) or component["collected_at"]
        if category == "NetworkInterfaces":
            adapter_uri = _link((payload.get("Links") or {}).get("NetworkAdapter"))
            if adapter_uri:
                component["adapter_source"] = adapter_uri
        bucket["items"].append(component)
        total += 1

    array_members: dict[str, list[str]] = {}

    def inspect(category: str, uri: str, depth: int = 0, *, expand: bool = True) -> None:
        if uri in visited:
            return
        visited.add(uri)
        try:
            advertised = array_members.get(category)
            if advertised and all(source.startswith(uri.rstrip("/") + "/") for source in advertised):
                # The current root's complete link array is another advertised
                # membership source. Avoid an inconsistent paginated view.
                categories.setdefault(category, {"items": [], "sources": []})["sources"].append(uri)
                for source in advertised:
                    inspect(category, source, depth + 1, expand=False)
                return
            expanded_uri = client._with_expand(uri) if expand else uri
            try:
                payload = read(expanded_uri)
            except RedfishError:
                # Some implementations reject $expand on a singleton or
                # collection. The ordinary advertised link remains usable.
                payload = read(uri)
            if not expand and (payload.get("error") or not isinstance(payload.get("Id"), str) or not payload["Id"]):
                raise RedfishError("Inventory resource is missing its identity")
            if isinstance(payload.get("Members"), list):
                members: dict[str, dict[str, Any]] = {}
                member_times: dict[str, str] = {}
                seen_pages = {expanded_uri}
                page = payload
                page_time = receipt_times.get(expanded_uri) or receipt_times.get(uri)
                expected = page.get("Members@odata.count")
                next_uri: str | None = None
                for _ in range(6):
                    for member in page.get("Members", []):
                        if isinstance(member, dict) and isinstance(member.get("@odata.id"), str):
                            members[member["@odata.id"]] = member
                            if page_time:
                                member_times[member["@odata.id"]] = page_time
                    if len(members) > MAX_PER_CATEGORY:
                        failures.append({"category": category, "source": uri, "error": "Inventory collection exceeds item limit"})
                        break
                    next_uri = page.get("Members@odata.nextLink") or page.get("@odata.nextLink")
                    if isinstance(expected, int) and len(members) >= expected:
                        next_uri = None
                    if not next_uri:
                        break
                    expanded_next = client._with_expand(next_uri)
                    if expanded_next in seen_pages:
                        failures.append({"category": category, "source": uri, "error": "Repeated Redfish pagination link; collection may be incomplete"})
                        break
                    seen_pages.add(expanded_next)
                    page_source = expanded_next
                    try:
                        try:
                            page = read(expanded_next)
                            page_time = receipt_times.get(expanded_next)
                        except RedfishError:
                            # A costly expansion can fail while the advertised
                            # ordinary page still lists every member. Preserve
                            # its pagination query and fetch sparse members.
                            parts = urlsplit(next_uri)
                            query = "&".join(part for part in parts.query.split("&")
                                            if unquote_plus(part.split("=", 1)[0]) != "$expand")
                            page_source = urlunsplit(parts._replace(query=query))
                            page = read(page_source)
                            page_time = receipt_times.get(page_source)
                    except RedfishError as exc:
                        failures.append({"category": category, "source": page_source, "error": str(exc)[:200]})
                        break
                else:
                    if next_uri:
                        failures.append({"category": category, "source": uri, "error": "Inventory collection exceeded page limit"})
                if isinstance(expected, int) and len(members) < expected and not any(
                        issue["category"] == category and issue["source"] == uri for issue in failures):
                    failures.append({"category": category, "source": uri, "error": "Inventory collection may be incomplete"})
                categories.setdefault(category, {"items": [], "sources": []})["sources"].append(uri)
                def embedded(member: dict[str, Any]) -> bool:
                    # A collection member with only an ID/name is not a full
                    # expansion; fetch its resource before treating omitted
                    # hardware fields as unavailable.
                    keys = {key for key in member if not key.startswith("@")}
                    details = {"Model", "SerialNumber", "PartNumber", "FirmwareVersion",
                               "CapacityMiB", "CapacityBytes", "Manufacturer", "Status"}
                    return len(keys) >= 5 and bool(keys & details)
                with ThreadPoolExecutor(max_workers=3) as pool:
                    pending = {member["@odata.id"]: pool.submit(read, member["@odata.id"])
                               for member in members.values() if not embedded(member)}
                    for member in members.values():
                        child_uri = member.get("@odata.id")
                        if not isinstance(child_uri, str):
                            continue
                        try:
                            child = member if embedded(member) else pending[child_uri].result()
                            child_time = member_times.get(child_uri) if embedded(member) else receipt_times.get(child_uri)
                            record(category, child_uri, child, child_time)
                            if depth < 2:
                                for name in CHILD_LINKS.get(category, ()):
                                    nested = _link(child.get(name))
                                    if nested:
                                        inspect(name, nested, depth + 1)
                                    elif (name in ("StorageControllers", "Controllers") and
                                          isinstance(child.get(name), list) and
                                          not (name == "StorageControllers" and _link(child.get("Controllers")))):
                                        for index, entry in enumerate(child[name][:MAX_PER_CATEGORY]):
                                            if isinstance(entry, dict):
                                                record("Storage controllers", _link(entry) or f"{child_uri}#{name}/{index}", entry, child_time)
                                # Drives are sometimes advertised as an array of links.
                                if category == "Storage" and isinstance(child.get("Drives"), list):
                                    for item in child["Drives"][:MAX_PER_CATEGORY]:
                                        nested = _link(item)
                                        if nested:
                                            inspect("Drives", nested, depth + 1)
                        except RedfishError as exc:
                            failures.append({"category": category, "source": child_uri, "error": str(exc)[:200]})
            else:
                record(category, uri, payload, receipt_times.get(expanded_uri) or receipt_times.get(uri))
                if depth < 2:
                    for name in CHILD_LINKS.get(category, ()):
                        nested = _link(payload.get(name))
                        if nested:
                            inspect(name, nested, depth + 1)
        except RedfishError as exc:
            failures.append({"category": category, "source": uri, "error": str(exc)[:200]})

    # Establish every root before a large primary-system subtree consumes the
    # scan budget. Retain the actual successful responses during this scan.
    for _, uri in roots:
        try:
            read(uri)
        except RedfishError:
            pass  # The ordinary root path below records its scoped failure.
    # Root arrays are complete membership advertisements too (for example,
    # ComputerSystem.PCIeDevices/PCIeFunctions). Scope every link to this BMC
    # before persisting it; retain only this claim's catalog for continuation.
    for kind, root_uri in roots:
        root = responses.get(root_uri)
        if root is None:
            continue
        for name in (("Processors",) if kind == "secondary_system" else ROOT_LINKS[kind]):
            entries = root.get(name)
            if not isinstance(entries, list):
                continue
            if name == "TrustedModules":
                # Structured ComputerSystem data, retained with the root's
                # fields and receipt time, rather than resource links.
                continue
            try:
                if len(entries) > MAX_PER_CATEGORY:
                    raise RedfishError("Inventory collection exceeds item limit")
                sources = []
                for entry in entries:
                    source = _link(entry)
                    if source is None:
                        raise RedfishError("Inventory membership link is missing")
                    parts = urlsplit(client.checked_url(source))
                    sources.append(urlunsplit(("", "", parts.path, parts.query, "")))
                sources = list(dict.fromkeys(sources))
                expected = root.get(name + "@odata.count")
                if expected is not None and (type(expected) is not int or expected != len(sources)):
                    raise RedfishError("Inventory collection may be incomplete")
                array_members[name] = list(dict.fromkeys(array_members.get(name, []) + sources))
                if len(array_members[name]) > MAX_PER_CATEGORY:
                    raise RedfishError("Inventory collection exceeds item limit")
                categories.setdefault(name, {"items": [], "sources": []})["advertised_members"] = array_members[name]
            except RedfishError as exc:
                failures.append({"category": name, "source": root_uri, "error": str(exc)[:200]})

    # Accelerator processors first, then chassis and managers, before the
    # primary system's large memory/storage tree. All roots were read above.
    def walk_roots():
        for kind, uri in sorted(roots, key=lambda root: root[0] == "system"):
            try:
                root = read(uri)
                root_category = {"system": "System", "secondary_system": "Subsystems",
                                 "chassis": "Chassis", "manager": "Management controllers"}[kind]
                record(root_category, uri, root)
                if kind == "chassis":
                    # Older C880A firmware exposes fan/PSU inventory in legacy resources.
                    for parent, child in (("Thermal", "Fans"), ("Power", "PowerSupplies")):
                        linked = _link(root.get(parent))
                        if linked:
                            try:
                                legacy = read(linked)
                                entries = legacy.get(child)
                                if isinstance(entries, list):
                                    for index, entry in enumerate(entries[:MAX_PER_CATEGORY]):
                                        if isinstance(entry, dict):
                                            record(child, _link(entry) or f"{linked}#{child}/{index}", entry, receipt_times.get(linked))
                            except RedfishError as exc:
                                failures.append({"category": child, "source": linked, "error": str(exc)[:200]})
                if kind == "system":
                    boot_options = _link((root.get("Boot") or {}).get("BootOptions"))
                    if boot_options:
                        inspect("BootOptions", boot_options)
                for name in (("Processors",) if kind == "secondary_system" else ROOT_LINKS[kind]):
                    linked = _link(root.get(name))
                    if isinstance(root.get(name), list) and name in array_members:
                        for source in array_members[name]:
                            inspect(name, source, expand=False)
                    if linked:
                        failures_before = len(failures)
                        inspect(name, linked)
                        if kind == "secondary_system" and name == "Processors":
                            # A failed processor read does not tell us which type
                            # it was. Mark both accelerator categories so the
                            # store can retain only the failed last-good assets.
                            for issue in failures[failures_before:]:
                                if issue["category"] == "Processors":
                                    failures.extend({**issue, "category": category}
                                                    for category in ("GPUs", "FPGAs"))
            except RedfishError as exc:
                failures.append({"category": {"system": "System", "secondary_system": "Subsystems",
                                              "chassis": "Chassis", "manager": "Management controllers"}[kind],
                                 "source": uri, "error": str(exc)[:200]})
        for category, uri in retry_sources or []:
            inspect(category, uri, expand=uri not in categories.get(category, {}).get("advertised_members", []))

    walk_roots()
    if categories.get("Fans", {}).get("items"):
        failures[:] = [issue for issue in failures if issue["category"] != "ThermalSubsystem"]
    # Retry failed pages/members after the rest of the walk, while retaining
    # every successful response and its receipt. Rewalking resolves collection
    # membership and aggregate-incomplete flags without re-fetching successes.
    recoverable = {issue["source"] for issue in failures if isinstance(failed_reads.get(issue["source"]),
        (RedfishTimeoutError, RedfishTransportError, RedfishUnavailableError)) or (
        isinstance(failed_reads.get(issue["source"]), RedfishHTTPError) and
        (failed_reads[issue["source"]].status == 429 or failed_reads[issue["source"]].status >= 500))}
    initial_missing = len(recoverable) or len(retry_sources or [])
    recovery_started = time.monotonic()
    if recoverable and fatal is None and time.monotonic() < deadline:
        for uri in recoverable:
            failed_reads.pop(uri, None)
            failed_reads.pop(client._with_expand(uri), None)
        failures.clear()
        visited.clear()
        walk_roots()
    recovery_seconds = (time.monotonic() - cycle_started if retry_sources else
                        time.monotonic() - recovery_started if recoverable else 0.0)
    adapters = {item["source"]: item["fields"] for item in categories.get("NetworkAdapters", {}).get("items", [])}
    for interface in categories.get("NetworkInterfaces", {}).get("items", []):
        adapter = adapters.get(interface.get("adapter_source"))
        if not adapter:
            continue
        for source_key, target_key in (("Model", "AdapterModel"), ("Manufacturer", "AdapterManufacturer"),
                                       ("PartNumber", "AdapterPartNumber"),
                                       ("FirmwarePackageVersion", "AdapterFirmwareVersion"),
                                       ("FirmwareVersion", "AdapterFirmwareVersion")):
            if adapter.get(source_key) and not interface["fields"].get(target_key):
                interface["fields"][target_key] = adapter[source_key]
    if categories.get("Fans", {}).get("items"):
        # The tested C880A returns HTTP 500 on ThermalSubsystem while its
        # legacy Thermal/Fans path works. Do not report a misleading fault.
        failures = [issue for issue in failures if issue["category"] != "ThermalSubsystem"]
    unresolved = (len(recoverable & {issue["source"] for issue in failures}) if recoverable else
                  len({(category, uri) for category, uri in retry_sources or []
                       if any(issue["category"] == category for issue in failures)}))
    collected_at = datetime.now(timezone.utc).isoformat()
    return {"categories": categories, "failures": failures, "request_retries": retries,
            "initial_missing": initial_missing, "recovered": initial_missing - unresolved,
            "unresolved": unresolved, "recovery_seconds": round(recovery_seconds, 3),
            "collected_at": collected_at,
            "full_collected_at": (retry_snapshot.get("full_collected_at") or retry_snapshot["collected_at"]
                                  if retry_snapshot else collected_at),
            "request_count": requests}
