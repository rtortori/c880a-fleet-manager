"""Read-only Redfish action discovery and strict execution-plan allowlists."""

from __future__ import annotations

from typing import Any

from .redfish import RedfishClient, RedfishError


POWER_ACTIONS = {
    "power_on": ("On", "Off", "Power On", "Starts the server host."),
    "power_off": ("GracefulShutdown", "On", "Power Off",
                           "Requests an orderly host shutdown; running workloads may stop."),
    "force_power_off": ("ForceOff", "On", "Force Power Off",
                        "Immediately cuts host power without an orderly shutdown; unsaved work may be lost."),
    "reboot_server": ("GracefulRestart", "On", "Reboot Server",
                       "Requests an orderly host restart; running workloads will be interrupted."),
}


def _linked(resource: dict[str, Any], key: str) -> str | None:
    value = resource.get(key)
    link = value.get("@odata.id") if isinstance(value, dict) else None
    return link if isinstance(link, str) and link.startswith("/redfish/v1/") else None


def _action(client: RedfishClient, resource: dict[str, Any], resource_uri: str,
            action_name: str, parameter: str) -> tuple[str | None, set[str]]:
    """Accept only this resource's exact standard action path and advertised values."""
    actions = resource.get("Actions")
    metadata = actions.get(f"#{action_name}") if isinstance(actions, dict) else None
    if not isinstance(metadata, dict):
        return None, set()
    target = metadata.get("target")
    if target != f"{resource_uri}/Actions/{action_name}":
        return None, set()
    inline = metadata.get(f"{parameter}@Redfish.AllowableValues")
    values = {item for item in inline if isinstance(item, str)} if isinstance(inline, list) else set()
    info_uri = metadata.get("@Redfish.ActionInfo")
    if isinstance(info_uri, str) and info_uri.startswith(resource_uri + "/"):
        try:
            info = client.get(info_uri)
            parameters = info.get("Parameters")
            if isinstance(parameters, list):
                for item in parameters:
                    if isinstance(item, dict) and item.get("Name") == parameter:
                        allowed = item.get("AllowableValues")
                        if isinstance(allowed, list):
                            values.update(value for value in allowed if isinstance(value, str))
        except RedfishError:
            pass
    return target, values


def discover_actions(client: RedfishClient, discovered: dict[str, Any],
                     operation: str | None = None) -> dict[str, Any]:
    """Fetch current state and capabilities; never mutates the BMC."""
    if operation is not None and operation not in (*POWER_ACTIONS, "reboot_bmc", "collect_support_bundle"):
        raise ValueError("Unsupported server action")
    result: dict[str, Any] = {"power_state": None, "actions": {}, "warnings": []}
    system_uri = discovered.get("system_uri")
    if ((operation is None or operation in POWER_ACTIONS)
            and isinstance(system_uri, str) and system_uri.startswith("/redfish/v1/Systems/")):
        try:
            system = client.get(system_uri)
            state = system.get("PowerState")
            result["power_state"] = state if state in {"On", "Off"} else None
            target, allowed = _action(client, system, system_uri, "ComputerSystem.Reset", "ResetType")
            if target:
                for key, (reset_type, required_state, label, impact) in POWER_ACTIONS.items():
                    if operation is not None and key != operation:
                        continue
                    if reset_type in allowed and state == required_state:
                        result["actions"][key] = {"label": label, "impact": impact,
                                                   "target": target, "payload": {"ResetType": reset_type}}
                if (state == "On" and operation in (None, "reboot_server")
                        and "reboot_server" not in result["actions"] and "ForceRestart" in allowed):
                    result["actions"]["reboot_server"] = {
                        "label": "Reboot Server",
                        "impact": "Immediately restarts the host without an orderly shutdown; unsaved work may be lost.",
                        "target": target, "payload": {"ResetType": "ForceRestart"}}
        except RedfishError:
            result["warnings"].append("System action discovery failed")
    managers = discovered.get("resources", {}).get("managers", [])
    manager_uris = [uri for uri in managers if isinstance(uri, str)
                    and uri.startswith("/redfish/v1/Managers/") and uri.count("/") == 4]
    manager_uri = next((uri for uri in manager_uris if uri.endswith("/BMC")), None)
    manager_uri = manager_uri or (manager_uris[0] if manager_uris else None)
    if not manager_uri or operation in POWER_ACTIONS:
        return result
    try:
        manager = client.get(manager_uri)
        if operation in (None, "reboot_bmc"):
            target, allowed = _action(client, manager, manager_uri, "Manager.Reset", "ResetType")
            if target and "ForceRestart" in allowed:
                result["actions"]["reboot_bmc"] = {
                    "label": "Reboot BMC", "impact": "Management access, monitoring, and vKVM will disconnect temporarily; the host may keep running.",
                    "target": target, "payload": {"ResetType": "ForceRestart"}}
        if operation == "reboot_bmc":
            return result
        logs_uri = _linked(manager, "LogServices")
        if not logs_uri or not logs_uri.startswith(manager_uri + "/"):
            return result
        services = client.members(logs_uri, max_pages=2, max_members=32)
        diagnostic_uri = next((item.get("@odata.id") for item in services
                               if isinstance(item, dict) and isinstance(item.get("@odata.id"), str)
                               and item["@odata.id"] == logs_uri + "/DiagnosticLog"), None)
        if not diagnostic_uri:
            return result
        diagnostic = client.get(diagnostic_uri)
        target, types = _action(client, diagnostic, diagnostic_uri,
                                "LogService.CollectDiagnosticData", "DiagnosticDataType")
        if not target:
            return result
        payload = None
        if "OEM" in types:
            _, oem_types = _action(client, diagnostic, diagnostic_uri,
                                   "LogService.CollectDiagnosticData", "OEMDiagnosticDataType")
            if "ALL" in oem_types:
                payload = {"DiagnosticDataType": "OEM", "OEMDiagnosticDataType": "ALL"}
        if payload is None and "Manager" in types:
            payload = {"DiagnosticDataType": "Manager"}
        entries_uri = _linked(diagnostic, "Entries")
        if payload and entries_uri == diagnostic_uri + "/Entries":
            result["actions"]["collect_support_bundle"] = {
                "label": "Collect Tech Support",
                "impact": "Starts a diagnostic collection on the BMC. The bundle may contain sensitive support data.",
                "target": target, "payload": payload, "entries_uri": entries_uri}
    except RedfishError:
        result["warnings"].append("BMC action discovery failed")
    return result
