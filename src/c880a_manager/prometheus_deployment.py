"""Supervisor-owned matched HTTPS/Prometheus generation activation."""
import time
import uuid

from .deployment import atomic_config, read_config
from .prometheus_service import PrometheusError
from .state_operation import installation_lease

JOURNAL = "deployment.prometheus.json"


def _record(managed, value):
    atomic_config(managed.data_dir, JOURNAL, value)


def _activate(managed, value):
    managed.control.set_enabled(False)
    if managed.control.active():
        raise PrometheusError("Prometheus stopped state could not be confirmed")
    atomic_config(managed.root, "active.json", value)
    enabled = value["settings"]["enabled"]
    managed.control.set_enabled(enabled)
    if enabled and not managed.wait_ready(value):
        raise PrometheusError("Prometheus HTTPS activation was not confirmed")
    if not enabled and managed.control.active():
        raise PrometheusError("Prometheus disabled state was not confirmed")


def begin_deployment(managed, proposed):
    with installation_lease(managed.data_dir):
        if read_config(managed.data_dir, name=JOURNAL):
            raise PrometheusError("HTTPS activation recovery is pending")
        if read_config(managed.root, name="pending.json"):
            raise PrometheusError("Prometheus settings recovery is pending")
        previous = managed.active()
        record = {"id":uuid.uuid4().hex, "phase":"preparing",
                  "previous_manager":read_config(managed.data_dir), "previous":previous,
                  "proposed":proposed}
        _record(managed, record)
        candidate = managed.prepare(previous["settings"], deployment=proposed)
        record.update(candidate=candidate, phase="activating")
        _record(managed, record)  # Both prior configurations survive interruption.
        _activate(managed, candidate)
        record["phase"] = "checking-candidate"
        _record(managed, record)
        return {"id":record["id"], "deployment":proposed, "managed":True, "recovering":False}


def _publish_manager(managed, record):
    atomic_config(managed.data_dir, "deployment.previous.json", record["previous_manager"])
    recovery = read_config(managed.data_dir, name="deployment.recovery.json")
    if recovery:
        for field in ("manager_port", "port_start", "port_end", "console_port_offset", "bmc_ca"):
            recovery[field] = record["proposed"].get(field)
        recovery["manager_origin"] = f"https://localhost:{record['proposed']['manager_port']}"
        atomic_config(managed.data_dir, "deployment.recovery.json", recovery)
    atomic_config(managed.data_dir, "deployment.json", record["proposed"])
    (managed.data_dir / "deployment.pending.json").unlink(missing_ok=True)


def recovery_unconfirmed(managed):
    record = read_config(managed.data_dir, name=JOURNAL)
    if not record:
        return
    record["phase"] = "unconfirmed"
    _record(managed, record)
    atomic_config(managed.data_dir, "deployment.last.json", {"id":record["id"], "status":"unconfirmed",
        "at":time.time(), "reason":"HTTPS and Prometheus recovery is unconfirmed; keep recovery files and check service status"})


def recover_deployment(managed):
    with installation_lease(managed.data_dir):
        record = read_config(managed.data_dir, name=JOURNAL)
        if not record:
            return None
        try:
            # An interrupted final commit finishes forward after another health
            # check; it must not undo a configuration already accepted.
            applied = record.get("outcome") == "applied"
            if applied:
                _publish_manager(managed, record)
                value, deployment = record["candidate"], record["proposed"]
            else:
                value, deployment = record["previous"], record["previous_manager"]
                atomic_config(managed.data_dir, "deployment.json", deployment)
                (managed.data_dir / "deployment.pending.json").unlink(missing_ok=True)
            record["phase"] = "recovering"
            _record(managed, record)
            _activate(managed, value)
            record["phase"] = "checking-candidate" if applied else "checking-prior"
            _record(managed, record)
            return {"id":record["id"], "deployment":deployment, "managed":True, "recovering":not applied}
        except Exception:
            recovery_unconfirmed(managed)
            raise PrometheusError("HTTPS and Prometheus recovery is unconfirmed") from None


def confirm_deployment(managed, identifier, *, applied):
    """Called only after the supervisor verifies manager, exporters and discovery."""
    with installation_lease(managed.data_dir):
        record = read_config(managed.data_dir, name=JOURNAL)
        phase = "checking-candidate" if applied else "checking-prior"
        if record.get("id") != identifier or record.get("phase") != phase:
            raise PrometheusError("HTTPS activation health check changed")
        expected = record["candidate"] if applied else record["previous"]
        if managed.active() != expected:
            raise PrometheusError("Prometheus activation changed before confirmation")
        if expected["settings"]["enabled"]:
            if not managed.control.active() or not managed.ready(expected):
                raise PrometheusError("Prometheus HTTPS health check changed")
        elif managed.control.active():
            raise PrometheusError("Prometheus disabled state changed")
        record["outcome"] = "applied" if applied else "reverted"
        _record(managed, record)
        if applied:
            _publish_manager(managed, record)
        message = ("HTTPS and Prometheus verified" if expected["settings"]["enabled"] else
                   "HTTPS verified; Prometheus remains disabled")
        if not applied:
            message = "Previous " + message[0].lower() + message[1:]
        atomic_config(managed.data_dir, "deployment.last.json", {"id":identifier, "status":record["outcome"],
            "at":time.time(), "reason":message})
        (managed.data_dir / JOURNAL).unlink()
