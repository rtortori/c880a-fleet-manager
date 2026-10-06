#!/usr/bin/env python3
"""Remove an installer-managed Linux service and its durable state."""

from __future__ import annotations

import json
import os
from pathlib import Path
import grp
import pwd
import shutil
import subprocess
import sys

from scripts import install_linux as install


def _service_account() -> pwd.struct_passwd:
    try:
        account = pwd.getpwnam(install.SERVICE_USER)
    except KeyError:
        raise RuntimeError("The manager service account is missing") from None
    if account.pw_dir != install.SERVICE_HOME or account.pw_shell != "/usr/sbin/nologin":
        raise RuntimeError("The manager service account has an unexpected configuration")
    try:
        group = grp.getgrnam(install.SERVICE_USER)
    except KeyError:
        pass
    else:
        if group.gr_gid != account.pw_gid or any(
            member != install.SERVICE_USER for member in group.gr_mem
        ):
            raise RuntimeError("Service group is in use; inspect it before removal")
    return account


def _validated_rules(plan: dict[str, object]) -> list[list[str]]:
    rules = plan.get("owned_firewall_rules", [])
    if not isinstance(rules, list) or any(not isinstance(rule, list) for rule in rules):
        raise RuntimeError("Installer firewall record is invalid")
    try:
        expected = install.firewall_rules(
            str(plan["interface"]), str(plan["address"]), int(plan["port"]),
            int(plan.get("port_start", install.EXPORTER_START)),
            int(plan.get("port_end", install.EXPORTER_END)),
            int(plan.get("console_port_offset", install.CONSOLE_OFFSET)))
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(f"Installer firewall record is invalid: {exc}") from None
    if any(rule not in expected for rule in rules) or len({tuple(rule) for rule in rules}) != len(rules):
        raise RuntimeError("Installer firewall record contains an unrecognized rule")
    if rules and not shutil.which("ufw"):
        raise RuntimeError("UFW is missing; restore it or remove the recorded rules manually")
    return rules


def _purge_paths() -> None:
    for path in (install.DATA_DIR, install.BACKUP_ROOT):
        if path.is_symlink():
            raise RuntimeError(f"Refusing to purge symbolic link: {path}")
    if install.DATA_DIR.exists():
        shutil.rmtree(install.DATA_DIR)
    if install.BACKUP_ROOT.exists():
        shutil.rmtree(install.BACKUP_ROOT)


def _remaining() -> str:
    paths = (install.APP_ROOT, install.DATA_DIR, install.BACKUP_ROOT, install.UNIT_PATH,
             install.PROM_UNIT_PATH, install.PROM_POLICY_PATH)
    return ", ".join(str(path) for path in paths if path.exists() or path.is_symlink()) or "none"


def _remove_service_account(account: pwd.struct_passwd) -> None:
    install.run("userdel", install.SERVICE_USER)
    try:
        group = grp.getgrnam(install.SERVICE_USER)
    except KeyError:  # Ubuntu may remove the private group with the user.
        return
    if group.gr_gid != account.pw_gid or any(
        member != install.SERVICE_USER for member in group.gr_mem
    ):
        raise RuntimeError("Service group is in use; inspect it before removal")
    install.run("groupdel", install.SERVICE_USER)


def uninstall() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("Run uninstall.sh with sudo")
    if not shutil.which("systemctl"):
        raise RuntimeError("systemctl is required")
    install.secure_backup_root()
    install.lifecycle_guard()
    install.verify_prometheus_ownership()
    if install.UPGRADE_PENDING.exists():
        raise RuntimeError("An upgrade recovery is pending; run install.sh to recover it first")
    if install.PENDING_PLAN.exists():
        raise RuntimeError("An installation is pending; run install.sh to recover it first")
    installed = install.managed_installation()
    if not installed:
        if any(path.exists() or path.is_symlink() for path in
               (install.PROM_UNIT_PATH, install.PROM_POLICY_PATH)):
            raise RuntimeError("Prometheus service ownership is unconfirmed; recover the installation before removal")
        if install.APP_ROOT.exists() or install.UNIT_PATH.exists():
            raise RuntimeError("Installation is incomplete or not installer-managed; inspect it manually")
        if install.DATA_DIR.is_symlink():
            raise RuntimeError("Data path must not be a symbolic link")
        try:
            pwd.getpwnam(install.SERVICE_USER)
        except KeyError:
            account = None
        else:
            account = _service_account()
        if not install.DATA_DIR.exists() and not install.BACKUP_ROOT.exists() and account is None:
            print("Manager and app-owned state are already removed.")
            return
        if install.DATA_DIR.exists() and (account is None or
                                          install.DATA_DIR.stat().st_uid != account.pw_uid):
            raise RuntimeError("Persistent data has an unexpected owner")
        print(f"Remove retained data, credentials, certificates, and app logs: {install.DATA_DIR}")
        print(f"Remove all manager safety backups: {install.BACKUP_ROOT}")
        if account is not None:
            print(f"Remove dedicated manager service account: {install.SERVICE_USER}")
        print("No local recovery copy will remain. Type PURGE to confirm.")
        if input("Confirm purge: ").strip() != "PURGE":
            print("Uninstall canceled.")
            return
        _purge_paths()
        if account is not None:
            _remove_service_account(account)
        print("Retained manager state and backups removed.")
        if account is not None:
            print("Dedicated manager service account and group removed.")
        return

    account = _service_account()
    if install.DATA_DIR.stat().st_uid != account.pw_uid:
        raise RuntimeError("Persistent data has an unexpected owner")
    plan = json.loads(install.PLAN_PATH.read_text())
    if not isinstance(plan, dict):
        raise RuntimeError("Installer manifest is invalid")
    rules = _validated_rules(plan)
    saved = install.preserved_deployment()
    address, port = str(saved["address"]), int(saved["port"])
    active = install.run("systemctl", "is-active", "--quiet", install.UNIT_PATH.name,
                         check=False).returncode == 0
    managed_prometheus = install.prometheus_installed()
    print(f"\nUninstall: {install.package_version(install.APP_ROOT / 'source')} → removed")
    print(f"HTTPS: {install.origin(address, port)}/ · service stops")
    print(f"Remove service and virtual environment: {install.APP_ROOT}")
    print(f"Remove data, credentials, certificates, and app logs: {install.DATA_DIR}")
    print(f"Remove all manager safety backups: {install.BACKUP_ROOT}")
    if managed_prometheus:
        print("Remove managed Prometheus service, runtime, configuration, TSDB history and recovery copies")
        print(f"Remove product service authorization: {install.PROM_POLICY_PATH}")
        print("Shared OS packages and system journals retained")
    print(f"Firewall: remove {len(rules)} installer-owned UFW rule(s)")
    print(f"Remove dedicated manager service account: {install.SERVICE_USER}")
    print("Recovery requires an external backup. Type PURGE to confirm.")
    if input("Confirm uninstall: ").strip() != "PURGE":
        print("Uninstall canceled.")
        return

    deleted_rules: list[list[str]] = []
    deletion_started = False
    try:
        install.stop_manager()
        install.stop_prometheus()
        install.lifecycle_guard()
        install.run("systemctl", "disable", install.UNIT_PATH.name)
        for rule in reversed(rules):
            install.run("ufw", "--force", "delete", *rule[1:], locale_c=True)
            deleted_rules.append(rule)
        deletion_started = True
        install.remove_prometheus_files()
        install.UNIT_PATH.unlink()
        install.run("systemctl", "daemon-reload")
        shutil.rmtree(install.APP_ROOT)
        _purge_paths()
        _remove_service_account(account)
        print("Manager service, app, data, certificates, and safety backups removed; "
              f"{len(rules)} installer-owned firewall rule(s) removed.")
        print("Dedicated manager service account and group removed.")
    except Exception as exc:
        if deletion_started:
            raise RuntimeError(f"Uninstall stopped after deletion began. Remaining paths: "
                               f"{_remaining()}. Inspect service, account, and UFW state. Cause: {exc}") from exc
        try:
            for rule in reversed(deleted_rules):
                install.run(*rule, locale_c=True)
            install.run("systemctl", "enable", install.UNIT_PATH.name)
            if active:
                install.run("systemctl", "start", install.UNIT_PATH.name)
                install.https_health(address, port)
                install.start_prometheus()
                install.check_prometheus()
        except Exception as rollback_exc:
            raise RuntimeError(f"Uninstall failed before deletion and recovery is incomplete. "
                               f"Inspect service and UFW state. Cause: {rollback_exc}") from exc
        raise RuntimeError(f"Uninstall failed; previous installation is restored. Cause: {exc}") from exc


def main() -> None:
    os.umask(0o077)
    if sys.argv[1:] not in ([], ["--purge"]):
        raise RuntimeError("Usage: ./uninstall.sh [--purge]")
    uninstall()


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"Uninstall failed: {exc}", file=sys.stderr)
        sys.exit(1)
