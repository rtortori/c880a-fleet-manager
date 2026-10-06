"""Public version and source build identity for installed and local runs."""

from __future__ import annotations

import hashlib
from importlib.metadata import PackageNotFoundError, version as installed_version
from pathlib import Path
import tomllib


def _build_info(package: Path, install_root: Path) -> dict[str, str]:
    # The Linux installer copies source to /opt and installs the importable
    # package in its venv. Hash the retained source, as the installer does.
    if package.is_relative_to(install_root / "venv"):
        installed_source = install_root / "source"
        if (installed_source / "pyproject.toml").is_file():
            package = installed_source / "src" / "c880a_manager"
    source_root = package.parent.parent
    project = source_root / "pyproject.toml"
    try:
        with project.open("rb") as handle:
            app_version = tomllib.load(handle)["project"]["version"]
    except (OSError, KeyError, TypeError, ValueError):
        try:
            app_version = installed_version("c880a-manager")
        except PackageNotFoundError:
            app_version = "unknown"

    digest = hashlib.sha256()
    for source in sorted(package.rglob("*")):
        if (source.is_file() and not source.name.startswith("._")
                and source.suffix in {".py", ".js", ".css", ".html", ".woff2", ".tsv"}):
            digest.update(str(source.relative_to(source_root)).encode())
            digest.update(source.read_bytes())
    if project.is_file():
        digest.update(project.read_bytes())
    return {"version": app_version, "build": digest.hexdigest()[:8]}


def build_info() -> dict[str, str]:
    return _build_info(Path(__file__).resolve().parent, Path("/opt/c880a-manager"))
