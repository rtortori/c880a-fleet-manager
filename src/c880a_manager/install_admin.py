"""Fresh-install-only account provisioning entry point used before the service starts."""

from __future__ import annotations

import argparse
from pathlib import Path

from .storage import Store


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("data_dir", type=Path)
    args = parser.parse_args()
    Store(args.data_dir).provision_installer_admin()


if __name__ == "__main__":
    main()
