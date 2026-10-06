#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ $(uname -s) != Linux ]]; then
  echo "This uninstaller requires Linux." >&2
  exit 1
fi
cd -- "$repo_dir"
if [[ $EUID -eq 0 ]]; then
  exec python3 -B -m scripts.uninstall_linux "$@"
fi
exec sudo python3 -B -m scripts.uninstall_linux "$@"
