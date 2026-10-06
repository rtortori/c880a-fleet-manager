#!/usr/bin/env bash
set -euo pipefail

printf '\nCisco UCS C880A Manager | Installer\n\n'

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ $(uname -s) != Linux ]]; then
  echo "This installer requires Linux." >&2
  exit 1
fi
if [[ $EUID -eq 0 ]]; then
  exec python3 -B "$repo_dir/scripts/install_linux.py" "$repo_dir"
fi
exec sudo python3 -B "$repo_dir/scripts/install_linux.py" "$repo_dir"
