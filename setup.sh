#!/usr/bin/env bash
set -euo pipefail

python3 -m pip install -r requirements.txt

if command -v npm >/dev/null 2>&1; then
  npm --prefix crawlee install
else
  printf 'npm was not found; the optional Crawlee integration was not installed.\n' >&2
fi

printf 'Python dependencies installed. External security tools must be installed separately.\n'
