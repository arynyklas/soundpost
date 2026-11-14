#!/bin/sh
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
# Assemble a private site dir holding only PURE-Python packages copied from the
# repository venv (no .pyd/.so, no psycopg_binary/cryptography/pydantic_core),
# then print the PYTHONPATH to use. Usage: pysite.sh [SITE_DIR]
set -eu
SITE="${1:-/tmp/n0704-pysite}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC="${REFERENCE_VENV_SITE:-$ROOT/.venv/Lib/site-packages}"
rm -rf "$SITE"
mkdir -p "$SITE"
for pkg in psycopg httpx httpcore h11 anyio idna certifi sniffio; do
  [ -d "$SRC/$pkg" ] || continue
  if find "$SRC/$pkg" \( -name '*.pyd' -o -name '*.so' -o -name '*.dll' \) | grep -q .; then
    echo "skipping $pkg: contains compiled extensions" >&2
    continue
  fi
  cp -R "$SRC/$pkg" "$SITE/$pkg"
  for info in "$SRC/$pkg"-*.dist-info; do
    [ -d "$info" ] && cp -R "$info" "$SITE/"
  done
done
[ -f "$SRC/typing_extensions.py" ] && cp "$SRC/typing_extensions.py" "$SITE/typing_extensions.py"
find "$SITE" -name __pycache__ -type d -prune -exec rm -rf {} +
printf '%s:%s\n' "$SITE" "$ROOT/sdk/python/src"
