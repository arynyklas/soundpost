#!/bin/sh
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
# Assemble a private site dir holding exactly the hash-locked packages of examples/reference/requirements.lock
# (the pins of sdk/python/requirements-*.lock), installed for the interpreter that will run the apps, then print the
# PYTHONPATH to use (site dir, then the SDK source tree). Usage: pysite.sh [SITE_DIR]
# Environment: REFERENCE_PYTHON (default python3), REFERENCE_PIP_ARGS (extra pip arguments, e.g. `--no-index --find-links DIR`
# for a host without network access that has the locked wheels in DIR).
set -eu
SITE="${1:-/tmp/reference-pysite}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${REFERENCE_PYTHON:-python3}"
rm -rf "$SITE"
mkdir -p "$SITE"
# --require-hashes refuses any package that is not pinned with a hash; --only-binary keeps the install free of build steps;
# --no-deps because the lock already lists every dependency.
# shellcheck disable=SC2086
"$PY" -m pip install --quiet --require-hashes --no-deps --only-binary=:all: --disable-pip-version-check --target "$SITE" ${REFERENCE_PIP_ARGS:-} -r "$ROOT/examples/reference/requirements.lock"
find "$SITE" -name __pycache__ -type d -prune -exec rm -rf {} +
printf '%s:%s\n' "$SITE" "$ROOT/sdk/python/src"
