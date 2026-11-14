#!/bin/bash
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
# Runs one locked case file through its differential phase runner against the
# pinned oracles and prints a one-line summary plus every mismatching row.
#   conformance/query/author/run-phase.sh <language: promql|logql> <phase> <cases/file.json> [json-out]
# Run from the repository root with the Go toolchain on PATH. The file must be
# content-locked first (conformance/query/author/relock.py <file>).
set -u
lang=$1; phase=$2; file=$3; out=${4:-/tmp/run-phase.$$.json}
if [ "$lang" = promql ]; then profiles=promql-prometheus-3.1.0,promql-prometheus-3.13.5; else profiles=logql-loki-3.5.2; fi
go run ./cmd/soundpost-querycheck compare --phase "$phase" --cases "conformance/query/$file" --profiles "$profiles" --require-locked --runtime /usr/bin/docker > "$out" 2> "$out.err"
rc=$?
python3 - "$out" "$rc" <<'PY'
import json, sys
out, rc = sys.argv[1], sys.argv[2]
try:
    r = json.load(open(out))
except Exception as e:
    print("rc", rc, "no report:", e); sys.exit(0)
cases = r.get("cases") or r.get("Cases") or []
bad = [c for c in cases if c.get("mismatches")]
print("rc", rc, "compared", r.get("compared"), "failed", r.get("failed"), "mismatching rows", len(bad))
for c in bad:
    print("MISMATCH", c.get("profile"), c.get("id"))
    for m in c["mismatches"][:4]:
        print("   ", str(m)[:600])
PY
head -c 2000 "$out.err"
