#!/usr/bin/env python3
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Records the SHA-256 of case files in conformance/query/source-lock.json so
the differential runners accept them. Usage, from the repository root:

    python3 conformance/query/author/relock.py cases/release-promql-numeric.json ...
"""
import hashlib, os, re, sys, time

Q = "conformance/query"
LOCK = f"{Q}/source-lock.json"
ANCHOR = '    "cases/logql-metrics-order.json"'
guard = LOCK + ".relock"
for _ in range(600):
    try:
        fd = os.open(guard, os.O_CREAT | os.O_EXCL)
        os.close(fd)
        break
    except FileExistsError:
        time.sleep(0.1)
else:
    sys.exit("relock: lock file busy")
try:
    lock = open(LOCK, newline="").read()
    for name in sys.argv[1:]:
        digest = hashlib.sha256(open(f"{Q}/{name}", "rb").read()).hexdigest()
        entry = f'    "{name}": "{digest}"'
        pattern = re.compile(r'^    "' + re.escape(name) + r'": "[0-9a-f]{64}"', re.M)
        if pattern.search(lock):
            lock = pattern.sub(entry, lock)
        else:
            i = lock.index(ANCHOR)
            j = lock.index("\n", i)
            lock = lock[: j + 1] + entry + ",\n" + lock[j + 1 :]
    open(LOCK, "w", newline="").write(lock)
finally:
    os.unlink(guard)
