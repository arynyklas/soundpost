<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# SDK runtime support and qualification status

Status: **no runtime row is qualified for release.** `go run ./tools/qualify/cmd/qualify --suite runtime --matrix qualification/matrix.yaml --report <dir>` judges each row only against the build it names (object header, version output and platform are checked; a different version, OS or architecture never stands in) and exits non-zero until every required row is exercised and passing. Each row is exactly one of `exercised` (with raw safe series), `not_exercised`, `unsupported` or `denied`. An unavailable capability carries no number: zero is never reported for it.

| Runtime | Linux amd64 | Linux arm64 |
|---|---|---|
| CPython 3.12 (GIL) | exercised, **FAILED** on 3.12.3: `fixtures/sdk/profiles/python.py` exits 1 (`sys.monitoring.use_tool_id(PROFILER_ID)` raises "tool 2 is already in use" in the coexistence case; the same fixture passed on a Windows 3.14.2 build) | not exercised (no build) |
| CPython 3.13 / 3.14 (GIL) | not exercised (no build) | not exercised |
| Node 22 | exercised, profile fixture passed on 22.23.4 | not exercised |
| Node 24 | not exercised | not exercised |
| Bun 1.3.14 | exercised, profile fixture passed | not exercised |

What "passed" means: only the committed runtime-profile supplement fixture (03.09). HTTP/DB/job critical-path journeys need a private fixture environment and are not part of this suite. Windows-hosted runs (Python 3.14.2, Node 22.23.4, Bun 1.3.14) are recorded as non-required rows and qualify nothing on Linux. The frozen manifest patch levels (`fixtures/sdk/qualification.json`) differ from the builds installed here and stay `not_run`.

Overhead budgets for these runtimes are in [budgets.md](budgets.md); core server capture currently misses them.
