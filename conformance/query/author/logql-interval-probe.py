#!/usr/bin/env python3
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Authors and records the LogQL raw-log interval probe (02.07#14).

A raw log query (`{app="api"}`, optionally with a line filter) evaluated with interval > 0 keeps
the first entry and then every entry at least `interval` after (forward) or before (backward) the
last KEPT entry. A stored row carries a multiplicity (n identical entries); the owned engine emits
each kept entry with multiplicity 1, except after a kept entry before 1970 (the pinned readStreams
tests `lastEntry.Unix() < 0`). The probe runs eight fixture families (copies of a row inside one
stream, ties across streams, identical rows with distinct ids, a dense run over two streams, a line
filter that removes chain members, the interval boundary +-1 ns, rows at and before the epoch, ties
under a label_format that reorders the query-visible labels) over ten intervals (0 is the control
without thinning), six limits, both directions, range and instant, against the pinned Loki 3.5.2
reference. Rows are authored from the obligation text; no expectation is copied from any run.

From the repository root:

    python3 conformance/query/author/logql-interval-probe.py generate
    python3 conformance/query/author/relock.py cases/logql-interval-multiplicity.json
    conformance/query/author/native-oracle.sh build-loki
    conformance/query/author/native-oracle.sh setup <repo-dir>
    $NATIVE_ORACLE_DIR/qc-adapter compare --phase logql-metric \\
      --cases conformance/query/cases/logql-interval-multiplicity.json \\
      --profiles logql-loki-3.5.2 --require-locked --runtime $NATIVE_ORACLE_DIR/docker-shim > report.json
    python3 conformance/query/author/logql-interval-probe.py record report.json oci|native

`record` writes the reference observations of a passing run to
conformance/query/evidence/native-logql-interval-observations.json (content-locked in
source-lock.json), which TestOwnedMatchesRecordedNativeLogQLIntervalObservations replays without a
container runtime. The last argument states how the reference ran and is written into the file:
`oci` (the digest-locked image) or `native` (a native build of the pinned source archive, D63).
"""
import json
import sys

Q = "conformance/query"
CASES = f"{Q}/cases/logql-interval-multiplicity.json"
OUT = f"{Q}/evidence/native-logql-interval-observations.json"
S = 10**9
MS = 10**6

STREAMS = {
    "a": [("app", "api"), ("host", "a")],
    "b": [("app", "api"), ("host", "b")],
    "c": [("app", "api"), ("host", "c")],
}


def lab(pairs):
    return [{"name": k, "value": v} for k, v in pairs]


def eid(n):
    return f"{n:02x}" + "00" * 15


def entry(n, ts, stream, mult, line):
    return {"timestamp_ns": str(ts), "id": eid(n), "multiplicity": str(mult), "line": line,
            "stream_labels": lab(STREAMS[stream]), "structured_metadata": [], "fields": []}


def rows(spec):
    return [entry(i + 1, ts, st, m, line) for i, (ts, st, m, line) in enumerate(spec)]


FIXTURES = {
    # Several rows with multiplicity > 1 in one stream, two rows at the same timestamp.
    "dup-one-stream": dict(start=0, rows=rows([
        (1 * S, "a", 5, "n=1"), (1 * S, "a", 2, "n=2"), (1400 * MS, "a", 3, "n=3"), (2 * S, "a", 4, "n=4"),
        (2500 * MS, "a", 1, "n=5"), (3 * S, "a", 7, "n=6"), (5 * S, "a", 2, "n=7")])),
    # Rows of three streams at the same timestamps, distinct and equal lines, different multiplicities.
    "ties-streams": dict(start=0, rows=rows([
        (1 * S, "c", 2, "x"), (1 * S, "a", 3, "x"), (1 * S, "b", 1, "y"), (2 * S, "b", 4, "z"), (2 * S, "a", 1, "z"),
        (2 * S, "c", 2, "w"), (3 * S, "a", 2, "x"), (3 * S, "b", 2, "x"), (4 * S, "c", 3, "v")])),
    # The same stream, timestamp and line stored as three rows (distinct ids) of multiplicity 2, 3 and 4.
    "identical-rows": dict(start=0, rows=rows([
        (1 * S, "a", 2, "same"), (1 * S, "a", 3, "same"), (1 * S, "a", 4, "same"), (2 * S, "a", 2, "same"),
        (2 * S, "a", 2, "same"), (4 * S, "b", 5, "same")])),
    # Twelve rows 100 ms apart over two streams.
    "dense": dict(start=0, rows=rows([
        (i * 100 * MS, "ab"[i % 2], (i % 4) + 1, f"d{i}") for i in range(12)])),
    # A line filter removes rows that would otherwise be members of the kept chain.
    "filtered": dict(start=0, query='{app="api"} |= "err"', rows=rows([
        (1 * S, "a", 2, "err 1"), (1200 * MS, "a", 3, "ok 2"), (1500 * MS, "b", 2, "err 3"), (2 * S, "a", 1, "ok 4"),
        (2500 * MS, "a", 3, "err 5"), (3 * S, "b", 4, "err 6"), (3 * S, "a", 2, "err 7"), (4 * S, "a", 2, "ok 8")])),
    # Spacings of exactly 1 s, 1 s + 1 ns and 1 s - 1 ns between successive rows.
    "boundary": dict(start=0, rows=rows([
        (1 * S, "a", 2, "b1"), (2 * S, "a", 3, "b2"), (3 * S + 1, "a", 2, "b3"), (4 * S + 1, "b", 4, "b4"),
        (5 * S, "a", 1, "b5"), (6 * S - 1, "b", 3, "b6"), (7 * S - 1, "a", 2, "b7"), (8 * S, "a", 2, "b8")])),
    # One stream with rows before the epoch (a negative timestamp), at it and after it.
    "epoch": dict(start=-6 * S, rows=rows([
        (-4 * S, "a", 3, "e1"), (-3 * S, "a", 2, "e2"), (-3 * S, "a", 2, "e3"), (-2 * S, "a", 4, "e4"),
        (-1 * S, "a", 2, "e5"), (-1, "a", 3, "e6"), (0, "a", 2, "e7"), (1 * S, "a", 2, "e8"), (2 * S, "a", 2, "e9")])),
    # The ties of "ties-streams" under a label_format that makes stream a sort last by its query-visible label:
    # which tied entry is kept follows the ORIGINAL stream hash, the order of the answer the new labels.
    "relabelled": dict(start=0, grid=dict(intervals=[0, 500 * MS, 1 * S], limits=[1, 3, 100]),
                       query='{app="api"} | label_format host="{{ if eq .host \\"a\\" }}z{{ else }}{{ .host }}{{ end }}"',
                       rows=rows([
                           (1 * S, "c", 2, "x"), (1 * S, "a", 3, "x"), (1 * S, "b", 1, "y"), (2 * S, "b", 4, "z"), (2 * S, "a", 1, "z"),
                           (2 * S, "c", 2, "w"), (3 * S, "a", 2, "x"), (3 * S, "b", 2, "x"), (4 * S, "c", 3, "v")])),
}

INTERVALS = [0, 1, 100 * MS, 500 * MS, 1 * S - 1, 1 * S, 1 * S + 1, 1500 * MS, 2 * S, 10 * S]
LIMITS = [0, 1, 2, 3, 5, 100]
CONFIG = {"count_min_sketch_heap_size": "10000", "instant_log_lookback_ns": "30000000000"}


def case(name, direction, interval, limit, kind):
    f = FIXTURES[name]
    start = f["start"]
    end = start + 60 * S
    c = {"id": "logql-interval-multiplicity/%s/%s/i%d/l%d/%s" % (name, direction, interval, limit, kind),
         "phase": "logql-metric", "profiles": ["logql-loki-3.5.2"], "enabled_features": [],
         "configuration": CONFIG, "config_identity": "resolved-profile-manifest-default",
         "obligation": "logql-loki-3.5.2/log-ordering", "query": f.get("query", '{app="api"}'), "kind": kind,
         "direction": direction, "limit": str(limit), "interval_ns": str(interval), "entries": f["rows"]}
    if kind == "range":
        c.update(start_ns=str(start), end_ns=str(end), step_ns=str(S))
    else:
        c.update(time_ns=str(start + 30 * S))
    return c


def generate():
    cases = []
    for name, f in FIXTURES.items():
        intervals = f.get("grid", {}).get("intervals", INTERVALS)
        limits = f.get("grid", {}).get("limits", LIMITS)
        for direction in ("forward", "backward"):
            for interval in intervals:
                for limit in limits:
                    cases.append(case(name, direction, interval, limit, "range"))
        # The instant form of the raw query (the evaluation window is the 30 s look-back before the time).
        for direction in ("forward", "backward"):
            for interval in (500 * MS, 1 * S, 1 * S + 1, 2 * S):
                for limit in (3, 100):
                    if name != "relabelled":
                        cases.append(case(name, direction, interval, limit, "instant"))
    with open(CASES, "w", newline="\n") as f:
        json.dump({"schema": "soundpost-authored-logql-metric-cases-v1", "copyright": "Copyright 2026 Aryn Yklas",
                   "license": "Apache-2.0", "author": "Aryn Yklas", "phase": "logql-metric", "cases": cases},
                  f, separators=(",", ":"))
        f.write("\n")
    print("wrote", len(cases), "cases ->", CASES)


HOW = {
    "oci": "The reference ran as the digest-locked OCI image of source-lock.json.",
    "native": "The reference was a native build of the pinned source archive (sha256-verified against source-lock.json), "
              "not the digest-locked OCI image: the oracle.image_sha256 values of the run name the locked artifact the "
              "observation is bound to, not an image that executed.",
}


def record(report_path, how):
    report = json.load(open(report_path))
    assert report["failed"] == 0 and report["compared"] == len(report["cases"]), "record only a passing run"
    authored = {c["id"] for c in json.load(open(CASES))["cases"]}
    rows_ = []
    for c in report["cases"]:
        assert c["id"] in authored, c["id"]
        rows_.append({"case_id": c["id"], "reference": c["reference"]})
    assert len(rows_) == len(authored)
    rows_.sort(key=lambda r: r["case_id"])
    doc = {"provenance": "Observations of the pinned Loki 3.5.2 reference (commit 257d2f62bf8a81b44dea6fe88968d1d28c8e01e7, source archive "
                         "sha256 0db690662744694667c031a81d3e20cdd3a68a387a8050c8096bebbdf2ff8db2) through soundpost-querycheck's "
                         "logql-metric phase on conformance/query/cases/logql-interval-multiplicity.json (%d comparisons, 0 failed): raw log "
                         "queries with interval > 0 over stored rows of multiplicity > 1, both directions, limits, ties across streams, "
                         "line filters, the interval boundary and pre-epoch timestamps. Not authored predictions. " % report["compared"] + HOW[how],
           "rows": rows_}
    with open(OUT, "w", newline="\n") as f:
        json.dump(doc, f, separators=(",", ":"), ensure_ascii=False)
        f.write("\n")
    print("recorded", len(rows_), "observations ->", OUT)


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "generate":
        generate()
    elif len(sys.argv) == 4 and sys.argv[1] == "record" and sys.argv[3] in HOW:
        record(sys.argv[2], sys.argv[3])
    else:
        sys.exit(__doc__)
