#!/usr/bin/env python3
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Authors and records the shard/replica probe of the pinned Loki 3.5.2 (07.05#10, 02.12-W2).

The OCI oracle feeds the engine a single iterator below every merge and never shards, so it
cannot observe (a) which strings of a `shard_aggregations` list the shard mapper recognizes,
(b) what the real sharded evaluation does with entries that two shard inputs both deliver
(replicas), (c) what the querier-side merge iterators collapse. This probe drives the pinned
sources directly (conformance/query/author/logql-shard-probe/main.go, compiled inside the
sha256-verified source archive like the oracle driver) over inputs authored here from the
obligation texts (iterator-entry-merge, iterator-sample-merge, shard-capability-domain).
No expectation is copied from any run.

From the repository root:

    python3 conformance/query/author/logql-shard-probe.py generate
    python3 conformance/query/author/relock.py cases/logql-shard-replica-probe.json
    conformance/query/author/native-oracle.sh build-loki-shard-probe
    "$NATIVE_ORACLE_DIR/logql-shard-probe" < conformance/query/cases/logql-shard-replica-probe.json > observed.json
    python3 conformance/query/author/logql-shard-probe.py record observed.json
    python3 conformance/query/author/relock.py evidence/native-logql-shard-replica-observations.json

`record` writes the observations to conformance/query/evidence/native-logql-shard-replica-observations.json
(content-locked in source-lock.json), which TestOwnedMatchesRecordedNativeShardAndReplicaObservations
replays without a container runtime. The reference is a native build of the pinned source archive
(D63), not the digest-locked OCI image; the recorded file says so.
"""
import json
import sys

Q = "conformance/query"
CASES = f"{Q}/cases/logql-shard-replica-probe.json"
OUT = f"{Q}/evidence/native-logql-shard-replica-observations.json"
S = 10**9

NAMES = ["first_over_time", "last_over_time", "quantile_over_time", "approx_topk"]

GATE_QUERIES = [
    {"id": "first", "kind": "first_over_time", "query": 'first_over_time({app="api"} | logfmt | unwrap n [2s]) by (host)'},
    {"id": "last", "kind": "last_over_time", "query": 'last_over_time({app="api"} | logfmt | unwrap n [2s]) by (host)'},
    {"id": "quantile", "kind": "quantile_over_time", "query": 'quantile_over_time(0.5, {app="api"} | logfmt | unwrap n [2s]) by (host)'},
    {"id": "approx", "kind": "approx_topk", "query": 'approx_topk(2, count_over_time({app="api"}[2s]))'},
    {"id": "control", "kind": "always", "query": 'sum by (host) (count_over_time({app="api"}[2s]))'},
]


def gate_lists():
    lists = []
    for mask in range(16):
        names = [n for i, n in enumerate(NAMES) if mask >> i & 1]
        lists.append(("subset-%s" % "".join(str(mask >> i & 1) for i in range(4)), names))
    extra = [
        ("duplicate-approx", ["approx_topk", "approx_topk"]),
        ("duplicate-first-with-last", ["first_over_time", "first_over_time", "last_over_time"]),
        ("duplicate-all-twice", NAMES + NAMES),
        ("unknown-only", ["bogus"]),
        ("unknown-before-approx", ["bogus", "approx_topk"]),
        ("unknown-after-approx", ["approx_topk", "bogus"]),
        ("unknown-between", ["first_over_time", "bogus", "quantile_over_time"]),
        ("case-approx", ["Approx_TopK"]),
        ("case-first-upper", ["FIRST_OVER_TIME"]),
        ("case-first-with-last", ["First_Over_Time", "last_over_time"]),
        ("space-after", ["approx_topk "]),
        ("space-before", [" approx_topk"]),
        ("newline-after", ["approx_topk\n"]),
        ("prefix-approx", ["shard-approx_topk"]),
        ("prefix-first", ["shard-first_over_time"]),
        ("prefix-last-quantile", ["shard-last_over_time", "shard-quantile_over_time"]),
        ("csv-first-last", ["first_over_time,last_over_time"]),
        ("csv-approx-quantile", ["approx_topk,quantile_over_time"]),
        ("empty-string", [""]),
        ("empty-string-with-approx", ["", "approx_topk"]),
        ("reversed", list(reversed(NAMES))),
        ("other-range-aggregation", ["sum_over_time"]),
        ("variants-name", ["multi-variant-queries"]),
        ("topk-name", ["topk"]),
    ]
    return lists + extra


def entry(ts, host, line):
    return {"ts": str(ts), "host": host, "line": line}


def sample(ts, host, value, h):
    return {"ts": str(ts), "host": host, "value": value, "hash": str(h)}


LOG_FIXTURES = [
    # the same entries delivered by both shard inputs (replicas), with a second stream and a line repeated across streams
    ("replica", [[entry(1 * S, "a", "x"), entry(2 * S, "a", "y"), entry(2 * S, "b", "x")]] * 2),
    # a line repeated inside one input at one timestamp, delivered by both inputs
    ("replica-inner-dup", [[entry(1 * S, "a", "same"), entry(1 * S, "a", "same"), entry(2 * S, "a", "y")]] * 2),
    # no entry in common
    ("disjoint", [[entry(1 * S, "a", "x")], [entry(2 * S, "a", "y")]]),
    # one entry in common
    ("partial-overlap", [[entry(1 * S, "a", "x"), entry(2 * S, "a", "y")], [entry(2 * S, "a", "y"), entry(3 * S, "a", "z")]]),
    # two lines at one timestamp, the inputs list them in opposite orders
    ("same-ts-opposite-order", [[entry(1 * S, "a", "p"), entry(1 * S, "a", "q")], [entry(1 * S, "a", "q"), entry(1 * S, "a", "p")]]),
    # the same line at one timestamp in two streams, delivered by both inputs
    ("cross-stream-replica", [[entry(1 * S, "a", "same"), entry(1 * S, "b", "same")]] * 2),
    # same timestamp and line, but a different stream in each input
    ("same-line-other-stream", [[entry(1 * S, "a", "x")], [entry(1 * S, "b", "x")]]),
    # one entry delivered by three inputs
    ("triple-replica", [[entry(1 * S, "a", "x")]] * 3),
    # a line repeated inside the first input only
    ("inner-dup-first-only", [[entry(1 * S, "a", "d"), entry(1 * S, "a", "d")], [entry(2 * S, "a", "e")]]),
    # tied entries of two streams whose original stream hash order (g before c) is not their label order (c before g)
    ("cross-stream-hash-order", [[entry(1 * S, "c", "x"), entry(1 * S, "g", "x")], [entry(1 * S, "g", "x"), entry(1 * S, "c", "x")]]),
]

SAMPLE_FIXTURES = [
    ("replica-hash", [[sample(1 * S, "a", 1.0, 11), sample(2 * S, "a", 2.0, 12)]] * 2),
    ("replica-zero-hash", [[sample(1 * S, "a", 1.0, 0), sample(2 * S, "a", 2.0, 0)]] * 2),
    ("same-value-other-hash", [[sample(1 * S, "a", 1.0, 11)], [sample(1 * S, "a", 1.0, 12)]]),
    ("same-hash-other-value", [[sample(1 * S, "a", 1.0, 11)], [sample(1 * S, "a", 2.0, 11)]]),
    ("inner-dup-hash", [[sample(1 * S, "a", 1.0, 11), sample(1 * S, "a", 1.0, 11)]] * 2),
    ("cross-stream-same-hash", [[sample(1 * S, "a", 1.0, 11)], [sample(1 * S, "b", 1.0, 11)]]),
    ("partial-overlap-hash", [[sample(1 * S, "a", 1.0, 11), sample(2 * S, "a", 2.0, 12)], [sample(2 * S, "a", 2.0, 12), sample(3 * S, "a", 3.0, 13)]]),
]


def generate():
    doc = {"schema": "soundpost-authored-logql-shard-replica-cases-v1", "copyright": "Copyright 2026 Aryn Yklas",
           "license": "Apache-2.0", "author": "Aryn Yklas",
           "gating": {"queries": GATE_QUERIES, "lists": [{"id": i, "names": n} for i, n in gate_lists()]},
           "fixtures": [{"id": i, "inputs": ins} for i, ins in LOG_FIXTURES],
           "sample_fixtures": [{"id": i, "inputs": ins} for i, ins in SAMPLE_FIXTURES],
           "frontend": [], "merges": [], "sample_merges": []}
    for fid, _ in LOG_FIXTURES:
        for direction in ("forward", "backward"):
            for limit in (100, 2):
                doc["frontend"].append({"id": f"frontend/{fid}/{direction}/l{limit}", "fixture": fid, "direction": direction, "limit": limit})
            for mode in ("merge-all", "merge-first", "sort-all"):
                doc["merges"].append({"id": f"merge/{fid}/{direction}/{mode}", "fixture": fid, "direction": direction, "mode": mode})
    for fid, _ in SAMPLE_FIXTURES:
        for mode in ("merge-all", "merge-first", "sort-all"):
            doc["sample_merges"].append({"id": f"sample-merge/{fid}/{mode}", "fixture": fid, "mode": mode})
    with open(CASES, "w", newline="\n") as f:
        json.dump(doc, f, separators=(",", ":"))
        f.write("\n")
    print("wrote", CASES, "gating rows", len(doc["gating"]["lists"]) * len(GATE_QUERIES), "frontend", len(doc["frontend"]),
          "merges", len(doc["merges"]), "sample merges", len(doc["sample_merges"]))


HOW = ("The reference was a native build of the pinned source archive (sha256-verified against source-lock.json), "
       "not the digest-locked OCI image: the probe drives the pinned sources below the layer the OCI oracle's fixture "
       "driver reaches (the shard mapper's string switch, the real sharded frontend evaluation over two shard inputs, "
       "and the querier-side merge iterators), which the image does not expose.")


def record(path):
    observed = json.load(open(path))
    authored = json.load(open(CASES))
    assert observed["profile"] == "logql-loki-3.5.2" and observed["commit"] == "257d2f62bf8a81b44dea6fe88968d1d28c8e01e7"
    assert len(observed["gating"]) == len(authored["gating"]["lists"]) * len(authored["gating"]["queries"])
    assert [o["id"] for o in observed["frontend"]] == [c["id"] for c in authored["frontend"]]
    assert [o["id"] for o in observed["merges"]] == [c["id"] for c in authored["merges"]]
    assert [o["id"] for o in observed["sample_merges"]] == [c["id"] for c in authored["sample_merges"]]
    for group in ("frontend", "merges", "sample_merges"):
        for o in observed[group]:
            assert not o.get("error"), (o["id"], o["error"])
    doc = {"provenance": "Observations of the pinned Loki 3.5.2 (commit 257d2f62bf8a81b44dea6fe88968d1d28c8e01e7, source archive "
                         "sha256 0db690662744694667c031a81d3e20cdd3a68a387a8050c8096bebbdf2ff8db2, %s) on "
                         "conformance/query/cases/logql-shard-replica-probe.json: %d shard-mapper gating rows, %d sharded frontend runs of a raw "
                         "log query over two or three shard inputs, %d entry-iterator and %d sample-iterator merges. Not authored predictions. "
                         % (observed["compiler"], len(observed["gating"]), len(observed["frontend"]), len(observed["merges"]), len(observed["sample_merges"])) + HOW,
           "gating": observed["gating"], "frontend": observed["frontend"], "merges": observed["merges"], "sample_merges": observed["sample_merges"]}
    with open(OUT, "w", newline="\n") as f:
        json.dump(doc, f, separators=(",", ":"), ensure_ascii=False)
        f.write("\n")
    print("recorded ->", OUT)


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "generate":
        generate()
    elif len(sys.argv) == 3 and sys.argv[1] == "record":
        record(sys.argv[2])
    else:
        sys.exit(__doc__)
