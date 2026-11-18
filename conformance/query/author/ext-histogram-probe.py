#!/usr/bin/env python3
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Authors and records the extended-selector native-histogram probe (02.04#13).

22 native-histogram scenarios x 12 extended-selector queries (smoothed / anchored, on Prometheus
3.13.5 with promql-extended-range-selectors) x 5 instants, plus 22 x 7 x 5 plain-window control rows
on both pinned profiles (the evaluation phase requires applicable rows for both). Rows are authored
from the obligation text; no expectation is copied from any run.

From the repository root:

    python3 conformance/query/author/ext-histogram-probe.py generate
    python3 conformance/query/author/relock.py cases/promql-extended-histograms.json
    go run ./cmd/soundpost-querycheck compare --phase evaluation \\
      --cases conformance/query/cases/promql-extended-histograms.json \\
      --profiles promql-prometheus-3.1.0,promql-prometheus-3.13.5 --require-locked \\
      --runtime <docker> > report.json
    python3 conformance/query/author/ext-histogram-probe.py record report.json oci|native

`record` writes the reference observations of a passing run to
conformance/query/evidence/native-promql-extended-histogram-observations.json (content-locked in
source-lock.json), which TestOwnedMatchesRecordedNativeExtendedHistogramObservations replays
without a container runtime. The last argument states how the references ran and is written into
the file: `oci` (the digest-locked images) or `native`. Where no OCI runtime exists the references
can be built natively from the pinned archives: conformance/query/author/native-oracle.sh.
"""
import json
import struct
import sys

Q = "conformance/query"
CASES = f"{Q}/cases/promql-extended-histograms.json"
OUT = f"{Q}/evidence/native-promql-extended-histogram-observations.json"


def bits(f):
    return struct.pack(">d", f).hex()


NAN = "7ff8000000000001"
STALE = "7ff0000000000002"


def ih(sum_, count, zero_count=0, pos=None, neg=None, schema=0, hint="unknown", flavor="counter", zt=0.0, custom=None):
    h = {"flavor": flavor, "schema": schema, "zero_threshold": bits(zt), "sum": sum_ if isinstance(sum_, str) else bits(sum_),
         "count": str(count), "zero_count": str(zero_count),
         "positive_spans": [{"offset": o, "length": len(c)} for o, c in (pos or [])],
         "negative_spans": [{"offset": o, "length": len(c)} for o, c in (neg or [])],
         "positive_counts": [str(x) for _, c in (pos or []) for x in c], "reset_hint": hint}
    if neg:
        h["negative_counts"] = [str(x) for _, c in neg for x in c]
    if custom is not None:
        h["schema"] = -53
        h["custom_bounds"] = [bits(b) for b in custom]
    return {"integer": h}


def hs(t, h):
    return {"time": str(t * 10**9), "histogram": h}


def fs(t, f):
    return {"time": str(t * 10**9), "float_bits": f if isinstance(f, str) else bits(f)}


A = ih(6, 4, pos=[(1, [4])])
B = ih(12, 8, pos=[(1, [8])])
C = ih(20, 14, pos=[(1, [10, 4])])
SCENARIOS = {
    "01-rising": [hs(5, A), hs(15, B)],
    "02-reset": [hs(5, B), hs(15, A)],
    "03-schema-down": [hs(5, ih(6, 4, pos=[(1, [4])])), hs(15, ih(12, 8, schema=1, pos=[(2, [3, 5])]))],
    "04-schema-up": [hs(5, ih(12, 8, schema=1, pos=[(2, [3, 5])])), hs(15, ih(20, 14, pos=[(1, [14])]))],
    "05-zero-threshold": [hs(5, ih(6, 6, zero_count=2, pos=[(1, [4])], zt=0.5)), hs(15, ih(12, 12, zero_count=4, pos=[(1, [8])], zt=1.0))],
    "06-custom-same": [hs(5, ih(9, 6, custom=[1, 2], pos=[(0, [1, 2, 3])])), hs(15, ih(18, 12, custom=[1, 2], pos=[(0, [2, 4, 6])]))],
    "07-custom-bounds-change": [hs(5, ih(9, 6, custom=[1, 2], pos=[(0, [1, 2, 3])])), hs(15, ih(18, 12, custom=[1, 3], pos=[(0, [2, 4, 6])]))],
    "08-gauge-pair": [hs(5, ih(6, 4, pos=[(1, [4])], flavor="gauge", hint="gauge")), hs(15, ih(3, 2, pos=[(1, [2])], flavor="gauge", hint="gauge"))],
    "09-counter-then-gauge": [hs(5, A), hs(15, ih(3, 2, pos=[(1, [2])], flavor="gauge", hint="gauge"))],
    "10-gauge-then-counter": [hs(5, ih(6, 4, pos=[(1, [4])], flavor="gauge", hint="gauge")), hs(15, B)],
    "11-hint-reset": [hs(5, A), hs(15, ih(24, 16, pos=[(1, [16])], hint="reset"))],
    "12-hint-not-reset": [hs(5, B), hs(15, ih(6, 4, pos=[(1, [4])], hint="not_reset"))],
    "13-nan-sum": [hs(5, ih(NAN, 4, pos=[(1, [4])])), hs(15, ih(NAN, 8, pos=[(1, [6])]))],
    "14-float-then-hist": [fs(5, 2.0), hs(15, A)],
    "15-hist-then-float": [hs(5, A), fs(15, 3.0)],
    "16-single": [hs(15, A)],
    "17-three": [hs(5, A), hs(15, B), hs(25, C)],
    "18-stale-then-hist": [fs(5, STALE), hs(15, B)],
    "19-negative-and-zero": [hs(5, ih(0, 10, zero_count=2, pos=[(0, [1, 2, 3])], neg=[(0, [1, 1])])), hs(15, ih(0, 20, zero_count=4, pos=[(0, [2, 4, 6])], neg=[(0, [2, 2])]))],
    "20-exp-then-custom": [hs(5, A), hs(15, ih(18, 12, custom=[1, 2], pos=[(0, [2, 4, 6])]))],
    "21-wide-gap": [hs(5, A), hs(25, B)],
    "22-equal": [hs(5, A), hs(15, A)],
}
QUERIES = [
    "rate(m[10s] smoothed)", "rate(m[10s] anchored)", "increase(m[10s] smoothed)", "increase(m[10s] anchored)",
    "delta(m[10s] smoothed)", "delta(m[10s] anchored)", "histogram_count(rate(m[10s] smoothed))", "histogram_sum(increase(m[10s] anchored))",
    "m smoothed", "m anchored", "histogram_count(m smoothed)", "histogram_avg(m anchored)",
]
# Plain-window controls; rate/increase over histogram-only series of a plain name also observe review M3
# (no PossibleNonCounterInfo for float-free windows), the stddev/stdvar rows review M5 (custom-bucket histograms).
CONTROLS = ["rate(m[10s])", "increase(m[10s])", "histogram_count(m)", "histogram_stddev(m)", "histogram_stdvar(m)",
            "histogram_fraction(0, 2, m)", "histogram_quantile(0.5, m)"]
INSTANTS = [10, 15, 20, 25, 30]
LABELS = [{"name": "__name__", "value": "m"}, {"name": "job", "value": "generic"}]


def generate():
    cases = []
    for tag, queries, profiles, features in (("q", QUERIES, ["promql-prometheus-3.13.5"], ["promql-extended-range-selectors"]),
                                              ("c", CONTROLS, ["promql-prometheus-3.1.0", "promql-prometheus-3.13.5"], [])):
        for name, samples in SCENARIOS.items():
            for qi, q in enumerate(queries):
                for at in INSTANTS:
                    cases.append({
                        "id": "promql-extended-histograms/%s/%s%02d/t%d" % (name, tag, qi + 1, at),
                        "profiles": profiles, "enabled_features": features,
                        "query": q, "kind": "instant", "time": str(at * 10**9),
                        "series": [{"labels": LABELS, "samples": samples}],
                    })
    with open(CASES, "w", newline="\n") as f:
        json.dump({"phase": "evaluation", "cases": cases}, f, separators=(",", ":"))
        f.write("\n")
    print("wrote", len(cases), "cases ->", CASES)


HOW = {
    "oci": "The references ran as the digest-locked OCI images of source-lock.json.",
    "native": "The references were a native build of the pinned source archive (sha256-verified against source-lock.json), "
              "not the digest-locked OCI image: the oracle.image_sha256 values of the run name the locked artifact the "
              "observation is bound to, not an image that executed.",
}


def record(report_path, how):
    report = json.load(open(report_path))
    assert report["failed"] == 0 and report["compared"] == len(report["cases"]), "record only a passing run"
    authored = {c["id"] for c in json.load(open(CASES))["cases"]}
    rows = []
    for c in report["cases"]:
        assert c["id"] in authored, c["id"]
        rows.append({"profile": c["profile"], "case_id": c["id"], "reference": c["reference"]})
    rows.sort(key=lambda r: (r["profile"], r["case_id"]))
    doc = {"provenance": "Observations of the pinned Prometheus references (3.1.0 commit 7086161a93b262aa0949dbf2aba15a5a7b13e0a3, "
                         "3.13.5 commit f497435984d1ca1d84cda5ed309387ac2eb1f8f6) through soundpost-querycheck's evaluation phase on "
                         "conformance/query/cases/promql-extended-histograms.json (%d comparisons, 0 failed). Native-histogram corners of "
                         "the smoothed/anchored extended selectors. Not authored predictions. " % report["compared"] + HOW[how],
           "rows": rows}
    with open(OUT, "w", newline="\n") as f:
        # The authored cases are not repeated (they are content-locked in cases/); a file this size
        # (a case copy per row made it 6 MB) fails to read through ovnfs on the VMs.
        json.dump(doc, f, separators=(",", ":"), ensure_ascii=False)
        f.write("\n")
    print("recorded", len(rows), "observations ->", OUT)


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "generate":
        generate()
    elif len(sys.argv) == 4 and sys.argv[1] == "record" and sys.argv[3] in HOW:
        record(sys.argv[2], sys.argv[3])
    else:
        sys.exit(__doc__)
