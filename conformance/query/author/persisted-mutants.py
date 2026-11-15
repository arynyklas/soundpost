#!/usr/bin/env python3
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Mutation evidence for the persisted-path stages of the smoke runner
(internal/conformance/query/smoke: adapters, native histograms, LogQL logs, warm/cold
cache and injected scan faults; 02.12-W5..W8). Each mutant is one named, deliberate
product defect, applied to the product (never to the smoke runner or its case file);
the persisted-path test of BOTH layouts (single and three-voter distributed) must
fail on it and name the stage family that caught it. RUN ONLY IN A THROWAWAY COPY of
the repository (it rewrites product files in place and restores them):

    python3 conformance/query/author/persisted-mutants.py --throwaway-copy [name ...]
"""
import re, subprocess, sys

FAMILY = "persisted"
TESTS = "^(TestPersistedPathAnswersAreIdenticalAtEveryStage|TestDistributedPersistedPathAnswersAreIdenticalAtEveryStage)$"

# (name, stage family it must be caught by, file, old, new)
MUTANTS = [
    ("adapter-remote-write-float-bit-flipped", "adapter/remote-write", "internal/adapters/queryinput/remote_write.go",
     "\t\tbits := model.FloatBits(sm.bits)\n\t\tm.Value = &bits", "\t\tbits := model.FloatBits(sm.bits ^ 1)\n\t\tm.Value = &bits"),
    ("adapter-openmetrics-float-bit-flipped", "adapter/openmetrics-scrape", "internal/adapters/queryinput/openmetrics.go",
     "\t\tbits := model.FloatBits(s.bits)\n\t\tm := model.MetricPoint{Name: s.name,", "\t\tbits := model.FloatBits(s.bits ^ 1)\n\t\tm := model.MetricPoint{Name: s.name,"),
    ("adapter-loki-line-altered", "adapter/loki-push", "internal/adapters/queryinput/loki_push.go",
     "if err := l.entry(labels, ts, line, md); err != nil {", 'if err := l.entry(labels, ts, line+".", md); err != nil {'),
    ("adapter-conditions-status-altered", "adapter/conditions-webhook", "internal/adapters/queryinput/conditions.go",
     "Status: w.Status, Severity: w.Severity,", 'Status: w.Status + "x", Severity: w.Severity,'),
    ("native-integer-count-loses-precision", "native/", "internal/adapters/queryinput/remote_write.go",
     "Count: model.Uint64(h.countInt), ZeroCount:", "Count: model.Uint64(uint64(float64(h.countInt))), ZeroCount:"),
    ("compaction-drops-a-segment-group", "manifest-reconciles", "internal/storage/compact.go",
     "\tsort.Strings(keys)\n\tfor _, key := range keys {", "\tsort.Strings(keys)\n\tif len(keys) > 1 {\n\t\tkeys = keys[:len(keys)-1]\n\t}\n\tfor _, key := range keys {"),
    ("compaction-drops-log-pages", "logs/", "internal/storage/flush.go",
     "\t\t\tif hotOnly && p.Segment != \"\" {", "\t\t\tif !hotOnly && p.Kind == model.Log {\n\t\t\t\treturn nil\n\t\t\t}\n\t\t\tif hotOnly && p.Segment != \"\" {"),
    ("discovery-cursor-names-first-item", "logs/discovery", "internal/query/discover.go",
     'e.issueCursor(ctx, scope, "discover", digest, items[len(items)-1])', 'e.issueCursor(ctx, scope, "discover", digest, items[0])'),
    ("rule-never-leaves-pending", "logs/rule", "internal/rules/reducer.go",
     "if after == PhasePending && eval.At-st.Since >= forNS {", "if after == PhasePending && eval.At-st.Since >= forNS+1<<62 {"),
    ("live-entry-multiplicity-doubled", "logs/live", "internal/query/live.go",
     "Multiplicity: 1, Record: *payload.Log}", "Multiplicity: 2, Record: *payload.Log}"),
    ("cache-key-ignores-delete-generation", "faults/warm-entry-dies-with-the-delete-generation", "internal/auth/cache.go",
     "binary.BigEndian.PutUint64(n[8:], b.deletion)", "binary.BigEndian.PutUint64(n[8:], 0)"),
    ("cache-never-hits", "cache/warm", "internal/query/cache.go",
     "if res.Hit && !res.Negative {", "if false {"),
    ("cache-stores-failed-results", "leaves-no-cached-failure", "internal/query/cache.go",
     "\t\tif pr.Failure != nil || pr.Completeness != CompletenessComplete {\n\t\t\treturn\n\t\t}", "\t\tif pr.Completeness == \"never\" {\n\t\t\treturn\n\t\t}"),
    ("scan-error-ends-the-scan-quietly", "corrupt-never-empty", "internal/query/scan/metric.go",
     "\t\t\tif errors.Is(e, io.EOF) {\n\t\t\t\tif err = r.Account.Check(ctx); err != nil {", "\t\t\tif e != nil && (errors.Is(e, io.EOF) || true) {\n\t\t\t\tif err = r.Account.Check(ctx); err != nil {"),
    ("unavailable-scan-answers-empty", "missing-shard-is-unavailable-never-empty", "internal/query/scan/metric.go",
     "\tif err != nil {\n\t\treturn nil, err\n\t}\n\tdefer func() {\n\t\tce := rows.Close()", "\tif err != nil {\n\t\treturn &metricIterator{account: r.Account}, nil\n\t}\n\tdefer func() {\n\t\tce := rows.Close()"),
    ("deletion-during-compute-is-not-stale", "deletion-during-compute-is-stale-never-success", "internal/query/engine.go",
     "\tif now != gen {\n\t\treturn model.Fail(model.Stale)\n\t}", "\tif now != gen && false {\n\t\treturn model.Fail(model.Stale)\n\t}"),
]


def go_test():
    out = subprocess.run(["go", "test", "-count=1", "-timeout", "30m", "./internal/conformance/query/smoke", "-run", TESTS], capture_output=True, text=True)
    return out.returncode, out.stdout + out.stderr


def verdict(text):
    layouts = []
    for test, layout in (("TestPersistedPathAnswersAreIdenticalAtEveryStage", "single"), ("TestDistributedPersistedPathAnswersAreIdenticalAtEveryStage", "distributed")):
        if re.search(r"--- FAIL: " + test + r"\b", text):
            layouts.append(layout)
    steps = sorted({m.group(1) for m in re.finditer(r"FAIL ([A-Za-z0-9_./=:-]+) ", text)})
    return layouts, steps


if "--throwaway-copy" not in sys.argv:
    sys.exit("refusing to mutate a checkout that is not a throwaway copy")
only = [a for a in sys.argv[1:] if not a.startswith("--")]
rc, text = go_test()
print("baseline", "PASS" if rc == 0 else "FAIL", flush=True)
if rc:
    print(text[-3000:])
    sys.exit(1)
bad = 0
for name, family, path, old, new in MUTANTS:
    if only and name not in only:
        continue
    original = open(path, newline="").read()
    if original.count(old) != 1:
        print(f"{name}: UNAPPLICABLE (pattern found {original.count(old)} times in {path})")
        bad += 1
        continue
    open(path, "w", newline="").write(original.replace(old, new))
    try:
        rc, text = go_test()
    finally:
        open(path, "w", newline="").write(original)
    layouts, steps = verdict(text)
    hit = [s for s in steps if family in s]
    ok = rc != 0 and layouts == ["single", "distributed"] and bool(hit)
    bad += not ok
    print(f"{name}: {'KILLED' if ok else 'NOT-PROVEN'} rc={rc} layouts={layouts} family={family!r} named={len(hit)} first={hit[:2]} total-failing-steps={len(steps)}", flush=True)
    if not ok:
        print("   " + text[-1500:].replace("\n", "\n   "), flush=True)
rc, text = go_test()
print("restored", "PASS" if rc == 0 else "FAIL")
sys.exit(1 if bad or rc else 0)
