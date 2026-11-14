#!/usr/bin/env python3
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Authors the release case files that carry the ledger's positive/negative/
interaction case IDs, the release-cases.json manifest, the content locks and the
production bindings. Run from the repository root:

    python3 conformance/query/author/release-author.py

Rows are authored from the obligation text (signature/kind) and from the
committed fixtures; no expected answer is copied from an upstream run. The
differential runners (owned engine versus the pinned reference) decide whether
each row matches; this script never records a verdict.
"""
import copy, hashlib, json, os, sys

Q = "conformance/query"
LEDGER = json.load(open(f"{Q}/obligations.json"))["obligations"]
BY_ID = {o["id"]: o for o in LEDGER}
LOGQL = "logql-loki-3.5.2"
PROM = ["promql-prometheus-3.1.0", "promql-prometheus-3.13.5"]


def load(name):
    return json.load(open(f"{Q}/cases/{name}"))


functions = {c["id"]: c for c in load("promql-functions.json")["cases"]}
metrics = load("logql-metrics-order.json")
syntax_lq = load("logql-syntax-pipeline.json")
HIST = load("promql-histograms.json")["cases"][0]["series"][0]["samples"][1]["histogram"]

new_eval, new_lq_syntax, new_lq_metric = [], [], []
authored = {}  # case id -> (file key)


def role_ids(o):
    return o["positive_cases"][0], o["negative_cases"][0], o["interaction_cases"][0]


def put(bucket, key, row):
    assert row["id"] not in authored, row["id"]
    authored[row["id"]] = key
    bucket.append(row)


# --- PromQL: function-signature and aggregation ------------------------------
SERIES_F = {"labels": [{"name": "__name__", "value": "metric_total"}, {"name": "instance", "value": "generic-a"}, {"name": "job", "value": "generic"}],
            "samples": [{"time": "5000000000", "float_bits": "3ff0000000000000"}, {"time": "10000000000", "float_bits": "4008000000000000"}, {"time": "15000000000", "float_bits": "4020000000000000"}]}
syn_types = {}
for c in load("promql-syntax.json")["cases"]:
    if c.get("expected", {}).get("accepted") and c.get("obligation"):
        syn_types.setdefault(c["obligation"], c["expected"].get("type"))

for o in LEDGER:
    if o["profile"] not in PROM or o["kind"] not in ("function-signature", "aggregation"):
        continue
    pos, neg, inter = role_ids(o)
    base = o["id"]
    normal = functions.get(base + "/normal")
    invalid = functions.get(base + "/type-invalid")
    if not normal or not invalid:
        continue
    typ = "vector" if o["kind"] == "aggregation" else syn_types.get(base)
    if typ not in ("vector", "scalar"):
        continue
    for rid, src, query in ((pos, normal, normal["query"]), (neg, invalid, invalid["query"])):
        r = copy.deepcopy(src)
        r["id"], r["query"] = rid, query
        put(new_eval, "promql-evaluation", r)
    r = copy.deepcopy(normal)
    r["id"], r["query"] = inter, f"({normal['query']}) * 2" if typ == "vector" else f"vector({normal['query']}) * 2"
    put(new_eval, "promql-evaluation", r)

# --- PromQL: operator overloads, set operators, value types -------------------
OPS = {"add": "+", "sub": "-", "mul": "*", "div": "/", "mod": "%", "pow": "^", "atan2": "atan2",
       "eq": "==", "ne": "!=", "gt": ">", "ge": ">=", "lt": "<", "le": "<="}
FLOAT_S = {"labels": [{"name": "__name__", "value": "fl_total"}, {"name": "instance", "value": "generic-a"}, {"name": "job", "value": "generic"}],
           "samples": [{"time": "15000000000", "float_bits": "4000000000000000"}]}
HIST_S = {"labels": [{"name": "__name__", "value": "hs_total"}, {"name": "instance", "value": "generic-a"}, {"name": "job", "value": "generic"}],
          "samples": [{"time": "15000000000", "histogram": copy.deepcopy(HIST)}]}


def erow(rid, profile, query, series, enabled=()):
    return {"id": rid, "profiles": [profile], "enabled_features": list(enabled), "query": query, "kind": "instant", "time": "20000000000", "series": copy.deepcopy(series)}


for o in LEDGER:
    if o["profile"] not in PROM:
        continue
    pos, neg, inter = role_ids(o)
    p = o["profile"]
    if o["kind"] == "operator-overload":
        parts = o["id"].split("/")
        if len(parts) != 4 or parts[2] not in OPS or "-" not in parts[3]:
            continue
        op = OPS[parts[2]]
        left, right = parts[3].split("-")
        if {left, right} - {"float", "histogram"}:
            continue
        sel = {"float": "fl_total", "histogram": "hs_total"}
        series = []
        for k in (left, right):
            s = FLOAT_S if k == "float" else HIST_S
            if s not in series:
                series.append(s)
        if left == right:
            # two distinct selectors of the same kind
            second = copy.deepcopy(series[0])
            second["labels"][0]["value"] = sel[left].replace("_total", "2_total")
            series.append(second)
            rhs = sel[left].replace("_total", "2_total")
        else:
            rhs = sel[right]
        lhs = sel[left]
        put(new_eval, "promql-evaluation", erow(pos, p, f"{lhs} {op} {rhs}", series))
        put(new_eval, "promql-evaluation", erow(neg, p, f'"text" {op} {rhs}', series))
        put(new_eval, "promql-evaluation", erow(inter, p, f"{lhs} {op} on(job) {rhs}", series))
    elif o["kind"] == "set-operator":
        word = o["id"].split("/")[-1]
        series = [FLOAT_S, copy.deepcopy(FLOAT_S)]
        series[1]["labels"][0]["value"] = "fl2_total"
        put(new_eval, "promql-evaluation", erow(pos, p, f"fl_total {word} fl2_total", series))
        put(new_eval, "promql-evaluation", erow(neg, p, f"fl_total {word} fl2_total[10s]", series))
        put(new_eval, "promql-evaluation", erow(inter, p, f"fl_total {word} on(job) fl2_total", series))
    elif o["kind"] == "value-type":
        word = o["id"].split("/")[-1]
        series = [FLOAT_S]
        q = {"instant-vector": ("fl_total", "fl_total[10s] + 1", "fl_total + 1"),
             "range-vector": ("fl_total[10s]", "fl_total[10s] + 1", "sum_over_time(fl_total[10s])"),
             "scalar": ("1", "scalar(fl_total[10s])", "fl_total + 1"),
             "string": ('"text"', '"text" + 1', 'label_replace(fl_total, "dst", "$1", "job", "(.*)")')}.get(word)
        if not q:
            continue
        put(new_eval, "promql-evaluation", erow(pos, p, q[0], series))
        put(new_eval, "promql-evaluation", erow(neg, p, q[1], series))
        put(new_eval, "promql-evaluation", erow(inter, p, q[2], series))

# --- LogQL -------------------------------------------------------------------
metric_rows = {}
for c in metrics["cases"]:
    metric_rows.setdefault(c.get("obligation"), []).append(c)


def lq_metric(rid, template, query, enabled=None):
    r = copy.deepcopy(template)
    r["id"], r["query"] = rid, query
    r.pop("obligation", None)
    r.pop("binding_scope", None)
    if enabled is not None:
        r["enabled_features"] = enabled
    return r


def lq_syntax(rid, expr, accepted, typ="", enabled=()):
    exp = {"accepted": accepted}
    if accepted:
        exp["type"] = typ
    return {"id": rid, "phase": "syntax", "profiles": [LOGQL], "enabled_features": list(enabled), "input": {"expression": expr}, "expected": exp}


TEMPLATE = next(c for c in metrics["cases"] if c["id"] == "owned-logql-metric-aggregate-sum")
for o in LEDGER:
    if o["profile"] != LOGQL:
        continue
    pos, neg, inter = role_ids(o)
    name = o["id"].split("/")[-1]
    if o["kind"] == "vector-aggregation":
        en = ["approx_topk"] if name == "approx_topk" else []
        inner = 'count_over_time({app="api"}[2s])'
        if name in ("topk", "bottomk", "approx_topk"):
            q_pos, q_int, q_neg = f"{name}(1, {inner})", f"{name} by (app) (1, {inner})", f'{name}(1, {{app="api"}})'
        elif name in ("sort", "sort_desc"):
            q_pos, q_int, q_neg = f"{name}({inner})", f"{name}(sum by (app) ({inner}))", f'{name}({{app="api"}})'
        else:
            q_pos, q_int, q_neg = f"{name}({inner})", f"{name} by (app) ({inner})", f'{name}({{app="api"}})'
        put(new_lq_metric, "logql-metric", lq_metric(pos, TEMPLATE, q_pos, en))
        put(new_lq_metric, "logql-metric", lq_metric(inter, TEMPLATE, q_int, en))
        put(new_lq_syntax, "logql-syntax", lq_syntax(neg, q_neg, False, enabled=en))
    elif o["kind"] == "range-aggregation":
        rows = metric_rows.get(o["id"], [])
        if not rows:
            continue
        base = rows[0]
        put(new_lq_metric, "logql-metric", lq_metric(pos, base, base["query"], base["enabled_features"]))
        put(new_lq_metric, "logql-metric", lq_metric(inter, base, f"sum by (app) ({base['query']})", base["enabled_features"]))
        if name == "quantile_over_time":
            neg_q = 'quantile_over_time({app="api"})'
        else:
            neg_q = f'{name}({{app="api"}})'
        put(new_lq_syntax, "logql-syntax", lq_syntax(neg, neg_q, False))
    elif o["kind"] == "binary-operator":
        op = OPS.get(name)
        if not op or name == "atan2":
            continue
        rows = metric_rows.get(o["id"], [])
        if not rows:
            continue
        base = rows[0]
        put(new_lq_metric, "logql-metric", lq_metric(pos, base, base["query"], base["enabled_features"]))
        put(new_lq_metric, "logql-metric", lq_metric(inter, base, f"vector(2) {op} on() vector(3)", base["enabled_features"]))
        put(new_lq_syntax, "logql-syntax", lq_syntax(neg, f'{{app="api"}} {op} 1', False))

# --- Extension modules ---------------------------------------------------------
# Each conformance/query/author/ext_<name>.py defines build(ctx). ctx.put(file, row)
# adds a case row to cases/<file>; ctx.declare(file, language, phase, header) declares
# the file before the first put; ctx.bind(obligation_id, implementation, go_tests)
# records the production binding for an obligation whose three ledger cases the
# module authored. A module never records a verdict: the differential runners decide.
import glob, importlib.util, types
AUTHOR_DIR = os.path.dirname(os.path.abspath(__file__))
ext_files = {}
ext_bind = {}


def _declare(name, language, phase, header=None):
    cur = ext_files.setdefault(name, {"language": language, "phase": phase, "header": header or {}, "rows": []})
    assert (cur["language"], cur["phase"]) == (language, phase), name
    return cur


def _put(name, row):
    assert name in ext_files, "declare the case file first: " + name
    assert row["id"] not in authored, row["id"]
    authored[row["id"]] = name
    ext_files[name]["rows"].append(row)


def _bind(oid, implementation, go_tests):
    assert oid in BY_ID, oid
    assert oid not in ext_bind, oid
    ext_bind[oid] = (implementation, list(go_tests))


ctx = types.SimpleNamespace(LEDGER=LEDGER, BY_ID=BY_ID, role_ids=role_ids, load=load, erow=erow, put=_put, declare=_declare, bind=_bind,
                            Q=Q, PROM=PROM, LOGQL=LOGQL, HIST=HIST, FLOAT_S=FLOAT_S, HIST_S=HIST_S, OPS=OPS, authored=authored)
ONLY = sys.argv[sys.argv.index("--only") + 1] if "--only" in sys.argv else None
for ext_path in sorted(glob.glob(os.path.join(AUTHOR_DIR, "ext_*.py"))):
    if ONLY and os.path.basename(ext_path) != f"ext_{ONLY}.py":
        continue
    spec = importlib.util.spec_from_file_location(os.path.basename(ext_path)[:-3], ext_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.build(ctx)
if ONLY:
    # Iteration mode: write and content-lock only this module's case files; the
    # manifest, the bindings and acceptance.json are produced by a full run.
    import subprocess
    written = []
    for name, spec in sorted(ext_files.items()):
        spec["rows"].sort(key=lambda c: c["id"])
        with open(f"{Q}/{name}", "w", newline="\n") as f:
            json.dump({**spec["header"], "cases": spec["rows"]}, f, indent=2, ensure_ascii=False)
            f.write("\n")
        written.append(name)
    subprocess.check_call([sys.executable, os.path.join(AUTHOR_DIR, "relock.py"), *written])
    print("wrote and locked:", {n: len(ext_files[n]["rows"]) for n in written})
    sys.exit(0)

# --- Write -------------------------------------------------------------------
HEADER = {"copyright": "Copyright 2026 Aryn Yklas", "license": "Apache-2.0"}


def dump(path, doc):
    with open(path, "w", newline="\n") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")


def key(c):
    return c["id"]


new_eval.sort(key=key); new_lq_syntax.sort(key=key); new_lq_metric.sort(key=key)
files = {}
if new_eval:
    files["cases/release-promql-evaluation.json"] = {"phase": "evaluation", "cases": new_eval}
if new_lq_syntax:
    files["cases/release-logql-syntax.json"] = {"schema": "soundpost-authored-logql-cases-v1", **HEADER, "phases": ["syntax"], "cases": new_lq_syntax}
if new_lq_metric:
    files["cases/release-logql-metric.json"] = {"schema": "soundpost-authored-logql-metric-cases-v1", **HEADER, "author": "Aryn Yklas", "phase": "logql-metric", "cases": new_lq_metric}
for name, spec in sorted(ext_files.items()):
    spec["rows"].sort(key=key)
    files[name] = {**spec["header"], "cases": spec["rows"]}
for name, doc in files.items():
    dump(f"{Q}/{name}", doc)

# Content locks: the runners read each file by the SHA-256 recorded in the lock.
import re
lock_path = f"{Q}/source-lock.json"
lock = open(lock_path, newline="").read()
anchor = '    "cases/logql-metrics-order.json"'
for name in files:
    digest = hashlib.sha256(open(f"{Q}/{name}", "rb").read()).hexdigest()
    entry = f'    "{name}": "{digest}"'
    pattern = re.compile(r'^    "' + re.escape(name) + r'": "[0-9a-f]{64}"', re.M)
    if pattern.search(lock):
        lock = pattern.sub(entry, lock)
    else:
        i = lock.index(anchor)
        j = lock.index("\n", i)
        lock = lock[: j + 1] + entry + ",\n" + lock[j + 1 :]
open(lock_path, "w", newline="").write(lock)

manifest = {"schema": "soundpost-query-release-cases/1", "files": []}
if "cases/release-promql-evaluation.json" in files:
    manifest["files"].append({"path": "cases/release-promql-evaluation.json", "language": "promql", "phase": "evaluation"})
if "cases/release-logql-syntax.json" in files:
    manifest["files"].append({"path": "cases/release-logql-syntax.json", "language": "logql", "phase": "syntax"})
if "cases/release-logql-metric.json" in files:
    manifest["files"].append({"path": "cases/release-logql-metric.json", "language": "logql", "phase": "logql-metric"})
for name, spec in sorted(ext_files.items()):
    manifest["files"].append({"path": name, "language": spec["language"], "phase": spec["phase"]})
manifest["files"].append({"path": "cases/logql-templates.json", "language": "logql", "phase": "logql-template"})
dump(f"{Q}/release-cases.json", manifest)

# the committed template rows already carry ledger IDs and are in the manifest
for fname in ("logql-templates.json",):
    for c in load(fname)["cases"]:
        authored.setdefault(c["id"], fname)

# Bindings only for obligations whose three ledger case IDs are all authored.
bound = []
for o in LEDGER:
    ids = o["positive_cases"] + o["negative_cases"] + o["interaction_cases"]
    if all(i in authored for i in ids):
        bound.append(o)
# --- Production bindings -------------------------------------------------------
PROM_KINDS = {
    "function-signature": ("internal/query/promql", ["TestAuthoredSignatureArityTypeAndGateCases", "TestEveryFunctionOverload"]),
    "aggregation": ("internal/query/promql", ["TestAggregationSemantics", "TestEveryFunctionOverload"]),
    "operator-overload": ("internal/query/promql", ["TestEveryPromQLOperator", "TestVectorOperatorValuesAndNameRules"]),
    "set-operator": ("internal/query/promql", ["TestEveryPromQLOperator", "TestVectorOperatorValuesAndNameRules"]),
    "value-type": ("internal/query/promql", ["TestEveryPromQLOperator", "TestAuthoredSignatureArityTypeAndGateCases"]),
    "vector-aggregation": ("internal/query/logql", ["TestEveryLogQLMetricObligation", "TestEveryLogQLMetricInventoryBinding"]),
    "range-aggregation": ("internal/query/logql", ["TestEveryLogQLMetricObligation", "TestEveryLogQLMetricInventoryBinding"]),
    "binary-operator": ("internal/query/logql", ["TestEveryLogQLMetricObligation", "TestEveryLogQLMetricInventoryBinding"]),
    "template-function": ("internal/query/logql", ["TestTemplateEveryHelper"]),
    "template": ("internal/query/logql", ["TestTemplateEveryHelper"]),
}
acc_path = f"{Q}/acceptance.json"
acc = json.load(open(acc_path))
bindings = []
for o in bound:
    if o["kind"] not in PROM_KINDS or o["id"] in ext_bind:
        continue
    impl, tests = PROM_KINDS[o["kind"]]
    bindings.append({"obligation_id": o["id"], "implementation": impl,
                     "cases": o["positive_cases"] + o["negative_cases"] + o["interaction_cases"],
                     "go_tests": tests + ["TestReleaseBindingsResolveToLockedCaseRows"]})
ext_unbound = []
for oid, (impl, tests) in sorted(ext_bind.items()):
    o = BY_ID[oid]
    ids = o["positive_cases"] + o["negative_cases"] + o["interaction_cases"]
    if not all(i in authored for i in ids):
        ext_unbound.append(oid)
        continue
    bindings.append({"obligation_id": oid, "implementation": impl, "cases": ids,
                     "go_tests": list(tests) + ["TestReleaseBindingsResolveToLockedCaseRows"]})
if ext_unbound:
    print("extension bindings skipped (cases not all authored):", ext_unbound)
acc["production_bindings"] = bindings
if "--observe" in sys.argv:
    # --observe <go test -json output> <command>: record the tests that passed in that exact output.
    evidence, command = sys.argv[sys.argv.index("--observe") + 1], sys.argv[sys.argv.index("--observe") + 2]
    digest = hashlib.sha256(open(evidence, "rb").read()).hexdigest()
    passed = set()
    for line in open(evidence):
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("Action") == "pass" and ev.get("Test") and "/" not in ev["Test"]:
            passed.add(ev["Test"])
    acc["test_observations"] = [{"name": n, "passed": True, "command": command, "evidence_sha256": digest} for n in sorted(passed)]
json.dump(acc, open(acc_path, "w", newline="\n"), indent=2, ensure_ascii=False)
open(acc_path, "a", newline="\n").write("\n")
print("bindings:", len(bindings))
print("authored rows:", {k: len(v["cases"]) for k, v in files.items()})
print("obligations with all three cases authored:", len(bound), "of", len(LEDGER))
