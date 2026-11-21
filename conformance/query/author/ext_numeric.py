# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Authors the `numeric` partition: function-numeric-domain rows for the 22 math
functions plus the numeric/semantic facts and families. Every row is a real
differential evaluation row (owned engine versus the pinned Prometheus oracle).
Expected values are never produced here: the differential runner decides, and
the independent Go tests (internal/query/promql/release_numeric*_test.go) hold
the hand-authored binary64 expectations. Helpers live in numeric_lib.py; the
fact/family row specs live in numeric_facts_*.py."""
import importlib.util, math, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from numeric_lib import *  # noqa: E402,F401,F403

FILE_FUNCTIONS = "cases/release-numeric-functions.json"
FILE_FACTS = "cases/release-numeric-facts.json"
PI = math.pi
# (positive: in-domain values, negative: out-of-domain / overflow / invalid-kind values).
NUMERIC = {
    "abs": ([-INF, -2.5, NZ, 0.0, SUB, 3.75, INF], [NAN]),
    "acos": ([-1.0, -0.5, NZ, 0.0, SUB, 0.5, 1.0], [-1.5, 2.0, 1.0000000000000002, INF, -INF, NAN]),
    "acosh": ([1.0, 1.0000000000000002, 2.0, 1e300, INF], [0.5, 0.0, NZ, -3.0, -INF, SUB, NAN]),
    "asin": ([-1.0, -0.5, NZ, 0.0, SUB, 0.5, 1.0], [-2.0, 1.0000000000000002, INF, -INF, NAN]),
    "asinh": ([-INF, -2.5, NZ, 0.0, SUB, 3.75, INF], [NAN]),
    "atan": ([-INF, -2.5, NZ, 0.0, SUB, 3.75, INF], [NAN]),
    "atanh": ([-0.5, NZ, 0.0, SUB, 0.5, 1.0, -1.0], [-2.0, 1.0000000000000002, INF, -INF, NAN]),
    "ceil": ([-2.5, -0.5, NZ, 0.0, SUB, 0.5, 3.75, 4503599627370495.5, INF, -INF], [NAN]),
    "cos": ([-2.5, NZ, 0.0, SUB, 0.75, 1e22, PI / 2], [INF, -INF, NAN]),
    "cosh": ([-2.5, NZ, 0.0, SUB, 0.75, 710.0, -710.0, INF, -INF], [711.0, -711.0, 1e300, NAN]),
    "deg": ([-2.5, NZ, 0.0, SUB, 3.75, PI / 2, PI, INF, -INF], [1e307, -1e307, NAN]),
    "exp": ([-2.5, NZ, 0.0, SUB, 0.75, 1.0, 709.0, INF, -INF], [710.0, -746.0, 1e300, NAN]),
    "floor": ([-2.5, -0.5, NZ, 0.0, SUB, 0.5, 3.75, 4503599627370495.5, INF, -INF], [NAN]),
    "ln": ([SUB, 1e-300, 0.5, 1.0, math.e, 1e300, INF], [0.0, NZ, -1.0, -SUB, -INF, NAN]),
    "log10": ([SUB, 1e-300, 0.5, 1.0, 10.0, 1000.0, 1e300, INF], [0.0, NZ, -1.0, -SUB, -INF, NAN]),
    "log2": ([SUB, 1e-300, 0.5, 1.0, 8.0, 1024.0, 1e300, INF], [0.0, NZ, -1.0, -SUB, -INF, NAN]),
    "rad": ([-2.5, NZ, 0.0, SUB, 3.75, 180.0, 90.0, INF, -INF], [1.7976931348623157e308, NAN]),
    "sgn": ([-INF, -2.5, NZ, 0.0, SUB, 3.75, INF], [NAN]),
    "sin": ([-2.5, NZ, 0.0, SUB, 0.75, 1e22, PI / 2], [INF, -INF, NAN]),
    "sinh": ([-2.5, NZ, 0.0, SUB, 0.75, 710.0, -710.0, INF, -INF], [711.0, -711.0, 1e300, NAN]),
    "sqrt": ([NZ, 0.0, SUB, 0.25, 2.0, 1e300, INF], [-1.0, -SUB, -INF, NAN]),
    "tan": ([-2.5, NZ, 0.0, SUB, 0.75, 1e22, PI / 2], [INF, -INF, NAN]),
}
IMPL = "internal/query/promql"
FUNCTION_TESTS = ["TestReleaseNumericFunctionDomains", "TestReleaseNumericFiniteResultsAreGoMath"]
EXTRA_TESTS = {
    "ln": ["TestReleaseNumericLogSubnormalFollowsPinnedAmd64Math"],
    "log10": ["TestReleaseNumericLogSubnormalFollowsPinnedAmd64Math"],
}


def fixture(ctx, name, values, t=15, hist=True):
    out = [fser(name, [(t, v)], case="v%02d" % i) for i, v in enumerate(values)]
    if hist:
        out.append(hser(ctx, name, [(t, mkhist(ctx))], case="hist"))
    return out


def interactions(ctx, f, pos, idx):
    """The interaction row of function f: the function combined with a range query,
    aggregation, comparison, offset, @, subquery, range function or binary operator."""
    fin = [v for v in pos if math.isfinite(v)]
    a, b, c = (fin + fin)[:3]
    k = idx % 8
    if k == 0:  # range query: the value changes with the step
        s = [fser("nd_in", [(5, a), (15, b), (25, c)], case="v0"), fser("nd_in", [(5, c), (15, a), (25, b)], case="v1")]
        return spec("%s(nd_in)" % f, s, kind="range", start=5, end=25, step=5)
    if k == 1:  # aggregation over the result
        s = [fser("nd_in", [(15, a)], case="v0", grp="x"), fser("nd_in", [(15, b)], case="v1", grp="x"), fser("nd_in", [(15, c)], case="v2", grp="y")]
        return spec("sum by (grp) (%s(nd_in))" % f, s)
    if k == 2:  # bool comparison of the result
        s = [fser("nd_in", [(15, v)], case="v%02d" % i) for i, v in enumerate(pos)] + [hser(ctx, "nd_in", [(15, mkhist(ctx))], case="hist")]
        return spec("%s(nd_in) > bool 0" % f, s)
    if k == 3:  # offset: the older sample is used, the newer is ignored
        s = [fser("nd_in", [(5, a), (15, c)], case="v0"), fser("nd_in", [(5, b), (15, a)], case="v1")]
        return spec("%s(nd_in offset 10s)" % f, s)
    if k == 4:  # @ modifier selects a fixed evaluation time
        s = [fser("nd_in", [(5, a), (10, b), (15, c)], case="v0")]
        return spec("%s(nd_in @ 10)" % f, s)
    if k == 5:  # subquery over the function
        s = [fser("nd_in", [(5, a), (10, b), (15, c)], case="v0")]
        return spec("max_over_time(%s(nd_in)[15s:5s])" % f, s)
    if k == 6:  # composition with a range function
        s = [fser("nd_in", [(5, a), (10, b), (15, c)], case="v0")]
        return spec("%s(avg_over_time(nd_in[20s]))" % f, s)
    # binary operator against another function result, matched on a label
    s = [fser("nd_in", [(15, a)], case="v0"), fser("nd_in", [(15, b)], case="v1"), fser("nd_aux", [(15, c)], case="v0"), fser("nd_aux", [(15, a)], case="v1")]
    return spec("%s(nd_in) + on(case) %s(nd_aux)" % (f, f), s)


def build_functions(ctx):
    for idx, f in enumerate(sorted(NUMERIC)):
        pos, neg = NUMERIC[f]
        for prof in ctx.PROM:
            o = ctx.BY_ID["%s/numeric/%s" % (prof, f)]
            p_id, n_id, i_id = ctx.role_ids(o)
            ctx.put(FILE_FUNCTIONS, row(p_id, prof, "%s(nd_in)" % f, fixture(ctx, "nd_in", pos)))
            ctx.put(FILE_FUNCTIONS, row(n_id, prof, "%s(nd_in)" % f, fixture(ctx, "nd_in", neg)))
            ctx.put(FILE_FUNCTIONS, spec_row(i_id, prof, interactions(ctx, f, pos, idx)))
            ctx.bind(o["id"], IMPL, FUNCTION_TESTS + EXTRA_TESTS.get(f, []))


def load_module(name):
    path = os.path.join(HERE, name + ".py")
    if not os.path.exists(path):
        return None
    spec_ = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec_)
    spec_.loader.exec_module(module)
    return module


def build_facts(ctx, module_name, file_key):
    module = load_module(module_name)
    if module is None:
        return
    for signature, fn in module.FACTS.items():
        for prof in ctx.PROM:
            oid = "%s/%s" % (prof, signature)
            if oid not in ctx.BY_ID:
                continue
            o = ctx.BY_ID[oid]
            p_id, n_id, i_id = ctx.role_ids(o)
            pos, neg, inter = fn(ctx, prof)
            for rid, s in ((p_id, pos), (n_id, neg), (i_id, inter)):
                ctx.put(file_key, spec_row(rid, prof, s))
            ctx.bind(oid, IMPL, module.TESTS[signature])


def build(ctx):
    ctx.declare(FILE_FUNCTIONS, "promql", "evaluation", {"phase": "evaluation"})
    build_functions(ctx)
    ctx.declare(FILE_FACTS, "promql", "evaluation", {"phase": "evaluation"})
    for module_name in ("numeric_facts_a", "numeric_facts_b", "numeric_facts_c"):
        build_facts(ctx, module_name, FILE_FACTS)
    scratch = load_module("numeric_scratch")
    if scratch is not None:  # local experiments only; removed before hand-off
        ctx.declare("cases/release-numeric-scratch.json", "promql", "evaluation", {"phase": "evaluation"})
        for i, s in enumerate(scratch.ROWS(ctx)):
            for prof in ctx.PROM:
                ctx.put("cases/release-numeric-scratch.json", spec_row("scratch/%03d/%s" % (i, prof), prof, s))
