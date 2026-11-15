# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Wave-6 annotation de-duplication and NaN-payload rows (02.12-W3 part B).

Every row is a real differential evaluation row against both PromQL pins; the
oracle decides each verdict. No expected value is written here. The rows vary
what the pinned engines key annotations on (rendered text: metric name, value,
operator, aggregation name) across call sites, and which NaN payload survives
sum()/avg()/... and the range functions that share the Kahan step, over input
payloads, operand order and group size."""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from ext_histogram import ih, fh, hs, fl, series, labels, row, bits, HE, HE2, HG, HC1, HC2, HQ  # noqa: E402

FILE = "cases/promql-wave6-annotations-nan.json"
BOTH = ["promql-prometheus-3.1.0", "promql-prometheus-3.13.5"]
P31, P313 = BOTH
INF = float("inf")
TU = ["type-and-unit-labels"]
EXP = ["promql-experimental-functions"]

N1, N2, N3, N4 = "7ff8000000000001", "7ff8000000000002", "7ff8000000000003", "7ff8000000000004"
NNEG = "fff8000000000001"
SNAN = "7ff0000000000001"
STALE = "7ff0000000000002"

ROWS = []  # (short, query, series, profiles, enabled, kind, grid)


def R(short, query, ser, profiles=BOTH, enabled=(), kind="instant", **grid):
    ROWS.append((short, query, ser, tuple(profiles), tuple(enabled), kind, grid))


def fb(t, v):
    return {"time": str(int(t * 1_000_000_000)), "float_bits": v if isinstance(v, str) else bits(v)}


def group(name, vals, t=15, **kv):
    """One single-sample series per value, label i = a, b, c ... in order."""
    return [series(name, [fb(t, v)], i=chr(97 + k), **kv) for k, v in enumerate(vals)]


def window(name, vals, **kv):
    """One series with samples at 5s, 10s, 15s, ... (all inside a [20s] window)."""
    return [series(name, [fb(5 * (k + 1), v) for k, v in enumerate(vals)], **kv)]


# --- NaN payload in aggregations ------------------------------------------------
PAYLOADS = {
    "n1n2": [N1, N2],
    "n2n1": [N2, N1],
    "neg-pos": [NNEG, N2],
    "pos-neg": [N2, NNEG],
    "n1n2n3": [N1, N2, N3],
    "n3n2n1": [N3, N2, N1],
    "n1n2n3n4": [N1, N2, N3, N4],
    "fin-n1-fin-n2": [1.0, N1, 3.0, N2],
    "n1-fin-n2-fin": [N1, 1.0, N2, 3.0],
    "n2-fin-fin-n1": [N2, 1.0, 3.0, N1],
    "fin-fin-n1": [1.0, 2.0, N1],
    "n1-fin-n2": [N1, 2.0, N2],
    "inf-ninf-n1": [INF, -INF, N1],
    "n1-inf-ninf-n2": [N1, INF, -INF, N2],
    "snan-n2": [SNAN, N2],
    "n2-snan": [N2, SNAN],
    "single-n1": [N1],
    "stale-n1": [STALE, N1],
    "n1-stale-n2": [N1, STALE, N2],
    "five": [N1, N2, N3, N4, NNEG],
}
AGGS = ["sum", "avg", "stddev", "stdvar", "min", "max", "count", "group", 'quantile(0.5, %s)', 'topk(1, %s)', 'bottomk(2, %s)']
for pk, vals in PAYLOADS.items():
    for ak in AGGS:
        q = ak % "nanp" if "%s" in ak else "%s(nanp)" % ak
        a = ak.split("(")[0]
        R("agg/%s/%s" % (a, pk), q, group("nanp", vals))
    R("agg/sum-by/%s" % pk, "sum by (job) (nanp)", group("nanp", vals, job="g"))
    R("agg/sum-without/%s" % pk, "sum without (i) (nanp)", group("nanp", vals, job="g"))
# two groups, payloads split across groups
R("agg/sum-by-two-groups", "sum by (job) (nanp)",
  group("nanp", [N1, N2], job="g1") + [series("nanp", [fb(15, N3)], i="c", job="g2"), series("nanp", [fb(15, N4)], i="d", job="g2")])
# nested aggregation: payloads flow through two levels
R("agg/sum-of-sum", "sum(sum by (job) (nanp))",
  group("nanp", [N1, N2], job="g1") + [series("nanp", [fb(15, N3)], i="c", job="g2"), series("nanp", [fb(15, N4)], i="d", job="g2")])

# --- NaN payload in range functions (same Kahan step as sum()) ---------------------
RANGE_FNS = ["sum_over_time", "avg_over_time", "stddev_over_time", "stdvar_over_time", "min_over_time", "max_over_time",
             "last_over_time", "count_over_time", "present_over_time", "changes", "resets", "delta", "idelta", "increase", "rate",
             "irate", "deriv"]
WINDOWS = {
    "n1n2": [N1, N2],
    "n2n1": [N2, N1],
    "n1n2n3": [N1, N2, N3],
    "n3n2n1": [N3, N2, N1],
    "fin-n1-fin": [1.0, N1, 3.0],
    "n1-fin-n2": [N1, 2.0, N2],
    "neg-pos": [NNEG, N2],
    "fin-n1-n2": [1.0, N1, N2],
    "n1-n2-fin": [N1, N2, 4.0],
    "inf-ninf-n1": [INF, -INF, N1],
    "snan-n2": [SNAN, N2],
    "four": [N1, 1.0, N2, N3],
}
for wk, vals in WINDOWS.items():
    for fn in RANGE_FNS:
        R("range/%s/%s" % (fn, wk), "%s(nanp_total[20s])" % fn, window("nanp_total", vals))
    R("range/quantile_over_time/%s" % wk, "quantile_over_time(0.5, nanp[20s])", window("nanp", vals))
    R("range/predict_linear/%s" % wk, "predict_linear(nanp[20s], 60)", window("nanp", vals))
    R("range/holt/%s" % wk, "double_exponential_smoothing(nanp[20s], 0.5, 0.5)", window("nanp", vals), enabled=EXP)
    R("range/mad/%s" % wk, "mad_over_time(nanp[20s])", window("nanp", vals), enabled=EXP, profiles=[P313])
    R("range/ts_of_max/%s" % wk, "ts_of_max_over_time(nanp[20s])", window("nanp", vals), enabled=EXP, profiles=[P313])

# --- NaN payload in binary operators (arithNaN, both operands NaN) ----------------
for op in ["+", "-", "*", "/", "%", "^", "atan2"]:
    R("binary/vector-%s" % op.replace("%", "mod").replace("^", "pow"), "nanp{i=\"a\"} %s ignoring(i) nanp{i=\"b\"}" % op,
      group("nanp", [N1, N2]))
    R("binary/vector-rev-%s" % op.replace("%", "mod").replace("^", "pow"), "nanp{i=\"b\"} %s ignoring(i) nanp{i=\"a\"}" % op,
      group("nanp", [N1, N2]))
    R("binary/scalar-%s" % op.replace("%", "mod").replace("^", "pow"), "nanp{i=\"a\"} %s scalar(nanp{i=\"b\"})" % op,
      group("nanp", [N1, N2]))
    R("binary/scalar-lhs-%s" % op.replace("%", "mod").replace("^", "pow"), "scalar(nanp{i=\"a\"}) %s scalar(nanp{i=\"b\"})" % op,
      group("nanp", [N1, N2]))
R("binary/self-sub", "nanp - nanp", group("nanp", [N1, N2]))
R("binary/neg", "-nanp", group("nanp", [N1, NNEG]))
R("binary/nan-literal", "nanp + NaN", group("nanp", [N1, N2]))

# --- annotation de-duplication across call sites -----------------------------------
FL = group("fl", [1.0, 2.0])
FOO = lambda n: [series(n, [fb(10, 1.0), fb(15, 3.0)], job="x")]
HMIX = [series("hm", [hs(15, HE)], job="x"), series("hm", [fb(15, 1.0)], job="y")]
HIS = lambda n="hm": [series(n, [hs(15, HE)], job="x")]
HIS2 = HIS("hm") + HIS("hn")
FLH = [series("fl", [fb(15, 2.0)], job="x")] + HIS("hm")
HGAUGE = lambda n: [series(n, [hs(5, HG), hs(10, HG), hs(15, HG)], job="x")]
HCOUNTER = lambda n: [series(n, [hs(5, HE2), hs(10, HE2), hs(15, HE2)], job="x")]


def A(short, query, ser, **kw):
    R("ann/" + short, query, ser, **kw)


# float aggregations ignoring histograms
for ag in ["min", "max", "stddev", "stdvar"]:
    A("ignored-%s-twice" % ag, "%s(hm) + %s(hm)" % (ag, ag), HIS())
    A("ignored-%s-twice-or" % ag, "%s(hm) or %s(hm)" % (ag, ag), HIS())
A("ignored-min-max", "min(hm) + max(hm)", HIS())
A("ignored-max-stddev", "max(hm) + stddev(hm)", HIS())
A("ignored-two-metrics", "max(hm) + max(hn)", HIS2)
A("ignored-quantile-twice", "quantile(0.5, hm) + quantile(0.5, hm)", HIS())
A("ignored-quantile-differing-phi", "quantile(0.5, hm) + quantile(0.4, hm)", HIS())
A("ignored-sum-group", "sum(hm) + sum(hm)", HIS())
A("ignored-sum-mixed", "sum(hm) + sum(hm)", HMIX)
A("mixed-sum-avg", "sum(hm) + avg(hm)", HMIX)
A("mixed-avg-twice", "avg(hm) + avg(hm)", HMIX)
A("mixed-sum-by", "sum by (job) (hm) + sum by (job) (hm)", HMIX)
A("mixed-sum-over-time-twice", "sum_over_time(hm[20s]) + sum_over_time(hm[20s])",
  [series("hm", [fb(10, 1.0), hs(15, HE)], job="x")])
A("mixed-sum-over-time-two-metrics", "sum_over_time(hm[20s]) + sum_over_time(hn[20s])",
  [series("hm", [fb(10, 1.0), hs(15, HE)], job="x"), series("hn", [fb(10, 1.0), hs(15, HE)], job="x")])
A("mixed-rate-twice", "rate(hm[20s]) + rate(hm[20s])", [series("hm", [fb(10, 1.0), hs(15, HE)], job="x")])
A("mixed-rate-two-metrics", "rate(hm[20s]) + rate(hn[20s])",
  [series("hm", [fb(10, 1.0), hs(15, HE)], job="x"), series("hn", [fb(10, 1.0), hs(15, HE)], job="x")])
A("mixed-rate-rate-increase", "rate(hm[20s]) + increase(hm[20s])", [series("hm", [fb(10, 1.0), hs(15, HE)], job="x")])
# invalid quantile / ratio values in the text
A("quantile-same", "quantile(2, fl) + quantile(2, fl)", FL)
A("quantile-differing", "quantile(2, fl) + quantile(3, fl)", FL)
A("quantile-neg-pos", "quantile(-1, fl) + quantile(2, fl)", FL)
A("quantile-neg-same", "quantile(-1, fl) or quantile(-1, fl)", FL)
A("quantile-nan-twice", "quantile(NaN, fl) + quantile(NaN, fl)", FL)
A("quantile-inf", "quantile(Inf, fl) + quantile(Inf, fl)", FL)
A("quantile-inf-ninf", "quantile(Inf, fl) + quantile(-Inf, fl)", FL)
A("quantile-over-time-same", "quantile_over_time(2, fl[20s]) + quantile_over_time(2, fl[20s])", FL)
A("quantile-over-time-differing", "quantile_over_time(2, fl[20s]) + quantile_over_time(3, fl[20s])", FL)
A("quantile-agg-over-time", "quantile(2, fl) + quantile_over_time(2, fl[20s])", FL)
A("hq-same", "histogram_quantile(2, hm) + histogram_quantile(2, hm)", HIS())
A("hq-differing", "histogram_quantile(2, hm) + histogram_quantile(3, hm)", HIS())
A("hq-two-metrics", "histogram_quantile(2, hm) + histogram_quantile(2, hn)", HIS2)
A("hq-multi-phi", "histogram_quantiles(hm, \"q\", 2, 3)", HIS(), enabled=EXP, profiles=[P313])
A("limit-ratio-same", "limit_ratio(2, fl) + limit_ratio(2, fl)", FL, enabled=EXP)
A("limit-ratio-differing", "limit_ratio(2, fl) + limit_ratio(3, fl)", FL, enabled=EXP)
A("limit-ratio-two-series", "limit_ratio(2, fl) or limit_ratio(-2, fl)", FL, enabled=EXP)
# non-counter info: the metric name is part of the text
A("noncounter-same", "rate(foo[20s]) + rate(foo[20s])", FOO("foo"))
A("noncounter-two-names", "rate(foo[20s]) + rate(bar[20s])", FOO("foo") + FOO("bar"))
A("noncounter-rate-increase", "rate(foo[20s]) + increase(foo[20s])", FOO("foo"))
A("noncounter-rate-irate", "rate(foo[20s]) + irate(foo[20s])", FOO("foo"))
A("noncounter-or", "rate(foo[20s]) or rate(foo[20s])", FOO("foo"))
A("noncounter-two-series-same-name", "rate(foo[20s])",
  [series("foo", [fb(10, 1.0), fb(15, 3.0)], job="x"), series("foo", [fb(10, 1.0), fb(15, 3.0)], job="y")])
A("noncounter-total-and-plain", "rate(foo_total[20s]) + rate(foo[20s])", FOO("foo_total") + FOO("foo"))
A("noncounter-three-sites", "rate(foo[20s]) + rate(foo[20s]) + rate(foo[20s])", FOO("foo"))
A("noncounter-nested", "sum(rate(foo[20s])) + sum(rate(foo[20s]))", FOO("foo"))
A("noncounter-label-name", "rate({__name__=\"foo\"}[20s]) + rate(foo[20s])", FOO("foo"))
A("noncounter-no-float-output", "rate(foo[20s])", [series("foo", [fb(15, 3.0)], job="x")])
A("noncounter-histogram-only", "rate(hm[20s])", HCOUNTER("hm"))
A("noncounter-histogram-only-twice", "rate(hm[20s]) + rate(hm[20s])", HCOUNTER("hm"))
A("noncounter-mixed-drop", "rate(foo[20s])", [series("foo", [fb(10, 1.0), hs(15, HE)], job="x")])
A("noncounter-label-feature", "rate(foo[20s]) + rate(foo[20s])", FOO("foo"), enabled=TU, profiles=[P313])
A("noncounter-sum-over-time-style", "increase(foo[20s]) + increase(foo[20s])", FOO("foo"))
A("noncounter-one-sample", "rate(foo[20s]) + rate(foo[20s])", [series("foo", [fb(15, 3.0)], job="x")])
A("noncounter-expired", "rate(foo[20s])", [series("foo", [fb(5, 3.0), fb(6, 3.0)], job="x")])
# histogram metric-type warnings
A("not-counter-twice", "rate(hg[20s]) + rate(hg[20s])", HGAUGE("hg"))
A("not-counter-two-metrics", "rate(hg[20s]) + rate(hh[20s])", HGAUGE("hg") + HGAUGE("hh"))
A("not-gauge-twice", "delta(hc[20s]) + delta(hc[20s])", HCOUNTER("hc"))
A("not-gauge-two-metrics", "delta(hc[20s]) + delta(hd[20s])", HCOUNTER("hc") + HCOUNTER("hd"))
A("not-gauge-delta-deriv", "delta(hc[20s]) + deriv(hc[20s])", HCOUNTER("hc"))
# binary operator incompatibility: operator/types in the text
A("incompat-same", "(hm + fl) or (hm + fl)", HIS() + [series("fl", [fb(15, 2.0)], job="x")])
A("incompat-two-ops", "(hm + fl) or (hm - fl)", HIS() + [series("fl", [fb(15, 2.0)], job="x")])
A("incompat-order", "(hm + fl) or (fl + hm)", HIS() + [series("fl", [fb(15, 2.0)], job="x")])
A("incompat-scalar", "(hm * 2) or (hm * 2)", HIS())
A("incompat-hist-scalar-div", "(2 / hm) or (2 / hm)", HIS())
A("incompat-hist-hist-mul", "(hm * hm) or (hm * hm)", HIS())
A("incompat-hist-hist-mul-vs-div", "(hm * hm) or (hm / hm)", HIS())
# mixed exponential / custom layouts
CUSTOM = [series("hm", [hs(15, HE)], job="x"), series("hm", [hs(15, HC1)], job="y")]
A("mixed-exp-custom-sum-twice", "sum(hm) + sum(hm)", CUSTOM)
A("mixed-exp-custom-avg-sum", "sum(hm) + avg(hm)", CUSTOM)
A("mixed-exp-custom-rate", "rate(hm[20s]) + rate(hm[20s])", [series("hm", [hs(10, HE), hs(15, HC1)], job="x")])
CUST2 = [series("hm", [hs(15, HC1)], job="x"), series("hm", [hs(15, HC2)], job="y")]
A("incompat-bounds-sum-twice", "sum(hm) + sum(hm)", CUST2)
A("incompat-bounds-sum-avg", "sum(hm) + avg(hm)", CUST2)
A("incompat-bounds-by-job", "sum by (job) (hm) + sum by (job) (hm)", CUST2)
# classic histograms: monotonicity, bad bucket, mixed classic/native
CLASSIC = lambda n, counts: [series(n, [fb(15, c)], le=le) for le, c in zip(["1", "2", "+Inf"], counts)]
A("monotonic-same", "histogram_quantile(0.5, hb_bucket) + histogram_quantile(0.5, hb_bucket)", CLASSIC("hb_bucket", [5, 3, 8]))
A("monotonic-two-phi", "histogram_quantile(0.5, hb_bucket) + histogram_quantile(0.6, hb_bucket)", CLASSIC("hb_bucket", [5, 3, 8]))
A("monotonic-two-metrics", "histogram_quantile(0.5, hb_bucket) + histogram_quantile(0.5, hc_bucket)",
  CLASSIC("hb_bucket", [5, 3, 8]) + CLASSIC("hc_bucket", [5, 3, 8]))
A("bad-bucket-same", "histogram_quantile(0.5, hb_bucket) + histogram_quantile(0.5, hb_bucket)",
  [series("hb_bucket", [fb(15, 1.0)], le="x"), series("hb_bucket", [fb(15, 2.0)], le="+Inf")])
A("bad-bucket-two-metrics", "histogram_quantile(0.5, hb_bucket) + histogram_quantile(0.5, hc_bucket)",
  [series("hb_bucket", [fb(15, 1.0)], le="x"), series("hc_bucket", [fb(15, 1.0)], le="x")])
A("mixed-classic-native-same", "histogram_quantile(0.5, hm) + histogram_quantile(0.5, hm)",
  [series("hm", [hs(15, HE)], job="x"), series("hm", [fb(15, 1.0)], job="y", le="1"), series("hm", [fb(15, 2.0)], job="y", le="+Inf")])
# range-query sort warning (3.13.5 only)
A("sort-twice", "sort(fl) + sort(fl)", FL, kind="range", start=15, end=20, step=5, profiles=[P313])
A("sort-desc-twice", "sort_desc(fl) or sort(fl)", FL, kind="range", start=15, end=20, step=5, profiles=[P313])
# per-step duplication in range queries
A("range-quantile-steps", "quantile(2, fl)", FL, kind="range", start=10, end=20, step=5)
A("range-noncounter-steps", "rate(foo[20s]) + rate(foo[20s])", FOO("foo"), kind="range", start=15, end=25, step=5)
A("range-ignored-steps", "max(hm) + max(hm)", HIS(), kind="range", start=15, end=25, step=5)
# NaN fraction / quantile histogram corners
HNAN = ih(10, 0, float("nan"), pos=([(0, 3)], [1, 2, 3]))
A("nan-quantile-twice", "histogram_quantile(0.5, hm) + histogram_quantile(0.5, hm)", [series("hm", [hs(15, HNAN)], job="x")], profiles=[P313])
A("nan-fraction-twice", "histogram_fraction(0, 1, hm) + histogram_fraction(0, 1, hm)", [series("hm", [hs(15, HNAN)], job="x")], profiles=[P313])
A("nan-fraction-two-metrics", "histogram_fraction(0, 1, hm) + histogram_fraction(0, 1, hn)",
  [series("hm", [hs(15, HNAN)], job="x"), series("hn", [hs(15, HNAN)], job="x")], profiles=[P313])
A("nan-fraction-bounds", "histogram_fraction(0, 1, hm) + histogram_fraction(0, 2, hm)", [series("hm", [hs(15, HNAN)], job="x")], profiles=[P313])


def build(ctx):
    ctx.declare(FILE, "promql", "evaluation", {"phase": "evaluation"})
    for short, query, ser, profiles, enabled, kind, grid in ROWS:
        for p in profiles:
            ctx.put(FILE, row("%s/wave6/%s" % (p, short), p, query, ser, enabled=enabled, kind=kind, **grid))
