# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Histogram/annotation obligations (partition `histogram`). Every row is a
real differential evaluation row; the pinned oracle decides each verdict."""
import copy, math, os, struct

BOTH = ["promql-prometheus-3.1.0", "promql-prometheus-3.13.5"]
P31, P313 = BOTH
FILE = "cases/release-histogram.json"
NS = 1_000_000_000


def bits(f):
    return struct.pack(">d", f).hex()


def labels(name, **kv):
    items = {"__name__": name}
    items.update(kv)
    return [{"name": k, "value": v} for k, v in sorted(items.items())]


def fl(t, v, st=None):
    s = {"time": str(int(t * NS)), "float_bits": bits(v)}
    if st is not None:
        s["start_timestamp_ns"] = str(int(st * NS))
    return s


def _spans(spans):
    return [{"offset": o, "length": n} for o, n in spans]


def ih(count, zero, total, pos=(), neg=(), schema=0, zt=0.0, flavor="counter", reset="unknown", custom=None):
    """Integer histogram; pos/neg = (spans, absolute counts)."""
    h = {"flavor": flavor, "schema": schema, "zero_threshold": bits(zt), "sum": bits(total), "count": str(count),
         "zero_count": str(zero), "positive_spans": _spans(pos[0]) if pos else [], "negative_spans": _spans(neg[0]) if neg else [],
         "positive_counts": [str(c) for c in pos[1]] if pos else [], "reset_hint": reset}
    if neg:
        h["negative_counts"] = [str(c) for c in neg[1]]
    if custom is not None:
        h["custom_bounds"] = [bits(b) for b in custom]
    return {"integer": h}


def fh(count, zero, total, pos=(), neg=(), schema=0, zt=0.0, flavor="counter", reset="unknown", custom=None):
    h = {"flavor": flavor, "schema": schema, "zero_threshold": bits(zt), "sum": bits(total), "count": bits(count),
         "zero_count": bits(zero), "positive_spans": _spans(pos[0]) if pos else [], "negative_spans": _spans(neg[0]) if neg else [],
         "positive_buckets": [bits(c) for c in pos[1]] if pos else [], "negative_buckets": [bits(c) for c in neg[1]] if neg else [],
         "reset_hint": reset}
    if custom is not None:
        h["custom_bounds"] = [bits(b) for b in custom]
    return {"float": h}


def hs(t, h, st=None):
    s = {"time": str(int(t * NS)), "histogram": copy.deepcopy(h)}
    if st is not None:
        s["start_timestamp_ns"] = str(int(st * NS))
    return s


def series(name, samples, **kv):
    return {"labels": labels(name, **kv), "samples": samples}


def row(rid, profile, query, ser, enabled=(), kind="instant", **grid):
    r = {"id": rid, "profiles": [profile], "enabled_features": list(enabled), "query": query, "kind": kind, "series": copy.deepcopy(ser)}
    if kind == "instant":
        r["time"] = str(int(grid.get("t", 20) * NS))
    else:
        r["start"] = str(int(grid["start"] * NS))
        r["end"] = str(int(grid["end"] * NS))
        r["step"] = str(int(grid["step"] * NS))
    for k in ("lookback_ns", "subquery_step_ns"):
        if k in grid:
            r[k] = str(grid[k])
    return r


NAN = float("nan")
INF = float("inf")
J = {"job": "generic"}
EXP = ["promql-experimental-functions"]
TU = ["type-and-unit-labels"]
ST = ["use-start-timestamps"]
DN = ["promql-delayed-name-removal"]

# --- histogram fixtures (instant at t=20s, samples at 15s) ----------------------
HE = ih(10, 2, 12.5, pos=([(0, 3)], [1, 2, 3]), neg=([(0, 2)], [1, 1]))
HE2 = ih(4, 0, 6, pos=([(1, 1)], [4]))
HQ = ih(10, 0, 20.0, pos=([(1, 3)], [2, 5, 3]))
HEr = ih(4, 0, 6, pos=([(1, 1)], [4]), reset="reset")
HEn = ih(4, 0, 6, pos=([(1, 1)], [4]), reset="not_reset")
HG = ih(4, 0, 6, pos=([(1, 1)], [4]), flavor="gauge", reset="gauge")
HC1 = ih(6, 0, 9, pos=([(0, 3)], [1, 2, 3]), schema=-53, custom=[1.0, 2.0])
HC2 = ih(6, 0, 9, pos=([(0, 3)], [1, 2, 3]), schema=-53, custom=[1.0, 3.0])
HC2b = ih(7, 0, 12, pos=([(0, 3)], [2, 3, 2]), schema=-53, custom=[1.0, 3.0])
HNAN = ih(10, 0, NAN, pos=([(0, 3)], [1, 2, 3]))
TE = ih(18, 3, 20.0, pos=([(1, 3)], [2, 4, 6]), neg=([(1, 2)], [1, 2]), zt=0.5)
TEp = ih(15, 3, 20.0, pos=([(1, 3)], [2, 4, 6]), zt=0.5)
TC = ih(20, 0, 30.0, pos=([(0, 4)], [2, 5, 8, 5]), schema=-53, custom=[1.0, 2.0, 4.0])
TCn = ih(20, 0, 30.0, pos=([(0, 4)], [2, 5, 8, 5]), schema=-53, custom=[-1.0, 1.0, 4.0])
TCf = ih(13, 0, 20.0, pos=([(0, 4)], [0, 5, 8, 0]), schema=-53, custom=[1.0, 2.0, 4.0])
H2 = lambda n: ih(n, 0, 1.5 * n, pos=([(1, 1)], [n]))
HS0 = ih(6, 0, 9.0, pos=([(1, 3)], [1, 2, 3]))
HS1 = ih(8, 0, 12.0, pos=([(2, 4)], [1, 2, 2, 3]), schema=1)
HS0z = ih(5, 2, 7.0, pos=([(1, 2)], [1, 2]), zt=0.5)


def hser(name, h, t=15, **kv):
    return series(name, [hs(t, h)], **kv)


def fser(name, v, t=15, **kv):
    return series(name, [fl(t, v)], **kv)


def classic(name, counts, t=15, extra=None, **kv):
    out = [series(name, [fl(t, c)], le=le, **kv) for le, c in zip(["+Inf", "1", "2"], [counts[2], counts[0], counts[1]])]
    return out + (extra or [])


def cwin(name, vals, times, **kv):
    """classic buckets with several samples per bucket; vals = {le: [..]}"""
    return [series(name, [fl(t, v) for t, v in zip(times, vs)], le=le, **kv) for le, vs in vals.items()]


ROWS = []  # (short, role, query, series, enabled, kind, profiles, grid)


def R(short, role, query, ser, enabled=(), kind="instant", profiles=BOTH, **grid):
    ROWS.append((short, role, query, ser, tuple(enabled), kind, tuple(profiles), grid))


def trio(short, pos, neg, inter, profiles=BOTH, enabled=()):
    for role, spec in (("positive", pos), ("negative", neg), ("interaction", inter)):
        q, ser = spec[0], spec[1]
        kw = dict(spec[2]) if len(spec) > 2 else {}
        kw.setdefault("enabled", enabled)
        kw.setdefault("profiles", profiles)
        R(short, role, q, ser, **kw)


def catalogue():
    # ---- annotation rules present in both pins -------------------------------
    trio("annotation/BadBucketLabelWarning",
         ("histogram_quantile(0.5, cb_bucket)", classic("cb_bucket", [1, 2, 3], **J) + [fser("cb_bucket", 1, le="x", **J)]),
         ("histogram_quantile(0.5, cb_bucket)", classic("cb_bucket", [1, 2, 3], **J)),
         ("histogram_quantile(0.9, sum by (le) (rate(cb_bucket[10s])))",
          cwin("cb_bucket", {"+Inf": [30, 60, 90, 120], "1": [10, 20, 30, 40], "2": [20, 40, 60, 80], "x": [5, 6, 7, 8]}, [10, 15, 20, 25], **J),
          {"kind": "range", "start": 20, "end": 25, "step": 5}))
    trio("annotation/HistogramIgnoredInAggregationInfo",
         ("max(hs_total)", [hser("hs_total", HE, a="1", **J), fser("hs_total", 5, a="2", **J)]),
         ("sum(hs_total)", [hser("hs_total", HE, a="1", **J), hser("hs_total", HE2, a="2", **J)]),
         ("max by (job) (hs_total) * 2", [hser("hs_total", HE, a="1", **J), fser("hs_total", 5, a="2", **J)]))
    trio("annotation/HistogramQuantileForcedMonotonicityInfo",
         ("histogram_quantile(0.5, cb_bucket)", classic("cb_bucket", [3, 2, 5], **J)),
         ("histogram_quantile(0.5, cb_bucket)", classic("cb_bucket", [1, 2, 5], **J)),
         ("histogram_quantile(0.5, sum by (le) (rate(cb_bucket[10s])))",
          cwin("cb_bucket", {"+Inf": [20, 40, 60], "1": [10, 20, 30], "2": [10, 15, 20]}, [12, 16, 20], **J)))
    trio("annotation/IncompatibleCustomBucketsHistogramsWarning",
         ("hc1_total + hc2_total", [hser("hc1_total", HC1, **J), hser("hc2_total", HC2, **J)]),
         ("hc1_total + hc3_total", [hser("hc1_total", HC1, **J), hser("hc3_total", HC1, **J)]),
         ("sum by (job) ({__name__=~\"hc[12]_total\"})", [hser("hc1_total", HC1, **J), hser("hc2_total", HC2, **J)]), profiles=[P31])
    trio("annotation/IncompatibleTypesInBinOpInfo",
         ("hs_total + 1", [hser("hs_total", HE, **J)]),
         ("hs_total * 2", [hser("hs_total", HE, **J)]),
         ("sum by (job) (hs_total + on(job) fl_total)", [hser("hs_total", HE, **J), fser("fl_total", 2, **J)]))
    trio("annotation/InvalidQuantileWarning",
         ("quantile(2, fl_total)", [fser("fl_total", 1, **J)]),
         ("quantile(1, fl_total)", [fser("fl_total", 1, **J)]),
         ("quantile by (job) (1.5, fl_total) > 0", [fser("fl_total", 1, **J)]))
    trio("annotation/InvalidRatioWarning",
         ("limit_ratio(2, fl_total)", [fser("fl_total", 1, **J)]),
         ("limit_ratio(1, fl_total)", [fser("fl_total", 1, **J)]),
         ("limit_ratio(-1.5, sum by (job) (fl_total))", [fser("fl_total", 1, **J)]), enabled=EXP)
    trio("annotation/MixedClassicNativeHistogramsWarning",
         ("histogram_quantile(0.5, m)", classic("m", [1, 2, 3], **J) + [hser("m", HE2, **J)]),
         ("histogram_quantile(0.5, m)", classic("m", [1, 2, 3], **J) + [hser("m", HE2, job="other")]),
         ("histogram_quantile(0.5, m) or on() vector(0)", classic("m", [1, 2, 3], **J) + [hser("m", HE2, **J)]))
    trio("annotation/MixedExponentialCustomHistogramsWarning",
         ("sum(h_total)", [hser("h_total", HE2, a="1", **J), hser("h_total", HC1, a="2", **J)]),
         ("sum(h_total)", [hser("h_total", HE2, a="1", **J), hser("h_total", HE, a="2", **J)]),
         ("sum by (job) (sum_over_time(h_total[20s]))", [series("h_total", [hs(10, HE2), hs(15, HC1)], **J)]))
    trio("annotation/MixedFloatsHistogramsWarning",
         ("sum(h_total)", [hser("h_total", HE2, a="1", **J), fser("h_total", 1, a="2", **J)]),
         ("sum(h_total)", [fser("h_total", 2, a="1", **J), fser("h_total", 1, a="2", **J)]),
         ("avg by (job) (sum_over_time(h_total[20s]))", [series("h_total", [fl(10, 1), hs(15, HE2)], **J)]))
    trio("annotation/NativeHistogramNotCounterWarning",
         ("rate(g_total[20s])", [series("g_total", [hs(10, HG), hs(15, HG)], **J)]),
         ("rate(g_total[20s])", [series("g_total", [hs(10, HE2), hs(15, HE2)], **J)]),
         ("histogram_count(rate(g_total[20s]))", [series("g_total", [hs(10, HG), hs(15, HG)], **J)]))
    trio("annotation/NativeHistogramNotGaugeWarning",
         ("delta(g_total[20s])", [series("g_total", [hs(10, HE2), hs(15, HE2)], **J)]),
         ("delta(g_total[20s])", [series("g_total", [hs(10, HG), hs(15, HG)], **J)]),
         ("histogram_sum(delta(g_total[20s]))", [series("g_total", [hs(10, HE2), hs(15, HE2)], **J)]))
    trio("annotation/PossibleNonCounterInfo",
         ("rate(gauge_metric[20s])", [series("gauge_metric", [fl(10, 1), fl(15, 2)], **J)]),
         ("rate(gauge_metric_total[20s])", [series("gauge_metric_total", [fl(10, 1), fl(15, 2)], **J)]),
         ("sum by (job) (rate(gauge_metric[20s]))", [series("gauge_metric", [fl(10, 1), fl(15, 2)], **J)]))
    # ---- annotation accumulation ----------------------------------------------
    many = [hser("hs_total", HE, a="1", **J), hser("hs_total", HE2, a="2", **J), hser("hs_total", HQ, a="3", **J), fser("hs_total", 5, a="4", **J)]
    trio("diagnostic/accumulation",
         ("max(hs_total)", many),
         ("max(hs_total) or quantile(2, fl_total)", many + [fser("fl_total", 1, **J)]),
         ("max(hs_total)", [series("hs_total", [hs(15, HE), hs(20, HE)], a="1", **J), series("hs_total", [hs(15, HE2), hs(20, HE2)], a="2", **J), series("hs_total", [fl(15, 5), fl(20, 6)], a="3", **J)],
          {"kind": "range", "start": 15, "end": 25, "step": 5}))
    trio("semantics/annotations",
         ("max(hs_total) or quantile(2, fl_total)", [hser("hs_total", HE, **J), fser("fl_total", 1, **J)]),
         ("sum(fl_total)", [fser("fl_total", 1, **J)]),
         ("rate(gauge_metric[10s])", [series("gauge_metric", [fl(10, 1), fl(15, 2), fl(20, 3), fl(25, 5)], **J)], {"kind": "range", "start": 15, "end": 25, "step": 5}))
    # ---- layout / reset / scale / variance ----------------------------------------
    hcm = [series("hcm_total", [hs(10, HC1), hs(15, HC2b)], **J)]
    hcs = [series("hcs_total", [hs(10, HC2), hs(15, HC2b)], **J)]
    trio("fact/histogram-layout-pin",
         ("sum_over_time(hcm_total[20s])", hcm),
         ("sum_over_time(hcs_total[20s])", hcs),
         ("resets(hcm_total[20s])", hcm))
    trio("semantics/histogram-layout",
         ("sum(h_total)", [hser("h_total", HS0, a="1", **J), hser("h_total", HS1, a="2", **J), hser("h_total", HS0z, a="3", **J)]),
         ("hexp_total + hc_total", [hser("hexp_total", HE2, **J), hser("hc_total", HC1, **J)]),
         ("histogram_sum(hs0_total + hs1_total)", [hser("hs0_total", HS0, **J), hser("hs1_total", HS1, **J)]))
    rs = lambda *hh: [hs(10, hh[0]), hs(15, hh[1])]
    base = ih(4, 0, 6.0, pos=([(1, 1)], [4]))
    resets_pos = [
        series("t_total", rs(base, ih(3, 0, 6.0, pos=([(1, 1)], [3]))), k="01-count", **J),
        series("t_total", rs(base, ih(5, 0, 6.0, pos=([(1, 1)], [5]), reset="reset")), k="02-hint-reset", **J),
        series("t_total", rs(base, ih(4, 0, 6.0, pos=([(2, 1)], [4]))), k="03-disappeared", **J),
        series("t_total", rs(base, ih(4, 0, 6.0, pos=([(2, 2)], [2, 2]), schema=1)), k="04-schema-up", **J),
        series("t_total", rs(ih(4, 0, 6.0, pos=([(1, 1)], [4]), zt=0.5), ih(4, 0, 6.0, pos=([(1, 1)], [4]), zt=0.1)), k="05-zt-down", **J),
        series("t_total", rs(ih(4, 0, 6.0, pos=([(1, 1)], [4]), reset="reset"), ih(2, 0, 6.0, pos=([(1, 1)], [2]), reset="not_reset")), k="06-notreset-wins", **J),
    ]
    resets_neg = [
        series("t_total", rs(base, base), k="01-same", **J),
        series("t_total", rs(base, ih(4, 0, 6.0, pos=([(1, 1)], [4]), flavor="gauge", reset="gauge")), k="02-gauge-flavor", **J),
        series("t_total", rs(base, ih(8, 0, 6.0, pos=([(1, 1)], [8]), reset="not_reset")), k="03-hint-notreset", **J),
        series("t_total", rs(base, ih(5, 0, 6.0, pos=([(1, 1), (1, 1)], [4, 1]))), k="04-more-buckets", **J),
        series("t_total", rs(ih(4, 0, 6.0, pos=([(2, 2)], [2, 2]), schema=1), ih(5, 0, 6.0, pos=([(1, 2)], [2, 3]))), k="05-schema-down", **J),
    ]
    trio("fact/histogram-reset",
         ("resets(t_total[20s])", resets_pos),
         ("resets(t_total[20s])", resets_neg),
         ("increase(t_total[20s])", [series("t_total", rs(base, ih(2, 0, 3.0, pos=([(1, 1)], [2]))), k="1-reset", **J), series("t_total", rs(base, ih(8, 0, 12.0, pos=([(1, 1)], [8]))), k="2-grow", **J)]))
    sc = lambda *hh: [series("t_total", [hs(15, h)], k=str(i), **J) for i, h in enumerate(hh)]
    trio("fact/histogram-scale",
         ("t_total * 2", sc(TE, TC)),
         ("t_total / 0", sc(TE, TC)),
         ("histogram_sum(2 * t_total) + 1", sc(TE, TC)))
    trio("fact/histogram-variance",
         ("histogram_stdvar(t_total)", sc(TE, TEp, TCf, HE, H2(4))),
         ("histogram_stddev(t_total)", sc(ih(0, 0, 0.0), TC)),
         ("histogram_stddev(sum by (job) (t_total))", [series("t_total", [hs(15, HE), hs(20, HE)], k="1", **J), series("t_total", [hs(15, HE), hs(20, HE)], k="2", **J)],
          {"kind": "range", "start": 15, "end": 25, "step": 10}))
    # ---- info() ------------------------------------------------------------------
    ib = lambda **kv: series("m_total", [fl(15, 1)], instance="a", job="j", **kv)
    tinfo = lambda t, **kv: series("target_info", [fl(t, 1)], instance="a", job="j", **kv)
    trio("fact/info-join",
         ("info(m_total)", [ib(), tinfo(15, region="eu"), tinfo(12, region="us")]),
         ("info(m_total, {region=\"zz\"})", [ib(), tinfo(15, region="eu")]),
         ("sum by (region) (info(m_total))", [series("m_total", [hs(15, HE2)], instance="a", job="j"), tinfo(15, region="eu")]), enabled=EXP)
    # ---- native quantile / fraction ---------------------------------------------------
    trio("fact/native-fraction",
         ("histogram_fraction(0, 3, t_total)", sc(TE, TEp, TC, TCn)),
         ("histogram_fraction(3, 0, t_total)", sc(TE, TC)),
         ("histogram_fraction(0, 2, sum by (job) (t_total)) * 100", [series("t_total", [hs(15, HQ)], k="1", **J), series("t_total", [hs(15, HQ)], k="2", **J)]))
    trio("fact/native-quantile",
         ("histogram_quantile(0.5, t_total)", sc(TE, TEp, TC, TCn)),
         ("histogram_quantile(2, t_total)", sc(TE, TC)),
         ("histogram_quantile(0.9, sum by (job) (t_total))", [series("t_total", [hs(15, HQ), hs(20, HQ)], k="1", **J), series("t_total", [hs(15, HQ), hs(20, HQ)], k="2", **J)],
          {"kind": "range", "start": 15, "end": 25, "step": 5}))
    catalogue_313()


def catalogue_313():
    only = [P313]
    trio("annotation/HistogramCounterResetCollisionWarning",
         ("a_total + b_total", [hser("a_total", HEr, **J), hser("b_total", HEn, **J)]),
         ("a_total + b_total", [hser("a_total", HEr, **J), hser("b_total", HE2, **J)]),
         ("sum(h_total)", [hser("h_total", HEr, a="1", **J), hser("h_total", HEn, a="2", **J)]), profiles=only)
    MR = lambda n, **kv: series(n, [fl(10, 1), fl(12, 4), hs(15, HE2), fl(17, 2)], **kv)
    trio("annotation/HistogramIgnoredInMixedRangeInfo",
         ("max_over_time(m[20s])", [MR("m", **J)]),
         ("max_over_time(m[20s])", [series("m", [hs(10, HE2), hs(15, HE2)], **J)]),
         ("sum by (job) (stddev_over_time(m[20s]))", [MR("m", **J)]), profiles=only)
    trio("annotation/IncompatibleBucketLayoutInBinOpWarning",
         ("hexp_total + hc_total", [hser("hexp_total", HE2, **J), hser("hc_total", HC1, **J)]),
         ("hexp_total + hexp2_total", [hser("hexp_total", HE2, **J), hser("hexp2_total", HE2, **J)]),
         ("histogram_count(hexp_total - hc_total) or on() vector(0)", [hser("hexp_total", HE2, **J), hser("hc_total", HC1, **J)]), profiles=only)
    trio("annotation/MismatchedCustomBucketsHistogramsInfo",
         ("hc1_total + hc2_total", [hser("hc1_total", HC1, **J), hser("hc2_total", HC2, **J)]),
         ("hc1_total + hc3_total", [hser("hc1_total", HC1, **J), hser("hc3_total", HC1, **J)]),
         ("sum by (job) ({__name__=~\"hc[12]_total\"})", [hser("hc1_total", HC1, **J), hser("hc2_total", HC2, **J)]), profiles=only)
    trio("annotation/NativeHistogramFractionNaNsInfo",
         ("histogram_fraction(0, 2, hn_total)", [hser("hn_total", HNAN, **J)]),
         ("histogram_fraction(0, 2, hs_total)", [hser("hs_total", HE, **J)]),
         ("histogram_fraction(0, 2, hn_total) * 2", [hser("hn_total", HNAN, **J)]), profiles=only)
    trio("annotation/NativeHistogramQuantileNaNResultInfo",
         ("histogram_quantile(0.99, hn_total)", [hser("hn_total", HNAN, **J)]),
         ("histogram_quantile(0.99, hs_total)", [hser("hs_total", HE, **J)]),
         ("histogram_quantile(0.99, hn_total) or on() vector(1)", [hser("hn_total", HNAN, **J)]), profiles=only)
    trio("annotation/NativeHistogramQuantileNaNSkewInfo",
         ("histogram_quantile(0.3, hn_total)", [hser("hn_total", HNAN, **J)]),
         ("histogram_quantile(0.3, hs_total)", [hser("hs_total", HE, **J)]),
         ("histogram_quantile(0.3, hn_total) + 1", [hser("hn_total", HNAN, **J)]), profiles=only)
    gm = lambda ty: [series("m_total", [fl(10, 1), fl(15, 2)], __type__=ty, **J)]
    trio("annotation/PossibleNonCounterLabelInfo",
         ("rate(m_total[20s])", gm("gauge")),
         ("rate(m_total[20s])", gm("counter")),
         ("sum by (job) (rate(m_total[20s]))", gm("gauge")), profiles=only, enabled=TU)
    sm = [series("m_total", [fl(10, 1), fl(15, 2)], **J)]
    trio("annotation/SortInRangeQueryWarning",
         ("sort(m_total)", sm, {"kind": "range", "start": 10, "end": 20, "step": 5}),
         ("sort(m_total)", sm),
         ("sort_desc(sum by (job) (m_total))", sm, {"kind": "range", "start": 10, "end": 20, "step": 5}), profiles=only)
    A = series("a_total", [fl(10, 1), fl(15, 2)], x="1", **J)
    B = series("b_total", [fl(20, 1), fl(25, 3)], x="1", **J)
    B2 = series("b_total", [fl(10, 1), fl(15, 3)], x="1", **J)
    rng = {"kind": "range", "start": 15, "end": 25, "step": 5}
    sel = "rate({__name__=~\"a_total|b_total\"}[6s])"
    trio("fact/delayed-name-range-merge",
         (sel, [A, B], rng), (sel, [A, B2], rng), (sel + " * 2", [A, B], rng), profiles=only, enabled=DN)
    cap = lambda a, b: [series("t_total", [hs(10, H2(a)), hs(15, H2(b))], **J)]
    trio("fact/histogram-rate-zero-cap",
         ("rate(t_total[20s])", cap(1, 11)),
         ("rate(t_total[20s])", cap(100, 110)),
         ("rate(t_total[20s])", [series("t_total", [hs(10, TC), hs(15, ih(3, 0, 6.0, pos=([(0, 1)], [3]), schema=-53, custom=[7.0], reset="reset"))], **J)]), profiles=only)
    trio("fact/mixed-range-annotations",
         ("max_over_time(ma[20s]) or stddev_over_time(mb[20s]) or deriv(mc[20s]) or ts_of_min_over_time(md[20s])",
          [MR("ma", k="a", **J), MR("mb", k="b", **J), MR("mc", k="c", **J), MR("md", k="d", **J)]),
         ("ts_of_first_over_time(ma[20s]) or ts_of_last_over_time(mb[20s]) or max_over_time(mc[20s])",
          [MR("ma", k="a", **J), MR("mb", k="b", **J), series("mc", [hs(10, HE2), hs(15, HE2)], k="c", **J)]),
         ("sum(stddev_over_time(m[20s]))", [MR("m", **J)], {"kind": "range", "start": 20, "end": 25, "step": 5}), profiles=only, enabled=EXP)
    trio("fact/native-quantile-nans",
         ("histogram_quantile(0.99, hn_total)", [hser("hn_total", HNAN, **J)]),
         ("histogram_quantile(0.99, hs_total)", [hser("hs_total", HE, **J)]),
         ("histogram_quantile(0.3, hn_total) + on(job) histogram_fraction(0, 2, hn_total)", [hser("hn_total", HNAN, **J)]), profiles=only)
    typed = [series("m_total", [fl(10, 1), fl(15, 2)], __type__="counter", __unit__="seconds", **J)]
    trio("fact/reserved-name-removal",
         ("rate(m_total[20s])", typed),
         ("t_total </ 3", [series("t_total", [hs(15, TE)], __type__="histogram", __unit__="seconds", **J)]),
         ("rate(m_total[20s]) * 2", typed, {"enabled": TU + DN}), profiles=only)
    c3 = lambda a, b, c: [series("c_total", [fl(5, a[0], a[1]), fl(10, b[0], b[1]), fl(15, c[0], c[1])], **J)]
    h3 = lambda a, b, c: [series("c_total", [hs(5, H2(a[0]), a[1]), hs(10, H2(b[0]), b[1]), hs(15, H2(c[0]), c[1])], **J)]
    trio("fact/start-timestamp-reset",
         ("resets(c_total[20s])", c3((10, 1), (20, 6), (30, 6))),
         ("resets(c_total[20s])", c3((10, 1), (20, 0), (30, 0))),
         ("increase(c_total[20s])", h3((10, 1), (20, 6), (30, 6))), profiles=only, enabled=ST)
    trio("semantics/start-timestamps",
         ("rate(c_total[20s])", c3((10, 1), (20, 6), (30, 6))),
         ("rate(c_total[20s])", [series("c_total", [fl(5, 10), fl(10, 20), fl(15, 30)], **J)]),
         ("sum(increase(c_total[10s]))", h3((10, 1), (20, 6), (30, 6)) + [], {"kind": "range", "start": 15, "end": 20, "step": 5}), profiles=only, enabled=ST)
    sq = [series("t_total", [hs(5, H2(1)), hs(10, relh(2)), hs(15, relh(3))], k="1-hint-reset", **J),
          series("t_total", [hs(5, H2(4)), hs(10, ih(3, 0, 4.5, pos=([(1, 1)], [3]), reset="not_reset")), hs(15, ih(2, 0, 3.0, pos=([(1, 1)], [2]), reset="not_reset"))], k="2-hint-notreset", **J)]
    gq = [series("t_total", [hs(5, ih(1, 0, 1.5, pos=([(1, 1)], [1]), flavor="gauge", reset="gauge")), hs(10, ih(2, 0, 3.0, pos=([(1, 1)], [2]), flavor="gauge", reset="gauge"))], k="1-gauge", **J)]
    trio("fact/subquery-histogram-hints",
         ("resets(t_total[20s:5s])", sq),
         ("resets(t_total[20s:5s])", gq),
         ("rate(t_total[20s:5s])", sq), profiles=only)
    # ---- trimming ---------------------------------------------------------------------
    t4 = lambda *hh: [series("t_total", [hs(15, h)], k=str(i), **J) for i, h in enumerate(hh)]
    trio("fact/trim-finite-buckets",
         ("t_total </ 3", t4(TE, TEp, TC, TCn)),
         ("t_total </ 100", t4(TE, TEp)),
         ("sum(t_total </ 3)", t4(TE, TEp)), profiles=only)
    trio("fact/trim-infinity-crossing",
         ("t_total </ 0.5", t4(TC, TCn)),
         ("t_total </ -Inf", t4(TC, TCn)),
         ("histogram_sum(t_total >/ 5)", t4(TC, TCn)), profiles=only)
    trio("fact/trim-zero-infinite",
         ("t_total </ 0.25", t4(TE, TEp, TC)),
         ("t_total </ NaN", t4(TE, TEp, TC)),
         ("histogram_sum(t_total >/ -1)", t4(TE, TEp, TC)), profiles=only)
    trio("operator/trim-lower",
         ("t_total >/ 2", t4(TE, TC)),
         ("fl_total >/ 2", [fser("fl_total", 3, **J)]),
         ("sum(t_total >/ on(job) fl_total)", [hser("t_total", TE, **J), fser("fl_total", 2, **J)]), profiles=only)
    trio("operator/trim-upper",
         ("t_total </ 2", t4(TE, TC)),
         ("fl_total </ 2", [fser("fl_total", 3, **J)]),
         ("sum(t_total </ on(job) fl_total)", [hser("t_total", TE, **J), fser("fl_total", 2, **J)]), profiles=only)
    ty = lambda ty_, n="m_total": [series(n, [fl(10, 1), fl(15, 2)], __type__=ty_, **J)]
    trio("fact/type-unit-feature",
         ("rate(m_total[20s])", ty("gauge"), {"enabled": TU}),
         ("rate(m[20s])", ty("counter", "m"), {"enabled": TU}),
         ("sum by (job) (rate(m[20s]))", ty("counter", "m")), profiles=only)


def relh(n):
    return ih(n, 0, 1.5 * n, pos=([(1, 1)], [n]), reset="reset")


def build(ctx):
    ctx.declare(FILE, "promql", "evaluation", {"phase": "evaluation"})
    probe = os.environ.get("HPROBE")
    if probe:
        g = dict(globals())
        exec(open(probe).read(), g)
        for r in g["rows"]():
            ctx.put(FILE, r)
        return
    catalogue()
    have = {}
    for short, role, query, ser, enabled, kind, profiles, grid in ROWS:
        for p in profiles:
            oid = f"{p}/{short}"
            if oid not in ctx.BY_ID:
                continue
            rid = dict(zip(("positive", "negative", "interaction"), ctx.role_ids(ctx.BY_ID[oid])))[role]
            have.setdefault(oid, set()).add(role)
            ctx.put(FILE, row(rid, p, query, ser, enabled=enabled, kind=kind, **grid))
    mine = sorted(have)
    assert len(mine) == 68, len(mine)  # the histogram partition
    for oid in mine:
        assert have[oid] == {"positive", "negative", "interaction"}, (oid, have[oid])
    # Production bindings: the owned-engine Go tests (hand-authored expectations,
    # internal/query/promql/release_histogram_test.go) that observe each rule's
    # arithmetic or annotation facts; the oracle rows are the differential half.
    T = "TestReleaseHistogram"
    annot = [T + "AnnotationRules", T + "AggregationAnnotationAnchorsAtArgument", T + "BinaryAnnotationsSpanWholeExpression"]
    tests = {
        "annotation/": annot,
        "diagnostic/accumulation": [T + "AnnotationsDeduplicate", T + "AnnotationRules"],
        "semantics/annotations": annot + [T + "AnnotationsDeduplicate"],
        "fact/histogram-layout-pin": [T + "LayoutReconciliation", T + "BinaryAnnotationsSpanWholeExpression"],
        "semantics/histogram-layout": [T + "LayoutReconciliation", T + "BinaryAnnotationsSpanWholeExpression"],
        "fact/histogram-reset": [T + "ResetDetectionClauses"],
        "fact/histogram-scale": [T + "ScaleFacts"],
        "fact/histogram-variance": [T + "VarianceFacts", T + "VarianceZeroCrossingCustomBucketIsZero"],
        "fact/info-join": [T + "InfoJoinFacts", T + "InfoNewerOriginalTimestampWins"],
        "fact/native-fraction": [T + "QuantileAndFractionFacts", T + "FractionCustomBucketSpanningZero"],
        "fact/native-quantile-nans": [T + "QuantileAndFractionFacts"],
        "fact/native-quantile": [T + "QuantileAndFractionFacts"],
        "fact/histogram-rate-zero-cap": [T + "RateZeroCap", T + "RateResetKeepsFirstSampleCountForZeroCap"],
        "fact/mixed-range-annotations": [T + "MixedRangeAnnotations"],
        "fact/delayed-name-range-merge": [T + "DelayedNameRangeMerge"],
        "fact/reserved-name-removal": [T + "ReservedNameRemoval"],
        "fact/start-timestamp-reset": [T + "StartTimestampResetPredicate"],
        "semantics/start-timestamps": [T + "StartTimestampResetPredicate"],
        "fact/subquery-histogram-hints": [T + "SubqueryClearsExplicitResetHints"],
        "fact/trim-": [T + "TrimFacts", T + "TrimSumIsDeterministic"],
        "operator/trim-": [T + "TrimFacts"],
        "fact/type-unit-feature": [T + "TypeUnitFeatureSwitchesCounterHeuristic"],
    }
    for oid in mine:
        short = oid.split("/", 1)[1]
        names = None
        for key, value in tests.items():
            if short == key or (key.endswith("-") or key.endswith("/")) and short.startswith(key):
                names = value
                break
        assert names, oid
        ctx.bind(oid, "internal/query/promql", names)
