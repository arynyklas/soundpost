# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""numeric partition, semantic families: arithmetic, comparison, ieee, lookback,
ordering, range-window. Each FACTS function returns (positive, negative,
interaction) row specs for one profile; the differential runner decides every
verdict."""
from numeric_lib import *

PAIRS = [("a_pos", 5.0, 2.0), ("b_negdiv", -5.0, 2.0), ("c_negrhs", 5.0, -2.0), ("d_zeros", 0.0, NZ), ("e_nzero", NZ, 0.0), ("f_infs", INF, -INF), ("g_samesign", INF, INF),
         ("h_nan", NAN, 1.0), ("i_div0", 1.0, 0.0), ("j_frac", 2.0, 0.5), ("k_cuberoot", -8.0, 1.0 / 3.0), ("l_tenths", 0.1, 0.2), ("m_big", 1e308, 1e308), ("n_ninf", -INF, 2.0)]


def pair_series(xname="sx", yname="sy", pairs=PAIRS, t=15):
    out = []
    for case, x, y in pairs:
        out.append(fser(xname, [(t, x)], case=case))
        out.append(fser(yname, [(t, y)], case=case))
    return out


def hist_series(ctx):
    return [hser(ctx, "hx", [(15, mkhist(ctx, 4))], case="a"), hser(ctx, "hy", [(15, mkhist(ctx, 6))], case="a"), hser(ctx, "hz", [(15, mkhist(ctx, 4))], case="a"),
            fser("sx", [(15, 3.0)], case="a")]


def arithmetic(ctx, prof):
    ops = ["+", "-", "*", "/", "%", "^", "atan2"]
    parts = [("sx %s sy" % o, "f%d" % i) for i, o in enumerate(ops)]
    hp = [("hx + hy", "h_add"), ("hy - hx", "h_sub"), ("hx * 2", "h_mul"), ("2 * hx", "h_mulrev"), ("hx / 2", "h_div"), ("hx * -1", "h_neg"), ("hx * 0", "h_zero")]
    pos = spec(union(parts + hp), pair_series() + hist_series(ctx))
    bad = [("hx + sx", "add_hf"), ("hx ^ 2", "pow"), ("2 / hx", "div_fh"), ("hx * hy", "mul_hh"), ("hx % 2", "mod"), ("hx - 1", "sub_hs"), ("hx atan2 hy", "atan2_hh"), ("1 + hx", "add_sh")]
    neg = spec(union(bad), hist_series(ctx))
    rs = [fser("sx", [(5, 1.0), (15, 2.0), (25, 4.0)], job="j", case="a"), fser("sx", [(5, 3.0), (15, -1.0), (25, 0.0)], job="j", case="b"), fser("sx", [(5, 10.0), (15, 20.0), (25, 30.0)], job="k", case="c"),
          fser("sy", [(5, 2.0), (15, 4.0), (25, 8.0)], job="j", case="a"), fser("sy", [(5, 0.0), (15, NZ), (25, 2.0)], job="j", case="b"), fser("sy", [(5, 5.0), (15, 4.0), (25, 3.0)], job="k", case="c"),
          hser(ctx, "hx", [(5, mkhist(ctx, 2)), (15, mkhist(ctx, 4)), (25, mkhist(ctx, 8))], job="j", case="a"), hser(ctx, "hy", [(5, mkhist(ctx, 1)), (15, mkhist(ctx, 3)), (25, mkhist(ctx, 5))], job="j", case="a")]
    inter = spec(union([("sum by (job) (sx / on(case) sy)", "div"), ("sum by (job) (sx ^ ignoring(job) sy)", "pow"), ("sum by (job) (sx % on(case, job) sy)", "mod"),
                        ("histogram_count(hx + hy)", "hadd"), ("histogram_sum(hx * 2 - hy)", "hsub"), ("sx * on(case) group_left() sy offset 10s", "off")]), rs, kind="range", start=15, end=25, step=5)
    return pos, neg, inter


def comparison(ctx, prof):
    ops = [">", "<", ">=", "<=", "==", "!="]
    parts = [("sx %s sy" % o, "f%d" % i) for i, o in enumerate(ops)] + [("sx %s bool sy" % o, "b%d" % i) for i, o in enumerate(ops)]
    parts += [("sx > 3", "gt3"), ("3 < sx", "rev3"), ("sx == bool 5", "eqb"), ("vector(1 == bool 1)", "ss"), ("vector(2 > bool 3)", "ss2"), ("hx == hz", "h_eq"), ("hx != hy", "h_ne"), ("hx == hy", "h_eqne")]
    pos = spec(union(parts), pair_series() + hist_series(ctx))
    bad = [("hx > hy", "gt_hh"), ("hx < sx", "lt_hf"), ("hx <= 3", "le_hs"), ("hx >= hy", "ge_hh"), ("hx == sx", "eq_hf"), ("hx != 3", "ne_hs")]
    neg = spec(union(bad), hist_series(ctx))
    rs = [fser("sx", [(5, 1.0), (15, 5.0), (25, 3.0)], job="j", case="a"), fser("sx", [(5, NAN), (15, 2.0), (25, INF)], job="j", case="b"), fser("sx", [(5, 4.0), (15, 4.0), (25, 4.0)], job="k", case="c"),
          fser("sy", [(5, 2.0), (15, 5.0), (25, 3.0)], job="j", case="a"), fser("sy", [(5, 1.0), (15, 2.0), (25, INF)], job="j", case="b"), fser("sy", [(5, 5.0), (15, 3.0), (25, NAN)], job="k", case="c")]
    inter = spec(union([("sum by (job) (sx > bool sy)", "gtb"), ("count by (job) (sx == sy)", "eqcount"), ("sx != on(case) sy", "ne"), ("max by (job) (sx >= bool sy)", "geb"), ("sx > 2", "gt2")]),
                 rs, kind="range", start=5, end=25, step=10)
    return pos, neg, inter


def ieee(ctx, prof):
    vals = [("a_pz", 0.0), ("b_nz", NZ), ("c_pinf", INF), ("d_ninf", -INF), ("e_nan", NAN), ("f_sub", SUB), ("g_one", 1.0), ("h_nan_payload", "7ff8000000000123"), ("i_negnan", "fff8000000000001")]
    s = [fser("ie", [(15, v)], case=c) for c, v in vals] + [fser("ie2", [(15, v)], case=c) for c, v in vals] + [hser(ctx, "hx", [(15, mkhist(ctx, 4))], case="a")]
    parts = [("-ie", "neg"), ("ie * 0", "mul0"), ("ie / 0", "div0"), ("0 * ie", "zmul"), ("ie - ie", "selfsub"), ("ie + ie2", "add"), ("ie * ie2", "mul"), ("ie == ie", "eq"), ("ie != ie", "ne"),
             ("ie > bool ie2", "gtb"), ("ie == bool ie2", "eqb"), ("ie < ie2", "lt"), ("ie ^ 0", "pow0"), ("ie % ie2", "mod"), ("ie atan2 ie2", "atan2"), ("max(ie)", "max"), ("min(ie)", "min"),
             ("max by (case) (ie)", "maxby"), ("ie and ie2", "and"), ("hx", "hist")]
    pos = spec(union(parts), s)
    stale = [fser("ie_s", [(15, 1.0)], case="a_ok"), fser("ie_s", [(10, 1.0), (15, STALE_BITS)], case="b_stale"), fser("ie_s", [(15, NAN_BITS)], case="c_nan"),
             fser("ie_s", [(15, NAN_BITS)], case="d_nan_again"),
             fser("ie_t", [(15, STALE_BITS)], case="a_only_stale"), mixed("ie_h", [(10, mkhist(ctx)), (15, mkhist(ctx, 4, sum_bits=STALE_BITS))], case="a_stale_hist")]
    neg = spec(union([("ie_s", "sel"), ("count(ie_s)", "count"), ("ie_s != ie_s", "ne"), ("ie_s == ie_s", "eq"), ("absent(ie_t)", "absent_t"), ("absent(ie_h)", "absent_h"), ("sum(ie_s)", "sum"),
                      ("count(ie_t)", "count_t"), ("ie_t", "sel_t"), ("ie_h", "sel_h")]), stale)
    g = [fser("ie_g", [(5, 1.0), (10, STALE_BITS), (15, 3.0), (20, NAN), (25, STALE_BITS)], case="a"), fser("ie_g", [(5, NZ), (15, 0.0), (25, -1.0)], case="b"), fser("ie_g", [(5, INF), (15, -INF), (25, 1.0)], case="c")]
    inter = spec(union([("ie_g", "sel"), ("ie_g + 1", "add"), ("sum(ie_g)", "sum"), ("count_over_time(ie_g[10s])", "cnt"), ("last_over_time(ie_g[10s])", "last"), ("ie_g == ie_g", "eq"), ("ie_g * 0", "mul0"),
                        ("rate(ie_g[15s])", "rate")]), g, kind="range", start=5, end=30, step=5)
    return pos, neg, inter


def lookback(ctx, prof):
    stale_h = mkhist(ctx, 4, sum_bits=STALE_BITS)
    f = [fser("lbf", [(100.0, 1.0)], case="a_at_bound"), fser("lbf", [(100.001, 2.0)], case="b_inside"), fser("lbf", [(399.999, 3.0)], case="c_late"), fser("lbf", [(400.0, 4.0)], case="d_target"),
         fser("lbf", [(50.0, 5.0), (120.0, STALE_BITS)], case="e_stale"), mixed("lbf", [(100.5, mkhist(ctx)), (300.0, stale_h)], case="f_stale_hist"), hser(ctx, "lbf", [(250.0, mkhist(ctx))], case="g_hist"),
         fser("lbf", [(399.9995, 6.0), (400.5, 7.0)], case="h_future")]
    pos = spec(union([("lbf", "now"), ("lbf offset 100s", "off"), ("lbf @ 300", "at300"), ("lbf @ 100.5", "at100"), ("lbf offset -50s", "negoff"), ("last_over_time(lbf[100s])", "lot")]), f, time=400)
    g = [fser("lbg", [(100.0, 1.0)], case="a_at_bound"), fser("lbg", [(99.0, 2.0)], case="b_before"), fser("lbg", [(400.5, 3.0)], case="c_future"), fser("lbg", [(150.0, 4.0), (399.0, STALE_BITS)], case="d_stale"),
         mixed("lbg", [(150.0, mkhist(ctx)), (399.5, stale_h)], case="e_stale_hist")]
    neg = spec(union([("lbg", "now"), ("lbg @ 400", "at"), ("lbg offset 600s", "off600"), ("lbg @ 200", "lbg200")]), g, time=400)
    r = [fser("lbi", [(100.0, 1.0)], job="j", case="c0"), fser("lbi", [(100.5, 2.0)], job="j", case="c1"), fser("lbi", [(250.0, 4.0), (399.5, STALE_BITS)], job="k", case="c2"), fser("lbi", [(400.5, 8.0)], job="k", case="c3")]
    inter = spec(union([("lbi", "sel"), ("sum by (job) (lbi)", "sum"), ("count(lbi)", "count"), ("max_over_time(lbi[3s:1s])", "subq"), ("lbi offset 50s", "off")]), r, kind="range", start=399, end=402, step=1)
    return pos, neg, inter


def ordering(ctx, prof):
    m = [fser("ord_m", [(15, v)], case=c) for c, v in zip(("a", "b", "c", "d", "e", "f"), (3.0, 9.0, 1.0, 7.0, 5.0, 2.0))]
    pos = spec("topk(4, ord_m)", m)
    n = [fser("ord_n", [(15, v)], case=c) for c, v in zip(("a", "b", "c", "d", "e"), (3.0, NAN, 1.0, 7.0, -2.0))]
    neg = spec("sort_desc(ord_n)", n)
    rs = [fser("ord_z", [(5, 1.0), (15, 2.0), (25, 3.0)], case="z", job="b"), fser("ord_a", [(5, 4.0), (15, 5.0), (25, 6.0)], case="y", job="b"), fser("ord_a", [(5, 7.0), (15, 8.0), (25, 9.0)], case="a", job="a"),
          fser("ord_b", [(15, 10.0), (25, 11.0)], case="a", job="a")]
    inter = spec('label_replace(ord_z, "q", "x", "", "") or label_replace(ord_b, "q", "x", "", "") or label_replace(ord_a, "q", "x", "", "") or bottomk(2, ord_a)', rs, kind="range", start=5, end=25, step=10)
    return pos, neg, inter


def range_window(ctx, prof):
    a = fser("rw", [(0.0, 1.0), (0.001, 2.0), (10.0, 3.0), (20.0, 4.0), (20.001, 5.0)], case="a")
    b = fser("rw", [(5.0, 1.0), (10.0, STALE_BITS), (15.0, 3.0)], case="b")
    c = fser("rw", [(2.0, 9.0)], case="c_far")
    d = hser(ctx, "rw", [(5.0, mkhist(ctx, 2)), (19.0, mkhist(ctx, 5))], case="d_hist")
    pos = spec("rw[20s]", [a, b, c, d])
    neg = spec("rwn[15s]", [fser("rwn", [(5.0, 1.0)], case="a_on_bound"), fser("rwn", [(1.0, 2.0)], case="b_before"), fser("rwn", [(20.5, 3.0)], case="c_after"), fser("rwn", [(12.0, STALE_BITS)], case="d_stale_only")])
    rs = [fser("rw", [(0.0, 1.0), (4.0, 2.0), (10.0, 3.0), (14.0, 4.0), (20.0, 5.0), (30.0, 6.0)], case="a"), fser("rw", [(6.0, 1.0), (10.0, STALE_BITS), (16.0, 3.0)], case="b")]
    inter = spec(union([("count_over_time(rw[10s])", "cnt"), ("sum_over_time(rw[10s])", "sum"), ("last_over_time(rw[10s])", "last"), ("min_over_time(rw[10s])", "min"), ("sum_over_time(rw[10s] offset 5s)", "off"),
                        ("max_over_time(rw[10s] @ 20)", "at")]), rs, kind="range", start=10, end=30, step=10)
    return pos, neg, inter


FACTS = {
    "semantics/arithmetic": arithmetic,
    "semantics/comparison": comparison,
    "semantics/ieee": ieee,
    "semantics/lookback": lookback,
    "semantics/ordering": ordering,
    "semantics/range-window": range_window,
}
TESTS = {
    "semantics/arithmetic": ["TestReleaseNumericArithmeticSemantics", "TestReleaseNumericHistogramScalarOperationsDropEmptyBuckets"],
    "semantics/comparison": ["TestReleaseNumericComparisonSemantics"],
    "semantics/ieee": ["TestReleaseNumericIEEESemantics", "TestReleaseNumericMaxMinOverTimeSignedZeroKeepsFirst"],
    "semantics/lookback": ["TestReleaseNumericLookbackBoundary"],
    "semantics/ordering": ["TestReleaseNumericOrderingSemantics", "TestReleaseNumericRangeResultSeriesSortedByLabels"],
    "semantics/range-window": ["TestReleaseNumericRangeWindowSemantics"],
}
