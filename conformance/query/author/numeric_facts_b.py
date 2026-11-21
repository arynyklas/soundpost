# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""numeric partition, facts B: quantile-values, rate-extrapolation, regression,
round-clamp, scalar-sample-kind, smoothing, utc-calendar, instant-latest-two.
Each FACTS function returns (positive, negative, interaction) row specs for one
profile; the differential runner decides every verdict."""
from numeric_lib import *

EXP = ("promql-experimental-functions",)


def quantile_values(ctx, prof):
    mixed_vals = [fser("qv_m", [(15, v)], case=c) for c, v in zip("abcde", (3.0, 1.0, NAN, 5.0, 2.0))]
    fin = [fser("qv_f", [(15, v)], case=c) for c, v in zip("abcd", (3.0, 1.0, 5.0, 2.0))]
    one = [fser("qv_1", [(15, 7.0)], case="a")]
    two = [fser("qv_2", [(15, 1.0)], case="a"), fser("qv_2", [(15, 3.0)], case="b")]
    over = [fser("qv_o", [(5, 4.0), (10, 1.0), (15, 3.0), (19, 2.0)], case="a"), fser("qv_o", [(15, 6.0)], case="b"), fser("qv_o", [(5, NAN), (10, 1.0), (15, 2.0)], case="c")]
    parts = [("quantile(%s, qv_m)" % q, "m" + q) for q in ("0", "0.25", "0.5", "0.75", "1")]
    parts += [("quantile(%s, qv_f)" % q, "f" + q) for q in ("0", "0.3", "0.5", "1")]
    parts += [("quantile(0.5, qv_1)", "n1"), ("quantile(0.5, qv_2)", "n2"), ("quantile(0, qv_2)", "n2lo"), ("quantile(1, qv_2)", "n2hi")]
    parts += [("quantile_over_time(%s, qv_o[20s])" % q, "o" + q) for q in ("0", "0.5", "0.9", "1")]
    pos = spec(union(parts), mixed_vals + fin + one + two + over)
    nparts = [("quantile(-1, qv_f)", "lo"), ("quantile(2, qv_f)", "hi"), ("quantile(NaN, qv_f)", "nan"), ("quantile(0.5, qv_none)", "empty"),
              ("quantile_over_time(0.5, qv_none[20s])", "oempty"), ("quantile_over_time(-0.5, qv_o[20s])", "olo"), ("quantile_over_time(1.5, qv_o[20s])", "ohi"),
              ("quantile_over_time(0.5, qv_o[1s])", "owindow")]
    neg = spec(union(nparts), fin + over)
    grp = [fser("qv_g", [(5, 1.0), (15, 2.0), (25, 4.0)], job="a", case="x"), fser("qv_g", [(5, 3.0), (15, 6.0), (25, 8.0)], job="a", case="y"),
           fser("qv_g", [(5, 9.0), (15, 7.0), (25, NAN)], job="b", case="z")]
    inter = spec(union([("quantile by (job) (0.5, qv_g)", "agg"), ("quantile_over_time(0.5, qv_g[20s])", "over")]), grp, kind="range", start=15, end=25, step=10)
    return pos, neg, inter


def rate_extrapolation(ctx, prof):
    def ctr(case, times, base=0.0, step=10.0):
        return fser("rx_total", [(t, base + i * step) for i, t in enumerate(times)], case=case)
    valid = [
        ctr("a_keep", [41, 51, 61, 71, 81, 91]),
        ctr("b_half_hi", [51, 61, 71, 81, 91]),
        ctr("c_keep_lo", [50.999, 60.999, 70.999, 80.999, 90.999]),
        ctr("d_rightedge", [41, 51, 61, 71, 81, 89]),
        fser("rx_total", [(45, 10.0), (55, 20.0), (65, 5.0), (75, 15.0), (85, 25.0)], case="e_reset"),
        fser("rx_total", [(45, 1.0), (55, 2.0), (65, 3.0), (75, 4.0)], case="f_zero"),
        fser("rx_total", [(50, 5.0), (60, 25.0)], case="g_two"),
        fser("rx_total", [(45, 8.0), (55, 6.0), (65, 4.0)], case="h_gauge"),
    ]
    parts = [("rate(rx_total[60s])", "rate"), ("increase(rx_total[60s])", "inc"), ("delta(rx_total[60s])", "delta")]
    pos = spec(union(parts), valid, time=100)
    # the mixed-kind series are read by one call only: annotations with the same text are merged by the references
    invalid = [fser("rx_total", [(30, 1.0)], case="a_outside"), fser("rx_total", [(70, 3.0)], case="b_one"), fser("rx_total", [(55, 2.0), (75, 4.0)], case="z_ok"),
               mixed("rxm_total", [(55, 1.0), (75, mkhist(ctx))], case="a_mixed"), mixed("rxm_total", [(55, mkhist(ctx)), (75, 2.0)], case="b_mixed_rev")]
    neg = spec(union(parts + [("rate(rxm_total[60s])", "mixed")]), invalid, time=100)
    series = [fser("rx_total", [(5, 0.0), (15, 10.0), (25, 20.0), (35, 5.0), (45, 15.0), (55, 25.0), (65, 35.0)], job="j", case="a"),
              fser("rx_total", [(5, 1.0), (20, 3.0), (35, 7.0), (50, 9.0), (65, 14.0)], job="j", case="b"),
              fser("rx_total", [(10, 100.0), (30, 120.0), (50, 130.0)], job="k", case="c")]
    inter = spec(union([("sum by (job) (rate(rx_total[30s]))", "sum"), ("sum by (job) (increase(rx_total[30s]))", "inc"), ("max by (job) (delta(rx_total[30s]))", "delta")]),
                 series, kind="range", start=30, end=70, step=10)
    return pos, neg, inter


T0 = 1700000100.0


def regression(ctx, prof):
    def ser(case, vals, step=10.0, t0=T0):
        n = len(vals)
        return fser("rg", [(t0 - (n - 1 - i) * step, v) for i, v in enumerate(vals)], case=case)
    valid = [ser("a_const", [7.0] * 5), ser("b_linear", [0.0, 1.0, 2.0, 3.0, 4.0]), ser("c_two", [2.0, 5.0]), ser("d_tenths", [0.1, 0.2, 0.3, 0.45]),
             ser("e_smallgap", [1.0, 2.0, 3.0, 4.0], step=0.001), ser("f_curved", [1.0, 4.0, 9.0, 16.0, 25.0])]
    parts = [("deriv(rg[60s])", "deriv"), ("predict_linear(rg[60s], 30)", "pl30"), ("predict_linear(rg[60s], 0)", "pl0"), ("predict_linear(rg[60s], -15)", "plneg")]
    pos = spec(union(parts), valid, time=T0)
    invalid = [ser("a_one", [3.0]), ser("b_pinf", [INF] * 4), ser("c_opposite", [INF, -INF]), ser("d_nan", [1.0, NAN, 3.0]), ser("e_constneginf", [-INF] * 3),
               {"labels": labels("rg", case="f_hist"), "samples": [{"time": ms(T0 - 5), "histogram": mkhist(ctx)}, {"time": ms(T0 - 2), "histogram": mkhist(ctx, 6)}]},
               ser("z_ok", [1.0, 3.0])]
    neg = spec(union(parts), invalid, time=T0)
    rng = [fser("rg", [(T0 - 50 + 10 * i, v) for i, v in enumerate([1.0, 3.0, 2.0, 6.0, 4.0, 9.0, 10.0])], job="j", case="a"),
           fser("rg", [(T0 - 50 + 10 * i, 5.0) for i in range(7)], job="j", case="b"),
           fser("rg", [(T0 - 50 + 10 * i, v) for i, v in enumerate([0.5, 1.5, 4.5, 4.5, 5.5, 8.5, 9.5])], job="k", case="c")]
    inter = spec(union([("sum by (job) (deriv(rg[30s]))", "deriv"), ("sum by (job) (predict_linear(rg[30s], 60))", "pl")]), rng, kind="range", start=T0 - 20, end=T0 + 10, step=10)
    return pos, neg, inter


def round_clamp(ctx, prof):
    vals = [-2.5, -1.5, -0.5, 0.25, 0.5, 1.5, 2.5, 7.0, 1e300, INF, -INF, NAN, NZ]
    s = [fser("rc", [(15, v)], case="v%02d" % i) for i, v in enumerate(vals)] + [hser(ctx, "rc", [(15, mkhist(ctx))], case="hist")]
    pos = spec(union([("round(rc)", "r"), ("round(rc, 0.5)", "r05"), ("round(rc, 2)", "r2"), ("round(rc, -2)", "rm2"), ("round(rc, 0.1)", "r01"), ("round(rc, 1e-300)", "rtiny"),
                      ("clamp(rc, -1, 1)", "c11"), ("clamp(rc, 1, 1)", "c_eq"), ("clamp_min(rc, 0)", "cmin"), ("clamp_max(rc, 0)", "cmax"), ("clamp(rc, -INF, INF)", "cinf")]), s)
    neg = spec(union([("round(rc, 0)", "r0"), ("round(rc, -0)", "rn0"), ("round(rc, Inf)", "rinf"), ("round(rc, -Inf)", "rminf"), ("round(rc, NaN)", "rnan"), ("clamp(rc, 5, 1)", "cinv"),
                      ("clamp(rc, NaN, 1)", "cnanmin"), ("clamp(rc, 0, NaN)", "cnanmax"), ("clamp_min(rc, NaN)", "cminnan"), ("clamp_max(rc, NaN)", "cmaxnan")]), s)
    rs = [fser("rc", [(5, 0.5), (15, 1.5), (25, 2.5)], job="j", case="a"), fser("rc", [(5, -0.5), (15, -1.5), (25, 0.24)], job="j", case="b"), fser("rc", [(5, 10.25), (15, 10.75), (25, 11.5)], job="k", case="c")]
    inter = spec(union([("sum by (job) (round(rc, 0.5))", "sumr"), ("clamp(avg_over_time(rc[20s]), -1, 2)", "avgc"), ("round(rc offset 10s, 2)", "roff")]), rs, kind="range", start=15, end=25, step=5)
    return pos, neg, inter


def scalar_sample_kind(ctx, prof):
    old = prof.endswith("3.1.0")
    fl = [fser("sk_f", [(15, 3.0)], case="a")]
    hs = [hser(ctx, "sk_h", [(15, mkhist(ctx))], case="a")]
    fh = [fser("sk_fh", [(15, 5.0)], case="a"), hser(ctx, "sk_fh", [(15, mkhist(ctx))], case="b")]
    ff = [fser("sk_ff", [(15, 1.0)], case="a"), fser("sk_ff", [(15, 2.0)], case="b")]
    hh = [hser(ctx, "sk_hh", [(15, mkhist(ctx))], case="a"), hser(ctx, "sk_hh", [(15, mkhist(ctx, 6))], case="b")]
    allseries = fl + hs + fh + ff + hh
    sc = lambda n: ("vector(scalar(%s))" % n, n)
    if old:
        pos = spec(union([sc("sk_f"), sc("sk_h")]), allseries)  # exactly one vector element: the float, or the histogram's F=0
        neg = spec(union([sc("sk_fh"), sc("sk_ff"), sc("sk_hh"), sc("sk_none")]), allseries)
    else:
        pos = spec(union([sc("sk_f"), sc("sk_fh")]), allseries)  # exactly one float element, histogram peers ignored
        neg = spec(union([sc("sk_h"), sc("sk_ff"), sc("sk_hh"), sc("sk_none")]), allseries)
    rs = [fser("sk_f", [(5, 2.0), (15, 4.0), (25, 8.0)], case="a"), fser("sk_ff", [(5, 1.0), (15, 2.0), (25, 3.0)], case="a"), fser("sk_ff", [(5, 5.0), (15, 6.0), (25, 7.0)], case="b"),
          fser("sk_fh", [(5, 9.0), (15, 9.5)], case="a"), hser(ctx, "sk_fh", [(5, mkhist(ctx)), (15, mkhist(ctx, 5)), (25, mkhist(ctx, 6))], case="b")]
    inter = spec(union([("sk_ff * scalar(sk_f)", "mul"), ("vector(scalar(sk_fh) + 1)", "fh"), ("vector(scalar(sk_f) > bool 3)", "cmp")]), rs, kind="range", start=10, end=30, step=10)
    return pos, neg, inter


def smoothing(ctx, prof):
    sm = [fser("sm", [(5, 1.0), (10, 3.0), (15, 2.0), (20, 5.0), (25, 4.0)], case="a_series"), fser("sm", [(5, 2.0), (10, 2.0), (15, 2.0)], case="b_flat"),
          fser("sm", [(10, 1.0), (20, 4.0)], case="c_two")]
    nxt0 = 5e-324
    below1 = 0.9999999999999999
    pos = spec(union([("double_exponential_smoothing(sm[30s], %s, %s)" % (a, b), t) for a, b, t in
                      [("0.5", "0.5", "mid"), ("0.1", "0.9", "lowhigh"), ("5e-324", "0.5", "sf_min"), (repr(below1), "0.5", "sf_max"), ("0.5", "5e-324", "tf_min"), ("0.5", repr(below1), "tf_max")]]), sm, enabled=EXP)
    s2 = sm + [fser("sm1", [(15, 3.0)], case="a_one"), hser(ctx, "sm_h", [(10, mkhist(ctx)), (15, mkhist(ctx, 6))], case="a_hist"),
               mixed("sm_m", [(5, 1.0), (10, mkhist(ctx)), (15, 4.0)], case="a_mixed"), mixed("sm_m", [(5, 1.0), (10, mkhist(ctx))], case="b_floatthenhist")]
    neg = spec(union([("double_exponential_smoothing(sm[30s], NaN, 0.5)", "sfnan"), ("double_exponential_smoothing(sm[30s], 0.5, NaN)", "tfnan"),
                      ("double_exponential_smoothing(sm1[30s], 0.5, 0.5)", "one"), ("double_exponential_smoothing(sm_h[30s], 0.5, 0.5)", "histonly"),
                      ("double_exponential_smoothing(sm_m[30s], 0.5, 0.5)", "mixed"), ("double_exponential_smoothing(sm_none[30s], 0.5, 0.5)", "none")]), s2, enabled=EXP)
    rs = [fser("sm", [(5 + 5 * i, v) for i, v in enumerate([1.0, 3.0, 2.0, 5.0, 4.0, 8.0, 6.0])], job="j", case="a"), fser("sm", [(5 + 5 * i, v) for i, v in enumerate([2.0, 2.5, 3.5, 3.0, 4.0, 4.5, 5.0])], job="j", case="b"),
          fser("sm", [(5 + 5 * i, v) for i, v in enumerate([10.0, 9.0, 7.0, 4.0, 0.0, -5.0, -11.0])], job="k", case="c")]
    inter = spec(union([("sum by (job) (double_exponential_smoothing(sm[20s], 0.5, 0.5))", "sum"), ("double_exponential_smoothing(sm[15s], 0.3, 0.8) > bool 2", "cmp")]), rs, enabled=EXP, kind="range", start=20, end=40, step=10)
    return pos, neg, inter


CAL_FUNCS = ("day_of_month", "day_of_week", "day_of_year", "days_in_month", "hour", "minute", "month", "year")


def utc_calendar(ctx, prof):
    when = {"a_epoch": 0.0, "b_neg09": -0.9, "c_leap2000": 951782400.0, "d_nonleap2100": 4107456000.0 + 86399.0, "e_ye_before": 1704067199.0, "f_ye_after": 1704067200.0,
            "g_frac": 1700000000.9, "h_mar2100": 4107542400.0, "i_dec_1999": 946598400.0 + 82800.0 + 3599.0}
    T = 951786061.0  # 2000-02-29 01:01:01 UTC
    series = [fser("cal", [(T - 5, v)], case=c) for c, v in when.items()] + [hser(ctx, "cal", [(T - 5, mkhist(ctx))], case="z_hist")]
    parts = [("%s(cal)" % f, f) for f in CAL_FUNCS] + [("%s()" % f, f + "0") for f in CAL_FUNCS]
    pos = spec(union(parts), series, time=T)
    odd = [fser("cal", [(T - 5, v)], case=c) for c, v in [("a_nan", NAN), ("b_pinf", INF), ("c_ninf", -INF), ("d_huge", 1e19), ("e_neghuge", -1e19), ("f_negone", -1.0)]]
    odd += [hser(ctx, "calh", [(T - 5, mkhist(ctx))], case="a_hist")]
    neg = spec(union([("%s(cal)" % f, f) for f in CAL_FUNCS] + [("%s(calh)" % f, "h" + f) for f in CAL_FUNCS] + [("%s(cal_none)" % f, "n" + f) for f in CAL_FUNCS]), odd, time=T)
    rs = [fser("cal", [(946598400.0 + 86400 * i, 946598400.0 + 86400 * i) for i in range(0, 12)], case="a")]
    span = 951696000.0  # 2000-02-28 00:00:00 UTC
    inter = spec(union([("day_of_month()", "dom"), ("day_of_year()", "doy"), ("days_in_month()", "dim"), ("month(vector(time()))", "monvec"), ("day_of_week(cal offset 1d)", "dowoff")]),
                 [fser("cal", [(span - 10, span - 10), (span + 86390, span + 86390)], case="a")], kind="range", start=span + 3600, end=span + 3 * 86400 + 3600, step=86400)
    return pos, neg, inter


def instant_latest_two(ctx, prof):
    def h(n, reset=False):
        return mkhist(ctx, n)
    il = [
        fser("il", [(50, 1.0), (60, 4.0), (80, 9.0)], case="a_ff"),
        fser("il", [(60, 10.0), (80, 3.0)], case="b_reset"),
        mixed("il", [(40, h(2)), (60, 1.0), (80, 3.0)], case="c_old_hist_then_floats"),
        fser("il", [(20, 1.0), (60, 2.0), (80, 8.0)], case="d_gap"),
    ]
    ilh = [hser(ctx, "ilh", [(60, h(4)), (80, h(10))], case="a_hh"), hser(ctx, "ilh", [(60, h(10)), (80, h(4))], case="b_hist_reset")]
    parts = [("irate(il[40s])", "irate"), ("idelta(il[40s])", "idelta"), ("irate(ilh[40s])", "hirate"), ("idelta(ilh[40s])", "hidelta")]
    pos = spec(union(parts), il + ilh, time=90)
    # each mixed-kind metric is read by exactly one call: annotations with the same text are merged by the references
    bad = [fser("il", [(80, 5.0)], case="c_one"), fser("il", [(10, 5.0), (20, 7.0)], case="d_outside"), fser("il", [(60, 1.0), (80, 3.0)], case="z_ok"),
           mixed("ilx", [(60, 1.0), (80, h(4))], case="a_fh"), mixed("ily", [(60, h(4)), (80, 2.0)], case="b_hf"), hser(ctx, "ilh", [(80, h(4))], case="b_one")]
    neg = spec(union([("irate(il[40s])", "irate"), ("idelta(il[40s])", "idelta"), ("irate(ilx[40s])", "mix_fh"), ("idelta(ily[40s])", "mix_hf"), ("irate(ilh[40s])", "one_hist")]), bad, time=90)
    rs = [fser("il", [(5 + 10 * i, v) for i, v in enumerate([0.0, 5.0, 9.0, 20.0, 3.0, 8.0, 12.0])], job="j", case="a"),
          fser("il", [(5 + 10 * i, v) for i, v in enumerate([1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0])], job="j", case="b"),
          hser(ctx, "ilh", [(5 + 10 * i, h(n)) for i, n in enumerate([2, 4, 9, 3, 7, 12, 20])], job="j", case="h")]
    inter = spec(union([("sum by (job) (irate(il[20s]))", "sum"), ("max by (job) (idelta(il[20s]))", "max"), ("histogram_count(irate(ilh[20s]))", "hcount"), ("histogram_sum(idelta(ilh[20s]))", "hsum")]),
                 rs, kind="range", start=25, end=65, step=10)
    return pos, neg, inter


FACTS = {
    "fact/quantile-values": quantile_values,
    "fact/rate-extrapolation": rate_extrapolation,
    "fact/regression": regression,
    "fact/round-clamp": round_clamp,
    "fact/scalar-sample-kind": scalar_sample_kind,
    "fact/smoothing": smoothing,
    "fact/utc-calendar": utc_calendar,
    "fact/instant-latest-two": instant_latest_two,
}
TESTS = {
    "fact/quantile-values": ["TestReleaseNumericQuantileValues"],
    "fact/rate-extrapolation": ["TestReleaseNumericRateExtrapolation"],
    "fact/regression": ["TestReleaseNumericRegression"],
    "fact/round-clamp": ["TestReleaseNumericRoundClamp"],
    "fact/scalar-sample-kind": ["TestReleaseNumericScalarSampleKind"],
    "fact/smoothing": ["TestReleaseNumericSmoothing"],
    "fact/utc-calendar": ["TestReleaseNumericUTCCalendar"],
    "fact/instant-latest-two": ["TestReleaseNumericInstantLatestTwo"],
}
