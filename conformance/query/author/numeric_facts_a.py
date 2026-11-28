# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""numeric partition, facts A: absent-derived-labels, aggregation-parameters,
classic-quantile, float-sum-mean, lookback-boundary, matching-labels,
quantile-tolerance. Each FACTS function returns (positive, negative, interaction)
row specs for one profile; the differential runner decides every verdict."""
from numeric_lib import *

EXP = ("promql-experimental-functions",)


def absent_derived_labels(ctx, prof):
    s = [fser("ad_m", [(15, 1.0)], job="a"), hser(ctx, "ad_h", [(15, mkhist(ctx))], job="a")]
    pos = spec(union([
        ('absent(ad_none{job="a",instance="b"})', "eq"),
        ('absent(ad_none{job="a",job="b"})', "dup"),
        ('absent(ad_none{job=~"a.*",instance="b",env!="x"})', "re"),
        ('absent({__name__="ad_none",job="a"})', "name"),
        ('absent(sum(ad_none))', "agg"),
        ('absent(ad_m{job="zzz"})', "nomatch"),
        ('absent_over_time(ad_none{job="a",instance="b"}[5m])', "aot"),
        ('absent_over_time(ad_none{job="a",job="b"}[5m])', "aotdup"),
    ]), s)
    neg = spec(union([
        ('absent(ad_m)', "p1"),
        ('absent(ad_m{job="a"})', "p2"),
        ('absent(ad_h)', "histonly"),
        ('absent_over_time(ad_h[1m])', "aoth"),
        ('absent_over_time(ad_m[1m])', "aotf"),
    ]), s)
    s2 = [fser("ad_m", [(15, 1.0)], job="a"), hser(ctx, "ad_h", [(25, mkhist(ctx))], job="a")]
    inter = spec(union([
        ('absent(ad_m{job="a"})', "abs"),
        ('absent_over_time(ad_h{job="a"}[10s])', "aoth"),
        ('absent(sum(ad_m{job="a"}))', "sumabs"),
    ]), s2, kind="range", start=0, end=40, step=10)
    return pos, neg, inter


def aggregation_parameters(ctx, prof):
    m = [fser("ap_m", [(5, v)], case=c) for c, v in zip("abcd", (4.0, 3.0, 2.0, 1.0))]
    pos = spec(union([
        ("topk(2, ap_m)", "t2"), ("topk(1.9, ap_m)", "t19"), ("topk(1, ap_m)", "t1"), ("bottomk(2, ap_m)", "b2"), ("bottomk(100, ap_m)", "b100"),
        ("quantile(0.5, ap_m)", "q5"), ("quantile(0, ap_m)", "q0"), ("quantile(1.5, ap_m)", "qhi"), ("quantile(-1, ap_m)", "qlo"), ("quantile(NaN, ap_m)", "qnan"),
        ("limitk(2, ap_m)", "lk2"), ("limit_ratio(0.5, ap_m)", "lr5"), ("limit_ratio(-0.5, ap_m)", "lrn5"), ("limit_ratio(2, ap_m)", "lr2"), ("limit_ratio(-1, ap_m)", "lrn1"),
        ("limit_ratio(0, ap_m)", "lr0"), ("limit_ratio(1, ap_m)", "lr1"), ("limit_ratio(-0, ap_m)", "lrn0"), ("limit_ratio(Inf, ap_m)", "lrinf"), ("limit_ratio(-Inf, ap_m)", "lrminf"),
        ("topk(0.9, ap_m)", "t09"), ("topk(0, ap_m)", "t0"), ("topk(-1, ap_m)", "tm1"), ("bottomk(-1, ap_m)", "bm1"),
    ] + ([] if prof.endswith("3.1.0") else [("topk(-Inf, ap_m)", "tminf")])), m, enabled=EXP)
    # NaN is not convertible to int64 on 3.1.0 (a classified execution error); the 3.13.5 reference
    # reports a NaN parameter with unclassified text, so its out-of-range form is +Inf.
    neg = spec("topk(NaN, ap_m)" if prof.endswith("3.1.0") else "topk(Inf, ap_m)", m)
    k = [fser("ap_k", [(10, 1.0), (20, 2.0), (30, 3.0)])]
    inter = spec("topk(scalar(ap_k), ap_m)", m + k, kind="range", start=10, end=30, step=10)
    return pos, neg, inter


def classic_quantile(ctx, prof):
    def bucket(name, counts, **kv):
        return [fser(name + "_bucket", [(15, c)], le=le, **kv) for le, c in counts]
    ok = bucket("cq", [("0.1", 2.0), ("0.5", 6.0), ("1", 10.0), ("+Inf", 10.0)], instance="i1")
    inf = bucket("cq_inf", [("1", 5.0), ("+Inf", 10.0)], instance="i1")
    negb = bucket("cq_neg", [("-5", 3.0), ("5", 10.0), ("+Inf", 10.0)], instance="i1")
    dup = bucket("cq_dup", [("1", 3.0), ("1.0", 2.0), ("+Inf", 5.0)], instance="i1")
    pos = spec(union([
        ("histogram_quantile(0, cq_bucket)", "q0"), ("histogram_quantile(0.25, cq_bucket)", "q25"), ("histogram_quantile(0.5, cq_bucket)", "q50"),
        ("histogram_quantile(0.9, cq_bucket)", "q90"), ("histogram_quantile(1, cq_bucket)", "q100"),
        ("histogram_quantile(0.9, cq_inf_bucket)", "inf"), ("histogram_quantile(0.1, cq_neg_bucket)", "neg"), ("histogram_quantile(0.5, cq_dup_bucket)", "dup"),
    ]), ok + inf + negb + dup)
    noinf = bucket("cq_noinf", [("1", 3.0), ("2", 5.0)], instance="i1")
    one = bucket("cq_one", [("+Inf", 5.0)], instance="i1")
    zero = bucket("cq_zero", [("1", 0.0), ("+Inf", 0.0)], instance="i1")
    badle = bucket("cq_bad", [("abc", 3.0), ("+Inf", 5.0)], instance="i1")
    dec = bucket("cq_dec", [("1", 6.0), ("2", 4.0), ("+Inf", 8.0)], instance="i1")
    neg = spec(union([
        ("histogram_quantile(-1, cq_bucket)", "lo"), ("histogram_quantile(2, cq_bucket)", "hi"), ("histogram_quantile(NaN, cq_bucket)", "nan"),
        ("histogram_quantile(0.5, cq_noinf_bucket)", "noinf"), ("histogram_quantile(0.5, cq_one_bucket)", "one"), ("histogram_quantile(0.5, cq_zero_bucket)", "zero"),
        ("histogram_quantile(0.5, cq_bad_bucket)", "badle"), ("histogram_quantile(0.5, cq_dec_bucket)", "decrease"),
    ]), ok + noinf + one + zero + badle + dec)
    series = []
    for inst, scale in (("i1", 1.0), ("i2", 2.0)):
        for le, base in (("0.1", 1.0), ("0.5", 3.0), ("1", 5.0), ("+Inf", 5.0)):
            series.append(fser("cq_bucket", [(5, 0.0), (15, base * scale * 2), (25, base * scale * 4), (35, base * scale * 8)], instance=inst, le=le))
    for le, base in (("1", 6.0), ("2", 4.0), ("+Inf", 8.0)):
        series.append(fser("cq_dec_bucket", [(5, 0.0), (15, base), (25, base * 2), (35, base * 4)], instance="i3", le=le))
    inter = spec(union([
        ("histogram_quantile(0.9, sum by (le) (rate(cq_bucket[20s])))", "agg"),
        ("histogram_quantile(0.5, rate(cq_dec_bucket[20s]))", "dec"),
    ]), series, kind="range", start=20, end=40, step=10)
    return pos, neg, inter


def float_sum_mean(ctx, prof):
    def fm(name, cases):
        return [fser(name, samples, case=c) for c, samples in cases]
    finite = fm("fm", [
        ("cancel", [(5, 1e16), (10, 1.0), (15, -1e16)]),
        ("single", [(15, 3.5)]),
        ("uneven", [(5, 1.0), (6, 2.0), (14.5, 3.0)]),
        ("tenths", [(5, 0.1), (10, 0.2), (15, 0.3)]),
        ("variance", [(5, 2.0), (10, 4.0), (15, 9.0)]),
    ])
    across = fm("fma", [("a", [(15, 0.1)]), ("b", [(15, 0.2)]), ("c", [(15, 0.3)]), ("d", [(15, 1e16)]), ("e", [(15, -1e16)])])
    ops = ("sum_over_time", "avg_over_time", "stdvar_over_time", "stddev_over_time")
    pos = spec(union([("%s(fm[20s])" % o, o[:4]) for o in ops] + [("sum(fma)", "sum"), ("avg(fma)", "avg"), ("stdvar(fma)", "var"), ("stddev(fma)", "dev")]), finite + across)
    hard = fm("fm", [
        ("overflow", [(5, 1.7e308), (10, 1.7e308), (15, -1.7e308)]),
        ("overflow3", [(5, 1.7e308), (10, 1.7e308), (15, 1.7e308)]),
        ("samesign", [(5, INF), (10, INF)]),
        ("opposite", [(5, INF), (10, -INF)]),
        ("nan", [(5, NAN), (10, 1.0)]),
        ("neginf", [(5, -INF), (10, 2.0)]),
    ])
    neg = spec(union([("%s(fm[20s])" % o, o[:4]) for o in ops] + [("sum(fm)", "sum"), ("avg(fm)", "avg"), ("stdvar(fm)", "var"), ("sum_over_time(fm_none[20s])", "none")]), hard)
    series = [fser("fm", [(5, 1e16), (15, 1.0), (25, -1e16), (35, 0.5)], job="j", case="a"), fser("fm", [(5, 0.1), (15, 0.2), (25, 0.3), (35, 0.4)], job="j", case="b"),
              fser("fm", [(5, 1.0), (15, 2.0), (25, 4.0), (35, 8.0)], job="k", case="c")]
    inter = spec(union([("sum by (job) (avg_over_time(fm[20s]))", "avgsum"), ("sum by (job) (sum_over_time(fm[20s]))", "sumsum"), ("avg by (job) (stdvar_over_time(fm[20s]))", "var")]),
                 series, kind="range", start=15, end=35, step=10)
    return pos, neg, inter


def lookback_boundary(ctx, prof):
    stale_h = mkhist(ctx, 4, sum_bits=STALE_BITS)
    ok = [fser("lb", [(99.999, 1.0)], case="before"), fser("lb", [(100.0, 2.0)], case="at_bound"), fser("lb", [(100.001, 3.0)], case="inside"),
          fser("lb", [(400.0, 4.0)], case="at_target"), fser("lb", [(400.001, 5.0)], case="after_target"), fser("lb", [(50.0, 6.0), (300.0, 7.0)], case="latest"),
          fser("lb", [(100.5, 8.0), (300.0, STALE_BITS)], case="stale_float"),
          mixed("lb", [(100.5, mkhist(ctx)), (300.0, stale_h)], case="stale_hist"), hser(ctx, "lb", [(399.0, mkhist(ctx))], case="hist_ok"),
          fser("lb", [(100.5, 1.0), (200.0, STALE_BITS), (250.0, 9.0)], case="resumed_after_stale")]
    pos = spec("lb", ok, time=400)
    none = [fser("lbx", [(99.999, 1.0)], case="before"), fser("lbx", [(100.0, 2.0)], case="at_bound"), fser("lbx", [(400.001, 5.0)], case="after_target"),
            fser("lbx", [(100.5, 8.0), (300.0, STALE_BITS)], case="stale_float"), mixed("lbx", [(100.5, mkhist(ctx)), (300.0, stale_h)], case="stale_hist"),
            fser("lbx", [(100.5, 1.0), (300.0, STALE_BITS)], case="stale_then_gap"), fser("lbx", [(100.5, 1.0), (399.0, STALE_BITS)], case="stale_near_target")]
    neg = spec("lbx", none, time=400)
    rng = [fser("lbr", [(100.0, 1.0)], case="s0"), fser("lbr", [(100.5, 2.0)], case="s1"), fser("lbr", [(100.5, 3.0), (399.5, STALE_BITS)], case="s2"),
           fser("lbr", [(401.0, 4.0)], case="s3"), fser("lbr", [(100.5, 5.0), (399.0, 6.0)], case="s4")]
    inter = spec("lbr", rng, kind="range", start=399, end=402, step=1)
    return pos, neg, inter


def matching_labels(ctx, prof):
    a = [fser("ml_a", [(15, 2.0)], job="x", instance="1", extra="e"), fser("ml_a", [(15, 3.0)], job="x", instance="2", extra="f"), fser("ml_a", [(15, 5.0)], job="y", instance="1", extra="e")]
    b = [fser("ml_b", [(15, 10.0)], job="x", instance="1", extra="e2"), fser("ml_b", [(15, 20.0)], job="y", instance="1", extra="f2")]
    other = [fser("ml_one", [(15, 100.0)], job="x", extra="z"), fser("ml_c", [(15, 7.0)], job="x"), fser("ml_d", [(15, 11.0)], region="r")]
    pos = spec(union([
        ("ml_b + on(job) ml_c", "on"), ("ml_b + ignoring(extra, instance) ml_c", "ignoring"), ("ml_c + on() ml_d", "empty_on"),
        ("ml_a * on(job) group_left(extra) ml_one", "gl_include"), ("ml_a * on(job) group_left(extra) ml_c", "gl_absent"),
        ("ml_a * on(job) group_left(nolabel) ml_one", "gl_nolabel"), ("ml_c + on(__name__) ml_c", "on_name"), ("ml_c + ignoring(nolabel) ml_c", "ign_absent"),
        ("ml_one * on(job) group_right(instance) ml_a", "group_right"),
    ]), a + b + other)
    dup = [fser("ml_dup", [(15, 1.0)], job="x", instance="1", extra="e"), fser("ml_dup", [(15, 2.0)], job="x", instance="1", extra="f"), fser("ml_c", [(15, 7.0)], job="x")]
    neg = spec("ml_dup * on(job) group_left(extra) ml_c", dup)
    rs = [fser("ml_a", [(5, 2.0), (15, 4.0), (25, 8.0)], job="x", instance="1", extra="e"), fser("ml_a", [(5, 3.0), (15, 6.0), (25, 9.0)], job="x", instance="2", extra="f"),
          fser("ml_one", [(5, 100.0), (15, 200.0), (25, 300.0)], job="x", extra="z")]
    inter = spec("sum by (job, extra) (ml_a * on(job) group_left(extra) ml_one)", rs, kind="range", start=10, end=30, step=10)
    return pos, neg, inter


def quantile_tolerance(ctx, prof):
    def b(inst, c1, c2, c3, c4):
        return [fser("qt_bucket", [(15, c)], instance=inst, le=le) for le, c in (("1", c1), ("2", c2), ("3", c3), ("+Inf", c4))]
    big = 1000000000000.0
    pos_s = b("below_eps", big + 1, big, 2 * big, 2 * big) + b("zero_rule", 1e-320, 0.0, 5.0, 5.0) + b("equal", 4.0, 4.0, 8.0, 8.0) + b("subnormal_pair", 3e-320, 2e-320, 6.0, 8.0)
    # histogram_quantile emits its series in no defined order: sort() fixes it (the four values are distinct)
    pos = spec("sort(histogram_quantile(0.5, qt_bucket))", pos_s)
    neg_s = b("exact_eps", big + 1, big - 1, 2 * big, 2 * big) + b("above_eps", big + 2, big - 1, 2 * big, 2 * big) + b("zero_rule_over", 3e-320, 0.0, 5.0, 5.0) + b("material", 10.0, 6.0, 12.0, 12.0)
    neg = spec("sort(histogram_quantile(0.5, qt_bucket))", neg_s)
    ser = []
    for inst, f in (("i1", 1.0), ("i2", 1.0)):
        for le, c in (("1", big / 2 + 1), ("2", big / 2), ("3", big), ("+Inf", big)):
            ser.append(fser("qt_bucket", [(5, 0.0), (15, c * f), (25, c * f * 2)], instance=inst, le=le))
    inter = spec(union([("histogram_quantile(0.5, sum by (le) (qt_bucket))", "sum"), ("histogram_quantile(0.9, sum by (le) (rate(qt_bucket[20s])))", "rate")]), ser, kind="range", start=15, end=25, step=10)
    return pos, neg, inter


FACTS = {
    "fact/absent-derived-labels": absent_derived_labels,
    "fact/aggregation-parameters": aggregation_parameters,
    "fact/classic-quantile": classic_quantile,
    "fact/float-sum-mean": float_sum_mean,
    "fact/lookback-boundary": lookback_boundary,
    "fact/matching-labels": matching_labels,
    "fact/quantile-tolerance": quantile_tolerance,
}
TESTS = {
    "fact/absent-derived-labels": ["TestReleaseNumericAbsentDerivedLabels"],
    "fact/aggregation-parameters": ["TestReleaseNumericAggregationParameters", "TestReleaseNumericAggregationParameterEvaluationPerProfile"],
    "fact/classic-quantile": ["TestReleaseNumericClassicQuantile"],
    "fact/float-sum-mean": ["TestReleaseNumericFloatSumMean"],
    "fact/lookback-boundary": ["TestReleaseNumericLookbackBoundary"],
    "fact/matching-labels": ["TestReleaseNumericMatchingLabels"],
    "fact/quantile-tolerance": ["TestReleaseNumericQuantileTolerance"],
}
