# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Semantic-family, error-class, extended-range, fill, versioned-primitive and
configuration obligations (11.15 worker `semantics`). Every row is authored from
the obligation rule text over small hand-built fixtures; the differential runners
(owned engine against the pinned reference) decide whether it matches."""
import copy
import struct

NS = 1_000_000_000
EVAL = "cases/release-semantics-eval.json"
SYN = "cases/release-semantics-syntax.json"
P31, P313 = "promql-prometheus-3.1.0", "promql-prometheus-3.13.5"
BOTH = (P31, P313)
NAN = "7ff8000000000001"


def fb(x):
    return struct.pack(">d", x).hex()


def ser(name, labels=None, samples=((15, 1.0),), hist=None):
    lab = {"__name__": name, **(labels or {})}
    out = []
    for t, v in samples:
        t_ns = str(int(t * NS))
        if isinstance(v, dict):
            out.append({"time": t_ns, "histogram": copy.deepcopy(v)})
        elif isinstance(v, str):
            out.append({"time": t_ns, "float_bits": v})
        else:
            out.append({"time": t_ns, "float_bits": fb(v)})
    return {"labels": [{"name": k, "value": lab[k]} for k in sorted(lab)], "samples": out}


def row(q, series, t=20, rng=None, enabled=(), lookback=None, substep=None):
    r = {"query": q, "series": series, "enabled": list(enabled)}
    if rng:
        r["rng"] = rng
    else:
        r["t"] = t
    if lookback:
        r["lookback"] = lookback
    if substep:
        r["substep"] = substep
    return r


def sort_series(series):
    """The owned selector orders series by label set; the reference keeps fixture
    order, so fixtures are authored (and emitted) in label-set order."""
    out = copy.deepcopy(series)
    out.sort(key=lambda s: [(l["name"], l["value"]) for l in s["labels"]])
    return out


def build(ctx):
    ctx.declare(EVAL, "promql", "evaluation", {"phase": "evaluation"})
    ctx.declare(SYN, "promql", "syntax", {"schema": "soundpost-authored-syntax-cases-v1", "phase": "syntax"})
    HIST = ctx.HIST

    def eval_row(rid, profile, spec):
        r = {"id": rid, "profiles": [profile], "enabled_features": spec["enabled"], "query": spec["query"],
             "series": sort_series(spec["series"])}
        if "rng" in spec:
            s, e, st = spec["rng"]
            r.update({"kind": "range", "start": str(int(s * NS)), "end": str(int(e * NS)), "step": str(int(st * NS))})
        else:
            r.update({"kind": "instant", "time": str(int(spec["t"] * NS))})
        if "lookback" in spec:
            r["lookback_ns"] = str(spec["lookback"])
        if "substep" in spec:
            r["subquery_step_ns"] = str(spec["substep"])
        # dict order: keep id first for readability
        return {k: r[k] for k in ("id", "profiles", "enabled_features", "query", "kind", "time", "start", "end", "step", "lookback_ns", "subquery_step_ns", "series") if k in r}

    def syn_row(rid, profile, expr, accepted, typ=None, category=None, enabled=()):
        exp = {"accepted": accepted}
        if accepted and typ:
            exp["type"] = typ
        if not accepted and category:
            exp["category"] = category
        return {"id": rid, "profiles": [profile], "enabled_features": list(enabled), "input": {"expression": expr}, "expected": exp}

    def family(sem, pos, neg, inter, profiles=BOTH, bind=None):
        """pos/neg/inter: row() specs (evaluation) or ('syn', expr, accepted, type, category)."""
        for p in profiles:
            oid = f"{p}/{sem}"
            ids = ctx.role_ids(ctx.BY_ID[oid])
            for rid, spec in zip(ids, (pos, neg, inter)):
                if isinstance(spec, tuple) and spec[0] == "syn":
                    _, expr, accepted, typ, cat = spec[:5]
                    ctx.put(SYN, syn_row(rid, p, expr, accepted, typ, cat, enabled=spec[5] if len(spec) > 5 else ()))
                else:
                    ctx.put(EVAL, eval_row(rid, p, spec))
            if bind:
                ctx.bind(oid, bind[0], bind[1])

    def counter(name, labels=None, samples=((5, 1), (10, 3), (15, 6), (20, 10))):
        return ser(name, labels, samples)

    m4 = [ser("m", {"job": "api"}, ((5, 1), (10, 2), (15, 3), (20, 4)))]

    # ---- semantics/at-offset -----------------------------------------------------
    family("semantics/at-offset",
           row("m @ 10 offset 5s", m4),
           ("syn", "m @ 10 @ 20", False, None, "syntax"),
           row("sum(m @ start() offset 5s) + on() sum(m)", m4, rng=(10, 20, 5)))

    # ---- semantics/errors --------------------------------------------------------
    dup = [ser("a", {"job": "x"}, ((15, 1),)), ser("b", {"job": "x"}, ((15, 2),))]
    family("semantics/errors",
           row('{__name__=~"a|b"} + 1', dup),
           row("abs(m[5s])", m4),
           row('sum({__name__=~"a|b"} + 1)', dup))

    # ---- semantics/grid ----------------------------------------------------------
    family("semantics/grid",
           row("m", m4, rng=(10, 22, 5)),
           row("m[5s]", m4, rng=(10, 20, 5)),
           row("scalar(sum(m)) * 2", m4, rng=(10, 20, 5)))

    # ---- semantics/name-removal (gate promql-delayed-name-removal) ----------------
    DN = ["promql-delayed-name-removal"]
    dnser = [ser("m", {"job": "api"}, ((15, 5),))]
    family("semantics/name-removal",
           row("abs(m)", dnser, enabled=DN),
           row('abs({__name__=~"a|b"})', dup, enabled=DN),
           row('label_replace(abs(m), "orig", "$1", "__name__", "(.*)")', dnser, enabled=DN))

    # ---- semantics/selector -------------------------------------------------------
    sel = [ser("m", {"job": "api", "instance": "1"}, ((15, 1),)),
           ser("m", {"job": "api", "instance": "2", "zone": "e1"}, ((15, 2),)),
           ser("m", {"job": "web", "instance": "3"}, ((15, 3),)),
           ser("m", {"job": "web", "instance": "4", "zone": "w1"}, ((15, 4),)),
           ser("other", {"job": "api"}, ((15, 9),))]
    nl = [ser("m", {"job": "api", "v": "a\nb"}, ((15, 7),)), ser("m", {"job": "api", "v": "ab"}, ((15, 8),)), ser("m", {"job": "web", "v": "a\nb"}, ((15, 9),))]
    family("semantics/selector",
           row('m{job=~"api|web", instance!="4", zone=""}', sel),
           ("syn", '{job=~".*"}', False, None, "syntax"),
           row('sum by (job) (m{v=~"a.b"})', nl))

    # ---- semantics/set-operators --------------------------------------------------
    so = [ser("a", {"job": "x", "instance": "1"}, ((15, 1),)), ser("a", {"job": "x", "instance": "2"}, ((15, 2),)),
          ser("a", {"job": "y", "instance": "1"}, ((15, 3),)), ser("b", {"job": "x"}, ((15, 5),)), ser("b", {"job": "z"}, ((15, 6),))]
    family("semantics/set-operators",
           row("a or on(job) b", so),
           ("syn", "a and on(job) group_left b", False, None, "type"),
           row("sum(a and on(job) b)", so))

    # ---- semantics/subquery -------------------------------------------------------
    family("semantics/subquery",
           row("sum_over_time(m[10s:4s])", m4, t=22),
           ("syn", "(1)[5s:1s]", False, None, "type"),
           row("sum_over_time(m[10s:5s] @ end() offset 5s) * 2", m4, rng=(20, 30, 5)))

    # ---- semantics/vector-match ---------------------------------------------------
    vm = [ser("a", {"job": "x", "instance": "1"}, ((15, 2),)), ser("a", {"job": "x", "instance": "2"}, ((15, 3),)),
          ser("b", {"job": "x", "zone": "z1"}, ((15, 10),)), ser("c", {"job": "x", "instance": "1"}, ((15, 7),))]
    family("semantics/vector-match",
           row("a + c", vm),
           row("a + on(job) b", vm),
           row("sum by (zone) (a * on(job) group_left(zone) b)", vm))

    # ---- error classes observable in evaluation rows ----------------------------------
    ok_ser = [ser("a", {"job": "x"}, ((15, 1),)), ser("c", {"job": "y"}, ((15, 2),))]
    family("error/duplicate-labelset",
           row('{__name__=~"a|b"} + 1', dup),
           row('{__name__=~"a|c"} + 1', ok_ser),
           row('sum({__name__=~"a|b"} + 1)', dup))
    family("error/many-to-many",
           row("b + on(job) a", vm),
           row("a and on(job) b", vm),
           row("count(b > on(job) a)", vm))
    mm = [ser("a", {"job": "x", "instance": "1"}, ((15, 2),)), ser("b", {"job": "x", "zone": "p"}, ((15, 10),)), ser("b", {"job": "x", "zone": "q"}, ((15, 20),))]
    mm2 = [ser("a", {"job": "x", "zone": "p"}, ((15, 2),)), ser("a", {"job": "x", "zone": "q"}, ((15, 3),)), ser("b", {"job": "x", "zone": "r"}, ((15, 10),))]
    mm3 = [ser("a", {"job": "x", "instance": "1"}, ((15, 2),)), ser("b", {"job": "x", "zone": "p"}, ((15, 10),))]
    family("error/multiple-match",
           row("a + on(job) b", vm),
           row("a + on(job) group_left(zone) b", mm3),
           row("a * on(job) group_left(zone) b", mm2))
    mp = [ser("m", {"job": "x"}, ((15, 4),))]
    family("error/invalid-parameter",
           row("topk(1e19, m)", mp),
           row("quantile(1.5, m)", mp),
           row("sum(topk(1e19, m))", mp))

    # ---- error classes an oracle row cannot reconfigure: honest neighbouring rows ----
    # The row set observes the same query completing under the default context and
    # budget (no cancel/timeout/storage/budget failure) and a classified error that is
    # a different error class; the failure itself is observed by Go tests.
    for sem in ("error/cancel", "error/timeout", "error/storage", "error/sample-budget"):
        family(sem,
               row("sum_over_time(m[20s])", m4),
               row("sum(m[5s])", m4),
               row("sum(sum_over_time(m[20s]))", m4))
    # @ and negative offsets are engine option switches that both references enable.
    family("error/feature-validation",
           row("m @ 10", m4),
           row("m offset 5s", m4),
           row("sum(m offset -5s)", m4))
    # Range queries: a name-removal collision at any step is an error, never a merged series.
    rdup = [ser("a", {"job": "x"}, ((5, 1), (10, 2), (15, 3), (20, 4))), ser("b", {"job": "x"}, ((5, 4), (10, 5), (15, 6), (20, 7)))]
    for p in BOTH:
        for tag, q, enabled in (("plain-binary", '{__name__=~"a|b"} + 1', ()), ("plain-function", 'abs({__name__=~"a|b"})', ()),
                                ("delayed-function", 'abs({__name__=~"a|b"})', ["promql-delayed-name-removal"]),
                                ("delayed-binary", '{__name__=~"a|b"} + 1', ["promql-delayed-name-removal"])):
            ctx.put(EVAL, eval_row(f"{p}/release-semantics/extra/range-name-collision-{tag}", p, row(q, rdup, rng=(10, 20, 5), enabled=enabled)))
            # The colliding series are present at different steps only (1s lookback).
            rstag = [ser("a", {"job": "x"}, ((10, 1),)), ser("b", {"job": "x"}, ((15, 2),))]
            ctx.put(EVAL, eval_row(f"{p}/release-semantics/extra/range-name-collision-staggered-{tag}", p, row(q, rstag, rng=(10, 20, 5), enabled=enabled, lookback=NS)))
    # Extra differential rows: a comparison that filters both samples out versus the
    # same match groups kept (3.1.0 and 3.13.5 differ in when they notice the repeat).
    for p in BOTH:
        ctx.put(EVAL, eval_row(f"{p}/release-semantics/extra/comparison-filtered-repeat", p, row("a > on(job) b", vm)))
        ctx.put(EVAL, eval_row(f"{p}/release-semantics/extra/comparison-kept-repeat", p, row("a < on(job) b", vm)))
        for tag, q in (("topk-negative-overflow", "topk(-1e19, m)"), ("bottomk-negative-overflow", "bottomk(-1e19, m)"), ("topk-nan", "topk(NaN, m)"),
                       ("topk-inf", "topk(Inf, m)"), ("topk-max-int64-edge", "topk(9223372036854775807, m)"), ("topk-zero", "topk(0, m)"), ("topk-fraction", "topk(1.9, m)")):
            if tag == "topk-nan" and p == P313:
                continue  # the 3.13.5 reference's NaN parameter error text is unclassified by the oracle driver
            ctx.put(EVAL, eval_row(f"{p}/release-semantics/extra/aggregation-parameter-{tag}", p, row(q, mp)))

    # ---- facts --------------------------------------------------------------------------
    family("fact/subquery-alignment",
           row("sum_over_time(m[10s:4s])", m4, t=22),
           row("sum_over_time(m[10s:5s])", m4, t=20),
           row("sum_over_time(m[8s:3s] offset 2s)", m4, rng=(10, 23, 4)))

    # ---- extended range / fill (3.13.5) -----------------------------------------------
    XR = ["promql-extended-range-selectors"]
    c = [counter("c", {"job": "api"}), ser("d", {"job": "api"}, ((30, 5),))]
    family("fact/extended-endpoints",
           row("rate(c[10s] smoothed)", c, t=18, enabled=XR),
           row("rate(d[10s] smoothed)", c, t=18, enabled=XR),
           row("sum(increase(c[10s] anchored))", c, rng=(10, 20, 5), enabled=XR),
           profiles=(P313,))
    ch = [ser("h", {"job": "api"}, ((5, HIST), (10, HIST), (15, HIST), (20, HIST))), counter("c", {"job": "api"})]
    family("fact/extended-root-context",
           row("c[10s] anchored", ch, t=18, enabled=XR),
           row("c[10s:5s] smoothed", ch, t=18, enabled=XR),
           row("rate(h[10s] smoothed)", ch, t=18, enabled=XR),
           profiles=(P313,))
    family("semantics/extended-range",
           row("rate(c[10s] anchored)", c, t=18, enabled=XR),
           row("sum_over_time(c[10s] smoothed)", c, t=18, enabled=XR),
           row("changes(c[10s] anchored) + resets(c[10s] anchored)", c, t=18, enabled=XR),
           profiles=(P313,))
    FL = ["promql-binop-fill-modifiers"]
    fa = [ser("a", {"job": "x"}, ((15, 4),)), ser("a", {"job": "y"}, ((15, 6),)), ser("b", {"job": "x"}, ((15, 2),))]
    fn = [ser("a", {"job": "x"}, ((15, 4),)), ser("a", {"job": "y"}, ((15, 6),)), ser("b", {"job": "x"}, ((15, 2),)), ser("b", {"job": "y"}, ((15, NAN),))]
    family("fact/fill-operands",
           row("a + on(job) fill(0) b", fa, enabled=FL),
           row("a + on(job) fill(0) b", fn, enabled=FL),
           row("a > bool on(job) fill(0) b", fa, enabled=FL),
           profiles=(P313,))
    family("semantics/fill",
           row("a + on(job) fill_left(100) b", fa + [ser("b", {"job": "z"}, ((15, 7),))], enabled=FL),
           ("syn", "a + fill(0) b", False, None, "syntax", ()),
           row("a * on(job) group_left fill_right(1) b", fa, enabled=FL),
           profiles=(P313,))

    # ---- primitives ---------------------------------------------------------------------
    def vals(name, vs, extra=None):
        return [ser(name, {"job": "j", "i": str(i), "v": v, **(extra or {})}, ((15, float(i + 1)),)) for i, v in enumerate(vs)]

    caps = vals("m", ["aab", "ab", "b", "aa"])
    family("primitive/anchoring-captures-replacement",
           row('label_replace(m, "dst", "[$1x|${1}x|$$|$2]", "v", "(a+)(b*)")', caps),
           row('label_replace(m, "dst", "$1", "v", "(a)")', caps),
           row('sum by (dst) (label_replace(m, "dst", "$1", "v", "(.*)"))', vals("m", ["a\nb", "ab"])))
    asc = vals("m", ["abc_1", "éa", "٣", "ab", "٣٣"])
    ker = vals("m", ["\u212a", "k", "ſ", "s", "é", "1", "٣"])
    wb = vals("m", ["fooé", "foo é", "foo-bar", "foobar", "éfoo"])
    family("primitive/ascii-classes-boundaries",
           row('m{v=~"\\\\w+"}', asc),
           row('m{v=~"(?i)\\\\d+"}', ker),
           row('count(m{v=~".*\\\\bfoo\\\\b.*"})', wb))
    dia = vals("m", ["abc", "aXXb", "ab", "aab"])
    family("primitive/backend-dialect",
           row('label_replace(m, "dst", "${n}-$2", "v", "(?P<n>a+?)(?:b|X+)(b?)")', dia),
           ("syn", 'm{v=~"(a)\\\\1"}', False, None, "syntax"),
           row('count(m{v=~"(?s)a.+?b|(?i:AB){1,2}"})', dia))
    fold = vals("m", ["kx", "\u212ax", "KX", "ſx", "xk", "x\u212a"])
    family("primitive/matcher-optimization-fold-length",
           row('m{v=~"(?i)k.*"}', fold),
           row('m{v=~"(?i).*k"}', fold),
           row('count by (j) (m{v=~"(?i)k.*"})', fold))
    for p in BOTH:
        ctx.put(EVAL, eval_row(f"{p}/release-semantics/extra/fold-length-unoptimized-shape", p, row('m{v=~"(?i)k[a-z]"}', fold)))
    nrm = vals("m", ["CAFÉ", "Café", "café", "cafe\u0301", "TEA", "straße", "STRASSE"])
    family("primitive/normalization-version-selection",
           row('m{v=~"(?i)café|tea"}', nrm),
           row('m{v!~"(?i)café|tea"}', nrm),
           row('count(m{v=~"(?i)strasse|straße|café"})', nrm))
    nfk = vals("m", ["\ufb01", "fi", "FI", "\uff26\uff29", "\u0130", "i\u0307", "x"])
    for p in BOTH:
        for tag, q in (("fold-set", 'm{v=~"(?i)fi|bar"}'), ("fold-set-dotted-i", 'm{v=~"(?i)\u0130|bar"}'), ("fold-single", 'm{v=~"(?i)fi"}'), ("sensitive-set", 'm{v=~"fi|bar"}'), ("fold-set-fullwidth", 'm{v=~"(?i)\uff26\uff29|bar"}')):
            ctx.put(EVAL, eval_row(f"{p}/release-semantics/extra/normalization-{tag}", p, row(q, nfk)))
    gr = vals("m", ["αβγ", "abc", "٣", "Ⅷ", "x"])
    family("primitive/property-name-acceptance",
           row('m{v=~"\\\\p{Greek}+"}', gr),
           ("syn", 'm{v=~"\\\\p{Assigned}"}', False, None, "syntax"),
           row('count(m{v=~"\\\\p{L}+|\\\\p{Nd}"})', gr))
    kf = vals("m", ["ɤ", "Ɤ", "\u212a", "k", "ſ", "S"])
    family("primitive/simple-fold-version",
           row('m{v=~"(?i)k|s"}', kf),
           row('m{v=~"(?i)ɤ"}', kf),
           row('count by (j) (m{v=~"(?i)[ɤk]"})', kf))
    tab = vals("m", ["é", "\u1c89", "\U00011f00", "٣", "x", "\u0264", "\ua7cb"])
    family("primitive/unicode-table-membership",
           row('m{v=~"\\\\p{L}+"}', tab),
           ("syn", 'm{v=~"\\\\p{Garay}"}', False, None, "syntax"),
           row('count(m{v=~"[^\\\\p{Nd}\\\\p{L}]|(?i)\\\\p{Lu}"})', tab))
    u8 = vals("m", ["é", "a", "éa", "日本", "\ufffd"])
    family("primitive/utf8-runtime-semantics",
           row('m{v=~"^.$"}', u8),
           ("syn", 'm{v=~"(\\xff)"}', False, None, "syntax"),
           row('label_replace(m, "dst", "$2-$1", "v", "(.)(.)")', u8))

    # ---- configuration/query-options ----------------------------------------------------
    old = [ser("m", {"job": "api"}, ((20, 1),))]
    edge = [ser("m", {"job": "api"}, ((399.999, 1),))]
    lb = lambda sec: int(sec * NS)
    # fact/sample-budget: the oracle's budget (query.max-samples 50M) cannot be lowered by a row, so the
    # rows observe the same selector, window and subquery shapes completing under it; the unit costs and
    # peaks are checked by Go tests with hand-derived values.
    hs = [ser("h", {"job": "api"}, ((15, HIST),))]
    family("fact/sample-budget",
           row("histogram_count(h)", hs),
           row("sum(m[5s])", m4),
           row("count_over_time(m[10s:5s])", m4))
    family("configuration/query-options",
           row("m", old, t=400, lookback=lb(400)),
           row("m", edge, t=400, lookback=1_000_000),
           row("sum(m)", [ser("m", {"job": "api"}, ((95, 1), (105, 2), (118, 3), (140, 4)))], rng=(100, 130, 10), lookback=lb(15)))

    # ---- extra differential rows: regex dialect and Unicode category keys ---------------
    # Authored acceptance: exact case-sensitive runtime category/script keys and Any are
    # accepted; Cn and LC exist only in the 3.13.5 table set; everything else is rejected.
    for p in BOTH:
        for key, name in (("Cn", "cn"), ("LC", "lc"), ("Lc", "lc-mixed-case"), ("Any", "any"), ("Greek", "greek"), ("Assigned", "assigned"), ("Letter", "long-name")):
            accepted = key in ("Any", "Greek") or (p == P313 and key in ("Cn", "LC"))
            ctx.put(SYN, syn_row(f"{p}/release-semantics/extra/property-{name}", p, 'm{v=~"\\\\p{%s}"}' % key, accepted, None, None if accepted else "syntax"))
        for text, accepted, name in (("(?=a)", False, "lookahead"), ("(?<=a)", False, "lookbehind"), ("a++", False, "possessive"),
                                     ("a{1000}", True, "repeat-1000"), ("a{1001}", False, "repeat-1001"), ("(a{1000}){1000}", False, "repeat-nested"),
                                     ("(?P<n>a)(?:b)(?i)c(?s:.)", True, "perl-groups-and-flags"), ("(?U)a+", True, "ungreedy-flag"), ("[[:alpha:]\\d]", True, "posix-class"),
                                     ("[[:nosuch:]]", False, "posix-unknown")):
            ctx.put(SYN, syn_row(f"{p}/release-semantics/extra/dialect-{name}", p, 'm{v=~"%s"}' % text.replace("\\", "\\\\"), accepted, None, None if accepted else "syntax"))

    # ---- bindings: only obligations whose three case rows were authored above ---------------
    PROMQL, REGEX = "internal/query/promql", "internal/query/regexcompat"
    own = lambda *names: ["TestReleaseSemantics" + n for n in names]
    failure_classes = own("CancelIsNeverEmptySuccess", "TimeoutIsNeverEmptySuccess", "StorageFailureIsNeverEmptyData", "SampleBudgetNeverTruncates")
    bindings = {
        "semantics/at-offset": (PROMQL, ["TestExactGridOffsetSubquery", "TestPinnedTimestampAndDurationQuantization"] + own("EngineOptionsRejectAtAndNegativeOffset")),
        "semantics/errors": (PROMQL, failure_classes + ["TestLanguageFailuresRetainSemanticOrigins"] + own("CopiedGroupingLabelCollisionIsMultipleMatch", "DuplicateLabelsetErrorsAtTheSameStep", "InvalidParameterErrorsButQuantileWarns")),
        "semantics/grid": (PROMQL, ["TestNativeMillisecondDomainRangeGrid", "TestExactGridOffsetSubquery"]),
        "semantics/name-removal": (PROMQL, ["TestProfileMetadataSchemaRemovalAndDelayedCleanup", "TestVectorOperatorValuesAndNameRules"] + own("DuplicateLabelsetErrorsAtTheSameStep", "RangeQueryNameCollisionIsDuplicateLabelset", "LegacyDelayedRangeCollisionAcrossSteps")),
        "semantics/selector": (PROMQL, ["TestSelectorRegexUsesPinnedPrimitive", "TestVectorMissingEmptyLabelsAndGroupingUniqueness"]),
        "semantics/set-operators": (PROMQL, ["TestEveryPromQLOperator", "TestVectorOperatorValuesAndNameRules"] + own("ManyToManyNeedsUniqueOneSide")),
        "semantics/subquery": (PROMQL, ["TestNestedSubqueryResolution", "TestExactGridOffsetSubquery"] + own("SubqueryGridIsGloballyAligned")),
        "semantics/vector-match": (PROMQL, ["TestVectorMissingEmptyLabelsAndGroupingUniqueness", "TestGroupingInfrastructure"] + own("CopiedGroupingLabelCollisionIsMultipleMatch", "FilteredComparisonIsNotARepeatedMatch", "ManyToManyNeedsUniqueOneSide")),
        "semantics/extended-range": (PROMQL, ["TestNativeExtendedRejectedFunctionsFailDuringExecution", "TestNativeExtensionOnSubqueryIsAParseError", "TestNativeExtendedMatrixSelectorBoundaries", "TestPinnedGatedSyntax"]),
        "semantics/fill": (PROMQL, ["TestPinnedGatedSyntax"] + own("FillSubstitutesOnlyAbsentSides")),
        "error/duplicate-labelset": (PROMQL, own("DuplicateLabelsetErrorsAtTheSameStep", "RangeQueryNameCollisionIsDuplicateLabelset", "LegacyDelayedRangeCollisionAcrossSteps")),
        "error/many-to-many": (PROMQL, own("ManyToManyNeedsUniqueOneSide")),
        "error/multiple-match": (PROMQL, own("CopiedGroupingLabelCollisionIsMultipleMatch", "FilteredComparisonIsNotARepeatedMatch")),
        "error/invalid-parameter": (PROMQL, ["TestNativeTopkParameterRange"] + own("InvalidParameterErrorsButQuantileWarns")),
        "error/cancel": (PROMQL, own("CancelIsNeverEmptySuccess") + ["TestEvaluateReturnsTypedFaultsForCancellationAndRegexBudget"]),
        "error/timeout": (PROMQL, own("TimeoutIsNeverEmptySuccess")),
        "error/storage": (PROMQL, own("StorageFailureIsNeverEmptyData")),
        "error/sample-budget": (PROMQL, own("SampleBudgetNeverTruncates")),
        "error/feature-validation": (PROMQL, own("EngineOptionsRejectAtAndNegativeOffset")),
        "fact/subquery-alignment": (PROMQL, ["TestExactGridOffsetSubquery"] + own("SubqueryGridIsGloballyAligned")),
        "fact/extended-endpoints": (PROMQL, ["TestNativeSmoothedInstantSelector", "TestNativeExtendedRateFamilyValues", "TestNativeExtendedMatrixSelectorBoundaries"]),
        "fact/extended-root-context": (PROMQL, ["TestNativeExtendedMatrixSelectorBoundaries"] + own("ExtendedRootRejectsHistogramMatrices")),
        "fact/fill-operands": (PROMQL, own("FillSubstitutesOnlyAbsentSides")),
        "primitive/anchoring-captures-replacement": (REGEX, ["TestSearchLabelAnchoringAndNewlines", "TestCaptureReplacementAndEmptyProgression"]),
        "primitive/ascii-classes-boundaries": (REGEX, ["TestPinnedUnicodeAndSyntax"] + own("ASCIIClassesFoldWithoutUnicodeDigits")),
        "primitive/backend-dialect": (REGEX, ["TestPinnedUnicodeAndSyntax", "TestNoUnknownOrMismatchedProfileFallback"]),
        "primitive/matcher-optimization-fold-length": (REGEX, own("FoldPrefixSuffixByteLength")),
        "primitive/normalization-version-selection": (REGEX, own("MatchingDoesNotNormalizeLabelIdentity")),
        "primitive/property-name-acceptance": (REGEX, ["TestPropertyNamesRetainCallerParserDistinction", "TestPinnedUnicodeAndSyntax"]),
        "primitive/simple-fold-version": (REGEX, ["TestPinnedCaseHelpersAndErrorClassification"] + own("SimpleFoldOrbitsExcludeUnicode17Pairs")),
        "primitive/unicode-table-membership": (REGEX, ["TestPinnedUnicodeAndSyntax"]),
        "primitive/utf8-runtime-semantics": (REGEX, ["TestPinnedUnicodeAndSyntax"]),
        "configuration/query-options": (PROMQL, own("PerQueryLookbackOption", "PerStepStatisticsNeedEngineAndQueryOptIn", "EngineOptionsRejectAtAndNegativeOffset", "EngineLookbackZeroDefaultsToFiveMinutes")),
        "fact/sample-budget": (PROMQL, own("SampleUnitPeaksAndLimit", "HistogramPointCostsSizeUnits", "SampleBudgetNeverTruncates")),
    }
    for p in BOTH:
        for sem, (impl, tests) in bindings.items():
            oid = f"{p}/{sem}"
            if oid in ctx.BY_ID:
                ctx.bind(oid, impl, tests)
