# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Authors the `grammar` partition: PromQL grammar productions, lexical/number/
string facts, precedence, error classes and the 3.13.5 duration-expression,
fill and extended-range gates. Syntax rows carry hand-authored expectations
(accepted, value type, error category) that the differential runner checks
against both the owned parser and the pinned Prometheus parser; evaluation rows
are differential rows whose values are asserted independently by
internal/query/promql/release_grammar_test.go. This module never records a
verdict."""
import copy, struct

NS = 1_000_000_000
V, SC, M, STR = "vector", "scalar", "matrix", "string"
E = "promql-experimental-functions"
D = "promql-duration-expr"
F = "promql-binop-fill-modifiers"
X = "promql-extended-range-selectors"

SYN_FILE = "cases/release-grammar-syntax.json"
EVAL_FILE = "cases/release-grammar-evaluation.json"
SYN_HEADER = {"schema": "soundpost-authored-syntax-cases-v1", "phase": "syntax"}
EVAL_HEADER = {"phase": "evaluation"}


def A(expr, typ, feats=()):
    return ("s", expr, ("ok", typ), tuple(feats))


def R(expr, cat="syntax", feats=()):
    return ("s", expr, ("no", cat), tuple(feats))


def Ev(query, series=(), feats=(), kind="instant", **kw):
    return ("e", query, tuple(series), tuple(feats), kind, kw)


def bits(x):
    return struct.pack(">Q", struct.unpack(">Q", struct.pack(">d", x))[0]).hex()


def fser(name, samples, **kv):
    items = sorted([("__name__", name)] + list(kv.items()))
    return {"labels": [{"name": k, "value": v} for k, v in items],
            "samples": [{"time": str(int(round(t * 1000)) * 1_000_000), "float_bits": bits(v)} for t, v in samples]}


SIG = fser("sig", [(10, 1.0), (15, 2.0), (20, 3.0), (30, 6.0), (40, 10.0)], job="g")
SIG_R = fser("sig", [(0, 1.0), (10, 2.0), (20, 3.0), (30, 4.0), (40, 5.0)], job="g")
M1A = fser("m1", [(15, 2.0)], job="a")
M1B = fser("m1", [(15, 3.0)], job="b")
M2A = fser("m2", [(15, 10.0)], job="a")

T = {}

# --- error classes ------------------------------------------------------------
T["error/disabled-gate", "3.1.0"] = (
    A("limit_ratio(0.5, foo)", V, [E]),
    R("limit_ratio(0.5, foo)", "type", ["promql-delayed-name-removal"]),
    R("1 + sum(limitk(2, rate(foo[5m])))", "type"))
T["error/disabled-gate", "3.13.5"] = (
    A("foo + fill(0) bar", V, [F]),
    R("foo + fill(0) bar", "syntax", [D]),
    R("sum(rate(foo[5m] smoothed))", "syntax"))
T["error/lexical"] = (
    A("foo # trailing comment", V),
    R('foo{a="b\\q"}'),
    R("sum by (job) (rate(foo{a=\"b\"}[5x]))"))
T["error/regex-label"] = (
    A('foo{job=~"a(b|c)+"}', V),
    R('foo{job=~"("}'),
    R('sum(rate(foo{job=~"a(b"}[5m]))'))
T["error/syntax"] = (
    A("foo offset 5m @ 100", V),
    R("foo + "),
    R("sum(rate(foo[5m]) / ignoring(job) bar))"))
T["error/time-modifier"] = (
    A("foo offset -5m", V),
    R("foo @ 1 @ 2"),
    R("sum(rate(foo[5m] @ NaN))"))
T["error/type-arity"] = (
    A("clamp(foo, 0, 1)", V),
    R("clamp_min(foo)", "type"),
    R("sum(foo[5m])", "type"))

# --- numeric and string facts ---------------------------------------------------
T["fact/number-conversion"] = (
    Ev("0X_FF * 1_024 - 1e-3 + 010"),
    R("0x1.8p1"),
    R("sum(foo) * 1e309"))
T["fact/string-escapes"] = (
    Ev('"a\\x41\\101\\u00e9\\U0001F600\\a\\b\\f\\n\\r\\t\\v\\\\\\"z"'),
    R('"\\uD800"'),
    A('count_values("v\\x41\\u00e9", foo{job="a\\tb"})', V))
T["fact/zero-numeric-range", "3.1.0"] = (
    Ev("count_over_time(sig[0])", [SIG]),
    R("sig[0s]"),
    Ev("count_over_time(sig[0] offset 5s)", [SIG]))

# --- grammar productions --------------------------------------------------------
T["grammar/aggregate_expr"] = (
    A("sum(foo) by (job)", V),
    R("sum by (job) (foo) without (instance)"),
    A("topk(2, sum without (instance) (rate(foo[5m])))", V))
T["grammar/aggregate_modifier"] = (
    A("sum without () (foo)", V),
    R("sum by job (foo)"),
    A("count by (job) (sum without (instance, __name__) (foo))", V))
T["grammar/aggregate_op", "3.1.0"] = (
    A("limitk(2, foo)", V, [E]),
    R("limitk(2, foo)", "type"),
    A("topk(3, bottomk(5, sum by (job) (foo)))", V))
T["grammar/aggregate_op", "3.13.5"] = (
    A("limitk(2, foo)", V, [E]),
    R("limitk(2, foo)", "type"),
    A("topk(3, bottomk(5, sum by (job) (foo)))", V))
T["grammar/at_modifier_preprocessors"] = (
    A("foo @ start()", V),
    R("foo @ start(1)"),
    Ev("sig @ end() - sig @ start()", [SIG], kind="range", start=10, end=30, step=10))
T["grammar/bin_modifier", "3.1.0"] = (
    A("foo > bool on(job) group_left(zone) bar", V),
    R("foo > on(job) bool bar"),
    A("sum(foo > bool ignoring(instance) group_right(zone) bar) by (job)", V))
T["grammar/bin_modifier", "3.13.5"] = (
    A("foo > bool on(job) group_left(zone) fill_left(0) fill_right(1) bar", V, [F]),
    R("foo + fill(0) on(job) bar", "syntax", [F]),
    A("sum(foo > bool ignoring(instance) group_right(zone) bar) by (job)", V))
T["grammar/binary_expr"] = (
    A("foo + bar * 2", V),
    R("foo[5m] + bar", "type"),
    A("foo / on() group_left bar > bool 0.5", V))
T["grammar/bool_modifier"] = (
    Ev("fl_total > bool 1", [fser("fl_total", [(15, 2.0)], job="generic")]),
    R("foo + bool 1", "type"),
    Ev("(fl_total == bool 2) * 10 + (fl_total != bool 2)", [fser("fl_total", [(15, 2.0)], job="generic")]))
T["grammar/expr", "3.1.0"] = (
    A("sum(foo offset 5m) + (bar @ 10)", V),
    R("foo bar"),
    A("quantile(0.9, rate(foo[5m:1m] offset 1m)) * scalar(bar)", V))
T["grammar/expr", "3.13.5"] = (
    A("sum(foo offset (1m * 2)) + (bar @ 10)", V, [D]),
    R("foo bar"),
    A("quantile(0.9, rate(foo[5m:1m] offset 1m)) * scalar(bar)", V))
T["grammar/function_call"] = (
    A("round(foo, 0.5)", V),
    R("rate(foo)", "type"),
    A("histogram_quantile(0.9, sum by (le) (rate(foo_bucket[5m])))", V))
T["grammar/function_call_args"] = (
    A('label_join(foo, "a", "-", "b", "c")', V),
    R("abs(foo,)"),
    R("sum by (job) (abs(foo,))"))
T["grammar/function_call_body"] = (
    A("time()", SC),
    R("abs(foo"),
    A("vector(time()) + foo", V))
T["grammar/group_modifiers"] = (
    A("foo / on(job) group_left(zone) bar", V),
    R("foo / on(job) group_left(job) bar", "type"),
    R("sum(foo unless on(job) group_right bar) by (job)", "type"))
T["grammar/grouping_label", "3.1.0"] = (
    A('sum by (on, bool, "valid_name") (foo)', V),
    R('sum by ("") (foo)'),
    A('sum without ("a-b", "测") (foo{"a-b"="x"})', V))
T["grammar/grouping_label", "3.13.5"] = (
    A('sum by (on, bool, "valid_name") (foo)', V),
    R('sum by ("") (foo)'),
    A('sum without ("a-b", "测") (foo{"a-b"="x"})', V))
T["grammar/grouping_label_list"] = (
    A("sum by (a, b, c) (foo)", V),
    R("sum by (a, , b) (foo)"),
    A("sum by (a, b) (count by (b, c) (foo))", V))
T["grammar/grouping_labels"] = (
    A("sum by (a,) (foo)", V),
    R("sum by (a,,) (foo)"),
    A("sum without () (count by (a,) (foo))", V))
T["grammar/label_match_list"] = (
    A('foo{a="1", a!="2", a=~"1|3"}', V),
    R('foo{a="1" b="2"}'),
    A('sum(rate(foo{a=~"x.*", a!~"xy.*", b!=""}[5m]))', V))
T["grammar/label_matcher"] = (
    A('{"foo", job="x"}', V),
    R("foo{job=bar}"),
    A('sum(rate({"foo", job=~"a.*"}[5m]))', V))
T["grammar/label_matchers"] = (
    A('foo{job="a",}', V),
    R('{job=~".*", a=""}'),
    A('sum({job="a"}) + sum(foo{})', V))
T["grammar/match_op"] = (
    A('foo{a!~"x.*"}', V),
    R('foo{a=="x"}'),
    A('foo{a!~"x"} == bool bar{b=~"y"}', V))
T["grammar/matrix_selector"] = (
    A("foo[5m]", M),
    R("foo offset 5m [5m]"),
    A('rate(foo{a="b"}[5m] offset 1m)', V))
T["grammar/maybe_grouping_labels"] = (
    A("foo / on(job) group_left bar", V),
    R("foo / on(job) group_left (zone bar"),
    A("foo * ignoring() group_right() bar", V))
T["grammar/maybe_label"] = (
    A("sum by (on, ignoring, group_left, bool, offset, by) (foo)", V),
    R("sum by (1) (foo)"),
    A('foo{on="1", bool!="x"} * ignoring(by) bar', V))
T["grammar/metric_identifier"] = (
    A('job:requests:rate5m{a="b"} + offset', V),
    R('foo{a:b="c"}'),
    A("sum(foo:bar:baz) / on(job) group_left bar:x", V))
T["grammar/number"] = (
    A("0x7FFFFFFFFFFFFFFF + 1e3 + .5", SC),
    R("0xFFFFFFFFFFFFFFFFF"),
    R("foo * 1e309"))
T["grammar/number_duration_literal"] = (
    Ev("1h30m + 1w + 1ms"),
    R("1M"),
    A("rate(foo[1h30m]) * 2m", V))
T["grammar/offset_expr", "3.1.0"] = (
    A("foo offset 5m", V),
    R("sum(foo) offset 5m", "syntax"),
    A("rate(foo[5m] offset -1h)", V))
T["grammar/offset_expr", "3.13.5"] = (
    A("foo offset 5m", V),
    R("sum(foo) offset 5m", "syntax"),
    A("rate(foo[5m] offset (2 * 1h))", V, [D]))
T["grammar/on_or_ignoring"] = (
    A("foo + on(job, zone) bar", V),
    R("foo + ignoring job bar"),
    A("sum(foo / ignoring() bar) by (job)", V))
T["grammar/paren_expr"] = (
    A("(foo[5m])", M),
    R("()"),
    A("((foo + bar)) * (1 + 2)", V))
T["grammar/signed_number"] = (
    Ev("1 / -0"),
    R("foo @ --5"),
    A("sum(foo @ -100.5) + sum(foo @ +100)", V))
T["grammar/signed_or_unsigned_number"] = (
    A("foo @ 5m", V),
    R('foo @ "5"'),
    A("foo @ -1.5e3 offset 1m", V))
T["grammar/start"] = (
    A("foo  # c", V),
    R(""),
    R("sum(foo) sum(bar)"))
T["grammar/step_invariant_expr"] = (
    A("foo @ start() offset 5m", V),
    R("foo @ NaN"),
    A("sum_over_time(foo[5m:1m] @ end())", V))
T["grammar/string_identifier"] = (
    A('{"fo\\u006f", job="a"}', V),
    R('{"foo" "bar"}'),
    A('sum(rate({"foo", "job"="a"}[5m]))', V))
T["grammar/string_literal"] = (
    Ev('`line1\nline2\\n`'),
    R('"abc'),
    A("label_replace(foo, 'd', \"$1\", `s`, \"(.*)\")", V))
T["grammar/subquery_expr"] = (
    A("foo[5m:1m]", M),
    R("foo[5m:1m][1m:]", "type"),
    A("max_over_time(rate(foo[5m])[30m:1m] offset 5m)", V))
T["grammar/unary_expr"] = (
    A("-foo", V),
    R("-foo[5m]", "type"),
    Ev("-hs_total", ["hist"]))
T["grammar/unary_op"] = (
    A("+foo", V),
    R("!foo"),
    A("sum(+(-foo)) by (job)", V))
T["grammar/vector_selector"] = (
    A('foo{job="a"}', V),
    R('foo{__name__="bar"}'),
    A('{__name__=~"foo.*", job="a"}', V))

# --- semantics ------------------------------------------------------------------
T["semantics/lexical"] = (
    Ev("0X1f + 1_0 + 5m + .5E1 + 1 / -iNf"),
    R("1__2"),
    A("foo # c1\n + # c2\n bar", V))
T["semantics/precedence"] = (
    Ev("2 ^ 3 ^ 2 + -2 ^ 2"),
    R("1 == 1 == 1", "type"),
    Ev("fl_total + 1 * 2 ^ 2 > bool 5", [fser("fl_total", [(15, 2.0)], job="generic")]))

# --- 3.13.5-only obligations ----------------------------------------------------
T["duration-form/max_of", "3.13.5"] = (
    A("foo[max_of(1m, 2m)]", M, [D]),
    R("max_of(1m, 2m)", "type", [D]),
    A("foo[10m:max_of(step(), 30s)]", M, [D]))
T["duration-form/min_of", "3.13.5"] = (
    A("foo offset min_of(1h, 30m)", V, [D]),
    R("foo offset min_of(1h, 30m)", "syntax", [E]),
    A("foo[min_of(5m, 1h):min_of(1m, 30s)]", M, [D]))
T["duration-form/range", "3.13.5"] = (
    A("foo[range()]", M, [D]),
    R("range()", "type", [D]),
    A("foo[range() / 2:step()]", M, [D]))
T["duration-form/step", "3.13.5"] = (
    A("foo[10m:step()]", M, [D]),
    R("foo[10m:step()]", "syntax", [E]),
    A("sum_over_time(foo[step() * 4])", V, [D]))
T["fact/duration-runtime", "3.13.5"] = (
    Ev("sum_over_time(sig[step() * 2])", [SIG_R], [D], kind="range", start=20, end=40, step=10),
    R("foo[step() / 0]", "syntax", [D]),
    Ev("sum_over_time(sig[5m:step()] offset range())", [SIG_R], [D], kind="range", start=20, end=40, step=10))
T["grammar/anchored_expr", "3.13.5"] = (
    A("changes(foo[5m] anchored)", V, [X]),
    R("foo[5m] anchored smoothed", "syntax", [X]),
    A("sum by (job) (increase(foo[5m] anchored offset 1m))", V, [X]))
T["grammar/smoothed_expr", "3.13.5"] = (
    A("rate(foo[5m] smoothed)", V, [X]),
    R("foo[5m:1m] smoothed", "syntax", [X]),
    A("sum(delta(foo[5m] smoothed)) / 2", V, [X]))
T["grammar/duration_expr", "3.13.5"] = (
    A("foo[(1m + 30s) * 2]", M, [D]),
    R("foo[5m + 1m]", "syntax"),
    A("foo[10m:step()] offset (range() / 2)", M, [D]))
T["grammar/fill_modifiers", "3.13.5"] = (
    A("foo + fill_left(0) fill_right(1) bar", V, [F]),
    R("foo + fill(0) fill_left(1) bar", "syntax", [F]),
    A("sum(foo * on(job) group_left fill(0) bar) by (job)", V, [F]))
T["grammar/fill_value", "3.13.5"] = (
    A("foo + fill(-1.5) bar", V, [F]),
    R("foo + fill(bar) baz", "syntax", [F]),
    Ev("m1 + fill_right(Inf) m2", [M1A, M1B, M2A], [F]))
T["grammar/max_of_min_of", "3.13.5"] = (
    A("foo[max_of(1m, 2m)]", M, [D]),
    R("foo[min_of(1m, 2m, 3m)]", "syntax", [D]),
    A("foo[10m:min_of(step(), 30s)] offset max_of(1m, range())", M, [D]))
T["grammar/offset_duration_expr", "3.13.5"] = (
    A("foo offset (1h - 2h)", V, [D]),
    R("foo offset 106752d"),
    A("sum(foo offset -(5m * 2))", V, [D]))
T["grammar/paren_duration_expr", "3.13.5"] = (
    A("foo[(5m)]", M, [D]),
    R("foo[(5m)]", "syntax"),
    A("foo offset (((1m)))", V, [D]))
T["grammar/positive_duration_expr", "3.13.5"] = (
    A("foo[1ms:1ms]", M),
    R("foo[5m:0s]"),
    A("foo[5m - 5m]", M, [D]))
T["modifier/fill-typecheck", "3.13.5"] = (
    A("foo + fill(0) bar", V, [F]),
    R("foo + fill(0) 1", "type", [F]),
    R("sum(foo or fill(0) bar)", "type", [F]))
T["semantics/duration-expression", "3.13.5"] = (
    A("foo[10m:step() * 2]", M, [D]),
    R("foo[1m % 0]", "syntax", [D]),
    Ev("max_over_time(sig[min_of(range(), 1m):step()])", [SIG_R], [D], kind="range", start=20, end=40, step=10))
# 3.13.5 lexical/other families reuse the common rows above through the default key.


def spec_for(rule, ver):
    return T.get((rule, ver)) or T.get(rule)


def build(ctx):
    ctx.declare(SYN_FILE, "promql", "syntax", SYN_HEADER)
    ctx.declare(EVAL_FILE, "promql", "evaluation", EVAL_HEADER)
    mine = [l.strip() for l in open(".superpowers/sdd/approved-product/11.15-run/partition/grammar.txt") if l.strip()]
    for oid in mine:
        o = ctx.BY_ID[oid]
        p = o["profile"]
        ver = p.rsplit("-", 1)[1]
        rule = oid[len(p) + 1:]
        spec = spec_for(rule, ver)
        if spec is None:
            raise SystemExit("no spec for " + oid)
        for rid, item in zip(ctx.role_ids(o), spec):
            if item[0] == "s":
                _, expr, (kind, extra), feats = item
                exp = {"accepted": kind == "ok"}
                if kind == "ok":
                    exp["type"] = extra
                else:
                    exp["category"] = extra
                ctx.put(SYN_FILE, {"id": rid, "profiles": [p], "enabled_features": list(feats), "input": {"expression": expr}, "expected": exp})
            else:
                _, query, series, feats, kind, kw = item
                ser = [ctx.HIST_S if s == "hist" else s for s in series]
                row = {"id": rid, "profiles": [p], "enabled_features": list(feats), "query": query, "kind": kind}
                if kind == "instant":
                    row["time"] = str(20 * NS)
                else:
                    row["start"] = str(kw["start"] * NS)
                    row["end"] = str(kw["end"] * NS)
                    row["step"] = str(kw["step"] * NS)
                row["series"] = copy.deepcopy(ser)
                ctx.put(EVAL_FILE, row)
        ctx.bind(oid, "internal/query/promql", BINDINGS(rule))


def BINDINGS(rule):
    tests = ["TestReleaseGrammarRuleTable"]
    for prefix, names in FAMILIES:
        if rule.startswith(prefix):
            for n in names:
                if n not in tests:
                    tests.append(n)
    return tests


# rule prefix -> the independent Go tests (internal/query/promql/release_grammar*_test.go)
# that assert the rule's behavior beyond the differential syntax/evaluation rows.
G = "TestReleaseGrammar"
FAMILIES = [
    ("error/disabled-gate", [G + "DiagnosticStarts"]),
    ("error/lexical", [G + "DiagnosticStarts", G + "NumberLiterals", G + "StringEscapes", G + "CommentsAndNestedSigns"]),
    ("error/regex-label", [G + "RegexAndLabelErrors", G + "DiagnosticStarts"]),
    ("error/syntax", [G + "DiagnosticStarts"]),
    ("error/time-modifier", [G + "DiagnosticStarts", G + "AtModifierForms"]),
    ("error/type-arity", [G + "UnknownFunctionKeepsTypeCategory"]),
    ("fact/number-conversion", [G + "NumberLiterals", G + "DiagnosticStarts", G + "PrecedenceAndSignedValues"]),
    ("fact/string-escapes", [G + "StringEscapes"]),
    ("fact/zero-numeric-range", [G + "ZeroNumericRange"]),
    ("fact/duration-runtime", [G + "DurationRuntime", G + "DurationExpressionFormat"]),
    ("grammar/aggregate", [G + "CommentsAndNestedSigns", G + "DiagnosticStarts"]),
    ("grammar/at_modifier_preprocessors", [G + "AtModifierForms"]),
    ("grammar/step_invariant_expr", [G + "AtModifierForms", G + "DiagnosticStarts"]),
    ("grammar/signed_or_unsigned_number", [G + "AtModifierForms"]),
    ("grammar/signed_number", [G + "PrecedenceAndSignedValues", G + "NumberLiterals"]),
    ("grammar/unary", [G + "PrecedenceAndSignedValues"]),
    ("grammar/number", [G + "NumberLiterals", G + "PrecedenceAndSignedValues", G + "DiagnosticStarts"]),
    ("grammar/bool_modifier", [G + "PrecedenceAndSignedValues"]),
    ("grammar/binary_expr", [G + "PrecedenceAndSignedValues"]),
    ("grammar/bin_modifier", [G + "DiagnosticStarts"]),
    ("grammar/group_modifiers", [G + "DiagnosticStarts"]),
    ("grammar/on_or_ignoring", [G + "DiagnosticStarts"]),
    ("grammar/maybe_grouping_labels", [G + "DiagnosticStarts"]),
    ("grammar/function_call", [G + "UnknownFunctionKeepsTypeCategory", G + "DiagnosticStarts"]),
    ("grammar/label_match", [G + "DiagnosticStarts", G + "RegexAndLabelErrors"]),
    ("grammar/label_matcher", [G + "DiagnosticStarts", G + "RegexAndLabelErrors"]),
    ("grammar/match_op", [G + "DiagnosticStarts"]),
    ("grammar/grouping_label", [G + "RegexAndLabelErrors", G + "KeywordsAndMetricNames"]),
    ("grammar/metric_identifier", [G + "KeywordsAndMetricNames", G + "DiagnosticStarts"]),
    ("grammar/maybe_label", [G + "KeywordsAndMetricNames"]),
    ("grammar/vector_selector", [G + "DiagnosticStarts"]),
    ("grammar/matrix_selector", [G + "DiagnosticStarts"]),
    ("grammar/offset", [G + "DiagnosticStarts", G + "DurationExpressionFormat"]),
    ("grammar/subquery_expr", [G + "DiagnosticStarts"]),
    ("grammar/string", [G + "StringEscapes"]),
    ("grammar/number_duration_literal", [G + "NumberLiterals", G + "DurationLiteralsKeepTheirSpelling"]),
    ("grammar/start", [G + "DiagnosticStarts"]),
    ("grammar/expr", [G + "DiagnosticStarts"]),
    ("grammar/paren", [G + "DurationExpressionFormat"]),
    ("grammar/duration", [G + "DurationExpressionFormat", G + "DurationLiteralsKeepTheirSpelling", G + "DurationRuntime", G + "DiagnosticStarts"]),
    ("grammar/max_of_min_of", [G + "DurationExpressionFormat", G + "DurationRuntime", G + "DiagnosticStarts"]),
    ("grammar/paren_duration_expr", [G + "DurationExpressionFormat", G + "DiagnosticStarts"]),
    ("grammar/positive_duration_expr", [G + "DurationExpressionFormat", G + "DiagnosticStarts", G + "ZeroNumericRange"]),
    ("grammar/fill", [G + "DiagnosticStarts"]),
    ("grammar/anchored_expr", [G + "DiagnosticStarts"]),
    ("grammar/smoothed_expr", [G + "DiagnosticStarts"]),
    ("duration-form/", [G + "DurationExpressionFormat", G + "DurationRuntime", G + "DiagnosticStarts"]),
    ("modifier/fill-typecheck", [G + "DiagnosticStarts"]),
    ("semantics/duration-expression", [G + "DurationRuntime", G + "DurationLiteralsKeepTheirSpelling", G + "DiagnosticStarts"]),
    ("semantics/lexical", [G + "NumberLiterals", G + "CommentsAndNestedSigns", G + "PrecedenceAndSignedValues", G + "StringEscapes"]),
    ("semantics/precedence", [G + "PrecedenceAndSignedValues"]),
]
