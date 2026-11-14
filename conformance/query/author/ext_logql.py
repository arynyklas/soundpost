# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Authors the LogQL parser/filter/mutation/ordering/temporal/binary/function/
syntax/selector/labels/conversion/gated/security rows of the 11.15 language
campaign. Rows are inputs and, for the pipeline phase, authored expectations
derived from the obligation rule text; the differential runner compares the
owned engine with the pinned Loki 3.5.2 oracle and the row's own expectation.
"""
import copy

HDR = {"copyright": "Copyright 2026 Aryn Yklas", "license": "Apache-2.0"}
F_PIPE = "cases/release-logql-pipe.json"
F_SYN = "cases/release-logql-syn.json"
F_MET = "cases/release-logql-met.json"
F_TPL = "cases/release-logql-tpl.json"
S = 1_000_000_000


def lab(d):
    return [{"name": k, "value": v} for k, v in sorted(d.items())]


def eid(n):
    return f"{n:02x}" + "00" * 15


def entry(n, line, stream, ts, md=None):
    return {"timestamp_ns": str(ts), "id": eid(n), "multiplicity": "1", "line": line,
            "stream_labels": lab(stream), "structured_metadata": lab(md or {}), "fields": []}


def build(ctx):
    LOGQL = ctx.LOGQL

    def ids(ob):
        return ctx.role_ids(ctx.BY_ID[f"{LOGQL}/{ob}"])

    ctx.declare(F_PIPE, "logql", "pipeline", {"schema": "soundpost-authored-logql-cases-v1", **HDR, "phases": ["pipeline"]})
    ctx.declare(F_SYN, "logql", "syntax", {"schema": "soundpost-authored-logql-cases-v1", **HDR, "phases": ["syntax"]})
    ctx.declare(F_MET, "logql", "logql-metric", {"schema": "soundpost-authored-logql-metric-cases-v1", **HDR, "author": "Aryn Yklas", "phase": "logql-metric"})
    ctx.declare(F_TPL, "logql", "logql-template", {"phase": "logql-template", "authorship": "Independently authored Apache-2.0 inputs by Aryn Yklas; no stored oracle answers.",
                                                   "clock_contract": "Rows in this file observe no wall clock."})

    def pipe(rid, expr, line, retained=True, out=None, labels=None, absent=None, bits=None, stream=None, md=None, enabled=()):
        exp = {"retained": retained}
        if retained:
            exp["line"] = line if out is None else out
        if labels:
            exp["labels_subset"] = lab(labels)
        if absent:
            exp["absent_labels"] = list(absent)
        if bits is not None:
            exp["unwrapped_bits"] = bits
        row = {"id": rid, "phase": "pipeline", "profiles": [LOGQL], "enabled_features": list(enabled),
               "input": {"expression": expr, "entry": entry(1, line, stream or {"app": "api"}, 123, md)}, "expected": exp}
        ctx.put(F_PIPE, row)

    def syn(rid, expr, accepted, typ="", enabled=()):
        exp = {"accepted": accepted}
        if accepted:
            exp["type"] = typ
        ctx.put(F_SYN, {"id": rid, "phase": "syntax", "profiles": [LOGQL], "enabled_features": list(enabled), "input": {"expression": expr}, "expected": exp})

    def met(rid, query, entries, kind="instant", time=2 * S, start=0, end=None, step=S, direction="forward", limit=0, interval=0, enabled=()):
        ctx.put(F_MET, {"id": rid, "phase": "logql-metric", "profiles": [LOGQL], "enabled_features": list(enabled),
                        "configuration": {"count_min_sketch_heap_size": "10000", "instant_log_lookback_ns": "30000000000"},
                        "config_identity": "resolved-profile-manifest-default", "query": query, "kind": kind,
                        "time_ns": str(time), "start_ns": str(start), "end_ns": str(time if end is None else end), "step_ns": str(step),
                        "direction": direction, "limit": str(limit), "interval_ns": str(interval), "entries": copy.deepcopy(entries)})

    def tpl(rid, source, line="line", labels=None, ts="-1", tz="UTC"):
        ctx.put(F_TPL, {"id": rid, "profiles": [LOGQL], "source": source, "line": line, "timestamp_ns": ts, "labels": lab(labels or {"level": "warn"}), "fields": [], "timezone": tz})

    bound = []

    # ---- parsers -----------------------------------------------------------
    p, n, i = ids("json")
    pipe(p, '{app="api"} | json', '{"user":{"name":"ann","id":7},"ok":true,"app":"web","tags":["a","b"]}',
         labels={"user_name": "ann", "user_id": "7", "ok": "true", "app": "api", "app_extracted": "web"}, absent=["tags"])
    pipe(n, '{app="api"} | json', '{bad json', labels={"__error__": "JSONParserErr", "app": "api"})
    pipe(i, '{app="api"} | json first="items[0].name", n="items[1].id" | n >= 2', '{"items":[{"name":"x"},{"id":3}]}',
         labels={"first": "x", "n": "3"})
    bound.append("json")

    p, n, i = ids("logfmt")
    pipe(p, '{app="api"} | logfmt', 'level=warn msg="hello world" code=500 empty=', labels={"level": "warn", "msg": "hello world", "code": "500"}, absent=["empty"])
    pipe(n, '{app="api"} | logfmt --strict', 'a="unterminated', labels={"__error__": "LogfmtParserErr"})
    pipe(i, '{app="api"} | logfmt --keep-empty lvl="level", e="empty"', 'level=warn empty= x=1', labels={"lvl": "warn", "e": ""}, absent=["x"])
    bound.append("logfmt")

    p, n, i = ids("pattern")
    pipe(p, '{app="api"} | pattern "<ip> <_> <path> <status>"', '10.0.0.1 GET /index 200', labels={"ip": "10.0.0.1", "path": "/index", "status": "200"})
    pipe(n, '{app="api"} | pattern "GET <path>"', 'x 1', labels={"app": "api"}, absent=["path"])
    pipe(i, '{app="api"} | pattern "<_> GET <path>" | path = "/a"', 'xx GET /a', labels={"path": "/a"})
    bound.append("pattern")

    p, n, i = ids("regexp")
    pipe(p, '{app="api"} | regexp "(?P<method>\\\\w+) (?P<path>/\\\\S+)"', 'GET /items 200', labels={"method": "GET", "path": "/items"})
    syn(n, '{app="api"} | regexp "(\\\\w+)"', False)
    pipe(i, '{app="api"} | regexp "(?P<code>[0-9]+)" | code = ""', 'nodigits', labels={"app": "api"}, absent=["code"])
    bound.append("regexp")

    p, n, i = ids("unpack")
    pipe(p, '{app="api"} | unpack', '{"_entry":"hello world","region":"north","code":"7"}', out="hello world", labels={"region": "north", "code": "7"})
    pipe(n, '{app="api"} | unpack', 'plain text', labels={"__error__": "JSONParserErr"})
    pipe(i, '{app="api"} | unpack | json', '{"_entry":"{\\"a\\":\\"1\\"}","stream":"x"}', out='{"a":"1"}', labels={"stream": "x", "a": "1"})
    bound.append("unpack")

    # ---- filters -----------------------------------------------------------
    p, n, i = ids("ip")
    pipe(p, '{app="api"} |= ip("192.168.0.0/16")', 'conn from 192.168.4.7 ok')
    syn(n, '{app="api"} |= ip("192.168.0.300")', False)
    pipe(i, '{app="api"} | logfmt | addr = ip("10.0.0.1-10.0.0.9")', 'addr=10.0.0.5 x=1', labels={"addr": "10.0.0.5"})
    bound.append("ip")

    p, n, i = ids("label-filter")
    pipe(p, '{app="api"} | logfmt | status >= 400 and method = "GET"', 'status=503 method=GET', labels={"status": "503", "method": "GET"})
    pipe(n, '{app="api"} | logfmt | status > 400', 'status=abc', labels={"__error__": "LabelFilterErr", "status": "abc"})
    pipe(i, '{app="api"} | json | status > 400 or app = "api"', '{bad', labels={"__error__": "JSONParserErr", "app": "api"})
    bound.append("label-filter")

    p, n, i = ids("line-filters")
    pipe(p, '{app="api"} |= "GET" != "health" |~ "[0-9]{3}"', 'GET /items 200')
    syn(n, '{app="api"} |~ "("', False)
    pipe(i, '{app="api"} |= "GET" or "POST" |> "<_> /items <_>"', 'POST /items 201')
    bound.append("line-filters")

    # ---- mutation ----------------------------------------------------------
    p, n, i = ids("decolorize")
    pipe(p, '{app="api"} | decolorize', '\x1b[31merror\x1b[0m: \x1b[1;32mok\x1b[0m done', out="error: ok done", labels={"app": "api"})
    syn(n, '{app="api"} | decolorize "x"', False)
    pipe(i, '{app="api"} | decolorize |= "\\x1b[31merror"', '\x1b[31merror\x1b[0m: \x1b[1;32mok\x1b[0m done', out="error: ok done", labels={"app": "api"})
    bound.append("decolorize")

    p, n, i = ids("drop-keep")
    pipe(p, '{app="api"} | logfmt | drop level, host="b"', 'level=warn host=a msg=hi', labels={"host": "a", "msg": "hi", "app": "api"}, absent=["level"])
    pipe(n, '{app="api"} | logfmt | drop level="info"', 'level=warn host=a', labels={"level": "warn", "host": "a", "app": "api"})
    pipe(i, '{app="api"} | json | drop __error__', 'not json', labels={"app": "api"}, absent=["__error__", "__error_details__"])
    bound.append("drop-keep")

    p, n, i = ids("label-format")
    pipe(p, '{app="api"} | logfmt | label_format lvl=level | label_format msg="{{.lvl}}/{{.host}}"', 'level=warn host=a',
         labels={"lvl": "warn", "host": "a", "msg": "warn/a"}, absent=["level"])
    syn(n, '{app="api"} | label_format a=b, a=c', False)
    pipe(i, '{app="api"} | logfmt | label_format x=a, y="{{.a}}"', 'a=1', labels={"x": "1", "y": ""}, absent=["a"])
    bound.append("label-format")

    # ---- pipeline order, lexical, selectors, metadata -----------------------
    p, n, i = ids("pipeline-order")
    pipe(p, '{app="api"} |= "ok" | logfmt | status = "200"', 'ok status=200', labels={"status": "200"})
    pipe(n, '{app="api"} | status = "200" | logfmt', 'ok status=200', retained=False)
    pipe(i, '{app="api"} | json | line_format "got {{.a}}" |= "got 1"', '{"a":1}', out="got 1", labels={"a": "1"})
    bound.append("pipeline-order")

    p, n, i = ids("lexical")
    pipe(p, '{app="api"} |= "a\\tb"', 'a\tb')
    syn(n, '{app="api"} |= "\\q"', False)
    pipe(i, '{app="api"} |= `a\\tb`', 'a\\tb')
    bound.append("lexical")

    p, n, i = ids("structured-metadata")
    pipe(p, '{app="api"} | trace = "abc"', 'hello', labels={"trace": "abc", "app": "api"}, md={"trace": "abc"})
    pipe(n, '{app="api", trace = "abc"}', 'hello', retained=False, md={"trace": "abc"})
    mdf = [entry(1, "x", {"app": "api"}, 1 * S, {"trace": "abc"}), entry(2, "y", {"app": "api"}, 1_500_000_000, {"trace": "def"}), entry(3, "z", {"app": "api"}, 1_600_000_000, {"trace": "abc"})]
    met(i, 'sum by (trace) (count_over_time({app="api"}[2s]))', mdf)
    bound.append("structured-metadata")

    # ---- conversion ---------------------------------------------------------
    p, n, i = ids("unwrap")
    pipe(p, 'sum_over_time({app="api"} | logfmt | unwrap bytes(size) [1m])', 'size=2KiB', labels={"app": "api"}, bits="40a0000000000000")
    un = [entry(1, "n=abc", {"app": "api"}, 1 * S), entry(2, "n=3", {"app": "api"}, 1_200_000_000)]
    met(n, 'sum_over_time({app="api"} | logfmt | unwrap n [2s])', un)
    met(i, 'sum_over_time({app="api"} | logfmt | unwrap n | __error__ = "" [2s])', un)
    bound.append("unwrap")

    # ---- primitives: numeric / regexp / unicode (pipeline side) -------------
    # ---- ledger rows for binary/set/function/temporal/ordering/gated --------
    # metric fixture: counts at t=2s over (0,2s]: api/a=2, api/b=1, web/a=3, web/c=1
    fx = [entry(1, "n=1", {"app": "api", "host": "a"}, 1 * S), entry(2, "n=2", {"app": "api", "host": "a"}, 1_500_000_000),
          entry(3, "n=3", {"app": "api", "host": "b"}, 1 * S),
          entry(4, "n=4", {"app": "web", "host": "a"}, 500_000_000), entry(5, "n=5", {"app": "web", "host": "a"}, 1_200_000_000),
          entry(6, "n=6", {"app": "web", "host": "a"}, 1_800_000_000), entry(7, "n=7", {"app": "web", "host": "c"}, 1_100_000_000)]
    API = 'count_over_time({app="api"}[2s])'
    WEB = 'count_over_time({app="web"}[2s])'

    p, n, i = ids("binary-matching")
    met(p, f'sum by (host) ({API}) / on(host) sum by (host) ({WEB})', fx)
    syn(n, f'{API} + on(host) group_left group_right {WEB}', False)
    met(i, f'{API} < bool on(host) group_left sum by (host) ({WEB})', fx)
    bound.append("binary-matching")

    p, n, i = ids("set-operators")
    met(p, f'{API} and on(host) {WEB}', fx)
    syn(n, f'{API} and 1', False)
    met(i, f'sum by (host) ({API}) or sum by (host) ({WEB})', fx)
    bound.append("set-operators")

    p, n, i = ids("vector")
    met(p, 'vector(3)', fx)
    syn(n, 'vector({app="api"})', False)
    met(i, f'sum({API}) + on() vector(10)', fx)
    bound.append("vector")

    p, n, i = ids("label-replace")
    met(p, f'label_replace({API}, "h", "host-$1", "host", "(.*)")', fx)
    syn(n, f'label_replace({API}, "h", "$1", "host", "(")', False)
    met(i, f'sum by (h) (label_replace({API}, "h", "$1", "host", "(a|b)"))', fx)
    bound.append("label-replace")

    rt = [entry(1, "n=1", {"app": "api"}, 0), entry(2, "n=2", {"app": "api"}, 1 * S), entry(3, "n=3", {"app": "api"}, 1_500_000_000),
          entry(4, "n=4", {"app": "api"}, 1_700_000_000), entry(5, "n=5", {"app": "api"}, 4 * S)]
    p, n, i = ids("range-time")
    met(p, 'count_over_time({app="api"}[2s] offset 1s)', rt, kind="range", start=2 * S, end=5 * S, step=S)
    syn(n, 'count_over_time({app="api"} offset 1s [2s])', False)
    met(i, 'sum(count_over_time({app="api"}[2s]))', [entry(1, "a", {"app": "api"}, 0), entry(2, "b", {"app": "api"}, 1), entry(3, "c", {"app": "api"}, 2 * S), entry(4, "d", {"app": "api"}, 2 * S + 1)], time=2 * S)
    bound.append("range-time")

    ft = [entry(1, "n=5", {"app": "api", "host": "a"}, 1 * S), entry(2, "n=7", {"app": "api", "host": "a"}, 1 * S), entry(3, "n=3", {"app": "api", "host": "a"}, 1 * S),
          entry(4, "n=9", {"app": "api", "host": "a"}, 1_500_000_000), entry(5, "n=100", {"app": "api", "host": "b"}, 1 * S)]
    p, n, i = ids("first-last-ties")
    met(p, 'first_over_time({app="api", host="a"} | logfmt | unwrap n [2s])', ft)
    ties = [entry(1, "n=5", {"app": "api", "host": "a"}, 1 * S), entry(2, "n=9", {"app": "api", "host": "a"}, 1 * S), entry(3, "n=7", {"app": "api", "host": "a"}, 1 * S)]
    met(n, 'last_over_time({app="api"} | logfmt | unwrap n [2s])', ties)
    met(i, 'first_over_time({app="api"} | logfmt | unwrap n [2s]) by (app)', [entry(1, "n=5", {"app": "api", "host": "a"}, 1 * S), entry(2, "n=100", {"app": "api", "host": "c"}, 1 * S)])
    bound.append("first-last-ties")

    p, n, i = ids("selectors")
    sel = [entry(1, "x", {"app": "api", "host": "a"}, 1 * S), entry(2, "y", {"app": "api", "host": "ab"}, 1 * S), entry(3, "z", {"app": "api"}, 1 * S),
           entry(4, "w", {"app": "web", "host": "a"}, 1 * S)]
    met(p, '{app="api", host=~"a|"}', sel, kind="range", start=0, end=3 * S, limit=10)
    syn(n, '{app=~".*"}', False)
    met(i, '{app="api"} | level = "warn"', [entry(1, "hello", {"app": "api"}, 1 * S, {"level": "warn"}), entry(2, "other", {"app": "api"}, 1_500_000_000, {"level": "info"})],
        kind="range", start=0, end=3 * S, limit=10)
    bound.append("selectors")

    lo = [entry(1, "a1", {"app": "api", "host": "a"}, 1 * S), entry(2, "b1", {"app": "api", "host": "b"}, 1 * S), entry(3, "a2", {"app": "api", "host": "a"}, 2 * S),
          entry(4, "b2", {"app": "api", "host": "b"}, 2 * S), entry(5, "c1", {"app": "api", "host": "c"}, 3 * S)]
    p, n, i = ids("log-order-limit")
    met(p, '{app="api"}', lo, kind="range", start=0, end=5 * S, direction="backward", limit=3)
    met(n, '{app="api"} | logfmt | n > 1', [entry(1, "n=1", {"app": "api", "host": "a"}, 1 * S), entry(2, "n=2", {"app": "api", "host": "b"}, 1 * S), entry(3, "n=0", {"app": "api", "host": "a"}, 2 * S),
                                          entry(4, "n=3", {"app": "api", "host": "a"}, 3 * S), entry(5, "n=4", {"app": "api", "host": "c"}, 4 * S)], kind="range", start=0, end=5 * S, limit=2)
    met(i, '{app="api"} | logfmt', lo, kind="range", start=0, end=5 * S, direction="forward", limit=4, interval=S)
    bound.append("log-order-limit")

    p, n, i = ids("iterator-entry-merge")
    em = [entry(1, "x", {"app": "api", "host": "a"}, 1 * S), entry(2, "same", {"app": "api", "host": "a"}, 1 * S), entry(3, "A", {"app": "api", "host": "b"}, 1 * S),
          entry(4, "C", {"app": "api", "host": "c"}, 1 * S)]
    met(p, '{app="api"}', em, kind="range", start=0, end=3 * S, limit=10)
    met(n, '{app="api"}', [entry(1, "same", {"app": "api", "host": "a"}, 1 * S), entry(2, "same", {"app": "api", "host": "b"}, 1 * S), entry(3, "same", {"app": "api", "host": "a"}, 2 * S)],
        kind="range", start=0, end=3 * S, limit=10)
    met(i, '{app="api"}', [entry(1, "same", {"app": "api", "host": "a"}, 1 * S), entry(2, "same", {"app": "api", "host": "a"}, 1 * S), entry(3, "x", {"app": "api", "host": "a"}, 1 * S),
                           entry(4, "B", {"app": "api", "host": "b"}, 1 * S)], kind="range", start=0, end=3 * S, direction="backward", limit=3)
    bound.append("iterator-entry-merge")

    p, n, i = ids("iterator-sample-merge")
    sm = [entry(1, "n=3", {"app": "api", "host": "a"}, 1_500_000_000), entry(2, "n=2", {"app": "api", "host": "c"}, 1_500_000_000), entry(3, "n=1", {"app": "api", "host": "a"}, 1 * S)]
    met(p, 'last_over_time({app="api"} | logfmt | unwrap n [2s]) by (app)', sm)
    met(n, 'count_over_time({app="api"}[2s])', [entry(1, "same", {"app": "api"}, 1 * S), entry(2, "same", {"app": "api"}, 1 * S), entry(3, "same", {"app": "api"}, 1 * S)])
    met(i, 'sum by (host) (count_over_time({app="api"}[2s]))', [entry(1, "same", {"app": "api", "host": "a"}, 1 * S), entry(2, "same", {"app": "api", "host": "a"}, 1 * S),
                                                                 entry(3, "same", {"app": "api", "host": "b"}, 1 * S)])
    bound.append("iterator-sample-merge")

    p, n, i = ids("variants")
    V = ["multi-variant-queries"]
    met(p, 'variants(count_over_time({app="api"}[2s]),bytes_over_time({app="api"}[2s])) of ({app="api"}[2s])', fx, enabled=V)
    met(n, 'variants(count_over_time({app="api"}[2s])) of ({app="api"}[2s])', fx)
    met(i, 'variants(sum by (host) (count_over_time({app="api"}[2s])),rate({app="api"}[2s])) of ({app="api"}[2s])', fx, enabled=V)
    bound.append("variants")

    # shard-capability-domain: approx_topk is an explicit capability; k must be a positive integer; no grouping
    p, n, i = ids("shard-capability-domain")
    A = ["approx_topk", "shard-first_over_time"]
    met(p, 'approx_topk(2, first_over_time({app="api"} | logfmt | unwrap n [2s]) by (host))', ft, enabled=A)
    syn(n, 'approx_topk(0, count_over_time({app="api"}[2s]))', False, enabled=["approx_topk"])
    met(i, 'approx_topk(1, count_over_time({app="api"}[2s]))', fx, enabled=["shard-first_over_time", "shard-last_over_time", "shard-quantile_over_time"])
    bound.append("shard-capability-domain")

    # ---- template capabilities ----------------------------------------------
    p, n, i = ids("template-capabilities")
    tpl(p, '{{ and true (not false) }}/{{ printf "%05.1f|%q" 3.14159 .level }}/{{ len .level }}/{{ slice .level 1 3 }}/{{ html "<a&b>" }}/{{ urlquery "a b" }}')
    tpl(n, '{{ env "HOME" }}')
    tpl(i, '{{ $m := fromJson "{\\"a\\":[1,2]}" }}{{ with .level }}{{ if and (eq . "warn") (gt (len $m.a) 1) }}{{ index $m.a 1 }}{{ else }}no{{ end }}{{ end }}')
    bound.append("template-capabilities")

    # The five primitive version-difference obligations already carry their three template
    # rows in cases/logql-templates.json; they are bound here with their independent tests.
    bound += ["primitive/numeric-string-stdlib-version", "primitive/regexp-engine-identity", "primitive/template-version",
              "primitive/time-stdlib-version", "primitive/unicode-case-version"]

    T = "TestReleaseLogQL"
    tests = {
        "json": ["ParserStages"], "logfmt": ["ParserStages"], "pattern": ["ParserStages"], "regexp": ["ParserStages"], "unpack": ["ParserStages"],
        "ip": ["FilterStages"], "label-filter": ["FilterStages"], "line-filters": ["FilterStages"],
        "decolorize": ["MutationStages", "LineFilterHoistsOverDecolorize"],
        "drop-keep": ["MutationStages", "DropErrorLabelClearsDetails"],
        "label-format": ["MutationStages", "LabelFormatSnapshotIsTakenAtFirstTemplate"],
        "pipeline-order": ["MutationStages", "LineFilterHoistsOverDecolorize"],
        "lexical": ["LexicalAndUnwrapStages"], "unwrap": ["LexicalAndUnwrapStages"],
        "structured-metadata": ["SelectorsAndStructuredMetadata"], "selectors": ["SelectorsAndStructuredMetadata"],
        "binary-matching": ["BinaryMatchingAndSetOperators"], "set-operators": ["BinaryMatchingAndSetOperators"],
        "vector": ["VectorAndLabelReplace"], "label-replace": ["VectorAndLabelReplace"],
        "range-time": ["RangeWindowsAndTimeGrid"],
        "first-last-ties": ["FirstLastAndSampleIdentity"], "iterator-sample-merge": ["FirstLastAndSampleIdentity"],
        "log-order-limit": ["LogOrderLimitAndInterval"],
        "iterator-entry-merge": ["EntryMergeKeepsEncounterOrderOfTies", "EntryMergeTieBreaksByStreamHash", "EntryMergeInEnginePathOrdersTiesByLabels"],
        "variants": ["VariantsAndShardCapabilityDomain", "VariantsDisabledIsFeatureCategory"],
        "shard-capability-domain": ["VariantsAndShardCapabilityDomain", "ApproxTopkParameterIsFunctionArguments"],
        "template-capabilities": ["TemplateCapabilities"],
        "primitive/numeric-string-stdlib-version": ["PrimitiveNumericAndStringSemantics"],
        "primitive/regexp-engine-identity": ["PrimitiveRegexpEngineIdentity"],
        "primitive/template-version": ["PrimitiveTemplateVersion"],
        "primitive/time-stdlib-version": ["PrimitiveTimeSemantics"],
        "primitive/unicode-case-version": ["PrimitiveUnicodeEdition"],
    }
    for name in bound:
        ctx.bind(f"{LOGQL}/{name}", "internal/query/logql", [T + t for t in tests[name]])
