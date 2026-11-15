# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Authors the configuration/protocols and configuration/scrape-inheritance rows
of both pinned Prometheus profiles (decision D29, 02.12-W1).

Each ledger case (positive/negative/interaction) is one row of scenarios: a
Prometheus configuration document, the process features the reference is started
with, the authored acceptance, the authored refusal family@scope and the
effective values the obligation's rule text fixes. The expected values the
differential runner compares are the reference's own observation (the unmodified
upstream binary in the configuration-phase oracle variant); this module records
only what the rule text says and never a verdict.
"""

FILE = "cases/release-configuration.json"
HEADER = {"copyright": "Copyright 2026 Aryn Yklas", "license": "Apache-2.0",
          "schema": "soundpost-authored-prometheus-configuration-cases-v1", "phase": "configuration"}

D4 = "OpenMetricsText1.0.0,OpenMetricsText0.0.1,PrometheusText1.0.0,PrometheusText0.0.4"
PROTO_FIRST = "PrometheusProto," + D4
STATIC = "    static_configs:\n      - targets: ['127.0.0.1:9']\n"


def job(name, extra=""):
    body = "".join("    " + line + "\n" for line in extra.strip("\n").split("\n")) if extra else ""
    return f"  - job_name: {name}\n{body}{STATIC}"


def cfg(glob="", jobs=()):
    text = ""
    if glob:
        text += "global:\n" + "".join("  " + line + "\n" for line in glob.strip("\n").split("\n"))
    return text + "scrape_configs:\n" + "".join(jobs)


def sc(name, config, accepted=True, reason="", features=(), expect=None):
    s = {"name": name, "config": config, "accepted": accepted}
    if features:
        s["features"] = list(features)
    if reason:
        s["reason"] = reason
    if expect:
        s["expect"] = dict(expect)
    return s


def refuse(name, config, reason, features=()):
    return sc(name, config, False, reason, features)


def build(ctx):
    ctx.declare(FILE, "promql", "configuration", HEADER)
    for p in ctx.PROM:
        v310 = p.endswith("3.1.0")
        for kind in ("protocols", "scrape-inheritance"):
            o = ctx.BY_ID[f"{p}/configuration/{kind}"]
            pos, neg, inter = ctx.role_ids(o)
            rows = (protocols if kind == "protocols" else inheritance)(v310)
            for rid, scenarios in zip((pos, neg, inter), rows):
                ctx.put(FILE, {"id": rid, "profiles": [p], "obligation": o["id"], "scenarios": scenarios})
            ctx.bind(o["id"], "internal/sources", tests(kind))


def tests(kind):
    stem = "TestReleaseConfiguration" + ("Protocols" if kind == "protocols" else "ScrapeInheritance")
    return [stem + "Resolution", stem + "RefusesWhatThePinnedReleaseRefuses", "TestPromConfigDurationAndSizeGrammar",
            "TestReleaseConfigurationRecordedObservationsAreBoundToTheirInputs", "TestConfigurationOracleLockIsVerifiable"]


def protocols(v310):
    default_global = {"global.scrape_protocols": D4} if v310 else {"global.scrape_protocols": "<unset>"}
    positive = [
        sc("default-list", cfg("", [job("a")]), expect={**default_global, "job:a.scrape_protocols": D4}),
        sc("global-override-and-explicit-job", cfg("scrape_protocols: [PrometheusText0.0.4]", [job("a"), job("b", "scrape_protocols: [OpenMetricsText1.0.0, PrometheusProto]")]),
           expect={"global.scrape_protocols": "PrometheusText0.0.4", "job:a.scrape_protocols": "PrometheusText0.0.4", "job:b.scrape_protocols": "OpenMetricsText1.0.0,PrometheusProto"}),
        sc("null-lists-inherit", cfg("scrape_protocols: null", [job("a", "scrape_protocols: null")]), expect={"job:a.scrape_protocols": D4}),
        sc("all-five-known-names", cfg("", [job("a", "scrape_protocols: [PrometheusText1.0.0, OpenMetricsText0.0.1, PrometheusProto, PrometheusText0.0.4, OpenMetricsText1.0.0]")]),
           expect={"job:a.scrape_protocols": "PrometheusText1.0.0,OpenMetricsText0.0.1,PrometheusProto,PrometheusText0.0.4,OpenMetricsText1.0.0"}),
        sc("fallback-protocol-known", cfg("", [job("a", "fallback_scrape_protocol: PrometheusText0.0.4")]), expect={"job:a.fallback_scrape_protocol": "PrometheusText0.0.4"}),
        sc("single-protocol-global", cfg("scrape_protocols: [OpenMetricsText1.0.0]", [job("a")]), expect={"job:a.scrape_protocols": "OpenMetricsText1.0.0"}),
    ]
    negative = [
        refuse("empty-global-list", cfg("scrape_protocols: []", [job("a")]), "protocols_empty@global"),
        refuse("empty-job-list", cfg("", [job("a", "scrape_protocols: []")]), "protocols_empty@job:a"),
        refuse("duplicate-casefold-in-job", cfg("", [job("a", "scrape_protocols: [PrometheusProto, prometheusproto]")]), "protocols_duplicate@job:a"),
        refuse("duplicate-exact-in-global", cfg("scrape_protocols: [PrometheusText0.0.4, PrometheusText0.0.4]", [job("a")]), "protocols_duplicate@global"),
        refuse("unknown-protocol-in-job", cfg("", [job("a", "scrape_protocols: [Foo]")]), "protocols_unknown@job:a"),
        refuse("unknown-protocol-in-global", cfg("scrape_protocols: [X]", [job("a")]), "protocols_unknown@global"),
        refuse("known-name-wrong-case", cfg("", [job("a", "scrape_protocols: [prometheusproto]")]), "protocols_unknown@job:a"),
        refuse("unknown-before-casefold-duplicate", cfg("", [job("a", "scrape_protocols: [Foo, foo]")]), "protocols_unknown@job:a"),
        refuse("unknown-fallback-protocol", cfg("", [job("a", "fallback_scrape_protocol: Nope")]), "fallback_protocol_unknown@job:a"),
        refuse("empty-list-before-unknown-fallback", cfg("", [job("a", "scrape_protocols: []\nfallback_scrape_protocol: Nope")]), "protocols_empty@job:a"),
        refuse("list-is-not-a-sequence", cfg("", [job("a", "scrape_protocols: PrometheusProto")]), "invalid_value@document"),
    ]
    if v310:
        native = "native-histograms"
        created = "created-timestamp-zero-ingestion"
        interaction = [
            sc("native-histograms-feature-prefers-proto", cfg("", [job("a")]), features=[native], expect={"global.scrape_protocols": PROTO_FIRST, "job:a.scrape_protocols": PROTO_FIRST}),
            sc("created-timestamp-feature-prefers-proto", cfg("", [job("a")]), features=[created], expect={"global.scrape_protocols": PROTO_FIRST, "job:a.scrape_protocols": PROTO_FIRST}),
            sc("both-features", cfg("", [job("a")]), features=[native, created], expect={"job:a.scrape_protocols": PROTO_FIRST}),
            sc("feature-keeps-explicit-global", cfg("scrape_protocols: [PrometheusText0.0.4]", [job("a")]), features=[native], expect={"global.scrape_protocols": "PrometheusText0.0.4", "job:a.scrape_protocols": "PrometheusText0.0.4"}),
            sc("feature-keeps-explicit-job", cfg("", [job("a", "scrape_protocols: [PrometheusText1.0.0]")]), features=[native], expect={"global.scrape_protocols": PROTO_FIRST, "job:a.scrape_protocols": "PrometheusText1.0.0"}),
            sc("feature-null-global-list-takes-feature-default", cfg("scrape_protocols: null", [job("a")]), features=[native], expect={"global.scrape_protocols": PROTO_FIRST}),
            refuse("feature-does-not-excuse-empty-list", cfg("scrape_protocols: []", [job("a")]), "protocols_empty@global", features=[native]),
            sc("unrelated-feature-keeps-default", cfg("", [job("a")]), features=["ooo-native-histograms"], expect={"job:a.scrape_protocols": D4}),
            refuse("native-histogram-key-is-unknown-in-310", cfg("scrape_native_histograms: true", [job("a")]), "unknown_field@document"),
            refuse("job-native-histogram-key-is-unknown-in-310", cfg("", [job("a", "scrape_native_histograms: true")]), "unknown_field@document"),
        ]
    else:
        native = "native-histograms"
        created = "created-timestamp-zero-ingestion"
        interaction = [
            sc("global-native-true-prefers-proto", cfg("scrape_native_histograms: true", [job("a"), job("b", "scrape_native_histograms: false")]),
               expect={"global.scrape_protocols": "<unset>", "global.scrape_native_histograms": "true", "job:a.scrape_protocols": PROTO_FIRST, "job:a.scrape_native_histograms": "true", "job:b.scrape_protocols": D4, "job:b.scrape_native_histograms": "false"}),
            sc("job-native-true-prefers-proto", cfg("", [job("a", "scrape_native_histograms: true"), job("b")]), expect={"job:a.scrape_protocols": PROTO_FIRST, "job:b.scrape_protocols": D4}),
            sc("native-true-keeps-explicit-job-list", cfg("scrape_native_histograms: true", [job("a", "scrape_protocols: [PrometheusText0.0.4]")]), expect={"job:a.scrape_protocols": "PrometheusText0.0.4"}),
            sc("native-true-keeps-explicit-global-list", cfg("scrape_native_histograms: true\nscrape_protocols: [PrometheusText0.0.4]", [job("a")]), expect={"global.scrape_protocols": "PrometheusText0.0.4", "job:a.scrape_protocols": "PrometheusText0.0.4"}),
            sc("job-native-false-overrides-global-true", cfg("scrape_native_histograms: true", [job("a", "scrape_native_histograms: false")]), expect={"job:a.scrape_protocols": D4, "job:a.scrape_native_histograms": "false"}),
            sc("native-histograms-feature-is-a-noop", cfg("", [job("a")]), features=[native], expect={"global.scrape_protocols": "<unset>", "job:a.scrape_protocols": D4}),
            sc("created-timestamp-feature-sets-global-proto-first", cfg("", [job("a")]), features=[created], expect={"global.scrape_protocols": PROTO_FIRST, "job:a.scrape_protocols": PROTO_FIRST}),
            sc("start-timestamp-storage-feature-sets-global-proto-first", cfg("", [job("a")]), features=["st-storage", "xor2-encoding"], expect={"global.scrape_protocols": PROTO_FIRST, "job:a.scrape_protocols": PROTO_FIRST}),
            sc("feature-global-list-does-not-reach-native-false-job", cfg("scrape_native_histograms: false", [job("a")]), features=[created], expect={"job:a.scrape_protocols": PROTO_FIRST}),
            sc("feature-keeps-explicit-global", cfg("scrape_protocols: [PrometheusText0.0.4]", [job("a")]), features=[created], expect={"global.scrape_protocols": "PrometheusText0.0.4", "job:a.scrape_protocols": "PrometheusText0.0.4"}),
            refuse("feature-does-not-excuse-empty-list", cfg("scrape_protocols: []", [job("a")]), "protocols_empty@global", features=[created]),
            refuse("native-flag-must-be-boolean", cfg("scrape_native_histograms: maybe", [job("a")]), "invalid_value@document"),
            sc("utf8-validation-with-allow-utf8-escaping-default", cfg("", [job("a")]), expect={"global.metric_name_validation_scheme": "utf8", "job:a.metric_name_validation_scheme": "utf8", "job:a.metric_name_escaping_scheme": "allow-utf-8"}),
            sc("global-legacy-validation-escapes-with-underscores", cfg("metric_name_validation_scheme: legacy", [job("a")]), expect={"global.metric_name_validation_scheme": "legacy", "job:a.metric_name_validation_scheme": "legacy", "job:a.metric_name_escaping_scheme": "underscores"}),
            sc("job-legacy-does-not-inherit-utf8-escaping", cfg("", [job("a", "metric_name_validation_scheme: legacy")]), expect={"job:a.metric_name_validation_scheme": "legacy", "job:a.metric_name_escaping_scheme": "underscores"}),
            sc("job-utf8-over-global-legacy", cfg("metric_name_validation_scheme: legacy", [job("a", "metric_name_validation_scheme: utf8")]), expect={"job:a.metric_name_validation_scheme": "utf8", "job:a.metric_name_escaping_scheme": "allow-utf-8"}),
            sc("global-escaping-reaches-unset-job", cfg("metric_name_escaping_scheme: dots", [job("a"), job("b", "metric_name_escaping_scheme: values")]), expect={"job:a.metric_name_escaping_scheme": "dots", "job:b.metric_name_escaping_scheme": "values"}),
            sc("underscore-escaping-under-utf8-validation", cfg("", [job("a", "metric_name_escaping_scheme: underscores")]), expect={"job:a.metric_name_validation_scheme": "utf8", "job:a.metric_name_escaping_scheme": "underscores"}),
            refuse("allow-utf8-escaping-requires-utf8-validation", cfg("metric_name_validation_scheme: legacy\nmetric_name_escaping_scheme: allow-utf-8", [job("a")]), "escaping_requires_utf8@scrape"),
            refuse("unknown-job-escaping", cfg("", [job("a", "metric_name_escaping_scheme: nope")]), "escaping_scheme_unknown@scrape"),
            refuse("unknown-global-escaping", cfg("metric_name_escaping_scheme: nope", [job("a")]), "escaping_scheme_unknown@global"),
            refuse("unknown-validation-scheme", cfg("", [job("a", "metric_name_validation_scheme: nope")]), "validation_scheme_unknown@document"),
        ]
    return positive, negative, interaction


def limit_block(prefix=""):
    return ""


def inheritance(v310):
    G = {"global.scrape_interval": "1m", "global.scrape_timeout": "10s", "global.evaluation_interval": "1m"}
    positive = [
        sc("global-zero-values-take-defaults", cfg("scrape_interval: 0s\nscrape_timeout: 0s\nevaluation_interval: 0s", [job("a")]), expect={**G, "job:a.scrape_interval": "1m", "job:a.scrape_timeout": "10s"}),
        sc("absent-global-takes-defaults", cfg("", [job("a")]), expect={**G, "job:a.scrape_interval": "1m", "job:a.scrape_timeout": "10s"}),
        sc("short-global-interval-caps-default-timeout", cfg("scrape_interval: 5s", [job("a")]), expect={"global.scrape_interval": "5s", "global.scrape_timeout": "5s", "job:a.scrape_timeout": "5s"}),
        sc("global-timeout-zero-with-long-interval", cfg("scrape_interval: 30s\nscrape_timeout: 0", [job("a")]), expect={"global.scrape_timeout": "10s", "job:a.scrape_timeout": "10s"}),
        sc("global-timeout-equals-interval", cfg("scrape_interval: 10s\nscrape_timeout: 10s", [job("a")]), expect={"global.scrape_timeout": "10s", "job:a.scrape_interval": "10s"}),
        sc("global-timeout-with-default-interval", cfg("scrape_timeout: 5s", [job("a")]), expect={"global.scrape_interval": "1m", "global.scrape_timeout": "5s"}),
        sc("job-zero-values-inherit-global", cfg("scrape_interval: 20s\nscrape_timeout: 8s", [job("a", "scrape_interval: 0s\nscrape_timeout: 0s")]), expect={"job:a.scrape_interval": "20s", "job:a.scrape_timeout": "8s"}),
        sc("job-interval-below-global-timeout-caps-timeout", cfg("scrape_interval: 20s\nscrape_timeout: 8s", [job("a", "scrape_interval: 4s")]), expect={"job:a.scrape_interval": "4s", "job:a.scrape_timeout": "4s"}),
        sc("job-interval-above-global-timeout-keeps-timeout", cfg("scrape_interval: 20s\nscrape_timeout: 8s", [job("a", "scrape_interval: 9s")]), expect={"job:a.scrape_interval": "9s", "job:a.scrape_timeout": "8s"}),
        sc("job-timeout-equals-interval", cfg("", [job("a", "scrape_interval: 15s\nscrape_timeout: 15s")]), expect={"job:a.scrape_interval": "15s", "job:a.scrape_timeout": "15s"}),
        sc("job-timeout-below-inherited-interval", cfg("scrape_interval: 1h", [job("a", "scrape_timeout: 59m")]), expect={"job:a.scrape_interval": "1h0m0s", "job:a.scrape_timeout": "59m"}),
        sc("jobs-inherit-independently", cfg("scrape_interval: 1m", [job("a", "scrape_interval: 5s"), job("b")]), expect={"job:a.scrape_interval": "5s", "job:a.scrape_timeout": "5s", "job:b.scrape_interval": "1m", "job:b.scrape_timeout": "10s", "jobs": "a,b"}),
        sc("acquisition-defaults", cfg("", [job("a")]), expect={"job:a.honor_labels": "false", "job:a.honor_timestamps": "true", "job:a.track_timestamps_staleness": "false"}),
        sc("acquisition-explicit", cfg("", [job("a", "honor_labels: true\nhonor_timestamps: false\ntrack_timestamps_staleness: true"), job("b")]),
           expect={"job:a.honor_labels": "true", "job:a.honor_timestamps": "false", "job:a.track_timestamps_staleness": "true", "job:b.honor_labels": "false", "job:b.honor_timestamps": "true"}),
        sc("null-values-are-zero", cfg("scrape_interval:\nscrape_timeout: ~", [job("a", "scrape_interval:\nsample_limit:")]), expect={"job:a.scrape_interval": "1m", "job:a.scrape_timeout": "10s", "job:a.sample_limit": "0"}),
        sc("document-without-jobs", "global:\n  scrape_interval: 2m\n", expect={"global.scrape_interval": "2m", "global.scrape_timeout": "10s", "jobs": ""}),
        sc("empty-document", "", expect={**G, "jobs": ""}),
    ]
    negative = [
        refuse("global-timeout-above-interval", cfg("scrape_interval: 10s\nscrape_timeout: 11s", [job("a")]), "timeout_exceeds_interval@global"),
        refuse("global-timeout-above-default-interval", cfg("scrape_timeout: 2m", [job("a")]), "timeout_exceeds_interval@global"),
        refuse("job-timeout-above-interval", cfg("", [job("a", "scrape_interval: 15s\nscrape_timeout: 16s")]), "timeout_exceeds_interval@job:a"),
        refuse("job-timeout-above-global-interval", cfg("scrape_interval: 15s", [job("a", "scrape_timeout: 16s")]), "timeout_exceeds_interval@job:a"),
        refuse("job-timeout-above-default-interval", cfg("", [job("a", "scrape_timeout: 2m")]), "timeout_exceeds_interval@job:a"),
        refuse("invalid-duration-word", cfg("scrape_interval: abc", [job("a")]), "invalid_duration@document"),
        refuse("negative-duration", cfg("scrape_interval: -5s", [job("a")]), "invalid_duration@document"),
        refuse("bare-nonzero-number-duration", cfg("scrape_interval: 5", [job("a")]), "invalid_duration@document"),
        refuse("fractional-duration", cfg("scrape_interval: 1.5s", [job("a")]), "invalid_duration@document"),
        refuse("duration-units-out-of-order", cfg("scrape_interval: 30s1m", [job("a")]), "invalid_duration@document"),
        refuse("negative-limit", cfg("", [job("a", "sample_limit: -1")]), "invalid_value@document"),
        refuse("negative-global-limit", cfg("sample_limit: -1", [job("a")]), "invalid_value@document"),
        refuse("non-numeric-limit", cfg("", [job("a", "sample_limit: abc")]), "invalid_value@document"),
        refuse("bare-number-body-size", cfg("", [job("a", "body_size_limit: 1000")]), "invalid_size@document"),
        refuse("non-numeric-body-size", cfg("", [job("a", "body_size_limit: abc")]), "invalid_size@document"),
        refuse("lowercase-body-size-unit", cfg("", [job("a", "body_size_limit: 1kb")]), "invalid_size@document"),
        refuse("non-boolean-honor-labels", cfg("", [job("a", "honor_labels: perhaps")]), "invalid_value@document"),
        refuse("global-honor-labels-is-not-a-global-key", cfg("honor_labels: true", [job("a")]), "unknown_field@document"),
        refuse("document-is-a-list", "- a\n", "invalid_value@document"),
        refuse("scrape-configs-is-a-mapping", "scrape_configs: {}\n", "invalid_value@document"),
        refuse("global-is-a-scalar", "global: 5\n", "invalid_value@document"),
    ]
    limits = "sample_limit: {n}\ntarget_limit: {n}\nlabel_limit: {n}\nlabel_name_length_limit: {n}\nlabel_value_length_limit: {n}\nkeep_dropped_targets: {n}\nbody_size_limit: {b}"
    keys = ["sample_limit", "target_limit", "label_limit", "label_name_length_limit", "label_value_length_limit", "keep_dropped_targets"]

    def lim(n, b):
        return limits.format(n=n, b=b)

    def all_limits(prefix, n, b):
        e = {f"{prefix}.{k}": str(n) for k in keys}
        e[f"{prefix}.body_size_limit"] = str(b)
        return e

    interaction = [
        sc("limits-inherit-override-and-zero", cfg(lim(100, "2MB"), [job("a"), job("b", lim(1, "3KB")), job("c", lim(0, 0))]),
           expect={**all_limits("global", 100, 2 << 20), **all_limits("job:a", 100, 2 << 20), **all_limits("job:b", 1, 3 << 10), **all_limits("job:c", 100, 2 << 20)}),
        sc("global-limits-zero-mean-no-cap", cfg(lim(0, 0), [job("a"), job("b", lim(1, "1B"))]),
           expect={**all_limits("global", 0, 0), **all_limits("job:a", 0, 0), **all_limits("job:b", 1, 1)}),
        sc("job-limit-one-below-global", cfg("sample_limit: 100", [job("a", "sample_limit: 99")]), expect={"global.sample_limit": "100", "job:a.sample_limit": "99"}),
        sc("job-limit-equals-global", cfg("sample_limit: 100", [job("a", "sample_limit: 100")]), expect={"job:a.sample_limit": "100"}),
        sc("job-limit-one-above-global", cfg("sample_limit: 100", [job("a", "sample_limit: 101")]), expect={"job:a.sample_limit": "101"}),
        sc("job-limit-one-over-zero-global", cfg("sample_limit: 0", [job("a", "sample_limit: 1")]), expect={"global.sample_limit": "0", "job:a.sample_limit": "1"}),
        sc("each-limit-inherits-on-its-own", cfg(lim(7, "1KB"), [job("a", "sample_limit: 0\ntarget_limit: 2")]),
           expect={"job:a.sample_limit": "7", "job:a.target_limit": "2", "job:a.label_limit": "7", "job:a.body_size_limit": "1024"}),
        sc("body-size-units", cfg("", [job("a", "body_size_limit: 1KB"), job("b", "body_size_limit: 1KiB"), job("c", "body_size_limit: 1MB512KB"), job("d", "body_size_limit: 10GB"), job("e", "body_size_limit: 1B"), job("f", "body_size_limit: 0B")]),
           expect={"job:a.body_size_limit": "1024", "job:b.body_size_limit": "1024", "job:c.body_size_limit": "1572864", "job:d.body_size_limit": "10737418240", "job:e.body_size_limit": "1", "job:f.body_size_limit": "0"}),
        sc("millisecond-and-compound-durations", cfg("scrape_interval: 1500ms\nscrape_timeout: 500ms", [job("a"), job("b", "scrape_interval: 1h30m")]),
           expect={"global.scrape_interval": "1.5s", "global.scrape_timeout": "500ms", "job:a.scrape_interval": "1.5s", "job:b.scrape_interval": "1h30m", "job:b.scrape_timeout": "500ms"}),
        sc("calendar-unit-durations", cfg("scrape_interval: 1d", [job("a", "scrape_interval: 1w")]), expect={"global.scrape_interval": "24h", "job:a.scrape_interval": "168h"}),
        sc("bare-zero-duration-is-zero", cfg("scrape_interval: 0", [job("a")]), expect={"global.scrape_interval": "1m"}),
        sc("evaluation-interval-is-independent", cfg("scrape_interval: 7s\nevaluation_interval: 45s", [job("a")]), expect={"global.evaluation_interval": "45s", "job:a.scrape_interval": "7s", "job:a.scrape_timeout": "7s"}),
        refuse("global-error-wins-over-job-error", cfg("scrape_interval: 5s\nscrape_timeout: 9s", [job("a", "scrape_interval: 5s\nscrape_timeout: 9s")]), "timeout_exceeds_interval@global"),
        refuse("global-error-wins-over-job-type-error", cfg("scrape_interval: 5s\nscrape_timeout: 9s", [job("a", "sample_limit: -1")]), "timeout_exceeds_interval@global"),
        refuse("global-error-wins-when-it-comes-last", "scrape_configs:\n" + job("a", "sample_limit: -1") + "global:\n  scrape_interval: 5s\n  scrape_timeout: 9s\n", "timeout_exceeds_interval@global"),
        refuse("type-error-wins-over-job-timeout", cfg("", [job("a", "sample_limit: -1"), job("b", "scrape_interval: 5s\nscrape_timeout: 9s")]), "invalid_value@document"),
        refuse("global-type-error-skips-global-validation", cfg("sample_limit: -1\nscrape_interval: 5s\nscrape_timeout: 9s", [job("a")]), "invalid_value@document"),
        refuse("first-failing-job-is-reported", cfg("", [job("a", "scrape_protocols: []"), job("b", "scrape_interval: 5s\nscrape_timeout: 9s")]), "protocols_empty@job:a"),
        refuse("timeout-checked-before-protocols", cfg("", [job("a", "scrape_interval: 5s\nscrape_timeout: 9s\nscrape_protocols: []")]), "timeout_exceeds_interval@job:a"),
    ]
    if not v310:
        interaction.append(sc("native-feature-does-not-change-intervals", cfg("scrape_interval: 20s", [job("a")]), features=["native-histograms"], expect={"job:a.scrape_interval": "20s", "job:a.scrape_timeout": "10s"}))
    return positive, negative, interaction
