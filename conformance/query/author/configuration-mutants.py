#!/usr/bin/env python3
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Mutation evidence for the owned Prometheus scrape-configuration resolver
(internal/sources/prometheus_config.go, decision D29). Each mutant is one named,
deliberate defect; the replay tests must fail on it. RUN ONLY IN A THROWAWAY COPY
of the repository (it rewrites the resolver in place and restores it):

    python3 conformance/query/author/configuration-mutants.py --throwaway-copy
"""
import subprocess, sys

PATH = "internal/sources/prometheus_config.go"
MUTANTS = [
    ("casefold-duplicates-ignored", "folded := strings.ToLower(p)", "folded := p"),
    ("job-timeout-ignores-interval", "out.ScrapeTimeout = min(g.ScrapeTimeout, out.ScrapeInterval)", "out.ScrapeTimeout = g.ScrapeTimeout"),
    ("global-timeout-default-ignores-interval", "g.timeout = min(10*time.Second, g.interval)", "g.timeout = 10 * time.Second"),
    ("sample-limit-does-not-inherit", "out.Limits.Sample = inheritLimit(j.limits.Sample, g.Limits.Sample)", "out.Limits.Sample = j.limits.Sample"),
    ("job-timeout-equal-to-interval-refused", "if j.timeout > out.ScrapeInterval {", "if j.timeout >= out.ScrapeInterval {"),
    ("native-histograms-feature-does-not-prefer-proto-310", 'if f == "native-histograms" || f == "created-timestamp-zero-ingestion" {', 'if f == "created-timestamp-zero-ingestion" {'),
    ("native-job-does-not-prefer-proto-3135", "case out.ScrapeNativeHistograms:\n\t\t\tout.ScrapeProtocols = append([]string(nil), promProtocolsProto...)", "case false:\n\t\t\tout.ScrapeProtocols = append([]string(nil), promProtocolsProto...)"),
    ("legacy-job-inherits-utf8-escaping", 'case out.MetricNameValidation == "legacy":\n\t\t\tout.MetricNameEscaping = "underscores"', 'case false:\n\t\t\tout.MetricNameEscaping = "underscores"'),
    ("null-protocol-list-is-empty", "if promIsNull(n) {\n\t\treturn nil, false\n\t}\n\tif n.Kind != yaml.SequenceNode {", "if promIsNull(n) {\n\t\treturn nil, true\n\t}\n\tif n.Kind != yaml.SequenceNode {"),
    ("kilobyte-is-1000", '{"KB", 1 << 10}', '{"KB", 1000}'),
    ("global-error-not-immediate", "if err = d.validateGlobal(&globalRaw, features); err != nil {\n\t\t\t\t\t\t\treturn res, err\n\t\t\t\t\t\t}", "if err = d.validateGlobal(&globalRaw, features); err != nil {\n\t\t\t\t\t\t\td.typeError(PromConfigInvalidValue)\n\t\t\t\t\t\t}"),
    ("unknown-checked-before-duplicate", "\t\tfolded := strings.ToLower(p)\n\t\tif seen[folded] {\n\t\t\treturn promFail(PromConfigProtocolsDuplicate, scope)\n\t\t}\n\t\tif !promProtocolsKnown[p] {\n\t\t\treturn promFail(PromConfigProtocolsUnknown, scope)\n\t\t}", "\t\tfolded := strings.ToLower(p)\n\t\tif !promProtocolsKnown[p] {\n\t\t\treturn promFail(PromConfigProtocolsUnknown, scope)\n\t\t}\n\t\tif seen[folded] {\n\t\t\treturn promFail(PromConfigProtocolsDuplicate, scope)\n\t\t}"),
]

def go_test():
    out = subprocess.run(["go", "test", "-count=1", "./internal/conformance/query", "./internal/sources", "-run", "TestReleaseConfiguration(Protocols|ScrapeInheritance)(Resolution|Refuses)|TestPromConfig"], capture_output=True, text=True)
    return out.returncode, out.stdout + out.stderr


if "--throwaway-copy" not in sys.argv:
    sys.exit("refusing to mutate a checkout that is not a throwaway copy")
original = open(PATH, newline="").read()
rc, text = go_test()
print("baseline", "PASS" if rc == 0 else "FAIL", flush=True)
if rc:
    print(text[-2000:])
    sys.exit(1)
survivors = 0
for name, old, new in MUTANTS:
    if original.count(old) != 1:
        print(f"{name}: UNAPPLICABLE (pattern found {original.count(old)} times)")
        survivors += 1
        continue
    open(PATH, "w", newline="").write(original.replace(old, new))
    try:
        rc, text = go_test()
    finally:
        open(PATH, "w", newline="").write(original)
    failing = sorted({line.split()[2] for line in text.splitlines() if line.startswith("--- FAIL")})
    verdict = "KILLED" if rc else "SURVIVED"
    survivors += rc == 0
    detail = ""
    for line in text.splitlines():
        if "configuration_test.go" in line:
            detail = line.strip()[:240]
            break
    print(f"{name}: {verdict} by {failing[:6]} | {detail}", flush=True)
rc, text = go_test()
print("restored", "PASS" if rc == 0 else "FAIL")
sys.exit(1 if survivors or rc else 0)
