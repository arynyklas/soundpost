#!/bin/bash
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
# Runs the Go tests that production bindings cite and records the `go test -json`
# stream as the evidence file the observations are hashed over:
#   conformance/query/author/observe-go-tests.sh && \
#   python3 conformance/query/author/release-author.py --observe \
#     conformance/query/evidence/release-go-tests.jsonl "conformance/query/author/observe-go-tests.sh"
set -u
out=conformance/query/evidence/release-go-tests.jsonl
: > "$out"
go test -count=1 -json -run '^(TestAuthoredSignatureArityTypeAndGateCases|TestEveryFunctionOverload|TestAggregationSemantics|TestEveryPromQLOperator|TestVectorOperatorValuesAndNameRules)$' ./internal/query/promql >> "$out" || exit 1
go test -count=1 -json -run '^(TestEveryLogQLMetricObligation|TestEveryLogQLMetricInventoryBinding|TestTemplateEveryHelper)$' ./internal/query/logql >> "$out" || exit 1
go test -count=1 -json -run '^TestReleaseBindingsResolveToLockedCaseRows$' ./internal/conformance/query >> "$out" || exit 1
