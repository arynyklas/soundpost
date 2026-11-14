#!/bin/bash
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
# Runs the Go tests that production bindings cite and records the `go test -json`
# stream as the evidence file the observations are hashed over:
#   conformance/query/author/observe-go-tests.sh && \
#   python3 conformance/query/author/release-author.py --observe \
#     conformance/query/evidence/release-go-tests.jsonl "conformance/query/author/observe-go-tests.sh"
# The tests are listed in conformance/query/author/observed-tests.d/*.txt: one
# "<package> <TestName>" per line. A test name is unique across packages because
# the gate keys observations by name.
set -u
out=conformance/query/evidence/release-go-tests.jsonl
dir=conformance/query/author/observed-tests.d
: > "$out"
for pkg in $(cat "$dir"/*.txt | grep -v '^#' | awk 'NF==2{print $1}' | sort -u); do
	names=$(cat "$dir"/*.txt | grep -v '^#' | awk -v p="$pkg" 'NF==2 && $1==p{print $2}' | sort -u | paste -sd'|')
	go test -count=1 -json -run "^($names)\$" "$pkg" >> "$out" || exit 1
done
