//go:build soundpost_evaluation_oracle && prometheus_310

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/prometheus/prometheus/util/annotations"
)

// This global belongs to the isolated older UPSTREAM parser. The process runs
// exactly one immutable profile/feature group; no production registry is global.
func configureEngine(opts *promql.EngineOpts, enabled []string) {
	parser.EnableExperimentalFunctions = feature(enabled, "promql-experimental-functions")
	opts.EnableDelayedNameRemoval = feature(enabled, "promql-delayed-name-removal")
}
func allowedFeature(name string) bool {
	return name == "promql-experimental-functions" || name == "promql-delayed-name-removal"
}
func annotationIdentity(err error) string {
	if errors.Is(err, annotations.IncompatibleCustomBucketsHistogramsWarning) {
		return "IncompatibleCustomBucketsHistogramsWarning"
	}
	return commonAnnotationIdentity(err)
}
