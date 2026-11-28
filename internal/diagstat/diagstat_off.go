// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build !soundpost_diag

// Package diagstat is the counter registry of a diagnostic build (-tags soundpost_diag). Each component
// registers a function that reports its counters; the diagnostic endpoint of cmd/soundpost serves them
// together, so that a live investigation can read per-window counters next to the Go profiles. The shipped
// binaries are built without the tag: Register does nothing there and no counter is read.
package diagstat

// Source reports the counters of one component at the moment it is called.
type Source func() map[string]any

// Register is a no-op in a build without the diagnostic tag.
func Register(string, Source) {}
