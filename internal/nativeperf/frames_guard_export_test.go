// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"bytes"
	"context"
	"io"
	"testing"
)

// ResolveApprovedFrameUnderPolicy is the export_test seam of frames_guard_test.go (package nativeperf_test): it resolves
// one sample of an approved, file-backed mapping (build ab12, file offset 0x108) through the unexported resolveFrames
// with exactly the policy it is given, against a backend that serves the matching debug object and counts its reads.
// A policy reaches resolveFrames in a table only from a binding that SymbolBinding.validate has already accepted; this
// seam is how the guard inside resolveFrames is observed on its own.
func ResolveApprovedFrameUnderPolicy(t *testing.T, policy SymbolPolicy) (ResolvedFrame, int) {
	t.Helper()
	object := elfFixtureBytes(t, "approved_hot_loop")
	reads := 0
	backend := artifactTestResolver{func(context.Context) (io.ReadCloser, error) {
		reads++
		return io.NopCloser(bytes.NewReader(object)), nil
	}}
	table := MappingTable{
		process: frameProcess(),
		entries: []mappingEntry{{start: 4096, end: 8192, offset: 0x100, module: moduleOf("ab12")}},
		policy:  policy,
	}
	out, err := resolveFrames(context.Background(), []AddressFrame{{Task: frameTask(), IP: 4096 + 8}}, table, backend, newFrameCache())
	if err != nil || len(out) != 1 {
		t.Fatalf("resolve: %v %v", out, err)
	}
	return out[0], reads
}
