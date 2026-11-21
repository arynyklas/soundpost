//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"testing"
)

// The guard of a mapping reader re-resolves the task the PID names (its PID namespace and process start) and compares it
// with the authorized target before it looks at anything else: the pidfd, the executable and the cgroup it holds would
// still say "the same process" for a target whose namespace or start was never that process's, and the thread snapshot
// carries the target's claimed start only as a label. A target that claims another PID namespace or another process
// start than the process the PID names is therefore refused when the reader is created, with the one identity error, and
// leaves nothing behind (l4w33 mutation battery D, guardLocked).
func TestMappingReaderGuardRefusesATargetThatIsNotTheProcessThePIDNames(t *testing.T) {
	_, target, authorized := idleTarget(t)
	policy := DefaultSymbolPolicy(1)
	control, err := NewMappingReader(authorized, target, 1, policy)
	if err != nil {
		t.Skipf("the target cannot be read here: %v", err)
	}
	if err = control.Guard(); err != nil {
		t.Fatalf("the genuine target is refused by its own guard: %v", err)
	}
	control.Close()

	for _, tc := range []struct {
		name string
		edit func(*Target)
	}{
		{"another PID namespace", func(x *Target) { x.PIDNamespace++ }},
		{"another process start", func(x *Target) { x.ProcessStart++ }},
	} {
		forged := target
		forged.AllowedBuildIDs = append([]string(nil), target.AllowedBuildIDs...)
		tc.edit(&forged)
		before := openFDs(t)
		reader, err := NewMappingReader(AuthorizedTargets{targets: []Target{forged}, mode: authorized.mode}, forged, 1, policy)
		if reader != nil {
			reader.Close()
		}
		if !errors.Is(err, ErrTargetIdentity) || reader != nil {
			t.Errorf("%s: %v %v, want ErrTargetIdentity and no reader", tc.name, reader, err)
		}
		if after := openFDs(t); after != before {
			t.Errorf("%s: %d descriptors open after the refusal, %d before", tc.name, after, before)
		}
	}
}
