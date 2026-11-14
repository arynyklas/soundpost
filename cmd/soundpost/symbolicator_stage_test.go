// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import "testing"

// The staging vectors are exact too: any extra argument falls through to the normal CLI,
// and the dedicated names are not accepted in other spellings.
func TestStagingVectorsAreExact(t *testing.T) {
	for _, args := range [][]string{
		{"soundpost", stageWorkerFlag, "extra"},
		{"soundpost", stageProbeFlag, "extra"},
		{"soundpost", "--stage-worker-v2"},
		{"soundpost", "--stage-v1"},
		{stageWorkerFlag},
		{stageProbeFlag},
	} {
		if code, ok := symbolicateWorker(args); ok {
			t.Fatalf("%q ran as a stage (exit %d)", args, code)
		}
	}
	if stageWorkerFlag != "--stage-worker-v1" || stageProbeFlag != "--stage-probe-v1" {
		t.Fatalf("staging vectors changed: %q %q", stageWorkerFlag, stageProbeFlag)
	}
}
