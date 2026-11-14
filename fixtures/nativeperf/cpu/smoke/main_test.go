//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package main

import "testing"

func TestCanaryLeakCounterMeasuresPayloadMatches(t *testing.T) {
	if got := countCanaryLeaks([]byte(`{"kind":"cpu_sample","ip":"4660"}`)); got != 0 {
		t.Fatal(got)
	}
	payload := []byte("SOUNDPOST_CPU_LOCAL_CANARY_2026 SOUNDPOST_CPU_HEAP_CANARY_2026 SOUNDPOST_CPU_LOCAL_CANARY_2026")
	if got := countCanaryLeaks(payload); got != 3 {
		t.Fatalf("matches=%d, want 3", got)
	}
}
