//go:build linux && (amd64 || arm64)

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"
)

// stagedProbe runs one full probe through the staged launch (migrate, read back,
// release, exec, sandbox install, denial check) and returns its wall time.
func stagedProbe(t *testing.T, c Config) time.Duration {
	t.Helper()
	start := time.Now()
	r := Probe(context.Background(), c, ProbeFile)
	d := time.Since(start)
	if !r.Denied || r.Reason != Resolved {
		t.Errorf("staged probe: %+v", r)
	}
	return d
}

// Measures what the staged launch costs and proves two staged workers can be
// alive at once (the service runs two slots), each in its own limited group. The
// bound asserted is the product's own: a whole staged launch, end to end, must fit
// well inside ProcessTimeout; the distribution is logged for the report.
func TestStagedLaunchTimeAndTwoConcurrentWorkers(t *testing.T) {
	c := sandboxConfig(t)
	forceNoClone3(t)
	const runs = 20
	var seq []time.Duration
	for range runs {
		seq = append(seq, stagedProbe(t, c))
	}
	sort.Slice(seq, func(i, j int) bool { return seq[i] < seq[j] })
	t.Logf("STAGE sequential n=%d min=%s median=%s p90=%s max=%s", runs, seq[0], seq[runs/2], seq[runs*9/10], seq[runs-1])
	if seq[runs-1] >= ProcessTimeout/2 {
		t.Fatalf("slowest staged launch %s is not well inside ProcessTimeout %s", seq[runs-1], ProcessTimeout)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var conc []time.Duration
	before := groupNames(t, c.CgroupRoot)
	for range 10 {
		wg.Add(2)
		for range 2 {
			go func() {
				defer wg.Done()
				d := stagedProbe(t, c)
				mu.Lock()
				conc = append(conc, d)
				mu.Unlock()
			}()
		}
		wg.Wait()
	}
	sort.Slice(conc, func(i, j int) bool { return conc[i] < conc[j] })
	n := len(conc)
	t.Logf("STAGE two-concurrent n=%d min=%s median=%s p90=%s max=%s", n, conc[0], conc[n/2], conc[n*9/10], conc[n-1])
	if conc[n-1] >= ProcessTimeout/2 {
		t.Fatalf("slowest launch of two concurrent staged workers %s", conc[n-1])
	}
	for name := range groupNames(t, c.CgroupRoot) {
		if !before[name] {
			t.Errorf("private group %s left behind", name)
		}
	}
}
