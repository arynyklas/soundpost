// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"reflect"
	"soundpost/internal/model"
	"testing"
)

// Mutating the minimum-active-CPU watermark to a maximum, or learning topology
// from events, would incorrectly flush these traces before CPU1 has drained.
func TestReorderRequiresExplicitTopologyAndEveryCPUProgress(t *testing.T) {
	c := NewCorrelator(DefaultConfig(1))
	if _, err := c.Consume(correlationOut(0, false)); err == nil {
		t.Fatal("implicitly learned topology")
	}
	c = configuredCorrelation(t, 0, 1)
	feedCorrelation(t, c, correlationOut(0, false), correlationWake(40), correlationIn(55))
	if err := c.ReportProgress(0, 100000055); err != nil {
		t.Fatal(err)
	}
	got, err := c.Advance(55)
	if err != nil || len(got) != 0 {
		t.Fatalf("idle/unseen CPU assumed drained: %+v %v", got, err)
	}
	if err = c.ReportProgress(1, 100000054); err != nil {
		t.Fatal(err)
	}
	got, err = c.Advance(55)
	if err != nil || len(got) != 0 {
		t.Fatalf("crossed 100ms bound: %+v %v", got, err)
	}
	if err = c.ReportProgress(1, 100000055); err != nil {
		t.Fatal(err)
	}
	got, err = c.Advance(55)
	if err != nil || len(got) != 2 {
		t.Fatalf("safe progress did not flush: %+v %v", got, err)
	}
	if err = c.ReportProgress(3, 100000055); err == nil {
		t.Fatal("unknown CPU accepted")
	}
}
func TestReorderCrossCPUMigration(t *testing.T) {
	ordered, reordered := configuredCorrelation(t, 0, 1), configuredCorrelation(t, 0, 1)
	out, wake, in := correlationOut(0, false), correlationWake(40000000), correlationIn(55000000)
	wake.CPU = 1
	wake.Wakeup.TargetCPU = 1
	in.CPU = 1
	feedCorrelation(t, ordered, out, wake, in)
	feedCorrelation(t, reordered, in, out, wake)
	a, b := drainCorrelation(t, ordered, []uint32{0, 1}, 55000000), drainCorrelation(t, reordered, []uint32{0, 1}, 55000000)
	if !reflect.DeepEqual(a, b) || len(a) != 2 {
		t.Fatalf("migration/reorder differs: %+v %+v", a, b)
	}
}
func TestReorderCPUFailureAndHotplugRequireFreshProof(t *testing.T) {
	c := configuredCorrelation(t, 0, 1)
	feedCorrelation(t, c, correlationOut(0, false), correlationWake(40), correlationIn(55))
	gaps, err := c.ReportCPUFailure(1, 20)
	if err != nil || len(gaps) != 1 || !gaps[0].Correction {
		t.Fatalf("failure lacks gap: %+v %v", gaps, err)
	}
	if err = c.ReportProgress(0, 100000100); err != nil {
		t.Fatal(err)
	}
	if err = c.ReportProgress(1, 100000100); err == nil {
		t.Fatal("failed CPU made progress")
	}
	got, err := c.Advance(100)
	if err != nil || len(got) != 0 {
		t.Fatalf("failed CPU silently removed: %+v %v", got, err)
	}
	gaps, err = c.ChangeTopology(100, []uint32{0, 2})
	if err != nil || len(gaps) != 1 || !gaps[0].Correction {
		t.Fatalf("hotplug lacks gap: %+v %v", gaps, err)
	}
	feedCorrelation(t, c, correlationOut(110, true), correlationIn(130))
	if err = c.ReportProgress(0, 100000130); err != nil {
		t.Fatal(err)
	}
	got, err = c.Advance(130)
	if err != nil || len(got) != 0 {
		t.Fatal("new CPU assumed complete")
	}
	if err = c.ReportProgress(2, 100000130); err != nil {
		t.Fatal(err)
	}
	got, err = c.Advance(130)
	if err != nil || len(got) != 1 || got[0].Measure.Value != 20 {
		t.Fatalf("fresh epoch: %+v %v", got, err)
	}
}
func TestReorderTimestampBoundariesAndFinalProof(t *testing.T) {
	c := configuredCorrelation(t, 0)
	out, in := correlationOut(^uint64(0)-10, true), correlationIn(^uint64(0))
	out.Sequence = 1
	in.Sequence = 2
	feedCorrelation(t, c, in, out)
	if _, err := c.Finalize(model.MonoNano(^uint64(0))); err == nil {
		t.Fatal("finalized without drained proof")
	}
	if err := c.ReportProgress(0, model.MonoNano(^uint64(0))); err != nil {
		t.Fatal(err)
	}
	got, err := c.Finalize(model.MonoNano(^uint64(0)))
	if err != nil || len(got) != 1 || got[0].Measure.Value != 10 {
		t.Fatalf("overflow: %+v %v", got, err)
	}
	c = configuredCorrelation(t, 0)
	feedCorrelation(t, c, correlationOut(0, true), correlationIn(0))
	got = drainCorrelation(t, c, []uint32{0}, 0)
	for _, i := range got {
		if i.End < i.Start || i.Measure.Value != 0 {
			t.Fatalf("zero boundary: %+v", got)
		}
	}
}
func TestReorderRejectsRegressingProofAndConfiguration(t *testing.T) {
	c := NewCorrelator(DefaultConfig(1))
	for _, cpus := range [][]uint32{nil, {0, 0}} {
		if err := c.Configure(correlationDomain, cpus, 4<<20); err == nil {
			t.Fatal("invalid topology")
		}
	}
	if err := c.Configure(correlationDomain, []uint32{0}, 4<<20); err != nil {
		t.Fatal(err)
	}
	if err := c.Configure(correlationDomain, []uint32{0}, 4<<20); err == nil {
		t.Fatal("configured twice")
	}
	if err := c.ReportProgress(0, 500); err != nil {
		t.Fatal(err)
	}
	if err := c.ReportProgress(0, 499); err == nil {
		t.Fatal("regressing proof")
	}
}

func TestReorderUnknownWakeTargetAndOversizedTopologyRefuse(t *testing.T) {
	c := configuredCorrelation(t, 0)
	wake := correlationWake(40)
	wake.Wakeup.TargetCPU = 1
	gaps, err := c.Consume(wake)
	if err == nil || len(gaps) != 1 || !gaps[0].Correction {
		t.Fatalf("guessed missing target CPU complete: %+v %v", gaps, err)
	}
	cpus := make([]uint32, 257)
	for i := range cpus {
		cpus[i] = uint32(i)
	}
	fresh := NewCorrelator(DefaultConfig(1))
	if err = fresh.Configure(correlationDomain, cpus, 4<<20); err == nil {
		t.Fatal("silently omitted over-budget CPUs")
	}
}
