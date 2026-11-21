//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"os"
	"testing"
	"time"
)

// 04.02-C16 mutation battery re-run (mut0402, G063): every task an event names is vouched for, not only the one a switch
// goes to. Either side of a switch that has exited refuses the event, whichever side it is.
func TestSchedulerPublishVouchesForBothSidesOfASwitch(t *testing.T) {
	target, err := ResolveLocalTarget(os.Getpid())
	if err != nil {
		t.Skip("local target unresolved")
	}
	a := AuthorizedTargets{targets: []Target{target}, mode: ModeCPUOffCPU}
	threads, err := snapshotCPUThreads(a, correlationDomain)
	if err != nil || len(threads) == 0 {
		t.Skip("no thread snapshot")
	}
	prev, next := threads[0].task, threads[0].task
	next.TID++
	for _, tc := range []struct {
		name               string
		prevGone, nextGone bool
		refused            bool
	}{
		{"both live", false, false, false},
		{"the task switched out has exited", true, false, true},
		{"the task switched in has exited", false, true, true},
		{"both have exited", true, true, true},
	} {
		asked := map[TaskKey]int{}
		cpu := &cpuSource{targets: a, threads: threads, domain: correlationDomain, lastCheck: time.Now(), gone: func(k TaskKey) (bool, error) {
			asked[k]++
			return k == prev && tc.prevGone || k == next && tc.nextGone, nil
		}}
		s := &schedulerSource{done: make(chan struct{}), cpus: []uint32{0}, cpu: cpu}
		ev := SanitizedEvent{Kind: EventSwitch, Switch: &SchedulerSwitch{Previous: &prev, Next: &next, PreviousState: 1, MissingCallchain: ReasonMissingSwitchCallchain}}
		item, e := s.publish(ev)
		switch {
		case tc.refused && (!errors.Is(e, ErrThreadCoverageChanged) || item.Event != nil || s.terminal == nil):
			t.Errorf("%s: published %+v %v", tc.name, item, e)
		case !tc.refused && (e != nil || item.Event == nil):
			t.Errorf("%s: refused %v", tc.name, e)
		}
		if !tc.refused && (asked[prev] != 1 || asked[next] != 1) {
			t.Errorf("%s: asked %v, want each named task once", tc.name, asked)
		}
	}
}
