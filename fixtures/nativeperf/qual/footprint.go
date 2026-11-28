// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"unsafe"

	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// The memory a consumer of a capture holds is part of the aggregate budget: the harness retains every event it
// decodes (it replays them through the correlator and the row judges afterwards) and keeps the intervals the
// correlator returns. These functions count that retained memory from the struct sizes: every allocation rounded up
// to the 16-byte malloc granule, strings and slices by their length. They are arithmetic, not a measurement; the
// ledger's physical column (resident high-water marks) is the measurement they are checked against.

func alloc(n uintptr) uint64 { return uint64(n+15) &^ 15 }

// EventFootprint is the heap bytes one retained event holds beyond its slot in the retaining slice: the variant
// payload it points at, the callchains, the task identities and every identity string.
func EventFootprint(e nativeperf.SanitizedEvent) uint64 {
	n := uint64(len(e.Domain.HostID)+len(e.Domain.BootID)) + uint64(len(e.Task.BootID))
	switch {
	case e.CPUEvent != nil:
		n += alloc(unsafe.Sizeof(*e.CPUEvent)) + alloc(uintptr(len(e.CPUEvent.Callchain))*unsafe.Sizeof(nativeperf.CallchainEntry{}))
		if e.CPUEvent.Throttle != nil {
			n += alloc(unsafe.Sizeof(*e.CPUEvent.Throttle))
		}
	case e.Switch != nil:
		n += alloc(unsafe.Sizeof(*e.Switch)) + alloc(uintptr(len(e.Switch.SwitchOutCallchain))*unsafe.Sizeof(nativeperf.CallchainEntry{}))
		for _, t := range []*nativeperf.TaskKey{e.Switch.Previous, e.Switch.Next} {
			if t != nil {
				n += alloc(unsafe.Sizeof(*t)) + uint64(len(t.BootID))
			}
		}
	case e.Wakeup != nil:
		n += alloc(unsafe.Sizeof(*e.Wakeup)) + uint64(len(e.Wakeup.Target.BootID))
	case e.Mapping != nil:
		n += alloc(unsafe.Sizeof(*e.Mapping)) + uint64(len(e.Mapping.BuildID))
	case e.Loss != nil:
		n += alloc(unsafe.Sizeof(*e.Loss))
		if e.Loss.Throttle != nil {
			n += alloc(unsafe.Sizeof(*e.Loss.Throttle))
		}
	case e.Generation != nil:
		n += alloc(unsafe.Sizeof(*e.Generation))
	}
	return n
}

// EventsFootprint is the retained memory of a slice of events: its backing array (the capacity, not the length)
// plus the heap each event holds.
func EventsFootprint(events []nativeperf.SanitizedEvent) uint64 {
	n := alloc(uintptr(cap(events)) * unsafe.Sizeof(nativeperf.SanitizedEvent{}))
	for i := range events {
		n += EventFootprint(events[i])
	}
	return n
}

// IntervalsFootprint is the retained memory of the intervals a correlator returned: the backing array of the slice
// plus each interval's switch-out callchain and identity strings.
func IntervalsFootprint(intervals []nativeperf.Interval) uint64 {
	n := alloc(uintptr(cap(intervals)) * unsafe.Sizeof(nativeperf.Interval{}))
	for i := range intervals {
		iv := &intervals[i]
		n += uint64(len(iv.Task.BootID)+len(iv.Domain.HostID)+len(iv.Domain.BootID)) + alloc(uintptr(len(iv.SwitchOutCallchain))*unsafe.Sizeof(nativeperf.CallchainEntry{}))
	}
	return n
}
