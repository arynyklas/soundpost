//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"encoding/hex"
	"sort"

	"github.com/arynyklas/soundpost/internal/model"
)

// Mapping-epoch sideband (04.06). The CPU events ask the kernel for PERF_RECORD_MMAP2 of executable mappings
// (attr.mmap, attr.mmap2, attr.build_id; never mmap_data). A record carries the mapped address range, the file offset,
// the GNU build ID the kernel read from the mapped object (or device/inode numbers when it could not), the protection
// and the mapped file's PATH. The path is the private part: it stays in the kernel ring, where COMM names already are,
// and this decoder reads only fixed numeric offsets. It never copies, formats, logs or hashes the name bytes, and
// device/inode numbers are used only to tell anonymous memory from a file. A build ID leaves this file only when the
// operator's policy approved it (Target.AllowedBuildIDs); any other mapping is announced without identity, as the
// closed reason it falls under, so that it still supersedes what it replaced.
const (
	perfRecordMmap2     = 10
	perfMiscCPUModeMask = 7
	perfMiscUser        = 2
	perfMiscMmapBuildID = 1 << 14
	protExec            = 4
)

// mmap2 layout (little endian): header 8, pid 4, tid 4, addr 8, len 8, pgoff 8, then either build_id_size 1, two
// reserved bytes, a reserved byte and the 20-byte build ID, or maj 4, min 4, ino 8, ino_generation 8; prot 4, flags 4,
// the file name (NUL terminated, padded to 8) and the sample_id trailer for TID|TIME|CPU (pid 4, tid 4, time 8, cpu 4,
// reserved 4). The trailer is addressed from the end, so the name's length never matters.
const (
	mmap2FixedBytes   = 72
	mmap2MinBytes     = mmap2FixedBytes + 8 + 24
	mmap2MaxBytes     = 8192
	sidebandSweepMax  = 4096
	mmap2BuildIDBytes = 20
)

func processOf(t TaskKey) ProcessKey {
	return ProcessKey{BootID: t.BootID, PIDNamespace: t.PIDNamespace, TGID: t.TGID, ProcessStart: t.ProcessStart, Generation: t.Generation}
}

func (r *Ring) approvedBuild(id string) bool {
	for _, b := range r.builds {
		if b == id {
			return true
		}
	}
	return false
}

// decodeMmap2 turns one PERF_RECORD_MMAP2 of the ring's own thread into a mapping event. A non-executable mapping
// yields no event.
func decodeMmap2(v KernelRecordView, r *Ring) (SanitizedEvent, bool, error) {
	size := v.len()
	if !v.valid() || v.u32(0) != perfRecordMmap2 || size < mmap2MinBytes || size > mmap2MaxBytes || size%8 != 0 || v.u16(4)&perfMiscCPUModeMask != perfMiscUser {
		return SanitizedEvent{}, false, ErrRingMalformed
	}
	pid, tid := v.u32(8), v.u32(12)
	if pid != r.task.TGID || tid != r.task.TID {
		return SanitizedEvent{}, false, ErrTargetIdentity
	}
	if v.u32(size-24) != pid || v.u32(size-20) != tid {
		return SanitizedEvent{}, false, ErrRingMalformed
	}
	at, cpu := v.u64(size-16), v.u32(size-8)
	start, length, pgoff := v.u64(16), v.u64(24), v.u64(32)
	if at == 0 || length == 0 || start == 0 || start > userSpaceEnd || length > userSpaceEnd-start || pgoff > ^uint64(0)-length {
		return SanitizedEvent{}, false, ErrRingMalformed
	}
	if v.u32(64)&protExec == 0 {
		return SanitizedEvent{}, false, nil
	}
	update := MappingUpdate{Process: processOf(r.task), Start: model.Uint64(start), End: model.Uint64(start + length)}
	switch {
	case v.u16(4)&perfMiscMmapBuildID != 0:
		n := int(v.byteAt(40))
		if n < 1 || n > mmap2BuildIDBytes {
			return SanitizedEvent{}, false, ErrRingMalformed
		}
		raw := make([]byte, n)
		for i := range raw {
			raw[i] = v.byteAt(44 + i)
		}
		if id := hex.EncodeToString(raw); r.approvedBuild(id) {
			update.BuildID, update.FileOffset = id, model.Uint64(pgoff)
		} else {
			update.Reason = FrameUnapproved
		}
	case v.u32(40) == 0 && v.u32(44) == 0 && v.u64(48) == 0:
		// no device and no inode: anonymous memory, where a JIT keeps its code
		update.Reason = FrameJITMissing
	default:
		// a file the kernel could not read a build ID from: the identity is unknown, so it is not approved
		update.Reason = FrameUnapproved
	}
	return SanitizedEvent{Kind: EventMapping, Time: model.MonoNano(at), CPU: cpu, Mapping: &update}, true, nil
}

// sidebandTaken reports whether the record being consumed (at ring offset r.at, set by consume) was already handed out
// by sweepSideband; otherwise it marks it handed out. Only mapping announcements and ring overflows are swept.
func (r *Ring) sidebandTaken(v KernelRecordView) bool {
	if t := v.u32(0); t != perfRecordMmap2 && t != perfRecordLost {
		return false
	}
	if r.at < r.sideTaken {
		return true
	}
	r.sideTaken = r.at + uint64(v.len())
	return false
}

// sweepSideband hands out every mapping announcement and ring overflow that is already written to the ring but not yet
// consumed, without consuming anything: the records stay in the ring in order and are skipped when consume reaches
// them. A consumer that sweeps before it publishes a sample therefore holds every announcement the kernel had written
// before that sample's record, whichever thread's ring it sits in. emit may return errSweepFull to stop; the records
// not yet handed out are then dropped (the caller reports the overflow).
func (r *Ring) sweepSideband(emit func(KernelRecordView) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrAcquisitionClosed
	}
	if len(r.meta) < 1040 || len(r.data) == 0 {
		return ErrRingMalformed
	}
	head, tail := r.head(), r.tail()
	if head-tail > uint64(len(r.data)) {
		return ErrRingOverwrite
	}
	at := max(r.sideTaken, tail)
	for at < head {
		view, size, e := r.viewAt(at, head)
		if e != nil {
			return e
		}
		if t := view.u32(0); t == perfRecordMmap2 || t == perfRecordLost {
			r.at = at
			r.sideTaken = at + uint64(size)
			if e = emit(view); e != nil {
				r.sideTaken = head
				return e
			}
		}
		at += uint64(size)
	}
	r.sideTaken = max(r.sideTaken, head)
	return nil
}

type sweepFull struct{}

func (sweepFull) Error() string { return "native profiling: sideband sweep bound reached" }

var errSweepFull error = sweepFull{}

// sweepRings sweeps every ring and returns the events, oldest first. full reports that sidebandSweepMax was reached:
// the rest was dropped and the consumer owes a loss event.
func sweepRings(rings []*Ring, domain ClockDomain) (events []SanitizedEvent, full bool, err error) {
	for _, ring := range rings {
		e := ring.sweepSideband(func(v KernelRecordView) error {
			event, ok, err := decodeCPURecord(v, ring)
			if err != nil {
				return err
			}
			if !ok {
				return nil
			}
			if len(events) >= sidebandSweepMax {
				return errSweepFull
			}
			event.Domain = domain
			events = append(events, event)
			return nil
		})
		switch e {
		case nil:
		case errSweepFull:
			full = true
		default:
			return nil, false, e
		}
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].Time < events[j].Time })
	return events, full, nil
}

// approvedBuilds are the GNU build IDs the operator approved for the target process tgid.
func (a AuthorizedTargets) approvedBuilds(tgid uint32) []string {
	for _, t := range a.targets {
		if t.TGID == tgid {
			return append([]string(nil), t.AllowedBuildIDs...)
		}
	}
	return nil
}

// sidebandSweeper is what ProfileSource asks of the acquisition it wraps: every mapping announcement already written
// to any ring, so that none can still sit behind a sample it is about to publish.
type sidebandSweeper interface {
	sweepSideband() ([]SanitizedEvent, bool, error)
}

func (s *cpuSource) sweepSideband() ([]SanitizedEvent, bool, error) {
	s.nextMu.Lock()
	defer s.nextMu.Unlock()
	if s.terminal != nil {
		return nil, false, s.terminal
	}
	select {
	case <-s.done:
		return nil, false, ErrAcquisitionClosed
	default:
	}
	return sweepRings(s.rings, s.domain)
}

func (s *schedulerSource) sweepSideband() ([]SanitizedEvent, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminal != nil {
		return nil, false, s.terminal
	}
	select {
	case <-s.done:
		return nil, false, ErrAcquisitionClosed
	default:
	}
	return sweepRings(s.cpu.rings, s.cpu.domain)
}
