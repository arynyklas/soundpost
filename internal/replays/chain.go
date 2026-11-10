// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replays

import (
	"slices"
	"soundpost/internal/model"
)

// ChunkHash is the chain hash of a chunk: SHA-256 over its canonical JSON
// (sorted keys, no insignificant whitespace) exactly as sent.
func ChunkHash(c model.ReplayChunk) (model.Hash, error) {
	raw, err := model.CanonicalJSON(c)
	if err != nil {
		return model.Hash{}, model.Fail(model.Invalid)
	}
	return model.HashCanonical(raw), nil
}

// chunkMeta is everything the planner needs from a stored chunk. No node, event
// or text survives into it, so a plan is O(chunks) small records.
type chunkMeta struct {
	seq, cp        uint64
	hash, previous model.Hash
	cpHash         model.Hash
	gap            bool
	invalid        bool // failed closed-format validation when read back
	unsupported    bool // recorder version this server cannot reconstruct
	conflict       bool // two different chunks claim the sequence, or a foreign session
	wall           model.UnixNano
	session        model.ID
	clock          model.TraceClock
	policy         model.Revision
	loss           uint64
}

func (m chunkMeta) isCheckpoint() bool { return m.cp == m.seq }

// step is one planned event. Chunk-bearing steps are fetched at release.
type step struct {
	kind    EventKind
	seq     uint64
	through uint64
	reason  string
}

// plan walks sequences 1..max once and emits what may be released. Continuity
// is only ever proven by an unbroken verified hash chain from a verified
// checkpoint; every other chunk (including a staged future one) becomes part of
// a gap that ends at the next accepted checkpoint.
func plan(metas map[uint64]*chunkMeta, max uint64, indexed map[uint64]model.Hash) []step {
	var out []step
	var gap *step
	closeGap := func() {
		if gap != nil {
			out = append(out, *gap)
			gap = nil
		}
	}
	openGap := func(seq uint64, reason string) {
		if gap == nil {
			gap = &step{kind: EventGap, seq: seq, through: seq, reason: reason}
			return
		}
		gap.through = seq
	}
	var (
		have     bool
		lastHash model.Hash
		cpSeq    uint64
		cpHash   model.Hash
	)
	for s := uint64(1); s <= max; s++ {
		m, ok := metas[s]
		switch {
		case !ok:
			openGap(s, ReasonMissingChunk)
			have = false
			continue
		case m.conflict:
			openGap(s, ReasonConflictingChunk)
			have = false
			continue
		case m.invalid:
			openGap(s, ReasonInvalidChunk)
			have = false
			continue
		case m.unsupported:
			closeGap()
			out = append(out, step{kind: EventUnsupported, seq: s, through: s, reason: ReasonRecorderVersion})
			have = false
			continue
		}
		if want, pinned := indexed[s]; pinned && want != m.hash {
			openGap(s, ReasonIndexMismatch)
			have = false
			continue
		}
		if m.isCheckpoint() {
			// A checkpoint is self-contained, but it still may not contradict the
			// chunk before it when that chunk is present and trusted.
			if prev, ok := metas[s-1]; s > 1 && ok && !prev.conflict && !prev.invalid && !prev.unsupported && prev.hash != m.previous {
				openGap(s, ReasonHashMismatch)
				have = false
				continue
			}
			closeGap()
			if m.gap {
				out = append(out, step{kind: EventGap, seq: s, through: s, reason: ReasonRecorderGap})
			}
			out = append(out, step{kind: EventCheckpoint, seq: s, through: s})
			have, lastHash, cpSeq, cpHash = true, m.hash, s, m.hash
			continue
		}
		switch {
		case m.gap:
			openGap(s, ReasonRecorderGap)
			have = false
		case !have:
			openGap(s, ReasonNoCheckpoint)
		case m.previous != lastHash:
			openGap(s, ReasonHashMismatch)
			have = false
		case m.cp != cpSeq || m.cpHash != cpHash:
			openGap(s, ReasonDependencyMismatch)
			have = false
		default:
			out = append(out, step{kind: EventDelta, seq: s, through: s})
			lastHash = m.hash
		}
	}
	closeGap()
	return out
}

// windowSteps clips a plan to w. A delta that opens the window snaps back to the
// checkpoint it depends on and every verified step since, so a reader never
// receives a delta without its base or with a hole before it.
func windowSteps(steps []step, metas map[uint64]*chunkMeta, w ReplayWindow) []step {
	from, to := w.From, w.To
	if from == 0 {
		from = 1
	}
	if to == 0 {
		to = MaxSequence
	}
	var out []step
	for i, st := range steps {
		if st.through < from || st.seq > to {
			continue
		}
		if len(out) == 0 && st.kind == EventDelta {
			if dep := metas[st.seq].cp; dep < from {
				if j := slices.IndexFunc(steps[:i], func(x step) bool { return x.kind == EventCheckpoint && x.seq == dep }); j >= 0 {
					out = append(out, steps[j:i]...)
				}
			}
		}
		out = append(out, st)
	}
	return out
}
