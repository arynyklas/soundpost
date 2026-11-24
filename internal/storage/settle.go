// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// SettleBooks is what a settlement pass asks control about the windows it settled so far (control.Store
// implements it): the records stored under keys (model.SettledKey), those that exist.
type SettleBooks interface {
	SettledWindows(ctx context.Context, keys []string) (map[string]model.SettledWindow, error)
}

// settleState is what the settlement pass remembers between passes. A pass lists the windows of 64 slots; a
// window below the floor of its slot is settled (or carries no batch) and is not read again, and the parts
// of the open window are derived once, from the commands they cover, not at every pass. Both are only
// accelerations: a process that starts with none of it derives them again.
type settleState struct {
	mu    sync.Mutex
	floor [64]uint64
	tail  [64]tailParts
}

// tailParts are the complete parts of the open window of a slot, derived so far.
type tailParts struct {
	n     uint64 // window number
	first uint64 // index of its first command
	done  uint64 // parts derived: the commands of parts 0..done-1 were read
	parts []windowPart
}

// SettleCandidates lists the windows of every data group whose consumed reservations control may fold into
// a settled window (control.Store.SettleAdmissions) without asking what control settled already: every full
// window that carries batches and no redacted batch, with the digest of the reservations its batches
// consumed, and the complete parts of every open window. A window the engine has not derived yet is
// derived here and persisted (one pass over its commands, the same work the next snapshot cut would do).
func (e *Engine) SettleCandidates(ctx context.Context) ([]model.SettleCandidate, error) {
	return e.SettleCandidatesFor(ctx, nil)
}

// SettleCandidatesFor is SettleCandidates for a pass that asks control (books) which of the windows it
// settled: those are left out, and so are the parts of an open window that control settled, which keeps a
// pass proportional to what is not settled yet, not to the history. With nil books everything is offered.
func (e *Engine) SettleCandidatesFor(ctx context.Context, books SettleBooks) ([]model.SettleCandidate, error) {
	s := &e.settle
	s.mu.Lock()
	defer s.mu.Unlock()
	type slotWindows struct {
		sealed []windowRecord
		app    uint64
		from   uint64
	}
	var slots [64]slotWindows
	e.mu.Lock()
	if e.closed || e.failed {
		e.mu.Unlock()
		return nil, model.Fail(model.Unavailable)
	}
	if e.repl == nil {
		e.mu.Unlock()
		return nil, nil // not replicated: no windows, nothing to settle (the worker asks on every pass)
	}
	span := snapshotWindow
	for slot := range uint16(64) {
		slots[slot].app = e.indexes[slot]
		if books != nil {
			slots[slot].from = s.floor[slot]
		}
	}
	e.mu.Unlock()
	// A window the engine has not derived yet is derived here, which decodes every command in it (a second of
	// CPU for 4,096 commands of 10 KB). The 64 slots of a node are loaded alike and seal their first window
	// together, so this pass found 64 of them to derive: it did so under the engine lock, the lock every append
	// of every slot takes, and the acknowledgements stopped for the minute that took (the collapse at 820 s of
	// the single-host load, L2w20Admission21). The commands of an applied window never change except by
	// erasure, which takes cutMu exclusively (as for a snapshot cut, windowTableForCut): the derivation holds it
	// shared, per slot, and no engine lock.
	for slot := range uint16(64) {
		if err := ctx.Err(); err != nil {
			return nil, model.Fail(model.Cancelled)
		}
		sw := &slots[slot]
		e.cutMu.RLock()
		table, err := e.windowTableOf(slot, sw.app, true, true, sw.from)
		e.cutMu.RUnlock()
		if err != nil {
			return nil, err
		}
		sw.sealed = table
	}

	part := e.windowPartSpan(span)
	var keys []string
	for slot := range uint16(64) {
		group := e.group(uint16(slot))
		for _, w := range slots[slot].sealed {
			if w.Batches != 0 {
				keys = append(keys, model.SettledKey(group, w.N))
			}
		}
		if open, ok := openWindow(slots[slot].app, span); ok && part != 0 {
			keys = append(keys, model.SettledKey(group, open.n))
		}
	}
	var settled map[string]model.SettledWindow
	if books != nil && len(keys) != 0 {
		var err error
		if settled, err = books.SettledWindows(ctx, keys); err != nil {
			return nil, err
		}
	}

	var out []model.SettleCandidate
	for slot := range uint16(64) {
		if err := ctx.Err(); err != nil {
			return nil, model.Fail(model.Cancelled)
		}
		group := e.group(uint16(slot))
		sw := &slots[slot]
		floor, below := sw.from, true
		for _, w := range sw.sealed {
			key := model.SettledKey(group, w.N)
			done := w.Batches == 0
			if rec, ok := settled[key]; ok && rec.Complete() {
				done = true
			}
			if below && done {
				floor = w.N + 1
			} else {
				below = false
			}
			if done || w.Count != span || w.Redacted != 0 {
				continue
			}
			c := model.SettleCandidate{Group: group, N: w.N, Span: span, Batches: w.Batches, Charge: w.Charge}
			if part != 0 && len(w.Parts) != 0 {
				c.Part = part
				for _, p := range w.Parts {
					c.Parts = append(c.Parts, model.SettlePart{J: p.J, Batches: p.Batches, Charge: p.Charge})
				}
			}
			out = append(out, c)
		}
		if books != nil {
			s.floor[slot] = floor
		}
		if part == 0 {
			continue
		}
		open, ok := openWindow(sw.app, span)
		if !ok {
			continue
		}
		parts, err := e.tailPartsOf(uint16(slot), open, sw.app, part)
		if err != nil {
			return nil, err
		}
		have := settled[model.SettledKey(group, open.n)]
		c := model.SettleCandidate{Group: group, N: open.n, Span: span, Part: part, Open: true}
		for _, p := range parts {
			if p.Redacted != 0 {
				continue
			}
			if _, done := have.Settled(p.J); done && !have.Complete() {
				continue
			}
			c.Parts = append(c.Parts, model.SettlePart{J: p.J, Batches: p.Batches, Charge: p.Charge})
		}
		if len(c.Parts) != 0 {
			out = append(out, c)
		}
	}
	return out, nil
}

// openWindowOf is the open window of a slot that applied app commands: the window the next command falls
// into, when some of its commands are applied already.
type openWindowOf struct {
	n     uint64
	first uint64
}

func openWindow(app, span uint64) (openWindowOf, bool) {
	if app == 0 || app%span == 0 {
		return openWindowOf{}, false
	}
	n := app / span
	return openWindowOf{n: n, first: n*span + 1}, true
}

// tailPartsOf returns the complete parts that carry batches of the open window of slot, deriving the parts
// the cache does not hold from the commands they cover (a part is read once, outside any read transaction:
// fetchedCommands). The caller holds settle.mu and not e.mu: a command that physical erasure rewrites
// meanwhile keeps the digest of its part (the digest is the one of the original reservations).
func (e *Engine) tailPartsOf(slot uint16, open openWindowOf, app, part uint64) ([]windowPart, error) {
	t := &e.settle.tail[slot]
	complete := (app - open.first + 1) / part
	if t.n != open.n || t.first != open.first || t.done > complete {
		*t = tailParts{n: open.n, first: open.first}
	}
	src := e.fetchedCommands(slot)
	for j := t.done; j < complete; j++ {
		p, err := derivePart(src, open.first, part, uint32(j))
		if err != nil {
			return nil, err
		}
		if p.Batches != 0 {
			t.parts = append(t.parts, p)
		}
		t.done = j + 1
	}
	return t.parts, nil
}

// derivePart derives part j of the window that starts at first from the stored commands.
func derivePart(src commandSource, first, part uint64, j uint32) (windowPart, error) {
	p := windowPart{J: j}
	var run []ReservationEvidence
	start := first + uint64(j)*part
	err := src(start, part, func(index uint64, raw []byte) error {
		var entry walEntry
		if json.Unmarshal(raw, &entry) != nil {
			return model.Fail(model.Corrupt)
		}
		if entry.Type != "batch" && entry.Type != "batch_redacted" {
			return nil
		}
		ev, err := batchEvidence(entry)
		if err != nil {
			return err
		}
		if uint64(ev.Cursor.Index) != index {
			return model.Fail(model.Corrupt)
		}
		run = append(run, ev)
		p.Batches++
		if ev.Redacted {
			p.Redacted++
		}
		return nil
	})
	if err != nil {
		return p, err
	}
	if len(run) != 0 {
		p.Charge = chargeDigest(run)
	}
	return p, nil
}

// AdmittedBatch reports whether the data holds the batch the reservation names and returns the
// receipt it stored for it. Control asks it for a retry whose reservation it settled (no row
// answers it any more); the answer is read after the slot's read fence, like a receipt lookup.
func (e *Engine) AdmittedBatch(ctx context.Context, r model.AdmissionReservation) (model.Receipt, bool, error) {
	if err := e.replicaBeforeWrite(ctx, r.Slot); err != nil {
		return model.Receipt{}, false, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return model.Receipt{}, false, model.Fail(model.Unavailable)
	}
	var out model.Receipt
	found := false
	err := e.db.View(func(tx *bolt.Tx) error {
		raw, err := tableGet(tx, tblReceipts, batchKey(r.Org, r.Project, r.Source, r.Producer, r.Slot, r.Batch))
		if err != nil {
			return err
		}
		if raw == nil {
			return nil
		}
		if json.Unmarshal(raw, &out) != nil {
			return model.Fail(model.Corrupt)
		}
		found = true
		return nil
	})
	return out, found, err
}
