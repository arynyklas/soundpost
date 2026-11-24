// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"sort"
	"sync"

	"github.com/arynyklas/soundpost/internal/model"
)

// The lifecycle evidence journal (error occurrences feeding the issue lifecycle)
// is retained for its declared period. Before unprocessed evidence expires, the
// lifecycle must commit a durable evidence gap (issues.RecordGap). If that gap
// cannot commit, the journal is HELD: nothing is erased (the retention worker
// already refuses to erase unprocessed lifecycle evidence that no gap covers) and
// further admissions of the same evidence are accepted only while the reserved
// capacity lasts. A hold is the declaration "this project's error journal cannot
// shed what it holds"; its reserve is the number of canonical batch bytes the
// journal may still grow by before it rejects new evidence (retryable
// unavailable, detail "journal_reserve") rather than discard anything silently.
//
// The hold is in-memory state of this node, set and cleared by the leader-only
// journal-expiry producer (appcore); a restart loses it, and the producer sets it
// again on its next pass if the gap still cannot commit.

// JournalReserveDetail is the SafeDetail of an admission rejected because the
// project's held journal has no reserve left.
const JournalReserveDetail = "journal_reserve"

type journalKey struct{ org, project model.ID }

type journalHold struct {
	reserve, used, denied uint64
}

type journalHolds struct {
	mu   sync.Mutex
	held map[journalKey]*journalHold
}

// JournalHold is the operator-visible state of one held journal.
type JournalHold struct {
	Org, Project model.ID
	// Reserve is the bytes the held journal may still grow by when the hold began;
	// Used is how many of them admissions have taken; Denied counts the batches
	// refused once the reserve was spent.
	Reserve, Used, Denied uint64
}

// HoldJournal declares the project's error-evidence journal held with a reserve
// of reserveBytes. It is idempotent: a second call keeps the reserve already in
// use (a hold that is renewed every pass must not refill its reserve).
func (e *Engine) HoldJournal(org, project model.ID, reserveBytes uint64) {
	h := &e.journal
	h.mu.Lock()
	defer h.mu.Unlock()
	key := journalKey{org, project}
	if h.held == nil {
		h.held = map[journalKey]*journalHold{}
	}
	if _, ok := h.held[key]; !ok {
		h.held[key] = &journalHold{reserve: reserveBytes}
	}
}

// ReleaseJournal ends the hold (the gap committed); it reports whether a hold
// existed.
func (e *Engine) ReleaseJournal(org, project model.ID) bool {
	h := &e.journal
	h.mu.Lock()
	defer h.mu.Unlock()
	key := journalKey{org, project}
	_, ok := h.held[key]
	delete(h.held, key)
	return ok
}

// JournalHolds lists the held journals, ordered by organization and project.
func (e *Engine) JournalHolds() []JournalHold {
	h := &e.journal
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]JournalHold, 0, len(h.held))
	for k, v := range h.held {
		out = append(out, JournalHold{Org: k.org, Project: k.project, Reserve: v.reserve, Used: v.used, Denied: v.denied})
	}
	sort.Slice(out, func(i, j int) bool {
		if c := bytes.Compare(out[i].Org[:], out[j].Org[:]); c != 0 {
			return c < 0
		}
		return bytes.Compare(out[i].Project[:], out[j].Project[:]) < 0
	})
	return out
}

// admitJournal is the admission gate of held evidence. A batch with no error
// occurrence, and a batch of a project whose journal is not held, is never
// affected. A batch that carries error evidence consumes its canonical bytes from
// the reserve and is rejected, unchanged and retryable, when they do not fit.
func (e *Engine) admitJournal(org, project model.ID, records []model.Record, size uint64) error {
	h := &e.journal
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.held) == 0 {
		return nil
	}
	hold, ok := h.held[journalKey{org, project}]
	if !ok {
		return nil
	}
	evidence := false
	for _, r := range records {
		if r.Kind == model.ErrorKind {
			evidence = true
			break
		}
	}
	if !evidence {
		return nil
	}
	if hold.used+size > hold.reserve {
		hold.denied++
		f := model.Fail(model.Unavailable)
		f.Retryable, f.SafeDetail = true, JournalReserveDetail
		return f
	}
	hold.used += size
	return nil
}

var errorKindJSON = []byte(`"` + model.ErrorKind + `"`)

// ExpiringEntry is one error occurrence of the journal whose receipt deadline is
// at or before a horizon: where it sits in its data group (the origin cursor of
// its batch), its receipt deadline and its signal time.
type ExpiringEntry struct {
	Org, Project model.ID
	Cursor       model.Cursor
	Deadline     model.UnixNano
	At           model.UnixNano
}

// ExpiringErrorEvidence lists, without erasing or changing anything, the error
// occurrences whose receipt deadline is at or before horizon, in no particular
// order (one entry per record). It reads the retained commands the expiry pass
// reads and asks no guard: the caller decides what is unprocessed. A command
// is read once, however many plans are made (expiry_scan.go).
func (e *Engine) ExpiringErrorEvidence(ctx context.Context, horizon model.UnixNano) ([]ExpiringEntry, error) {
	return e.expiry.entries(ctx, e, horizon)
}
