// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"soundpost/internal/model"
)

// Read acquires the next range of a source and returns its admissible log
// records and the checkpoint that DESCRIBES that range.
//
// Read never advances the committed position: the returned checkpoint keeps
// cp.Position and carries the range as Pending (positions, counts and reason
// counters; no source content). The position only moves in
// Checkpoint.Acknowledge / Store.Commit, with the receipts of the batches built
// from the records. If cp already carries a Pending range (a lost acknowledgement
// or a restart), Read rebuilds exactly that range: the same records, so the same
// record and batch identifiers, and later lines are not folded into it.
//
// Every message is matched against the registered templates of the policy. A
// message matching none is counted by reason and dropped; its bytes live only in
// bounded buffers that are zeroed before Read returns.
func Read(ctx context.Context, p SourcePolicy, cp Checkpoint) ([]model.LogRecord, Checkpoint, error) {
	if err := p.Validate(); err != nil {
		return nil, cp, err
	}
	if cp.Source == "" {
		cp.Source = p.Name
	}
	if cp.Version == 0 {
		cp.Version = 1
	}
	if cp.Source != p.Name {
		return nil, cp, newError(p.Name, StatusUnknown, ReasonCheckpointState)
	}
	if p.Raw != nil && int64(p.Raw.Expires) <= p.now().UnixNano() {
		return nil, cp, newError(p.Name, StatusDenied, ReasonRawExpired)
	}
	if err := ctx.Err(); err != nil {
		return nil, cp, newError(p.Name, StatusUnknown, ReasonCancelled)
	}
	templates, err := compileTemplates(p)
	if err != nil {
		return nil, cp, err
	}
	limit := p.maxRecords()
	pending := cp.Pending
	if pending != nil {
		limit = int(pending.Scanned)
	}
	acq, err := acquire(ctx, p, cp, limit)
	if err != nil {
		return nil, cp, err
	}
	at := model.UnixNano(p.now().UnixNano())
	if pending != nil {
		at = pending.At
	}
	records, dropped := classifyEntries(p, templates, acq.entries, time.Unix(0, int64(at)).In(p.now().Location()))
	for k, v := range acq.dropped {
		dropped[k] += v
	}
	next := cp
	next.Pending = nil
	if pending != nil {
		if reproduces(pending, acq, records, dropped) {
			next.Pending = pending
			return records, next, nil
		}
		// The source no longer yields the recorded range (it was not
		// append-only). A new range replaces the intent explicitly and the
		// rebuild is counted, never hidden.
		dropped[DropRebuilt]++
	}
	if acq.scanned == 0 && len(acq.gaps) == 0 && acq.to == cp.Position {
		return nil, next, nil
	}
	group := model.NewID()
	next.Pending = &Pending{Group: group, At: at, To: acq.to, Scanned: acq.scanned, Records: uint32(len(records)), Gaps: acq.gaps}
	if len(dropped) > 0 {
		next.Pending.Dropped = dropped
	}
	if pending != nil {
		old := pending.Group
		next.Pending.Supersedes = &old
	}
	return records, next, nil
}

// DropRebuilt counts a pending range that the source no longer reproduced.
const DropRebuilt = "pending_rebuilt"

func reproduces(p *Pending, acq acquired, records []model.LogRecord, dropped map[string]uint64) bool {
	if p.To != acq.to || p.Scanned != acq.scanned || int(p.Records) != len(records) || len(p.Gaps) != len(acq.gaps) {
		return false
	}
	if len(p.Dropped) != len(dropped) {
		return false
	}
	for k, v := range p.Dropped {
		if dropped[k] != v {
			return false
		}
	}
	return true
}

func acquire(ctx context.Context, p SourcePolicy, cp Checkpoint, limit int) (acquired, error) {
	switch p.Kind {
	case KindFile:
		return acquireFile(ctx, p, p.File.Path, p.File.Rotated, p.File.StartAt, cp, limit)
	case KindSyslog:
		return acquireFile(ctx, p, p.Syslog.Path, p.Syslog.Rotated, p.Syslog.StartAt, cp, limit)
	case KindJournal:
		return acquireJournal(ctx, p, cp, limit)
	}
	return acquired{}, newError(p.Name, StatusUnknown, ReasonInvalidPolicy)
}

// classifyEntries applies framing, the tag allowlist and the template match to
// every acquired entry and zeroes the entry bytes. The returned records hold
// typed approved fields only.
func classifyEntries(p SourcePolicy, templates []compiledTemplate, entries []entry, now time.Time) ([]model.LogRecord, map[string]uint64) {
	dropped := map[string]uint64{}
	mp := p.modelPolicy()
	var records []model.LogRecord
	for i := range entries {
		e := &entries[i]
		msg, ts, tag, reason := frame(p, e, now)
		if reason == "" && p.Kind == KindSyslog && !containsString(p.Syslog.Tags, tag) {
			reason = DropUnapprovedSource
		}
		if reason == "" {
			var rec model.LogRecord
			if rec, reason = p.classify(templates, msg, ts, mp); reason == "" {
				records = append(records, rec)
			}
		}
		if reason != "" {
			dropped[reason]++
		}
		clear(e.msg)
		e.msg = nil
	}
	return records, dropped
}

// frame extracts the message, its source time and tag from one entry.
func frame(p SourcePolicy, e *entry, now time.Time) (msg []byte, ts model.UnixNano, tag, reason string) {
	switch p.Kind {
	case KindSyslog:
		t, m, at, ok := parseSyslog(e.msg, now)
		if !ok {
			return nil, 0, "", DropBadFrame
		}
		return m, at, t, ""
	case KindFile:
		if p.File.TimeLayout == "" {
			return e.msg, 0, "", ""
		}
		words := bytes.Count([]byte(p.File.TimeLayout), []byte(" ")) + 1
		parts := bytes.SplitN(e.msg, []byte(" "), words+1)
		if len(parts) != words+1 {
			return nil, 0, "", DropBadTimestamp
		}
		t, err := time.Parse(p.File.TimeLayout, string(bytes.Join(parts[:words], []byte(" "))))
		if err != nil {
			return nil, 0, "", DropBadTimestamp
		}
		return parts[words], model.UnixNano(t.UnixNano()), "", ""
	}
	return e.msg, e.at, e.tag, ""
}

// Identity binds a source to the installation: the organization, project and
// source of the grant, and the stable producer and per-process epoch of this
// agent. It carries no credential.
type Identity struct {
	Org, Project, Source, Producer, Epoch model.ID
}

// BuildBatches builds the deterministic batches of the pending range of cp:
// record and batch identifiers derive from the range, observed times from the
// source (or the recorded range time), so rebuilding after a lost
// acknowledgement yields byte-identical batches and the server deduplicates.
func BuildBatches(id Identity, p SourcePolicy, cp Checkpoint, recs []model.LogRecord) ([]model.Batch, error) {
	pend := cp.Pending
	if pend == nil || int(pend.Records) != len(recs) {
		return nil, newError(p.Name, StatusUnknown, ReasonCheckpointState)
	}
	var out []model.Batch
	if len(recs) > 0 {
		records := make([]model.Record, len(recs))
		for i := range recs {
			rc := recs[i]
			at := pend.At
			if rc.Timestamp != nil {
				at = *rc.Timestamp
			}
			records[i] = model.Record{ID: RecordID(pend.Group, PartLogs, i), Kind: model.Log, ObservedAt: at, Resource: p.Resource, Payload: model.Payload{Log: &rc}}
		}
		b, err := batchOf(id, p, BatchID(pend.Group, PartLogs), records)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	if len(pend.Gaps) > 0 {
		records := make([]model.Record, len(pend.Gaps))
		for i, g := range pend.Gaps {
			loss := &model.LossReport{Source: id.Source, Producer: id.Producer, Epoch: id.Epoch, Start: g.Start, End: g.End, Signal: model.Log, Reason: g.Reason, Count: model.Uint64(g.Count)}
			records[i] = model.Record{ID: RecordID(pend.Group, PartLoss, i), Kind: model.Loss, ObservedAt: g.End, Resource: p.Resource, Payload: model.Payload{Loss: loss}}
		}
		b, err := batchOf(id, p, BatchID(pend.Group, PartLoss), records)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

func batchOf(id Identity, p SourcePolicy, batch model.ID, records []model.Record) (model.Batch, error) {
	slot, err := model.OwnerSlot(id.Org, id.Project, id.Source, id.Producer, records[0])
	if err != nil {
		return model.Batch{}, newError(p.Name, StatusUnknown, ReasonInvalidPolicy)
	}
	for _, r := range records[1:] {
		if s, err := model.OwnerSlot(id.Org, id.Project, id.Source, id.Producer, r); err != nil || s != slot {
			return model.Batch{}, newError(p.Name, StatusUnknown, ReasonInvalidPolicy)
		}
	}
	return model.Batch{Version: 1, Project: id.Project, Source: id.Source, Producer: id.Producer, ID: batch, PolicyRevision: p.Revision, RouteSlot: slot, Records: records}, nil
}

// Submitter admits one batch and returns its durable receipt. The production
// implementation posts to the C03 ingest route and waits for the receipt.
type Submitter interface {
	Admit(ctx context.Context, b model.Batch) (model.Receipt, error)
}

// Pump runs the source cycle: read a range, record the intent durably, submit
// the batches, and only with their receipts commit the checkpoint.
type Pump struct {
	Policy SourcePolicy
	Store  *Store
	ID     Identity
	Submit Submitter
}

// CycleResult summarizes one cycle. Advanced says the committed position moved.
type CycleResult struct {
	Scanned  uint32
	Admitted uint32
	Batches  int
	Gaps     int
	Advanced bool
	Dropped  map[string]uint64
}

// Cycle performs one read-submit-commit round for the source. Any failure
// leaves the committed position where it was; the intent stays recorded so the
// next cycle resubmits exactly the same batches.
func (p *Pump) Cycle(ctx context.Context) (CycleResult, error) {
	name := p.Policy.Name
	var res CycleResult
	cp, err := p.Store.Load(name)
	if err != nil {
		return res, err
	}
	recs, next, err := Read(ctx, p.Policy, cp)
	if err != nil {
		if se, ok := AsError(err); ok && se.Reason != ReasonCancelled {
			p.Store.RecordHealth(name, se.Status, se.Reason, model.UnixNano(p.Policy.now().UnixNano()))
		}
		return res, err
	}
	if next.Pending == nil {
		if cp.Health.Status != StatusSupported {
			p.Store.RecordHealth(name, StatusSupported, ReasonNone, model.UnixNano(p.Policy.now().UnixNano()))
		}
		return res, nil
	}
	if cp.Pending == nil || cp.Pending.Group != next.Pending.Group {
		if err := p.Store.Prepare(next); err != nil {
			return res, err
		}
	}
	batches, err := BuildBatches(p.ID, p.Policy, next, recs)
	if err != nil {
		return res, err
	}
	receipts := make([]model.Receipt, 0, len(batches))
	for _, b := range batches {
		r, err := p.Submit.Admit(ctx, b)
		if err != nil {
			return res, fmt.Errorf("sources: %s: admit: %w", name, err)
		}
		receipts = append(receipts, r)
	}
	committed, err := p.Store.Commit(name, receipts...)
	if err != nil {
		return res, err
	}
	res = CycleResult{Scanned: next.Pending.Scanned, Admitted: next.Pending.Records, Batches: len(batches), Gaps: len(next.Pending.Gaps), Advanced: committed.Position != cp.Position, Dropped: next.Pending.Dropped}
	return res, nil
}
