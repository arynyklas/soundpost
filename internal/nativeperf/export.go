// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"soundpost/internal/ingest"
	"soundpost/internal/model"
	"soundpost/internal/policy"
	"sync"
	"time"
)

type BatchAdmitter interface {
	Admit(context.Context, policy.SourceGrant, model.Batch) (ingest.Receipt, error)
}

// ReceiptLookup is bound by the composition root to the current source
// credential. NotFound alone permits admission reconsideration; every other
// failure (denied, unknown, unavailable) leaves the immutable lane pending.
type ReceiptLookup interface {
	LookupReceipt(context.Context, model.ReceiptRequest) (model.Receipt, error)
}
type ExportConfig struct {
	Project, Source, Producer model.ID
	Resource                  model.Resource
	Limits                    ProfileLimits
	Capabilities              Capabilities
}
type exportBatch struct {
	batch     model.Batch
	hash      model.Hash
	attempted bool
	receipt   *model.Receipt
	profile   bool
}
type ExportStats struct {
	QueueBytes         uint64
	PendingBatches     uint32
	DroppedCaptures    uint64
	HistoricalReceipts uint64
	Admitted           bool
}
type Exporter struct {
	mu                         sync.Mutex
	admit                      BatchAdmitter
	lookup                     ReceiptLookup
	cfg                        ExportConfig
	lease                      WorkingReservation
	pending                    []exportBatch
	root                       model.ID
	inputHash                  model.Hash
	bytes, dropped, historical uint64
	receipt                    model.Receipt
	last                       model.ReceiptRequest
	closed                     bool
}

func NewExporter(a BatchAdmitter, l ReceiptLookup, c ExportConfig, reserved WorkingReservation) (*Exporter, error) {
	if a == nil || l == nil || reserved == nil || reserved.Bytes() < 2<<20 || c.Project == (model.ID{}) || c.Source == (model.ID{}) || c.Producer == (model.ID{}) || c.Limits.validate() != nil || c.Capabilities.Validate() != nil {
		return nil, ErrInvalid
	}
	c.Resource.Labels = append(model.Labels(nil), c.Resource.Labels...)
	mappings := make([]MappingTable, len(c.Limits.Mappings))
	for i, m := range c.Limits.Mappings {
		mappings[i] = MappingTable{process: m.process, policy: SymbolPolicy{FramePointersAbsent: m.policy.FramePointersAbsent}}
	}
	c.Limits.Mappings = mappings
	return &Exporter{admit: a, lookup: l, cfg: c, lease: reserved}, nil
}
func hashCapture(c ProfileChunk) (model.Hash, error) {
	h := sha256.New()
	if e := json.NewEncoder(h).Encode(c); e != nil {
		return model.Hash{}, e
	}
	var result model.Hash
	copy(result[:], h.Sum(nil))
	return result, nil
}
func (e *Exporter) Stats() ExportStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	var pending uint32
	for _, b := range e.pending {
		if b.receipt == nil {
			pending++
		}
	}
	return ExportStats{QueueBytes: e.bytes, PendingBatches: pending, DroppedCaptures: e.dropped, HistoricalReceipts: e.historical, Admitted: e.receipt.BatchID != (model.ID{}) && pending == 0}
}
func (e *Exporter) LastReceiptRequest() model.ReceiptRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.last
}

// DropReport exposes only bounded counters/reason, never dropped sample bytes.
// The caller exports this side-band C04 report after queue pressure clears.
func (e *Exporter) DropReport() model.LossReport {
	e.mu.Lock()
	defer e.mu.Unlock()
	var ack *model.Cursor
	if e.receipt.Cursor.Group != (model.ID{}) {
		owned := e.receipt.Cursor
		ack = &owned
	}
	return model.LossReport{Source: e.cfg.Source, Producer: e.cfg.Producer, Epoch: e.cfg.Producer, Start: e.cfg.Limits.Start, End: e.cfg.Limits.End, Signal: model.Profile, Reason: "queue_full", Count: model.Uint64(e.dropped), LastAck: ack, QueueBytes: model.Uint64(e.bytes), QueueRecords: model.Uint64(len(e.pending))}
}
func (e *Exporter) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	e.pending = nil
	e.bytes = 0
	return e.lease.Close()
}
func receiptIdentity(b exportBatch, r model.Receipt) bool {
	if r.Version != 1 || r.BatchID != b.batch.ID || r.Hash != b.hash || r.Cursor.Group == (model.ID{}) || r.Cursor.Index == 0 || len(r.SignalDeadlines) == 0 {
		return false
	}
	kinds := map[model.Kind]bool{}
	for _, row := range b.batch.Records {
		kinds[row.Kind] = true
	}
	var minimum model.UnixNano
	seen := map[model.Kind]bool{}
	for i, d := range r.SignalDeadlines {
		if !kinds[d.Kind] || seen[d.Kind] {
			return false
		}
		seen[d.Kind] = true
		if i == 0 || d.RetainUntil < minimum {
			minimum = d.RetainUntil
		}
	}
	return len(seen) == len(kinds) && r.RetainUntil == minimum
}
func isMissingReceipt(err error) bool {
	var fault *model.Fault
	if errors.As(err, &fault) {
		return fault.Code == model.NotFound
	}
	return false
}

// Send never ACKs a pending or merely queued capture. It freezes normalized
// per-slot bytes once; after any ambiguous admission lookup precedes normalize
// or Admit. This is local exporter state, not a parallel ingest transport.
func (e *Exporter) Send(ctx context.Context, g policy.SourceGrant, c ProfileChunk) (ingest.Receipt, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.lease.Bytes() < 2<<20 {
		return model.Receipt{}, ErrResourceBudget
	}
	if err := ctx.Err(); err != nil {
		return model.Receipt{}, err
	}
	if c.ProfileID != e.cfg.Limits.Profile || c.ProfileID == (model.ID{}) || c.PolicyRevision != e.cfg.Limits.PolicyRevision || c.Domain != e.cfg.Limits.Domain {
		return model.Receipt{}, ErrInvalid
	}
	if uint64(len(c.Events)+len(c.Intervals)) > (8<<20)/(32<<10) {
		e.dropped++
		return model.Receipt{}, ErrResourceBudget
	}
	h, err := hashCapture(c)
	if err != nil {
		return model.Receipt{}, err
	}
	if len(e.pending) > 0 {
		if c.ProfileID != e.root || h != e.inputHash {
			return model.Receipt{}, model.Fail(model.Conflict)
		}
		if e.receipt.BatchID != (model.ID{}) {
			complete := true
			for _, b := range e.pending {
				complete = complete && b.receipt != nil
			}
			if complete {
				r, err := e.lookup.LookupReceipt(ctx, e.last)
				if err != nil {
					return model.Receipt{}, err
				}
				if !r.Historical || r.BatchID != e.last.BatchID || r.Hash != e.last.OriginalHash {
					return model.Receipt{}, model.Fail(model.Corrupt)
				}
				for _, b := range e.pending {
					if b.batch.ID == r.BatchID && !receiptIdentity(b, r) {
						return model.Receipt{}, model.Fail(model.Corrupt)
					}
				}
				return r, nil
			}
		}
	}
	if len(e.pending) == 0 {
		if err = e.prepare(ctx, g, c); err != nil {
			if errors.Is(err, ErrResourceBudget) {
				e.dropped++
			}
			return model.Receipt{}, err
		}
		e.root = c.ProfileID
		e.inputHash = h
	}
	for i := range e.pending {
		b := &e.pending[i]
		if b.receipt != nil {
			continue
		}
		q := model.ReceiptRequest{Source: b.batch.Source, Producer: b.batch.Producer, RouteSlot: b.batch.RouteSlot, BatchID: b.batch.ID, OriginalHash: b.hash}
		if b.profile {
			e.last = q
		}
		if b.attempted {
			r, lookupErr := e.lookup.LookupReceipt(ctx, q)
			if lookupErr == nil {
				if !r.Historical || !receiptIdentity(*b, r) {
					return model.Receipt{}, model.Fail(model.Corrupt)
				}
				owned := r
				owned.SignalDeadlines = append([]model.SignalDeadline(nil), r.SignalDeadlines...)
				b.receipt = &owned
				e.historical++
				if b.profile {
					e.receipt = owned
				}
				continue
			}
			if !isMissingReceipt(lookupErr) {
				return model.Receipt{}, lookupErr
			}
			// A proved not-found may reconsider current admission, but cannot mutate
			// this already assigned batch identity into different canonical bytes.
			normalized, nerr := policy.Normalize(g, b.batch)
			if nerr != nil {
				return model.Receipt{}, nerr
			}
			if normalized.Hash != b.hash {
				return model.Receipt{}, model.Fail(model.Conflict)
			}
		}
		b.attempted = true
		r, admitErr := e.admit.Admit(ctx, g, b.batch)
		if admitErr != nil {
			return model.Receipt{}, admitErr
		}
		if !receiptIdentity(*b, r) {
			return model.Receipt{}, model.Fail(model.Corrupt)
		}
		r.SignalDeadlines = append([]model.SignalDeadline(nil), r.SignalDeadlines...)
		b.receipt = &r
		if b.profile {
			e.receipt = r
		}
	}
	if e.receipt.BatchID == (model.ID{}) {
		return model.Receipt{}, model.Fail(model.Unavailable)
	}
	result := e.receipt
	result.SignalDeadlines = append([]model.SignalDeadline(nil), result.SignalDeadlines...)
	// Retain identities/receipts for an idempotent repeat of the same capture.
	// Their bounded charge remains in this queue until exporter Close.
	return result, nil
}
func (e *Exporter) prepare(ctx context.Context, g policy.SourceGrant, input ProfileChunk) error {
	scope, err := g.Scope()
	if err != nil {
		return err
	}
	if err = g.Revalidate(ctx); err != nil {
		return err
	}
	if !scope.AllowsProject(e.cfg.Project) || !scope.AllowsSource(e.cfg.Source) {
		return model.Fail(model.Forbidden)
	}
	l := e.cfg.Limits
	l.Profile = input.ProfileID
	c, err := AssembleProfile(ctx, input.Events, input.Intervals, e.cfg.Capabilities, l)
	if err != nil {
		return err
	}
	if e.dropped > 0 {
		c.Truncated = true
		c.Complete = false
	}
	chunks, err := splitProfile(c)
	if err != nil {
		return err
	}
	records := make([]model.Record, 0, len(chunks)+2)
	for i := range chunks {
		chunk := chunks[i]
		records = append(records, model.Record{ID: model.NewID(), Kind: model.Profile, ObservedAt: l.Start, Resource: e.cfg.Resource, Payload: model.Payload{Profile: &chunk}})
	}
	reason := "coverage_unmeasured"
	if len(e.cfg.Capabilities.Reasons) > 0 {
		reason = string(e.cfg.Capabilities.Reasons[0])
	}
	coverage := func(c Coverage) string {
		if !c.Measured {
			return "unknown"
		}
		if c.Eligible == c.Observed {
			return "complete"
		}
		return "partial"
	}
	cap := model.Capability{Runtime: "native_linux", Version: "1", Build: "owned", OS: "linux", Arch: e.cfg.Capabilities.Arch, Signal: model.Profile, Method: "native_cpu", Status: string(e.cfg.Capabilities.CPU), Reason: reason, Coverage: model.Coverage{Frames: coverage(e.cfg.Capabilities.FrameCoverage), Threads: coverage(e.cfg.Capabilities.ThreadCoverage), Workers: "none", Tasks: "unknown"}, Clock: l.Clock.Domain, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano())}
	if cap.Arch == "" {
		cap.Arch = "unknown"
	}
	statuses := []Status{e.cfg.Capabilities.CPU, e.cfg.Capabilities.OffCPU, e.cfg.Capabilities.RunqueueSplit}
	methods := []string{"native_cpu", "native_offcpu", "native_runqueue_split"}
	for i, id := range c.NativeCapabilities {
		evidence := cap
		evidence.Method = methods[i]
		evidence.Status = string(statuses[i])
		if statuses[i] == Denied {
			evidence.Reason = string(ReasonPermission)
		} else if statuses[i] == Unsupported {
			evidence.Reason = string(ReasonEvent)
			for _, reason := range e.cfg.Capabilities.Reasons {
				if reason == ReasonTraceFS || reason == ReasonPlatform || reason == ReasonEvent {
					evidence.Reason = string(reason)
					break
				}
			}
			if i == 2 {
				evidence.Reason = string(ReasonAcquisition)
			}
		}
		records = append(records, model.Record{ID: id, Kind: model.CapabilityKind, ObservedAt: l.Start, Resource: e.cfg.Resource, Payload: model.Payload{Capability: &evidence}})
	}
	if c.Loss > 0 {
		reason := "ring_overflow"
		for _, evidence := range c.NativeLoss {
			if evidence.Reason == string(ReasonSampleLost) {
				reason = "truncated"
				break
			}
		}
		loss := model.LossReport{Source: e.cfg.Source, Producer: e.cfg.Producer, Epoch: input.ProfileID, Start: l.Start, End: l.End, Signal: model.Profile, Reason: reason, Count: c.Loss}
		records = append(records, model.Record{ID: model.NewID(), Kind: model.Loss, ObservedAt: l.Start, Resource: e.cfg.Resource, Payload: model.Payload{Loss: &loss}})
	}
	if e.dropped > 0 {
		loss := model.LossReport{Source: e.cfg.Source, Producer: e.cfg.Producer, Epoch: input.ProfileID, Start: l.Start, End: l.End, Signal: model.Profile, Reason: "queue_full", Count: model.Uint64(e.dropped), QueueBytes: model.Uint64(e.bytes), QueueRecords: model.Uint64(len(e.pending))}
		records = append(records, model.Record{ID: model.NewID(), Kind: model.Loss, ObservedAt: l.Start, Resource: e.cfg.Resource, Payload: model.Payload{Loss: &loss}})
	}
	lanes := map[uint16][]model.Record{}
	// Normalize each record using a temporary never-admitted identity. Only after
	// canonical owner routing is fixed do final immutable batch IDs get assigned.
	for _, record := range records {
		slot, err := model.OwnerSlot(scope.OrgID(), e.cfg.Project, e.cfg.Source, e.cfg.Producer, record)
		if err != nil {
			return err
		}
		probe := model.Batch{Version: 1, Project: e.cfg.Project, Source: e.cfg.Source, Producer: e.cfg.Producer, ID: model.ID{1}, PolicyRevision: input.PolicyRevision, RouteSlot: slot, Records: []model.Record{record}}
		normalized, err := policy.Normalize(g, probe)
		if err != nil {
			return err
		}
		for _, row := range normalized.Records {
			canonicalSlot, err := model.OwnerSlot(scope.OrgID(), e.cfg.Project, e.cfg.Source, e.cfg.Producer, row)
			if err != nil {
				return err
			}
			lanes[canonicalSlot] = append(lanes[canonicalSlot], row)
		}
	}
	slots := make([]int, 0, len(lanes))
	for slot := range lanes {
		slots = append(slots, int(slot))
	}
	sort.Ints(slots)
	var pending []exportBatch
	var charged uint64
	for _, slot := range slots {
		batch := model.Batch{Version: 1, Project: e.cfg.Project, Source: e.cfg.Source, Producer: e.cfg.Producer, ID: model.NewID(), PolicyRevision: input.PolicyRevision, RouteSlot: uint16(slot), Records: lanes[uint16(slot)]}
		n, err := policy.Normalize(g, batch)
		if err != nil {
			return err
		}
		cost := uint64(len(n.Canonical))*4 + 4096
		if cost > uint64(2<<20)-charged {
			return ErrResourceBudget
		}
		charged += cost
		item := exportBatch{batch: n.Batch, hash: n.Hash}
		for _, r := range batch.Records {
			item.profile = item.profile || r.Kind == model.Profile
		}
		pending = append(pending, item)
	}
	e.pending = pending
	e.bytes = charged
	return nil
}

// splitProfile reindexes only referenced frames/stacks into independently valid
// records before route/batch identity assignment. No missing data becomes zeros.
func splitProfile(c model.ProfileChunk) ([]model.ProfileChunk, error) {
	const limit = 192 << 10
	var out []model.ProfileChunk
	reset := func() model.ProfileChunk {
		v := c
		v.Frames = []model.ProfileFrame{}
		v.Stacks = []model.ProfileStack{}
		v.Samples = []model.ProfileSample{}
		v.Intervals = []model.ProfileInterval{}
		v.NativeLoss = nil
		v.Sequence = c.Sequence + model.Uint64(len(out))
		v.Complete = false
		if len(out) > 0 {
			v.Loss = 0
		}
		return v
	}
	current := reset()
	frameMap := map[uint32]uint32{}
	stackMap := map[uint32]uint32{}
	addStack := func(old uint32) (uint32, error) {
		if n, ok := stackMap[old]; ok {
			return n, nil
		}
		if int(old) >= len(c.Stacks) {
			return 0, ErrInvalid
		}
		var refs []uint32
		for _, f := range c.Stacks[old].Frames {
			if int(f) >= len(c.Frames) {
				return 0, ErrInvalid
			}
			n, ok := frameMap[f]
			if !ok {
				n = uint32(len(current.Frames))
				current.Frames = append(current.Frames, c.Frames[f])
				frameMap[f] = n
			}
			refs = append(refs, n)
		}
		n := uint32(len(current.Stacks))
		current.Stacks = append(current.Stacks, model.ProfileStack{Frames: refs})
		stackMap[old] = n
		return n, nil
	}
	// A conservative per-observation bound avoids repeated whole-chunk encoding.
	size := 4096
	flush := func() {
		out = append(out, current)
		current = reset()
		frameMap = map[uint32]uint32{}
		stackMap = map[uint32]uint32{}
		size = 4096
	}
	for _, s := range c.Samples {
		if int(s.Stack) >= len(c.Stacks) {
			return nil, ErrInvalid
		}
		cost := 1024
		for _, f := range c.Stacks[s.Stack].Frames {
			if int(f) >= len(c.Frames) {
				return nil, ErrInvalid
			}
			row := c.Frames[f]
			cost += 256 + len(row.Module) + len(row.Function) + len(row.Artifact) + len(row.Reason)
		}
		if cost > limit-4096 {
			return nil, ErrResourceBudget
		}
		if size+cost > limit {
			flush()
		}
		n, err := addStack(s.Stack)
		if err != nil {
			return nil, err
		}
		s.Stack = n
		current.Samples = append(current.Samples, s)
		size += cost
	}
	for _, i := range c.Intervals {
		if int(i.Stack) >= len(c.Stacks) {
			return nil, ErrInvalid
		}
		cost := 1024 + len(c.Stacks[i.Stack].Frames)*1024
		if cost > limit-4096 {
			return nil, ErrResourceBudget
		}
		if size+cost > limit {
			flush()
		}
		n, err := addStack(i.Stack)
		if err != nil {
			return nil, err
		}
		i.Stack = n
		current.Intervals = append(current.Intervals, i)
		size += cost
	}
	if len(c.NativeLoss) > 256 {
		return nil, ErrResourceBudget
	}
	for _, loss := range c.NativeLoss {
		if size+512 > limit {
			flush()
		}
		current.NativeLoss = append(current.NativeLoss, loss)
		size += 512
	}
	if len(current.Samples)+len(current.Intervals)+len(current.NativeLoss) > 0 {
		flush()
	}
	if len(out) == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	out[len(out)-1].Complete = c.Complete
	for _, chunk := range out {
		b, err := model.CanonicalJSON(chunk)
		if err != nil {
			return nil, err
		}
		if len(b) > limit {
			return nil, ErrResourceBudget
		}
	}
	return out, nil
}
