// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log/slog"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/host"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/sources"
)

// Build is the agent build string carried in capability records (set by the
// linker for releases).
var Build = "dev"

const (
	defaultPoll   = 5 * time.Second
	maxDrainLoops = 8
)

// Agent runs host collection and log pumps and submits their batches.
type Agent struct {
	cfg    Config
	res    model.Resource
	id     sources.Identity
	domain model.ClockDomain
	sub    sources.Submitter
	store  *sources.Store
	log    *slog.Logger
	now    func() time.Time

	hostPolicy host.HostPolicy
	hostEvery  time.Duration
	hostNext   time.Time
	pumps      []*pumpState

	mu       sync.Mutex
	hostLoss lossWindow
}

type pumpState struct {
	pump  *sources.Pump
	every time.Duration
	next  time.Time
}

// lossWindow remembers host metric batches that could not be admitted, so the
// loss is reported (not hidden) once the server is reachable again.
type lossWindow struct {
	count      uint64
	start, end model.UnixNano
}

// New builds the agent from its configuration: it reads the credential file,
// builds the HTTPS client and opens the checkpoint directory.
func New(cfg Config, log *slog.Logger) (*Agent, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	token, err := ReadCredential(cfg.CredentialFile)
	if err != nil {
		return nil, err
	}
	defer clear(token)
	client, err := NewClient(cfg.Server, cfg.CAFile, token, 0)
	if err != nil {
		return nil, err
	}
	return NewWithSubmitter(cfg, client, log)
}

// NewWithSubmitter builds the agent over any C03 submitter.
func NewWithSubmitter(cfg Config, sub sources.Submitter, log *slog.Logger) (*Agent, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	res, err := cfg.resource()
	if err != nil {
		return nil, err
	}
	org, _ := model.ParseID(cfg.Org)
	project, _ := model.ParseID(cfg.Project)
	source, _ := model.ParseID(cfg.Source)
	ident, err := loadIdentity(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	store, err := sources.OpenStore(cfg.StateDir)
	if err != nil {
		return nil, errors.New("agent: state directory unusable")
	}
	epoch := model.NewID()
	a := &Agent{
		cfg: cfg, res: res, sub: sub, store: store, log: log, now: time.Now,
		id:     sources.Identity{Org: org, Project: project, Source: source, Producer: ident.Producer, Epoch: epoch},
		domain: model.ClockDomain{Host: ident.Host, Boot: bootID(epoch), Runtime: epoch},
	}
	if h := cfg.Host; h != nil {
		if a.hostPolicy, err = h.policy(); err != nil {
			return nil, err
		}
		a.hostEvery = time.Duration(h.Interval)
	}
	for _, l := range cfg.Logs {
		p := l.SourcePolicy
		p.Revision, p.Resource = model.Revision(cfg.PolicyRevision), res
		every := time.Duration(l.Poll)
		if every == 0 {
			every = defaultPoll
		}
		a.pumps = append(a.pumps, &pumpState{pump: &sources.Pump{Policy: p, Store: store, ID: a.id, Submit: sub}, every: every})
	}
	return a, nil
}

// HostReport is the outcome of one host collection.
type HostReport struct {
	Ran          bool
	Samples      int
	Capabilities host.Capabilities
	Batches      int
	Admitted     int
	Err          error
}

// SourceReport is the outcome of one log source cycle.
type SourceReport struct {
	Name   string
	Result sources.CycleResult
	Status sources.Status
	Reason sources.Reason
	Err    error
}

// CycleReport is everything one cycle did. Err is the first hard failure.
type CycleReport struct {
	At                 model.UnixNano
	Host               HostReport
	Sources            []SourceReport
	CapabilitiesSent   bool
	CapabilitiesFailed bool
}

// Failed says some component did not complete.
func (r CycleReport) Failed() bool {
	if r.Host.Err != nil || r.CapabilitiesFailed {
		return true
	}
	for _, s := range r.Sources {
		if s.Err != nil {
			return true
		}
	}
	return false
}

// Cycle runs every component once, then publishes capability records.
func (a *Agent) Cycle(ctx context.Context) CycleReport {
	return a.run(ctx, true)
}

func (a *Agent) run(ctx context.Context, force bool) CycleReport {
	now := a.now()
	rep := CycleReport{At: model.UnixNano(now.UnixNano())}
	var capRecords []model.Record
	ran := false
	if a.cfg.Host != nil && (force || !now.Before(a.hostNext)) {
		ran = true
		a.hostNext = now.Add(a.hostEvery)
		var caps host.Capabilities
		rep.Host, caps = a.hostCycle(ctx)
		rep.Host.Capabilities = caps
		if recs, err := caps.Records(a.res, rep.At, a.capabilityTTL(), a.domain, Build); err == nil {
			capRecords = append(capRecords, recs...)
		} else {
			a.log.Error("host capability encoding failed")
		}
	}
	for _, ps := range a.pumps {
		if !force && now.Before(ps.next) {
			continue
		}
		ran = true
		ps.next = now.Add(ps.every)
		sr := a.sourceCycle(ctx, ps)
		rep.Sources = append(rep.Sources, sr)
		if rec, err := a.sourceCapability(ps.pump.Policy, sr, rep.At); err == nil {
			capRecords = append(capRecords, rec)
		}
	}
	if ran && len(capRecords) > 0 {
		rep.CapabilitiesSent, rep.CapabilitiesFailed = a.sendCapabilities(ctx, capRecords)
	}
	return rep
}

// Run cycles on the configured intervals until ctx ends.
func (a *Agent) Run(ctx context.Context) error {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		rep := a.run(ctx, false)
		if rep.Failed() && ctx.Err() == nil {
			a.log.Warn("cycle incomplete")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (a *Agent) capabilityTTL() time.Duration {
	ttl := 3 * a.hostEvery
	if ttl < time.Minute {
		ttl = time.Minute
	}
	return ttl
}

// ---------------------------------------------------------------- host

func (a *Agent) hostCycle(ctx context.Context) (HostReport, host.Capabilities) {
	rep := HostReport{Ran: true}
	batch, caps, err := host.Collect(ctx, a.hostPolicy)
	if err != nil {
		rep.Err = err
		a.log.Error("host collection failed", describe(err)...)
		return rep, caps
	}
	rep.Samples = len(batch.Samples)
	recs, err := batch.Records(a.res)
	if err != nil {
		rep.Err = err
		a.log.Error("host sample encoding failed", describe(err)...)
		return rep, caps
	}
	batches, err := a.batchesBySlot(recs)
	if err != nil {
		rep.Err = err
		return rep, caps
	}
	rep.Batches = len(batches)
	for _, b := range batches {
		if _, err := a.sub.Admit(ctx, b); err != nil {
			a.noteLoss(len(b.Records), batch.At)
			rep.Err = err
			a.log.Warn("host batch not admitted", describe(err)...)
			continue
		}
		rep.Admitted++
	}
	if rep.Admitted > 0 {
		a.flushLoss(ctx, batch.At)
	}
	a.log.Info("host cycle", "samples", rep.Samples, "batches", rep.Batches, "admitted", rep.Admitted, "unknown_or_denied", countNotSupported(caps))
	return rep, caps
}

func countNotSupported(c host.Capabilities) int {
	n := 0
	for _, x := range c {
		if x.Status != host.StatusSupported {
			n++
		}
	}
	return n
}

func (a *Agent) noteLoss(n int, at model.UnixNano) {
	a.mu.Lock()
	defer a.mu.Unlock()
	w := &a.hostLoss
	if w.count == 0 {
		w.start = at
	}
	w.count += uint64(n)
	w.end = at
}

// flushLoss reports host samples that could not be admitted earlier, once the
// server accepts data again. The report keeps its window until admitted.
func (a *Agent) flushLoss(ctx context.Context, at model.UnixNano) {
	a.mu.Lock()
	w := a.hostLoss
	a.mu.Unlock()
	if w.count == 0 {
		return
	}
	loss := &model.LossReport{Source: a.id.Source, Producer: a.id.Producer, Epoch: a.id.Epoch, Start: w.start, End: w.end, Signal: model.Metric, Reason: "transport", Count: model.Uint64(w.count)}
	rec := model.Record{ID: derived("hostloss.record", a.id.Epoch, w.start, w.end), Kind: model.Loss, ObservedAt: w.end, Resource: a.res, Payload: model.Payload{Loss: loss}}
	b, err := a.batchOf(derived("hostloss.batch", a.id.Epoch, w.start, w.end), []model.Record{rec})
	if err != nil {
		return
	}
	if _, err := a.sub.Admit(ctx, b); err != nil {
		return
	}
	a.mu.Lock()
	if a.hostLoss == w {
		a.hostLoss = lossWindow{}
	}
	a.mu.Unlock()
}

func derived(domain string, epoch model.ID, a, b model.UnixNano) model.ID {
	h := sha256.New()
	h.Write([]byte("soundpost.agent." + domain + "\x00"))
	h.Write(epoch[:])
	var n [16]byte
	binary.BigEndian.PutUint64(n[:8], uint64(a))
	binary.BigEndian.PutUint64(n[8:], uint64(b))
	h.Write(n[:])
	var id model.ID
	copy(id[:], h.Sum(nil))
	if id == (model.ID{}) {
		id[0] = 1
	}
	return id
}

// batchesBySlot groups records by their owner slot: one C03 batch has one
// route slot. Batch identifiers are fresh (host samples are not replayed).
func (a *Agent) batchesBySlot(recs []model.Record) ([]model.Batch, error) {
	bySlot := map[uint16][]model.Record{}
	for _, r := range recs {
		slot, err := model.OwnerSlot(a.id.Org, a.id.Project, a.id.Source, a.id.Producer, r)
		if err != nil {
			return nil, err
		}
		bySlot[slot] = append(bySlot[slot], r)
	}
	slots := make([]int, 0, len(bySlot))
	for s := range bySlot {
		slots = append(slots, int(s))
	}
	sort.Ints(slots)
	var out []model.Batch
	for _, s := range slots {
		rs := bySlot[uint16(s)]
		for len(rs) > 0 {
			n := min(len(rs), 512)
			out = append(out, model.Batch{Version: 1, Project: a.id.Project, Source: a.id.Source, Producer: a.id.Producer, ID: model.NewID(), PolicyRevision: model.Revision(a.cfg.PolicyRevision), RouteSlot: uint16(s), Records: rs[:n:n]})
			rs = rs[n:]
		}
	}
	return out, nil
}

func (a *Agent) batchOf(id model.ID, recs []model.Record) (model.Batch, error) {
	slot, err := model.OwnerSlot(a.id.Org, a.id.Project, a.id.Source, a.id.Producer, recs[0])
	if err != nil {
		return model.Batch{}, err
	}
	return model.Batch{Version: 1, Project: a.id.Project, Source: a.id.Source, Producer: a.id.Producer, ID: id, PolicyRevision: model.Revision(a.cfg.PolicyRevision), RouteSlot: slot, Records: recs}, nil
}

// ---------------------------------------------------------------- logs

func (a *Agent) sourceCycle(ctx context.Context, ps *pumpState) SourceReport {
	sr := SourceReport{Name: ps.pump.Policy.Name, Status: sources.StatusSupported}
	for i := 0; i < maxDrainLoops; i++ {
		res, err := ps.pump.Cycle(ctx)
		sr.Result.Scanned += res.Scanned
		sr.Result.Admitted += res.Admitted
		sr.Result.Batches += res.Batches
		sr.Result.Gaps += res.Gaps
		sr.Result.Advanced = sr.Result.Advanced || res.Advanced
		if err != nil {
			sr.Err = err
			if se, ok := sources.AsError(err); ok {
				sr.Status, sr.Reason = se.Status, se.Reason
			} else {
				sr.Status, sr.Reason = sources.StatusUnknown, sources.ReasonReadFailed
			}
			a.log.Warn("log source cycle failed", append(describe(err), "source", sr.Name)...)
			return sr
		}
		if res.Scanned == 0 && !res.Advanced {
			break
		}
	}
	a.log.Info("log source cycle", "source", sr.Name, "scanned", sr.Result.Scanned, "admitted", sr.Result.Admitted, "gaps", sr.Result.Gaps)
	return sr
}

func (a *Agent) sourceCapability(p sources.SourcePolicy, sr SourceReport, at model.UnixNano) (model.Record, error) {
	method := map[sources.Kind]string{sources.KindFile: "file_tail", sources.KindJournal: "journalctl", sources.KindSyslog: "syslog_file"}[p.Kind]
	status, reason, cov := "supported", "ok", "complete"
	if sr.Err != nil {
		cov = "unknown"
		switch sr.Status {
		case sources.StatusDenied:
			status = "denied"
		case sources.StatusUnsupported:
			status = "unsupported"
		default:
			status = "error"
		}
		reason = string(sr.Reason)
		if reason == "" {
			reason = string(sources.ReasonReadFailed)
		}
	}
	c := &model.Capability{
		Runtime: "soundpost-agent", Version: "1", Build: Build, OS: runtime.GOOS, Arch: runtime.GOARCH,
		Signal: model.Log, Method: method, Status: status, Reason: reason,
		Coverage: model.Coverage{Frames: cov, Threads: cov, Workers: cov, Tasks: cov},
		Clock:    a.domain, Expires: at + model.UnixNano(a.capabilityTTL()),
	}
	// A log source's capability is keyed by its alias in the method so several
	// sources of one kind stay distinguishable without exporting a path.
	c.Method = method + ":" + p.Name
	if len(c.Method) > 128 {
		return model.Record{}, errors.New("agent: capability method too long")
	}
	return model.Record{ID: model.NewID(), Kind: model.CapabilityKind, ObservedAt: at, Resource: a.res, Payload: model.Payload{Capability: c}}, nil
}

func (a *Agent) sendCapabilities(ctx context.Context, recs []model.Record) (sent, failed bool) {
	batches, err := a.batchesBySlot(recs)
	if err != nil {
		return false, true
	}
	for _, b := range batches {
		if _, err := a.sub.Admit(ctx, b); err != nil {
			a.log.Warn("capability batch not admitted", describe(err)...)
			failed = true
			continue
		}
		sent = true
	}
	return sent, failed
}

// describe turns an error into log attributes without ever printing its text:
// only the typed class, status and reason.
func describe(err error) []any {
	var se *sources.Error
	var f *model.Fault
	switch {
	case errors.As(err, &se):
		return []any{"class", "source", "status", string(se.Status), "reason", string(se.Reason)}
	case errors.As(err, &f):
		return []any{"class", "fault", "code", string(f.Code), "detail", f.SafeDetail}
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return []any{"class", "cancelled"}
	}
	return []any{"class", "internal"}
}
