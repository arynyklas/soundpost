// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"math"
	"sort"
	"strconv"
	"sync/atomic"
	"time"
)

type SourceCredential = auth.SourceCredential
type SourceGrant struct {
	service    *Service
	credential auth.SourceCredential
	scope      auth.Scope
	source     model.SourceAuthority
	deadline   time.Time
	retention  *Retention // the design s12 retention in force when the grant was resolved; nil when none is bound
}
type Service struct {
	auth      *auth.Service
	now       func() time.Time
	retention atomic.Pointer[RetentionResolver]
}

// Retention is the effective retention of one project at one instant, in whole days: the
// defaults of design section 12 layered with the audited organization and project versions in
// force then. RawDays applies to restricted_raw sources.
type Retention struct {
	Days    map[model.Kind]uint32
	RawDays uint32
}

// RetentionResolver resolves the retention in force for (org, project) at an instant. It is
// implemented by the retention package over the control state; policy takes it as an interface so
// admission does not import the deletion machinery.
type RetentionResolver interface {
	ResolveRetention(ctx context.Context, org, project model.ID, at model.UnixNano) (Retention, error)
}

// BindRetention makes admission take receipt deadlines from the resolver instead of from the
// retention days a source policy carries. Call it while wiring, before intake opens; it is safe
// to call at any time (grants resolved earlier keep what they resolved).
func (s *Service) BindRetention(r RetentionResolver) error {
	if r == nil {
		return model.Fail(model.Invalid)
	}
	s.retention.Store(&r)
	return nil
}

func New(a *auth.Service, now func() time.Time) (*Service, error) {
	if a == nil {
		return nil, model.Fail(model.Invalid)
	}
	if now == nil {
		now = time.Now
	}
	return &Service{auth: a, now: now}, nil
}
func (s *Service) ResolveSource(ctx context.Context, c SourceCredential, project, source model.ID, revision model.Revision) (SourceGrant, error) {
	src, e := s.auth.SourceAuthority(ctx, c, true)
	if e != nil {
		return SourceGrant{}, e
	}
	if src.Project != project || src.ID != source {
		return SourceGrant{}, model.Fail(model.Forbidden)
	}
	if src.Policy.Revision != revision {
		return SourceGrant{}, model.Fail(model.Stale)
	}
	scope, e := s.auth.SourceScope(ctx, c, false)
	if e != nil {
		return SourceGrant{}, e
	}
	grant := SourceGrant{service: s, credential: c, scope: scope, source: src, deadline: s.now().Add(5 * time.Second)}
	if r := s.retention.Load(); r != nil {
		// Resolved here, once, at the instant the batch is admitted: Normalize stamps absolute
		// deadlines from it and a later policy version never recomputes them.
		eff, e := (*r).ResolveRetention(ctx, src.Org, src.Project, model.UnixNano(s.now().UnixNano()))
		if e != nil {
			return SourceGrant{}, e
		}
		grant.retention = &eff
	}
	return grant, nil
}
func (g SourceGrant) Scope() (auth.Scope, error) {
	if g.service == nil || !g.service.now().Before(g.deadline) {
		return auth.Scope{}, model.Fail(model.Stale)
	}
	return g.scope, nil
}
func (g SourceGrant) Revalidate(ctx context.Context) error {
	if g.service == nil {
		return model.Fail(model.Forbidden)
	}
	_, e := g.service.auth.SourceAuthority(ctx, g.credential, true)
	return e
}
func Normalize(g SourceGrant, input model.Batch) (model.NormalizedBatch, error) {
	if g.service == nil || !g.service.now().Before(g.deadline) {
		return model.NormalizedBatch{}, model.Fail(model.Stale)
	}
	src := g.source
	if input.Version != 1 || input.Project != src.Project || input.Source != src.ID || input.Producer == (model.ID{}) || input.ID == (model.ID{}) || input.PolicyRevision != src.Policy.Revision || input.RouteSlot >= 64 || len(input.Records) == 0 || len(input.Records) > 512 {
		return model.NormalizedBatch{}, model.Fail(model.Invalid)
	}
	// Copy through the closed DTO codec. Normalization never mutates caller records.
	raw, e := json.Marshal(input)
	if e != nil {
		return model.NormalizedBatch{}, model.Fail(model.Invalid)
	}
	var b model.Batch
	if json.Unmarshal(raw, &b) != nil {
		return model.NormalizedBatch{}, model.Fail(model.Invalid)
	}
	kinds := map[model.Kind]bool{}
	series := map[string]bool{}
	ids := map[model.ID]bool{}
	for i := range b.Records {
		r := &b.Records[i]
		if ids[r.ID] {
			return model.NormalizedBatch{}, model.Fail(model.Invalid)
		}
		ids[r.ID] = true
		if e = model.ValidateRecord(r, src.Policy); e != nil {
			return model.NormalizedBatch{}, e
		}
		if r.Kind == model.Loss && (r.Payload.Loss.Source != b.Source || r.Payload.Loss.Producer != b.Producer) {
			return model.NormalizedBatch{}, model.Fail(model.Forbidden)
		}
		slot, err := model.OwnerSlot(src.Org, b.Project, b.Source, b.Producer, *r)
		if err != nil {
			return model.NormalizedBatch{}, err
		}
		if slot != b.RouteSlot {
			fault := model.Fail(model.Invalid)
			fault.SafeDetail = "route_slot_mismatch:expected_" + strconv.Itoa(int(slot))
			return model.NormalizedBatch{}, fault
		}
		rb, err := model.CanonicalJSON(r)
		if err != nil || len(rb) > 256<<10 {
			return model.NormalizedBatch{}, model.Fail(model.TooLarge)
		}
		kinds[r.Kind] = true
		if r.Kind == model.Metric {
			id, err := model.CanonicalSeriesID(b.Project, *r)
			if err != nil {
				return model.NormalizedBatch{}, err
			}
			series[id] = true
		}
	}
	canonical, e := model.CanonicalJSON(b)
	if e != nil {
		return model.NormalizedBatch{}, model.Fail(model.Invalid)
	}
	if len(canonical) > 4<<20 {
		return model.NormalizedBatch{}, model.Fail(model.TooLarge)
	}
	now := g.service.now().UnixNano()
	if now > math.MaxInt64-int64(7*24*time.Hour) {
		return model.NormalizedBatch{}, model.Fail(model.Invalid)
	}
	deadlines := make([]model.SignalDeadline, 0, len(kinds))
	for k := range kinds {
		days := src.Policy.RetentionDays[k]
		if g.retention != nil {
			days = g.retention.Days[k]
			if src.Policy.Class == "restricted_raw" && g.retention.RawDays != 0 {
				days = g.retention.RawDays
			}
		}
		duration := int64(days) * int64(24*time.Hour)
		if days == 0 || days > 3650 || now > math.MaxInt64-duration {
			return model.NormalizedBatch{}, model.Fail(model.Invalid)
		}
		deadlines = append(deadlines, model.SignalDeadline{Kind: k, RetainUntil: model.UnixNano(now + duration)})
	}
	sort.Slice(deadlines, func(i, j int) bool { return deadlines[i].Kind < deadlines[j].Kind })
	ss := make([]string, 0, len(series))
	for id := range series {
		ss = append(ss, id)
	}
	sort.Strings(ss)
	pb, e := model.CanonicalJSON(src.Policy)
	if e != nil {
		return model.NormalizedBatch{}, e
	}
	return model.NormalizedBatch{Batch: b, Org: src.Org, Hash: model.HashCanonical(canonical), Canonical: canonical, PolicyEpoch: model.Uint64(g.scope.PolicyEpoch()), PolicyHash: model.HashCanonical(pb).String(), AdmissionAt: model.UnixNano(now), Deadlines: deadlines, Series: ss}, nil
}
