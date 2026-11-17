// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
	"sort"
	"strings"
	"time"
)

func applyPolicyChange(scope auth.Scope, st *State, cmd Command) (Effect, error) {
	var req PolicyChange
	if err := strictPayload(cmd.Payload, &req); err != nil {
		return Effect{}, err
	}
	o, err := orgAdmin(scope, st)
	if err != nil {
		return Effect{}, err
	}
	org := scope.OrgID()
	switch {
	case req.Kind == "hold_place" && req.Hold != nil && req.Release == nil && req.Retention == nil:
		h := req.Hold
		reason, ok := cleanReason(h.Reason)
		if !ok || h.At <= 0 || h.Start < 0 || h.End != 0 && h.End <= h.Start || len(h.Projects) > 128 || len(h.Entities) > 128 || len(h.Signals) > 16 {
			return Effect{}, model.Fail(model.Invalid)
		}
		for _, k := range h.Signals {
			if !k.Valid() {
				return Effect{}, model.Fail(model.Invalid)
			}
		}
		for _, p := range h.Projects {
			_, live := o.Projects[p.String()]
			_, retired := st.RetiredProjects[org.String()+":"+p.String()]
			if !live && !retired { // data of an already retired project may still be physically present
				return Effect{}, model.Fail(model.NotFound)
			}
		}
		if st.Holds == nil {
			st.Holds = map[string]model.LegalHold{}
		}
		st.Holds[cmd.CommandID.String()] = model.LegalHold{ID: cmd.CommandID, Org: org, Projects: h.Projects, Signals: h.Signals, Start: h.Start, End: h.End, Entities: h.Entities, Reason: reason, PlacedBy: scope.PrincipalID(), PlacedAt: h.At}
		audit(st, scope.PrincipalID(), org, "hold.place", reason, h.At, []model.ID{cmd.CommandID})
		return Effect{AffectedIDs: []model.ID{cmd.CommandID}, Phase: "held"}, nil
	case req.Kind == "hold_release" && req.Release != nil && req.Hold == nil && req.Retention == nil:
		r := req.Release
		reason, ok := cleanReason(r.Reason)
		h, found := st.Holds[r.Hold.String()]
		if !ok || r.At <= 0 {
			return Effect{}, model.Fail(model.Invalid)
		}
		if !found || h.Org != org {
			return Effect{}, model.Fail(model.NotFound)
		}
		if h.Active() {
			by := scope.PrincipalID()
			h.ReleasedAt, h.ReleasedBy = r.At, &by
			st.Holds[r.Hold.String()] = h
			// Held deletions are never silently started: the administrator
			// resumes them explicitly with BeginFence. Erasure of expired or
			// logically deleted data blocked by this hold becomes possible; the
			// worker advances the delete generation before it erases.
			audit(st, scope.PrincipalID(), org, "hold.release", reason, r.At, []model.ID{r.Hold})
		}
		return Effect{AffectedIDs: []model.ID{r.Hold}, Phase: "released"}, nil
	case req.Kind == "retention_policy" && req.Retention != nil && req.Hold == nil && req.Release == nil:
		return applyRetention(scope, st, o, req.Retention, cmd.CommandID)
	}
	return Effect{}, model.Fail(model.Invalid)
}

func applyRetention(scope auth.Scope, st *State, o model.ControlOrg, r *SetRetention, command model.ID) (Effect, error) {
	reason, ok := cleanReason(r.Reason)
	if !ok || r.At <= 0 || r.Effective < 0 || len(r.Days) == 0 || len(r.Days) > 10 || r.RawDays > 7 || r.Artifacts > 3650 {
		return Effect{}, model.Fail(model.Invalid)
	}
	for k, d := range r.Days {
		if !k.Valid() || d == 0 || d > 3650 {
			return Effect{}, model.Fail(model.Invalid)
		}
	}
	key := scope.OrgID().String()
	if r.Project != nil {
		if _, ok := o.Projects[r.Project.String()]; !ok {
			return Effect{}, model.Fail(model.NotFound)
		}
		key += ":" + r.Project.String()
	}
	eff := r.Effective
	if eff == 0 {
		eff = r.At
	}
	if st.RetentionPolicies == nil {
		st.RetentionPolicies = map[string][]model.RetentionPolicyVersion{}
	}
	days := map[model.Kind]uint32{}
	for k, d := range r.Days {
		days[k] = d
	}
	// Versions are append-only history; an earlier version is never edited.
	v := model.RetentionPolicyVersion{Org: scope.OrgID(), Project: r.Project, Version: model.Uint64(len(st.RetentionPolicies[key]) + 1), Days: days, RawDays: r.RawDays, Artifacts: r.Artifacts, Effective: eff, Actor: scope.PrincipalID(), Reason: reason, At: r.At}
	st.RetentionPolicies[key] = append(st.RetentionPolicies[key], v)
	audit(st, scope.PrincipalID(), scope.OrgID(), "retention.policy", reason, r.At, []model.ID{command})
	return Effect{AffectedIDs: []model.ID{command}, Phase: "applied"}, nil
}

// Who declared an evidence gap. Only a worker gap authorizes expiry (see model.EvidenceGap).
const (
	GapDeclaredByWorker = "worker"
	GapDeclaredByAdmin  = "admin"
)

func gapID(g model.EvidenceGap) model.ID {
	h := sha256.New()
	for _, id := range []model.ID{g.Org, g.Project, g.Group} {
		h.Write(id[:])
	}
	var n [16]byte
	for i := range 8 {
		n[i], n[8+i] = byte(uint64(g.After)>>(56-8*i)), byte(uint64(g.Through)>>(56-8*i))
	}
	h.Write(n[:])
	if g.DeclaredBy == GapDeclaredByAdmin {
		// An administrator's statement about an interval is a different fact from the worker's
		// about the same interval, so it must neither replace nor be replaced by it.
		h.Write([]byte(GapDeclaredByAdmin))
	}
	var id model.ID
	copy(id[:], h.Sum(nil))
	return id
}

// recordGap commits one gap declared by `by` through `actor`. Control decides both, from the path
// the request arrived on; whatever the request body says is overwritten. A worker gap must
// enumerate its interval (Count == Through-After): it can never cover an entry it did not count.
func recordGap(st *State, g model.EvidenceGap, by string, actor model.ID) (model.EvidenceGap, error) {
	o, ok := st.Orgs[g.Org.String()]
	if !ok || g.Org == (model.ID{}) || g.Group == (model.ID{}) {
		return g, model.Fail(model.NotFound)
	}
	_, live := o.Projects[g.Project.String()]
	_, retired := st.RetiredProjects[g.Org.String()+":"+g.Project.String()]
	if !live && !retired {
		return g, model.Fail(model.NotFound)
	}
	if g.Through <= g.After || g.Count == 0 || g.Count > g.Through-g.After || g.End < g.Start || g.RecordedAt <= 0 || len(g.Signals) > 16 || len(g.Reason) == 0 || len(g.Reason) > 64 {
		return g, model.Fail(model.Invalid)
	}
	if by == GapDeclaredByWorker && g.Count != g.Through-g.After {
		return g, model.Fail(model.Invalid)
	}
	for _, k := range g.Signals {
		if !k.Valid() {
			return g, model.Fail(model.Invalid)
		}
	}
	g.DeclaredBy, g.Actor = by, &actor
	g.ID = gapID(g)
	if old, ok := st.EvidenceGaps[g.ID.String()]; ok {
		return old, nil
	}
	if st.EvidenceGaps == nil {
		st.EvidenceGaps = map[string]model.EvidenceGap{}
	}
	st.EvidenceGaps[g.ID.String()] = g
	// Numbers and a declarant only: an audit never carries telemetry.
	audit(st, actor, g.Org, "evidence.gap", fmt.Sprintf("%s declared_by=%s after=%d through=%d count=%d", g.Reason, by, uint64(g.After), uint64(g.Through), uint64(g.Count)), g.RecordedAt, []model.ID{g.ID, g.Group})
	return g, nil
}
func applyEvidenceGap(scope auth.Scope, st *State, cmd Command) (Effect, error) {
	var g model.EvidenceGap
	if err := strictPayload(cmd.Payload, &g); err != nil {
		return Effect{}, err
	}
	if _, err := orgAdmin(scope, st); err != nil {
		return Effect{}, err
	}
	g.Org = scope.OrgID()
	out, err := recordGap(st, g, GapDeclaredByAdmin, scope.PrincipalID())
	if err != nil {
		return Effect{}, err
	}
	return Effect{AffectedIDs: []model.ID{out.ID}, Phase: "recorded"}, nil
}

// RecordEvidenceGap is the retention worker's declaration that lifecycle evidence in
// (After, Through] of a data group, every entry of which it counted (Count == Through-After),
// expired before it was processed. It is idempotent by interval and audited. The declarant is
// always the worker, acting as the installation.
func (s *Store) RecordEvidenceGap(ctx context.Context, g model.EvidenceGap) (out model.EvidenceGap, err error) {
	err = s.Update(ctx, func(st *State) (e error) { out, e = recordGap(st, g, GapDeclaredByWorker, st.Installation); return })
	return
}
func (s *Store) EvidenceGaps(ctx context.Context, org, project model.ID) (out []model.EvidenceGap, err error) {
	err = s.View(ctx, func(st State) error {
		for _, g := range st.EvidenceGaps {
			if g.Org == org && (project == (model.ID{}) || g.Project == project) {
				out = append(out, g)
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
		return nil
	})
	return
}

// HoldSnapshot is the active legal holds of the control state this node had applied at
// control log index Applied. The zero value is "nothing read yet".
type HoldSnapshot struct {
	Applied uint64
	Holds   []model.LegalHold
	known   bool
}

// AppliedHolds returns the active legal holds of the control state this node has APPLIED,
// refreshing prev only when the applied index moved. It is deliberately not a linearizable
// read: it costs one local read transaction and one 8-byte watermark compare when nothing
// changed, so the erasing transaction can afford to ask before every batch and blob. A hold
// that has committed in the control group but is not yet applied on this node is invisible to
// it; that apply-lag window is the residual race and is bounded by the control apply latency
// (the physical pass's own linearizable View before it starts closes it for holds that were
// committed before the pass began).
func (s *Store) AppliedHolds(prev HoldSnapshot) (HoldSnapshot, error) {
	out := prev
	err := s.db.View(func(tx *bolt.Tx) error {
		var mark uint64
		if meta := tx.Bucket([]byte("replica_control")); meta != nil {
			mark = readWatermark(meta.Get([]byte("physical")))
		}
		if prev.known && prev.Applied == mark {
			return nil
		}
		var st struct{ Holds map[string]model.LegalHold }
		if json.Unmarshal(tx.Bucket([]byte("control")).Get([]byte("state")), &st) != nil {
			return model.Fail(model.Corrupt)
		}
		out = HoldSnapshot{Applied: mark, known: true}
		for _, h := range st.Holds {
			if h.Active() {
				out.Holds = append(out.Holds, h)
			}
		}
		sort.Slice(out.Holds, func(i, j int) bool { return out.Holds[i].ID.String() < out.Holds[j].ID.String() })
		return nil
	})
	return out, err
}

// CurrentHolds is AppliedHolds after a linearizable read: it first waits (ReadIndex, the same
// wait View makes) until this node has applied every control command that was committed when the
// call began, so a hold whose placement was acknowledged before the call is in the answer, and
// only then reads the applied state. It is what the erasing path asks right before it takes the
// engine lock (storage.EraseCandidate.Sync): the local-only AppliedHolds cannot see a hold that
// committed in the control group and has not been applied on this node yet. It fails closed: a
// node that cannot confirm it is current (no leader, partitioned, group failed) returns the
// error and the caller erases nothing.
func (s *Store) CurrentHolds(ctx context.Context, prev HoldSnapshot) (HoldSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return prev, err
	}
	if s.repl != nil {
		if _, err := s.repl.group.ReadIndex(ctx); err != nil {
			return prev, replicaFaultUnder(ctx, err)
		}
	}
	return s.AppliedHolds(prev)
}

// ControlLogPolicy says what ExpireControlLog may drop from the control log (design section 12,
// bounded control state). Zero values of the command bounds take the D4 retry-table bounds.
type ControlLogPolicy struct {
	// Now is the pass's clock.
	Now time.Time
	// AuditDays is the audit retention in days (365 by default). An organization's own "audit"
	// retention setting (admin retention command, signal audit) can only lengthen it for that
	// organization: an administrator cannot shorten the record of their own actions.
	AuditDays uint32
	// CommandWindow and CommandMax bound the applied-command log (Commands, CommandOwners): an
	// entry lives CommandWindow (default and ceiling replica.DefaultRetryWindow, 24 h: the revision
	// clock keeps that much history) or until the log holds more than CommandMax entries (default
	// replica.DefaultRetryMax), oldest first, whichever bounds first. A retry older than that is
	// answered as a fresh command, which the expected-revision rule rejects.
	CommandWindow time.Duration
	CommandMax    int
}

// ControlLogReport is what one expiry pass dropped (or, for a pass that found nothing, zeros).
type ControlLogReport struct {
	Audits   int // audit entries older than their organization's audit retention
	Commands int // applied commands older than the dedup window, and orphaned owner rows
	Capped   int // applied commands dropped by the count bound, oldest first
}

func (r ControlLogReport) none() bool { return r == ControlLogReport{} }

// revisionStampEvery is the finest age resolution of the applied-command log: the update funnel
// adds a RevisionClock stamp only when the newest one is at least this old.
const revisionStampEvery = time.Minute

// noteRevisionTime is the update funnel's stamp (replicatedUpdate), called with the state whose
// Revision is the one being committed: it records (Revision, now) when the newest stamp is at
// least revisionStampEvery old (the first update of a state that has none, a legacy state, stamps
// at once), then drops every stamp older than the dedup window except the newest of them, which
// stays as the anchor "everything up to this revision is at least that old". The clock holds at
// most about a window's worth of minutes, whatever the traffic and whether or not an expiry pass
// ever runs. A clock that moves backwards only delays the next stamp.
func noteRevisionTime(st *State, now int64) {
	if n := len(st.RevisionClock); n > 0 && now < st.RevisionClock[n-1].At+int64(revisionStampEvery) {
		return
	}
	st.RevisionClock = append(st.RevisionClock, model.RevisionStamp{Revision: st.Revision, At: now})
	cutoff := now - int64(replica.DefaultRetryWindow)
	drop := 0
	for drop+1 < len(st.RevisionClock) && st.RevisionClock[drop+1].At < cutoff {
		drop++
	}
	if drop > 0 {
		st.RevisionClock = append(st.RevisionClock[:0], st.RevisionClock[drop:]...)
	}
}

// auditDays is the audit retention that applies to an organization's audits: the default, or the
// longest "audit" retention setting the organization's administrators stored (never shorter).
func auditDays(st *State, org string, floor uint32) uint32 {
	days := floor
	o, ok := st.Orgs[org]
	if !ok {
		return days
	}
	for key, raw := range o.Settings {
		if !strings.HasPrefix(key, "retention:") {
			continue
		}
		var cfg auth.RetentionConfig
		if json.Unmarshal(raw, &cfg) == nil && cfg.Signal == "audit" && cfg.Days > days {
			days = cfg.Days
		}
	}
	return days
}

// expireControlLog applies the policy to st in place and reports what it dropped. It is a pure
// function of (st, policy): nothing reads a clock or a map order, so the planning read and the
// committing update compute the same answer from the same state.
//
// Never expired: the erasing and scrubbing audits (their ordinals and counts are the control
// scrub, journal-residue and attestation accounting, and are bounded by the permanent deletion
// tombstones), and audits with no time (nothing to age them by).
func expireControlLog(st *State, p ControlLogPolicy) ControlLogReport {
	var rep ControlLogReport
	now := p.Now.UnixNano()

	if len(st.Audits) > 0 {
		perOrg := map[string]int64{} // org -> oldest retained audit time (ns)
		kept := st.Audits[:0]
		for _, a := range st.Audits {
			exempt := a.Action == controlErasedAction || a.Action == controlScrubbedAction || a.Time <= 0
			if !exempt {
				cutoff, ok := perOrg[a.Org]
				if !ok {
					cutoff = now - int64(auditDays(st, a.Org, p.AuditDays))*int64(24*time.Hour)
					perOrg[a.Org] = cutoff
				}
				if a.Time < cutoff {
					rep.Audits++
					continue
				}
			}
			kept = append(kept, a)
		}
		if rep.Audits > 0 {
			clear(st.Audits[len(kept):]) // the dropped tail must not keep the dropped entries reachable
			st.Audits = kept
		}
	}

	window := p.CommandWindow
	if window <= 0 || window > replica.DefaultRetryWindow {
		window = replica.DefaultRetryWindow
	}
	limit := p.CommandMax
	if limit <= 0 {
		limit = replica.DefaultRetryMax
	}
	drop := func(id string) {
		delete(st.Commands, id)
		delete(st.CommandOwners, id)
	}
	// The newest revision the clock proves is older than the window: a command at or below it was
	// committed no later than that stamp. A command above the newest stamp has no upper bound on
	// its age yet and stays; so does one with no revision (nothing to date it by).
	cutoff := now - int64(window)
	var cut model.Revision
	for _, stamp := range st.RevisionClock {
		if stamp.At < cutoff && stamp.Revision > cut {
			cut = stamp.Revision
		}
	}
	if cut > 0 {
		for id, c := range st.Commands {
			if c.Revision != 0 && c.Revision <= cut {
				drop(id)
				rep.Commands++
			}
		}
	}
	if over := len(st.Commands) - limit; over > 0 {
		type aged struct {
			id       string
			revision model.Revision
		}
		all := make([]aged, 0, len(st.Commands))
		for id, c := range st.Commands {
			all = append(all, aged{id, c.Revision})
		}
		sort.Slice(all, func(i, j int) bool {
			if all[i].revision != all[j].revision {
				return all[i].revision < all[j].revision
			}
			return all[i].id < all[j].id
		})
		for _, c := range all[:over] {
			drop(c.id)
			rep.Capped++
		}
	}
	// The owner row of a command that is gone would otherwise stay forever.
	for id := range st.CommandOwners {
		if _, ok := st.Commands[id]; !ok {
			delete(st.CommandOwners, id)
			rep.Commands++
		}
	}
	return rep
}

// ExpireControlLog drops what the policy no longer keeps from the control log: audits older than
// their organization's audit retention and applied commands past the dedup window or the count
// bound. It reads the log first and commits nothing when nothing is due, so an idle installation
// pays one linearizable read. The commit leaves AuthorityRevision alone (writerExpireControlLog):
// it removes log rows and nothing an access decision reads, and the replay protection of an id the
// log forgot is the expected-revision rule, not the log.
func (s *Store) ExpireControlLog(ctx context.Context, p ControlLogPolicy) (ControlLogReport, error) {
	if p.Now.IsZero() || p.AuditDays == 0 {
		return ControlLogReport{}, model.Fail(model.Invalid)
	}
	var plan ControlLogReport
	if err := s.View(ctx, func(st State) error { plan = expireControlLog(&st, p); return nil }); err != nil {
		return ControlLogReport{}, err
	}
	if plan.none() {
		return plan, nil
	}
	var out ControlLogReport
	err := s.updateAs(ctx, writerExpireControlLog, func(st *State) error {
		out = expireControlLog(st, p)
		if out.none() {
			return errNothingToSettle // another voter's pass expired it first: commit nothing
		}
		return nil
	})
	if errors.Is(err, errNothingToSettle) {
		return ControlLogReport{}, nil
	}
	return out, err
}
