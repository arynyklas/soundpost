// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"context"
	"github.com/arynyklas/soundpost/internal/artifacts/refledger"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"slices"
)

// Issue holds: the producer side of reference retention.
//
// The issue producer groups the error occurrences a source ingested into issues. An occurrence
// names the source maps that resolve its frames (Frame.Artifact is the canonical artifact ID).
// The producer runs under the in-process system principal (D1), which holds issues.write and
// cannot hold artifacts.write, so it does not use Reference: it keeps one HOLD per (issue, map)
// instead. A hold is a ledger entry of kind issue whose cursor is the issue alone, so a hot
// fingerprint with a million occurrences costs one entry per map, not one per occurrence, and
// whose deadline rolls forward with the latest occurrence (the occurrence's record retention):
// the map is kept until the last retained record that uses it expires, exactly as the retention
// design asks, and an issue that stops occurring stops holding it.
//
// A hold lasts while its issue is open. SettleIssues (called by the producer every pass) reads
// the committed issue book in the same control transaction it changes the ledgers in, releases
// the holds of an issue that was resolved or ignored, and takes them again if it reopens. A
// release only ever shortens retention to the other holders' deadlines, never below the map's
// own upload deadline.

// The bounds of one HoldIssues call (one control transaction): distinct maps over all its
// issues, and issues. The producer splits a batch into calls that fit.
const (
	MaxHoldRoots  = 64
	MaxHoldIssues = 256
)

// IssueHold names the maps an issue's new occurrences use.
type IssueHold struct {
	Issue model.ID
	Roots []ArtifactID
	// Until is the latest deadline of the retained records that use the maps: the holds
	// last until then at the latest (clamped to MaxReferenceRetention).
	Until model.UnixNano
}

// HoldResult counts what a HoldIssues or SettleIssues call did.
type HoldResult struct {
	Held     int // map holds taken or extended
	Released int // map holds dropped because their issue is no longer open
	// Skipped counts maps that cannot be held: not a published map of the project, retired,
	// deleted, already past its retention (a late hold cannot revive it), over the per-issue
	// bound or with no room left in a full ledger. A map the occurrence merely names but
	// that does not exist is not an error.
	Skipped int
	// More reports that SettleIssues stopped at its per-call bound: call it again.
	More bool
}

// settleBound is how many holders one SettleIssues call changes.
const settleBound = 32

// holdScope admits only the system principal's issues.write scope over exactly one project,
// validated against the state the transaction changes.
func holdScope(scope auth.Scope, st model.ControlState) (org, project model.ID, err error) {
	if !scope.IsSystem() || scope.Permission() != auth.IssuesWrite || len(scope.ProjectIDs()) != 1 {
		return org, project, model.Fail(model.Forbidden)
	}
	if err = scope.ValidateControlState(st); err != nil {
		return org, project, err
	}
	return scope.OrgID(), scope.ProjectIDs()[0], nil
}

// holdSet is the ledgers a call changes.
type holdSet struct {
	st      model.ControlState
	org     model.ID
	project model.ID
	now     model.UnixNano
	ledgers map[model.ID]*refledger.Ledger
	changed map[model.ID]bool
}

// ledger returns the verified ledger of a root (nil when it has none), loaded once.
func (h *holdSet) ledger(root model.ID) (*refledger.Ledger, error) {
	if led, ok := h.ledgers[root]; ok {
		return led, nil
	}
	led, err := refledger.Load(h.st.Orgs[h.org.String()].Settings, h.project, root)
	if err != nil {
		return nil, err
	}
	h.ledgers[root] = led
	return led, nil
}

func (h *holdSet) key(root model.ID) string {
	return h.org.String() + ":" + h.project.String() + ":" + root.String()
}

func issueOrigin(issue model.ID) model.Cursor { return model.Cursor{Group: issue} }

// take adds or extends the issue's hold on one map. It reports false when the map cannot be
// held; an error is only a ledger that does not verify.
func (h *holdSet) take(issue, root model.ID, until model.UnixNano) (bool, error) {
	return h.hold(refledger.KindIssue, issueOrigin(issue), root, until)
}

// hold adds or extends the entry (kind, cursor) on one map: the shared core of an issue's hold
// and a profile's.
func (h *holdSet) hold(kind string, cursor model.Cursor, root model.ID, until model.UnixNano) (bool, error) {
	intent, ok := h.st.ArtifactIntents[h.key(root)]
	if !ok || intent.State != intentPublished || deletionCovers(h.st, intent.Map.Manifest) {
		return false, nil
	}
	led, err := h.ledger(root)
	if err != nil {
		return false, err
	}
	if led == nil {
		led = &refledger.Ledger{Project: h.project, Root: root}
		h.ledgers[root] = led
	}
	if led.Retired || max(intent.Manifest.RetainUntil, led.Latest()) <= h.now {
		return false, nil // fenced, or retention already elapsed: a late hold cannot revive it
	}
	i := slices.IndexFunc(led.Entries, func(e refledger.Entry) bool {
		return e.Kind == kind && e.Cursor == cursor
	})
	if i >= 0 {
		if until > led.Entries[i].RetainUntil {
			led.Entries[i].RetainUntil = until
			h.changed[root] = true
		}
		return true, nil
	}
	if !led.MakeRoom(h.now) {
		return false, nil
	}
	led.Entries = append(led.Entries, refledger.Entry{Kind: kind, Cursor: cursor, RetainUntil: until})
	h.changed[root] = true
	return true, nil
}

// drop removes the issue's hold on one map and reports whether there was one.
func (h *holdSet) drop(issue, root model.ID) (bool, error) {
	led, err := h.ledger(root)
	if err != nil || led == nil || led.Retired {
		return false, err
	}
	kept := led.Entries[:0]
	removed := false
	for _, e := range led.Entries {
		if e.Kind == refledger.KindIssue && e.Cursor == issueOrigin(issue) {
			removed = true
			continue
		}
		kept = append(kept, e)
	}
	led.Entries = kept
	if removed {
		h.changed[root] = true
	}
	return removed, nil
}

// plan turns the changed ledgers (Seq advanced) and the holder writes into a plan.
func (h *holdSet) plan(put map[model.ID]refledger.Holder, del []model.ID) plan {
	p := plan{project: h.project, putHolders: put, delHolders: del}
	roots := make([]model.ID, 0, len(h.changed))
	for root := range h.changed {
		roots = append(roots, root)
	}
	slices.SortFunc(roots, func(a, b model.ID) int { return slices.Compare(a[:], b[:]) })
	for _, root := range roots {
		led := h.ledgers[root]
		led.Seq++
		p.ledgers = append(p.ledgers, led)
	}
	return p
}

// issueWorkflow is the workflow of an issue in the committed state: known is false for an
// issue that is not in the book (not yet applied, erased, or grouped under another ID).
func issueWorkflow(st model.ControlState, org, project, issue model.ID) (workflow string, known bool) {
	gi, ok := st.GroupingIssues[model.ReleaseScopeKey(org, project, issue)]
	return gi.Workflow, ok
}

// HoldIssues takes the issues' holds on the maps their new occurrences name, in one control
// transaction, before the occurrences are applied to the issue book: a map is held before the
// first occurrence that needs it is counted, so no applied occurrence names an unheld map. An
// issue that is already known and is not open (resolved or ignored) only has its roots and
// deadline recorded; SettleIssues takes the holds if it reopens. Idempotent: a repeat, or a
// replay after a crash, extends nothing that is already held.
//
// scope is the runner's system issues.write scope over exactly one project.
func (l *Lifecycle) HoldIssues(ctx context.Context, scope auth.Scope, holds []IssueHold) (HoldResult, error) {
	distinct := map[model.ID]bool{}
	for _, h := range holds {
		if h.Issue == (model.ID{}) || len(h.Roots) == 0 || h.Until <= 0 {
			return HoldResult{}, model.Fail(model.Invalid)
		}
		for _, r := range h.Roots {
			if r == (model.ID{}) {
				return HoldResult{}, model.Fail(model.Invalid)
			}
			distinct[r] = true
		}
	}
	if len(holds) == 0 || len(holds) > MaxHoldIssues || len(distinct) > MaxHoldRoots {
		return HoldResult{}, model.Fail(model.Invalid)
	}
	var out HoldResult
	err := l.run(ctx, scope.OrgID(), false, func(st model.ControlState, now model.UnixNano) (plan, error) {
		out = HoldResult{}
		org, project, err := holdScope(scope, st)
		if err != nil {
			return plan{}, err
		}
		h := &holdSet{st: st, org: org, project: project, now: now, ledgers: map[model.ID]*refledger.Ledger{}, changed: map[model.ID]bool{}}
		put := map[model.ID]refledger.Holder{}
		var del []model.ID
		for _, hold := range holds {
			until := min(hold.Until, now+model.UnixNano(MaxReferenceRetention))
			prior, err := refledger.LoadHolder(settingsOf(st, org), project, hold.Issue)
			if err != nil { // an advisory record that does not parse is replaced
				prior = nil
			}
			next := refledger.Holder{Until: until}
			var roots []model.ID
			if prior != nil {
				next.Held, next.Until = prior.Held, max(prior.Until, until)
				roots = slices.Clone(prior.Roots)
			}
			roots = append(roots, hold.Roots...)
			workflow, known := issueWorkflow(st, org, project, hold.Issue)
			open := !known || workflow == "open"
			seen := map[model.ID]bool{}
			var kept []model.ID
			for _, root := range roots {
				if seen[root] {
					continue
				}
				seen[root] = true
				if len(kept) >= refledger.MaxHolderRoots {
					out.Skipped++
					continue
				}
				if open {
					ok, err := h.take(hold.Issue, root, next.Until)
					if err != nil {
						return plan{}, err
					}
					if !ok {
						out.Skipped++
						continue
					}
					out.Held++
				}
				kept = append(kept, root)
			}
			next.Roots = kept
			if open {
				next.Held = true
			}
			switch {
			case len(kept) > 0:
				if prior == nil || prior.Held != next.Held || prior.Until != next.Until || !slices.Equal(prior.Roots, next.Roots) {
					put[hold.Issue] = next // a repeat that changes nothing writes nothing
				}
			case prior != nil:
				del = append(del, hold.Issue)
			}
		}
		return h.plan(put, del), nil
	})
	return out, err
}

// SettleIssues reconciles the project's holds with the committed issue book, in one control
// transaction: the holds of an issue that is resolved or ignored are dropped, the holds of one
// that reopened are taken again (with the deadline recorded, never extended), and a holder
// whose deadline has passed is forgotten (its ledger entries lapse by themselves). An issue
// the book does not know keeps its holds until their deadline. It changes at most settleBound
// holders per call (More reports the rest) and commits nothing when nothing changed.
//
// scope is the runner's system issues.write scope over exactly one project.
func (l *Lifecycle) SettleIssues(ctx context.Context, scope auth.Scope) (HoldResult, error) {
	var out HoldResult
	err := l.run(ctx, scope.OrgID(), false, func(st model.ControlState, now model.UnixNano) (plan, error) {
		out = HoldResult{}
		org, project, err := holdScope(scope, st)
		if err != nil {
			return plan{}, err
		}
		type entry struct {
			issue  model.ID
			holder *refledger.Holder
			bad    bool
		}
		var list []entry
		refledger.EachHolder(settingsOf(st, org), project, func(issue model.ID, h *refledger.Holder, err error) {
			if issue != (model.ID{}) {
				list = append(list, entry{issue, h, err != nil})
			}
		})
		slices.SortFunc(list, func(a, b entry) int { return slices.Compare(a.issue[:], b.issue[:]) })
		h := &holdSet{st: st, org: org, project: project, now: now, ledgers: map[model.ID]*refledger.Ledger{}, changed: map[model.ID]bool{}}
		put := map[model.ID]refledger.Holder{}
		var del []model.ID
		changes := 0
		for _, e := range list {
			if changes >= settleBound {
				out.More = true
				break
			}
			switch {
			case e.bad || e.holder.Until <= now:
				del = append(del, e.issue) // advisory: the ledger entries lapse by their own deadline
				changes++
				continue
			}
			workflow, known := issueWorkflow(st, org, project, e.issue)
			if !known {
				continue
			}
			open := workflow == "open"
			switch {
			case open && !e.holder.Held:
				next := *e.holder
				kept := next.Roots[:0:0]
				for _, root := range e.holder.Roots {
					ok, err := h.take(e.issue, root, e.holder.Until)
					if err != nil {
						return plan{}, err
					}
					if ok {
						kept = append(kept, root)
						out.Held++
					} else {
						out.Skipped++
					}
				}
				next.Roots, next.Held = kept, true
				if len(kept) == 0 {
					del = append(del, e.issue)
				} else {
					put[e.issue] = next
				}
				changes++
			case !open && e.holder.Held:
				for _, root := range e.holder.Roots {
					removed, err := h.drop(e.issue, root)
					if err != nil {
						return plan{}, err
					}
					if removed {
						out.Released++
					}
				}
				next := *e.holder
				next.Held = false
				put[e.issue] = next
				changes++
			}
		}
		return h.plan(put, del), nil
	})
	return out, err
}

// MaxHoldProfiles bounds the profiles of one HoldProfiles call (one control transaction).
const MaxHoldProfiles = 256

// ProfileHold names the maps the retained chunks of one profile use. A profile is one root of
// the profile signal (ProfileChunk.Profile): all its chunks share one entry per map, so a
// profile of many chunks costs one ledger entry per map, not one per chunk.
type ProfileHold struct {
	Profile model.ID
	Roots   []ArtifactID
	// Until is the latest deadline of the retained chunks that use the maps (clamped to
	// MaxReferenceRetention).
	Until model.UnixNano
}

// profileOrigin is the canonical ledger cursor of a profile's hold: the profile root, index 1
// (profile entries must carry a non-zero index, refledger.ValidOrigin).
func profileOrigin(profile model.ID) model.Cursor { return model.Cursor{Group: profile, Index: 1} }

// HoldProfiles is the profile side of HoldIssues: it keeps the maps the frames of retained
// profile chunks name until the profile's retention deadline, under the system principal's
// issues.write scope (the runner's closed role set has no artifacts.write, D1), so a profile
// that names a map keeps it readable for symbolication as long as the profile itself is
// retained. A profile is not an issue: nothing releases the hold early; it is a ledger entry
// of kind profile that lapses by its own deadline. Idempotent: a repeat, or a replay after a
// crash, extends nothing that is already held and writes nothing.
//
// A map that cannot be held (not a published map of the project, retired, deleted, already
// past its retention, or a ledger with no room left) is counted in Skipped, never an error.
func (l *Lifecycle) HoldProfiles(ctx context.Context, scope auth.Scope, holds []ProfileHold) (HoldResult, error) {
	distinct := map[model.ID]bool{}
	for _, h := range holds {
		if h.Profile == (model.ID{}) || len(h.Roots) == 0 || len(h.Roots) > refledger.MaxHolderRoots || h.Until <= 0 {
			return HoldResult{}, model.Fail(model.Invalid)
		}
		for _, r := range h.Roots {
			if r == (model.ID{}) {
				return HoldResult{}, model.Fail(model.Invalid)
			}
			distinct[r] = true
		}
	}
	if len(holds) == 0 || len(holds) > MaxHoldProfiles || len(distinct) > MaxHoldRoots {
		return HoldResult{}, model.Fail(model.Invalid)
	}
	var out HoldResult
	err := l.run(ctx, scope.OrgID(), false, func(st model.ControlState, now model.UnixNano) (plan, error) {
		out = HoldResult{}
		org, project, err := holdScope(scope, st)
		if err != nil {
			return plan{}, err
		}
		h := &holdSet{st: st, org: org, project: project, now: now, ledgers: map[model.ID]*refledger.Ledger{}, changed: map[model.ID]bool{}}
		for _, hold := range holds {
			until := min(hold.Until, now+model.UnixNano(MaxReferenceRetention))
			seen := map[model.ID]bool{}
			for _, root := range hold.Roots {
				if seen[root] {
					continue
				}
				seen[root] = true
				ok, err := h.hold(refledger.KindProfile, profileOrigin(hold.Profile), root, until)
				if err != nil {
					return plan{}, err
				}
				if ok {
					out.Held++
				} else {
					out.Skipped++
				}
			}
		}
		return h.plan(nil, nil), nil
	})
	return out, err
}
