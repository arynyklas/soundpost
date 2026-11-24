// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/artifacts/refledger"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// The holds of the issue producer (holds.go): real application, real control state, real
// storage and a real system principal. The issue book is written straight into the control
// state (what the issue lifecycle commits), so each test names the workflow it needs.

func (f *lifeFx) system(t *testing.T, p auth.Permission) auth.Scope {
	t.Helper()
	s, err := f.app.Auth.AuthorizeSystem(context.Background(), f.org, []model.ID{f.project}, p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// setIssue commits an issue with the workflow into the book ("" removes it).
func (f *lifeFx) setIssue(t *testing.T, issue model.ID, workflow string) {
	t.Helper()
	if err := f.app.Control.Update(context.Background(), func(st *model.ControlState) error {
		if st.GroupingIssues == nil {
			st.GroupingIssues = map[string]model.GroupingIssue{}
		}
		key := model.ReleaseScopeKey(f.org, f.project, issue)
		if workflow == "" {
			delete(st.GroupingIssues, key)
			return nil
		}
		st.GroupingIssues[key] = model.GroupingIssue{ID: issue, Org: f.org, Project: f.project, Workflow: workflow}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func (f *lifeFx) ledgerOf(t *testing.T, a artifacts.Artifact) *refledger.Ledger {
	t.Helper()
	var out *refledger.Ledger
	if err := f.app.Control.View(context.Background(), func(st model.ControlState) (err error) {
		out, err = refledger.Load(st.Orgs[f.org.String()].Settings, f.project, a.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *lifeFx) holderOf(t *testing.T, issue model.ID) *refledger.Holder {
	t.Helper()
	var out *refledger.Holder
	if err := f.app.Control.View(context.Background(), func(st model.ControlState) (err error) {
		out, err = refledger.LoadHolder(st.Orgs[f.org.String()].Settings, f.project, issue)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *lifeFx) revision(t *testing.T) model.Revision {
	t.Helper()
	var rev model.Revision
	if err := f.app.Control.View(context.Background(), func(st model.ControlState) error { rev = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	return rev
}

func (f *lifeFx) effective(t *testing.T, a artifacts.Artifact) model.UnixNano {
	t.Helper()
	got, err := f.life.EffectiveRetention(context.Background(), f.scope(t, auth.ArtifactRead), a.ID)
	if err != nil {
		t.Fatalf("EffectiveRetention: %v", err)
	}
	return got
}

func hold(issue model.ID, until model.UnixNano, roots ...artifacts.ArtifactID) artifacts.IssueHold {
	return artifacts.IssueHold{Issue: issue, Roots: roots, Until: until}
}

// An open issue that groups occurrences naming a map holds it past the upload's own deadline;
// resolving the issue releases it; a reopening takes it again while the map is still retained
// and cannot revive one whose retention elapsed; the last release lets retention fence the map.
func TestLifecycleIssueHoldRetainsTheMapUntilTheIssueStopsBeingOpen(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	sys := f.system(t, auth.IssuesWrite)
	a := f.put(t, "held", false)
	issue := model.NewID()
	until := f.hours(48)

	res, err := f.life.HoldIssues(ctx, sys, []artifacts.IssueHold{hold(issue, until, a.ID)})
	if err != nil || res.Held != 1 || res.Skipped != 0 {
		t.Fatalf("hold: %+v %v", res, err)
	}
	if got := f.effective(t, a); got != until {
		t.Fatalf("effective retention %d, want the hold's deadline %d (the upload's own is %d)", got, until, a.Manifest.RetainUntil)
	}

	// Resolving the issue releases the hold.
	f.setIssue(t, issue, "resolved")
	res, err = f.life.SettleIssues(ctx, sys)
	if err != nil || res.Released != 1 || res.Held != 0 {
		t.Fatalf("settle after resolve: %+v %v", res, err)
	}
	if got := f.effective(t, a); got != a.Manifest.RetainUntil {
		t.Fatalf("a released map is retained until %d, want the upload's own %d", got, a.Manifest.RetainUntil)
	}
	if h := f.holderOf(t, issue); h == nil || h.Held || len(h.Roots) != 1 {
		t.Fatalf("the holder of a resolved issue: %+v", h)
	}
	// Settling again changes nothing and is not a control transaction.
	rev := f.revision(t)
	if res, err = f.life.SettleIssues(ctx, sys); err != nil || res != (artifacts.HoldResult{}) || f.revision(t) != rev {
		t.Fatalf("a second settle: %+v %v (revision %d -> %d)", res, err, rev, f.revision(t))
	}

	// A reopening takes the holds again (the map is still retained), with the recorded deadline.
	f.setIssue(t, issue, "open")
	if res, err = f.life.SettleIssues(ctx, sys); err != nil || res.Held != 1 || res.Released != 0 {
		t.Fatalf("settle after reopen: %+v %v", res, err)
	}
	if got := f.effective(t, a); got != until {
		t.Fatalf("a reopened issue holds the map until %d, want %d", got, until)
	}

	// Past the upload's own deadline the hold alone keeps the map: not fenced, not erasable.
	f.at(2 * time.Hour)
	if got := f.latest(t, a); got != until {
		t.Fatalf("a held map's latest reference is %d, want %d", got, until)
	}
	if f.ledgerOf(t, a).Retired {
		t.Fatal("a held map was fenced")
	}

	// Resolved for good: nothing retains the map any more, a reopening cannot revive it, the next
	// retention check fences it, and a fenced map takes no reference and is gone for its readers.
	f.setIssue(t, issue, "resolved")
	if res, err = f.life.SettleIssues(ctx, sys); err != nil || res.Released != 1 {
		t.Fatalf("final settle: %+v %v", res, err)
	}
	f.setIssue(t, issue, "open")
	if res, err = f.life.SettleIssues(ctx, sys); err != nil || res.Held != 0 || res.Skipped != 1 {
		t.Fatalf("a reopening revived an elapsed map: %+v %v", res, err)
	}
	if f.holderOf(t, issue) != nil {
		t.Fatal("the holder of a map that cannot be held again was kept")
	}
	if got := f.latest(t, a); got != 0 {
		t.Fatalf("a released, expired map answers %d, want 0 (erasable)", got)
	}
	if !f.ledgerOf(t, a).Retired {
		t.Fatal("the expired, released map was not fenced")
	}
	if err = f.life.Reference(ctx, f.scope(t, auth.ArtifactWrite), a.ID, f.origin(artifacts.ReferenceError), f.hours(5)); codeOf(err) != model.Conflict {
		t.Fatalf("a fenced map took a reference: %v", err)
	}
	if _, err = f.life.EffectiveRetention(ctx, f.scope(t, auth.ArtifactRead), a.ID); codeOf(err) != model.NotFound {
		t.Fatalf("a fenced map has an effective retention: %v", err)
	}
}

// A hold for an issue the book already knows to be resolved or ignored only records its maps (the
// producer holds before it applies the occurrences, and a regression applies them to a resolved
// issue before it reopens it): nothing retains the map past the upload's own deadline until the
// issue is open again, and then SettleIssues takes the recorded hold.
func TestLifecycleHoldOfAnIssueThatIsNotOpenOnlyRecordsItsMaps(t *testing.T) {
	for _, workflow := range []string{"resolved", "ignored"} {
		t.Run(workflow, func(t *testing.T) {
			f := newLifeFx(t, 1<<20)
			ctx := context.Background()
			sys := f.system(t, auth.IssuesWrite)
			a := f.put(t, "recorded", false)
			issue := model.NewID()
			f.setIssue(t, issue, workflow)
			until := f.hours(48)

			res, err := f.life.HoldIssues(ctx, sys, []artifacts.IssueHold{hold(issue, until, a.ID)})
			if err != nil || res.Held != 0 || res.Skipped != 0 {
				t.Fatalf("hold of a %s issue: %+v %v", workflow, res, err)
			}
			if got := f.effective(t, a); got != a.Manifest.RetainUntil {
				t.Fatalf("the map of a %s issue is retained until %d, want the upload's own %d", workflow, got, a.Manifest.RetainUntil)
			}
			if h := f.holderOf(t, issue); h == nil || h.Held || h.Until != until || len(h.Roots) != 1 {
				t.Fatalf("the recorded holder of a %s issue: %+v", workflow, h)
			}

			f.setIssue(t, issue, "open")
			if res, err = f.life.SettleIssues(ctx, sys); err != nil || res.Held != 1 || res.Released != 0 {
				t.Fatalf("settle after reopen: %+v %v", res, err)
			}
			if got := f.effective(t, a); got != until {
				t.Fatalf("a reopened issue holds the map until %d, want %d", got, until)
			}
		})
	}
}

// Another holder keeps the map when one issue lets go; an issue the book does not know keeps
// its holds until their deadline; a holder past its deadline is forgotten.
func TestLifecycleSettleKeepsOtherHoldersAndUnknownIssuesAndForgetsLapsedOnes(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	sys := f.system(t, auth.IssuesWrite)
	a := f.put(t, "shared", false)
	first, second, unknown := model.NewID(), model.NewID(), model.NewID()
	f.setIssue(t, first, "open")
	f.setIssue(t, second, "open")
	soon, late := f.hours(10), f.hours(20)
	if res, err := f.life.HoldIssues(ctx, sys, []artifacts.IssueHold{hold(first, late, a.ID), hold(second, soon, a.ID), hold(unknown, soon, a.ID)}); err != nil || res.Held != 3 {
		t.Fatalf("hold: %+v %v", res, err)
	}
	if got := f.effective(t, a); got != late {
		t.Fatalf("effective %d, want %d", got, late)
	}
	// The issue with the latest deadline resolves: the others still hold the map.
	f.setIssue(t, first, "ignored")
	if res, err := f.life.SettleIssues(ctx, sys); err != nil || res.Released != 1 {
		t.Fatalf("settle: %+v %v", res, err)
	}
	if got := f.effective(t, a); got != soon {
		t.Fatalf("effective %d after the longest holder let go, want the next one %d", got, soon)
	}
	if f.holderOf(t, unknown) == nil {
		t.Fatal("an issue the book does not know lost its holder")
	}
	// Past the deadline of the remaining holders they are forgotten; their ledger entries lapse by
	// themselves, and an issue the book never knew is forgotten the same way.
	f.at(11 * time.Hour)
	if res, err := f.life.SettleIssues(ctx, sys); err != nil || res.Released != 0 {
		t.Fatalf("settle after the deadline: %+v %v", res, err)
	}
	for name, issue := range map[string]model.ID{"second": second, "unknown": unknown} {
		if f.holderOf(t, issue) != nil {
			t.Errorf("the lapsed holder of the %s issue was kept", name)
		}
	}
	if f.holderOf(t, first) == nil {
		t.Error("the holder of the ignored issue (deadline not reached) was forgotten")
	}
}

// A map that cannot be held is skipped, never an error and never created: a name no published map
// has, a fenced map, a map whose retention already elapsed (a late hold cannot revive it).
func TestLifecycleHoldSkipsWhatCannotBeHeld(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	sys := f.system(t, auth.IssuesWrite)
	live, fenced, lapsed := f.put(t, "live", false), f.put(t, "fenced", false), f.put(t, "lapsed", false)
	bogus := model.NewID()
	issue := model.NewID()
	until := f.hours(100)
	res, err := f.life.HoldIssues(ctx, sys, []artifacts.IssueHold{hold(issue, until, live.ID, bogus)})
	if err != nil || res.Held != 1 || res.Skipped != 1 {
		t.Fatalf("live and bogus: %+v %v", res, err)
	}
	if h := f.holderOf(t, issue); h == nil || len(h.Roots) != 1 || h.Roots[0] != live.ID {
		t.Fatalf("the holder names a map it does not hold: %+v", h)
	}
	f.at(2 * time.Hour)
	if _, err = f.life.GC(ctx, f.scope(t, auth.ArtifactWrite), fenced.ID); err != nil {
		t.Fatal(err)
	}
	other := model.NewID()
	res, err = f.life.HoldIssues(ctx, sys, []artifacts.IssueHold{hold(other, until, fenced.ID, lapsed.ID)})
	if err != nil || res.Held != 0 || res.Skipped != 2 {
		t.Fatalf("fenced and lapsed: %+v %v", res, err)
	}
	if f.ledgerOf(t, lapsed) != nil {
		t.Fatal("a refused hold left a ledger behind")
	}
	if f.holderOf(t, other) != nil {
		t.Fatal("a hold of nothing left a holder behind")
	}
}

// Only the runner's system issues.write scope over the project may hold or settle; no human scope,
// no other system role, and the artifact lifecycle's own entry points refuse the system scope.
func TestLifecycleIssueHoldsNeedTheSystemIssuesWriteScope(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	a := f.put(t, "scope", false)
	issue := model.NewID()
	holds := []artifacts.IssueHold{hold(issue, f.hours(48), a.ID)}
	for name, scope := range map[string]auth.Scope{
		"human artifacts.write": f.scope(t, auth.ArtifactWrite),
		"human artifacts.read":  f.scope(t, auth.ArtifactRead),
		"system telemetry.read": f.system(t, auth.Read),
		"system org.admin":      f.system(t, auth.OrgAdmin),
	} {
		if _, err := f.life.HoldIssues(ctx, scope, holds); codeOf(err) != model.Forbidden {
			t.Errorf("%s: HoldIssues answered %v", name, err)
		}
		if _, err := f.life.SettleIssues(ctx, scope); codeOf(err) != model.Forbidden {
			t.Errorf("%s: SettleIssues answered %v", name, err)
		}
	}
	if f.ledgerOf(t, a) != nil {
		t.Fatal("a refused scope left a ledger behind")
	}
	sys := f.system(t, auth.IssuesWrite)
	if err := f.life.Reference(ctx, sys, a.ID, f.origin(artifacts.ReferenceError), f.hours(5)); codeOf(err) != model.NotFound {
		t.Errorf("Reference with the system scope: %v", err)
	}
	if _, err := f.life.GC(ctx, sys, a.ID); codeOf(err) != model.NotFound {
		t.Errorf("GC with the system scope: %v", err)
	}
	if err := f.life.Unreference(ctx, sys, a.ID, f.origin(artifacts.ReferenceError), 0); codeOf(err) != model.NotFound {
		t.Errorf("Unreference with the system scope: %v", err)
	}
	// Arguments.
	for name, bad := range map[string][]artifacts.IssueHold{
		"nothing":      nil,
		"zero issue":   {hold(model.ID{}, f.hours(1), a.ID)},
		"no roots":     {hold(issue, f.hours(1))},
		"zero root":    {hold(issue, f.hours(1), model.ID{})},
		"no deadline":  {hold(issue, 0, a.ID)},
		"too many map": {hold(issue, f.hours(1), manyRoots(artifacts.MaxHoldRoots+1)...)},
		"too many iss": manyIssues(artifacts.MaxHoldIssues+1, f.hours(1), a.ID),
	} {
		if _, err := f.life.HoldIssues(ctx, sys, bad); codeOf(err) != model.Invalid {
			t.Errorf("%s: HoldIssues answered %v", name, err)
		}
	}
}

func manyRoots(n int) []model.ID {
	out := make([]model.ID, n)
	for i := range out {
		out[i] = model.NewID()
	}
	return out
}

func manyIssues(n int, until model.UnixNano, root model.ID) []artifacts.IssueHold {
	out := make([]artifacts.IssueHold, n)
	for i := range out {
		out[i] = hold(model.NewID(), until+model.UnixNano(i), root)
	}
	return out
}

// A repeated hold, and one that would only shorten, changes nothing and is not a control
// transaction.
func TestLifecycleRepeatedIssueHoldIsNotACommit(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	sys := f.system(t, auth.IssuesWrite)
	a := f.put(t, "repeat", false)
	issue := model.NewID()
	f.setIssue(t, issue, "open")
	until := f.hours(48)
	if _, err := f.life.HoldIssues(ctx, sys, []artifacts.IssueHold{hold(issue, until, a.ID)}); err != nil {
		t.Fatal(err)
	}
	seq, rev := f.ledgerOf(t, a).Seq, f.revision(t)
	for name, h := range map[string]artifacts.IssueHold{"the same hold": hold(issue, until, a.ID), "a shorter one": hold(issue, f.hours(24), a.ID)} {
		res, err := f.life.HoldIssues(ctx, sys, []artifacts.IssueHold{h})
		if err != nil || res.Held != 1 {
			t.Fatalf("%s: %+v %v", name, res, err)
		}
		if f.ledgerOf(t, a).Seq != seq || f.revision(t) != rev {
			t.Fatalf("%s changed state: seq %d -> %d, revision %d -> %d", name, seq, f.ledgerOf(t, a).Seq, rev, f.revision(t))
		}
	}
	if got := f.effective(t, a); got != until {
		t.Fatalf("a shorter hold shortened retention to %d", got)
	}
	// A later deadline extends the same entry: still one hold of the issue.
	later := f.hours(72)
	if _, err := f.life.HoldIssues(ctx, sys, []artifacts.IssueHold{hold(issue, later, a.ID)}); err != nil {
		t.Fatal(err)
	}
	if got, led := f.effective(t, a), f.ledgerOf(t, a); got != later || len(led.Entries) != 1 {
		t.Fatalf("extension: effective %d (want %d), %d entries", got, later, len(led.Entries))
	}
}

// One entry per (issue, map): a hot map named by more issues than a ledger holds does not wedge
// the producer, and folding makes room without ever shortening retention.
func TestLifecycleIssueHoldsAreOneEntryPerIssueAndBounded(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	sys := f.system(t, auth.IssuesWrite)
	a := f.put(t, "hot", false)
	const issueCount = refledger.MaxEntries + 76
	base := f.hours(24)
	ids := make([]model.ID, 0, issueCount)
	var largest model.UnixNano
	for len(ids) < issueCount {
		n := min(artifacts.MaxHoldIssues, issueCount-len(ids))
		batch := make([]artifacts.IssueHold, n)
		for i := range batch {
			until := base + model.UnixNano(len(ids)+i)*model.UnixNano(time.Minute)
			largest = until
			batch[i] = hold(model.NewID(), until, a.ID)
		}
		res, err := f.life.HoldIssues(ctx, sys, batch)
		if err != nil || res.Held != n || res.Skipped != 0 {
			t.Fatalf("batch at %d: %+v %v", len(ids), res, err)
		}
		for _, h := range batch {
			ids = append(ids, h.Issue)
		}
	}
	led := f.ledgerOf(t, a)
	if len(led.Entries) >= refledger.MaxEntries+1 || len(led.Entries) == 0 {
		t.Fatalf("%d issues left %d ledger entries", issueCount, len(led.Entries))
	}
	if led.Floor == 0 {
		t.Fatal("no entry was folded")
	}
	if got := f.effective(t, a); got != largest {
		t.Fatalf("folding changed the effective retention to %d, want the largest deadline %d", got, largest)
	}
	// Releasing a folded issue cannot shorten retention below the others' deadlines.
	f.setIssue(t, ids[0], "resolved")
	if _, err := f.life.SettleIssues(ctx, sys); err != nil {
		t.Fatal(err)
	}
	if got := f.effective(t, a); got != largest {
		t.Fatalf("releasing one of %d issues moved the effective retention to %d", issueCount, got)
	}
}

// A hold, the release of another issue's hold and the GC fence racing on one map whose upload
// deadline has passed: whichever commits first wins, and a map is never both fenced and held.
func TestLifecycleIssueHoldRacesReleaseAndGCFence(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	sys := f.system(t, auth.IssuesWrite)
	write := f.scope(t, auth.ArtifactWrite)
	until := f.hours(100)
	var held, fenced, neither int
	for round := range 8 {
		a := f.put(t, "race"+string(rune('a'+round)), false)
		first := model.NewID()
		f.setIssue(t, first, "open")
		if _, err := f.life.HoldIssues(ctx, sys, []artifacts.IssueHold{hold(first, until, a.ID)}); err != nil {
			t.Fatal(err)
		}
		f.at(2 * time.Hour) // the upload's own deadline is over: only holds keep the map
		f.setIssue(t, first, "resolved")
		var wg sync.WaitGroup
		var res artifacts.HoldResult
		var holdErr, settleErr, gcErr error
		start := make(chan struct{})
		wg.Add(3)
		go func() {
			defer wg.Done()
			<-start
			res, holdErr = f.life.HoldIssues(ctx, sys, []artifacts.IssueHold{hold(model.NewID(), until, a.ID)})
		}()
		go func() {
			defer wg.Done()
			<-start
			_, settleErr = f.life.SettleIssues(ctx, sys)
		}()
		go func() {
			defer wg.Done()
			<-start
			_, gcErr = f.life.GC(ctx, write, a.ID)
		}()
		close(start)
		wg.Wait()
		if holdErr != nil || settleErr != nil {
			t.Fatalf("round %d: hold %v, settle %v", round, holdErr, settleErr)
		}
		led := f.ledgerOf(t, a)
		switch {
		case gcErr == nil && res.Held == 0 && led.Retired:
			fenced++
		case gcErr != nil && codeOf(gcErr) != model.Conflict:
			t.Fatalf("round %d: GC answered %v", round, gcErr)
		case gcErr != nil && res.Held == 1 && !led.Retired:
			held++
		case gcErr != nil && res.Held == 0 && !led.Retired:
			neither++ // the GC ran while the first issue still held the map, then the release made the second hold too late
		default:
			t.Fatalf("round %d: GC %v, hold %+v, fenced %v: the map is both fenced and held, or the answers disagree", round, gcErr, res, led.Retired)
		}
		f.at(0)
	}
	t.Logf("the second hold won %d rounds, the fence won %d, neither %d", held, fenced, neither)
}

// The issue holds read the workflow of the issues of one project on every pass of the issue producer, and a pass that finds nothing to change is a read:
// it must be the decode of the control state that every shared reader uses (and the project's own issues), never a decode of the whole blob of its own.
func TestIssueHoldPassesDoNotDecodeTheControlBlob(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	sys := f.system(t, auth.IssuesWrite)
	a := f.put(t, "held", false)
	issue := model.NewID()
	until := f.hours(48)
	f.setIssue(t, issue, "open")
	if res, err := f.life.HoldIssues(ctx, sys, []artifacts.IssueHold{hold(issue, until, a.ID)}); err != nil || res.Held != 1 {
		t.Fatalf("hold: %+v %v", res, err)
	}
	for range 2 { // the second settle proves it is idle; what these decode is shared by the rest
		if _, err := f.life.SettleIssues(ctx, sys); err != nil {
			t.Fatal(err)
		}
	}
	rev := f.revision(t)
	before := f.app.Control.DecodeStats()
	for range 10 {
		if res, err := f.life.SettleIssues(ctx, sys); err != nil || res != (artifacts.HoldResult{}) {
			t.Fatalf("an idle settle: %+v %v", res, err)
		}
		if res, err := f.life.HoldIssues(ctx, sys, []artifacts.IssueHold{hold(issue, until, a.ID)}); err != nil {
			t.Fatalf("a repeated hold: %+v %v", res, err)
		}
	}
	if got := f.app.Control.DecodeStats().Blobs - before.Blobs; got != 0 {
		t.Fatalf("20 issue-hold passes decoded the whole blob %d times, want never", got)
	}
	if f.revision(t) != rev {
		t.Fatal("an idle pass committed")
	}
}
