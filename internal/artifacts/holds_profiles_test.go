// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts_test

import (
	"context"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/artifacts/refledger"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

func profileHold(profile model.ID, until model.UnixNano, roots ...artifacts.ArtifactID) artifacts.ProfileHold {
	return artifacts.ProfileHold{Profile: profile, Roots: roots, Until: until}
}

func (f *lifeFx) profileEntries(t *testing.T, a artifacts.Artifact) []refledger.Entry {
	t.Helper()
	led := f.ledgerOf(t, a)
	if led == nil {
		return nil
	}
	var out []refledger.Entry
	for _, e := range led.Entries {
		if e.Kind == refledger.KindProfile {
			out = append(out, e)
		}
	}
	return out
}

// HoldProfiles is the profile producer's entry (system issues.write over one project) and
// admits nothing else; malformed arguments are refused before any state changes.
func TestLifecycleProfileHoldsNeedTheSystemIssuesWriteScopeAndValidArguments(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	a := f.put(t, "profile-scope", false)
	profile := model.NewID()
	holds := []artifacts.ProfileHold{profileHold(profile, f.hours(48), a.ID)}
	for name, scope := range map[string]auth.Scope{
		"human artifacts.write": f.scope(t, auth.ArtifactWrite),
		"system telemetry.read": f.system(t, auth.Read),
		"system org.admin":      f.system(t, auth.OrgAdmin),
	} {
		if _, err := f.life.HoldProfiles(ctx, scope, holds); codeOf(err) != model.Forbidden {
			t.Errorf("%s: HoldProfiles answered %v", name, err)
		}
	}
	if f.ledgerOf(t, a) != nil {
		t.Fatal("a refused scope left a ledger behind")
	}
	sys := f.system(t, auth.IssuesWrite)
	for name, bad := range map[string][]artifacts.ProfileHold{
		"nothing":     nil,
		"zero id":     {profileHold(model.ID{}, f.hours(1), a.ID)},
		"no roots":    {profileHold(profile, f.hours(1))},
		"zero root":   {profileHold(profile, f.hours(1), model.ID{})},
		"no deadline": {profileHold(profile, 0, a.ID)},
		"too many":    {profileHold(profile, f.hours(1), manyRoots(refledger.MaxHolderRoots+1)...)},
	} {
		if _, err := f.life.HoldProfiles(ctx, sys, bad); codeOf(err) != model.Invalid {
			t.Errorf("%s: HoldProfiles answered %v", name, err)
		}
	}
}

// One entry per (profile, map); a repeat or a shorter hold writes nothing; a later chunk
// extends the same entry; the hold lapses by its own deadline and never shortens another
// holder's retention.
func TestLifecycleProfileHoldIsOneEntryPerProfileAndLapses(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	sys := f.system(t, auth.IssuesWrite)
	a := f.put(t, "profile-hold", false)
	profile := model.NewID()
	until := f.hours(48)
	res, err := f.life.HoldProfiles(ctx, sys, []artifacts.ProfileHold{profileHold(profile, until, a.ID, a.ID)})
	if err != nil || res.Held != 1 || res.Skipped != 0 {
		t.Fatalf("hold: %+v %v", res, err)
	}
	if got := f.effective(t, a); got != until {
		t.Fatalf("effective retention %d, want the profile deadline %d", got, until)
	}
	entries := f.profileEntries(t, a)
	if len(entries) != 1 || entries[0].Cursor.Group != profile || entries[0].Cursor.Index == 0 || entries[0].RetainUntil != until {
		t.Fatalf("entries: %+v", entries)
	}
	seq, rev := f.ledgerOf(t, a).Seq, f.revision(t)
	for name, h := range map[string]artifacts.ProfileHold{"the same hold": profileHold(profile, until, a.ID), "a shorter one": profileHold(profile, f.hours(24), a.ID)} {
		if res, err = f.life.HoldProfiles(ctx, sys, []artifacts.ProfileHold{h}); err != nil || res.Held != 1 {
			t.Fatalf("%s: %+v %v", name, res, err)
		}
		if f.ledgerOf(t, a).Seq != seq || f.revision(t) != rev {
			t.Fatalf("%s changed state", name)
		}
	}
	later := f.hours(72)
	if _, err = f.life.HoldProfiles(ctx, sys, []artifacts.ProfileHold{profileHold(profile, later, a.ID)}); err != nil {
		t.Fatal(err)
	}
	if got := f.effective(t, a); got != later || len(f.profileEntries(t, a)) != 1 {
		t.Fatalf("extension: effective %d (want %d), %d entries", got, later, len(f.profileEntries(t, a)))
	}
	// Another profile is its own entry; an error reference with a later deadline is not shortened.
	other := model.NewID()
	errUntil := f.hours(200)
	f.ref(t, a, f.origin(artifacts.ReferenceError), errUntil)
	if _, err = f.life.HoldProfiles(ctx, sys, []artifacts.ProfileHold{profileHold(other, f.hours(24), a.ID)}); err != nil {
		t.Fatal(err)
	}
	if got := f.effective(t, a); got != errUntil || len(f.profileEntries(t, a)) != 2 {
		t.Fatalf("a profile hold changed another holder's retention: effective %d, %d profile entries", got, len(f.profileEntries(t, a)))
	}
	// Past every deadline nothing retains the map and the fence is taken.
	f.at(300 * time.Hour)
	if got := f.latest(t, a); got != 0 {
		t.Fatalf("a lapsed profile hold still retains the map until %d", got)
	}
}

// What cannot be held is skipped, never an error and never revived: an unknown root, a root
// whose retention has elapsed, and a retired (fenced) root.
func TestLifecycleProfileHoldSkipsWhatCannotBeHeld(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	sys := f.system(t, auth.IssuesWrite)
	second := f.put(t, "profile-second", false)
	elapsed := f.put(t, "profile-elapsed", false)
	profile := model.NewID()
	f.at(30 * 24 * time.Hour) // past the upload deadline of every map above
	res, err := f.life.HoldProfiles(ctx, sys, []artifacts.ProfileHold{profileHold(profile, f.hours(24*60), second.ID, elapsed.ID, model.NewID())})
	if err != nil || res.Held != 0 || res.Skipped != 3 {
		t.Fatalf("skips: %+v %v", res, err)
	}
	if len(f.profileEntries(t, elapsed)) != 0 || len(f.profileEntries(t, second)) != 0 {
		t.Fatal("a late profile hold revived an elapsed map")
	}
}
