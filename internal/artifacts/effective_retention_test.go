// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/artifacts/refledger"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

func detailOf(err error) string {
	var fault *model.Fault
	if errors.As(err, &fault) {
		return fault.SafeDetail
	}
	return ""
}

// D-new C07 end to end on the real application and real storage: a map whose upload deadline has
// passed stays readable (lookup, streamed bytes, windowed reads) exactly as long as a reference
// retains it, and an unreferenced sibling or a released reference is refused with the typed
// reason. The deadlines are real: the uploads are short, the test waits for them.
func TestLifecycleReferencedMapStaysReadableAfterItsUploadDeadline(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	raw := []byte(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA"}`)
	put := func(debug string, retain time.Duration) artifacts.Artifact {
		t.Helper()
		m := f.manifest(raw)
		m.DebugID, m.Path = debug, "dist/"+debug+".js"
		m.RetainUntil = model.UnixNano(time.Now().Add(retain).UnixNano())
		a, err := f.app.Artifacts.Put(ctx, f.scope(t, auth.ArtifactWrite), m, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	const short = 2 * time.Second
	referenced, bare := put("referenced", short), put("bare", short)
	origin := f.origin(artifacts.ReferenceError)
	f.ref(t, referenced, origin, f.hours(1))
	read := f.scope(t, auth.ArtifactRead)
	body := func(a artifacts.Artifact) ([]byte, error) {
		rc, err := f.app.Artifacts.Get(ctx, read, a.ID)
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}
	for _, a := range []artifacts.Artifact{referenced, bare} {
		if got, err := body(a); err != nil || len(got) == 0 {
			t.Fatalf("setup: a map within its retention is unreadable: %v", err)
		}
	}
	time.Sleep(time.Until(time.Unix(0, int64(referenced.Manifest.RetainUntil))) + 300*time.Millisecond)

	// The referenced map is readable by every path: Lookup, Get, a window, and its effective
	// retention is the reference's, not the upload's.
	if got, err := body(referenced); err != nil || len(got) == 0 {
		t.Fatalf("a referenced map past its upload deadline is unreadable: %v", err)
	}
	r, err := f.app.Artifacts.ReadAuthorized(ctx, read, referenced.ID, artifacts.Window{Offset: 1, Length: 5})
	if err != nil {
		t.Fatalf("windowed read of a referenced map: %v", err)
	}
	if chunk, rerr := io.ReadAll(r); rerr != nil || len(chunk) != 5 {
		t.Fatalf("window: %d bytes, %v", len(chunk), rerr)
	}
	r.Close()
	if _, err = f.app.Artifacts.Lookup(ctx, read, referenced.ID); err != nil {
		t.Fatalf("lookup of a referenced map: %v", err)
	}
	if got := f.effective(t, referenced); got <= referenced.Manifest.RetainUntil {
		t.Fatalf("effective retention %d does not exceed the upload's own %d", got, referenced.Manifest.RetainUntil)
	}

	// The unreferenced sibling is refused with the typed reason, on every path.
	for name, call := range map[string]func() error{
		"Get":    func() error { _, e := f.app.Artifacts.Get(ctx, read, bare.ID); return e },
		"Lookup": func() error { _, e := f.app.Artifacts.Lookup(ctx, read, bare.ID); return e },
		"Window": func() error {
			_, e := f.app.Artifacts.ReadAuthorized(ctx, read, bare.ID, artifacts.Window{})
			return e
		},
		"Effective": func() error { _, e := f.life.EffectiveRetention(ctx, read, bare.ID); return e },
	} {
		if err := call(); codeOf(err) != model.NotFound || detailOf(err) != auth.ArtifactRetentionElapsed {
			t.Errorf("%s of an elapsed, unreferenced map answered %v (detail %q)", name, err, detailOf(err))
		}
	}

	// Releasing the only reference ends readability: the effective retention is the upload's again.
	if err = f.life.Unreference(ctx, f.scope(t, auth.ArtifactWrite), referenced.ID, origin, 0); err != nil {
		t.Fatal(err)
	}
	if _, err = body(referenced); codeOf(err) != model.NotFound || detailOf(err) != auth.ArtifactRetentionElapsed {
		t.Fatalf("a map whose only reference was released stayed readable: %v", err)
	}
}

// A per-organization and a per-project retention override change how long a reference with no
// deadline keeps its map, hence its effective retention; the latest audited version in force
// wins, a version not yet in force changes nothing, and the project beats the organization.
func TestLifecycleDefaultReferenceRetentionFollowsAuditedPolicy(t *testing.T) {
	f := newArtifactFixture(t)
	ctx := context.Background()
	life := f.app.ArtifactLifecycle
	if life == nil {
		t.Fatal("the application has no artifact lifecycle")
	}
	n := 0
	artifactWithDefaultReference := func() float64 {
		t.Helper()
		n++
		raw := []byte(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA"}`)
		m := f.manifest(raw)
		m.DebugID, m.Path = "policy"+string(rune('a'+n)), "dist/policy"+string(rune('a'+n))+".js"
		a, err := f.app.Artifacts.Put(ctx, f.scope(t, auth.ArtifactWrite), m, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		o := artifacts.OriginCursor{Kind: artifacts.ReferenceBuild, Cursor: model.Cursor{Group: model.NewID(), Index: 1}}
		if err = life.Reference(ctx, f.scope(t, auth.ArtifactWrite), a.ID, o, 0); err != nil {
			t.Fatal(err)
		}
		eff, err := life.EffectiveRetention(ctx, f.scope(t, auth.ArtifactRead), a.ID)
		if err != nil {
			t.Fatal(err)
		}
		return time.Until(time.Unix(0, int64(eff))).Hours() / 24
	}
	version := func(project *model.ID, days uint32, effective model.UnixNano) {
		t.Helper()
		key := f.org.String()
		if project != nil {
			key += ":" + project.String()
		}
		if err := f.app.Control.Update(ctx, func(st *model.ControlState) error {
			if st.RetentionPolicies == nil {
				st.RetentionPolicies = map[string][]model.RetentionPolicyVersion{}
			}
			st.RetentionPolicies[key] = append(st.RetentionPolicies[key], model.RetentionPolicyVersion{Org: f.org, Project: project,
				Version: model.Uint64(len(st.RetentionPolicies[key]) + 1), Artifacts: days, Effective: effective, Actor: model.NewID(), Reason: "policy fixture", At: 1})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	near := func(got, want float64) bool { return got > want-0.01 && got < want+0.01 }
	if got := artifactWithDefaultReference(); !near(got, 90) {
		t.Fatalf("no override: %.3f days, want the default 90", got)
	}
	version(nil, 30, 1)
	if got := artifactWithDefaultReference(); !near(got, 30) {
		t.Fatalf("organization override of 30 days: %.3f", got)
	}
	version(&f.project, 7, 1)
	if got := artifactWithDefaultReference(); !near(got, 7) {
		t.Fatalf("project override of 7 days: %.3f (the project beats the organization)", got)
	}
	version(&f.project, 14, 2)
	if got := artifactWithDefaultReference(); !near(got, 14) {
		t.Fatalf("a later project version of 14 days: %.3f", got)
	}
	version(&f.project, 3, model.UnixNano(time.Now().Add(24*time.Hour).UnixNano()))
	if got := artifactWithDefaultReference(); !near(got, 14) {
		t.Fatalf("a version not yet in force changed the retention: %.3f", got)
	}
}

// 09.04-W5 (race gap): a Reference of a map whose retention has already elapsed is refused whether
// or not retention has fenced it yet; it used to be accepted and was only harmless because reads
// ignored the ledger. A map still retained by another reference takes new ones.
func TestLifecycleReferenceOfAnElapsedUnfencedMapIsRefused(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	write := f.scope(t, auth.ArtifactWrite)
	elapsed, retained := f.put(t, "elapsed", false), f.put(t, "retained", false)
	f.ref(t, retained, f.origin(artifacts.ReferenceBuild), f.hours(4))

	f.at(2 * time.Hour) // past the upload deadline of both, before the fence is taken
	if err := f.life.Reference(ctx, write, elapsed.ID, f.origin(artifacts.ReferenceError), f.hours(5)); codeOf(err) != model.Conflict {
		t.Fatalf("a reference of an elapsed, unfenced map: %v", err)
	}
	if f.ledgerOf(t, elapsed) != nil {
		t.Fatal("a refused reference left a ledger behind")
	}
	if got := f.latest(t, elapsed); got != 0 {
		t.Fatalf("nothing retains the elapsed map yet its latest reference is %d", got)
	}
	// A map that a reference still retains is not elapsed, so it takes a further reference.
	if err := f.life.Reference(ctx, write, retained.ID, f.origin(artifacts.ReferenceError), f.hours(6)); err != nil {
		t.Fatalf("a retained map refused a reference: %v", err)
	}
	f.at(7 * time.Hour) // now its references have all lapsed too
	if err := f.life.Reference(ctx, write, retained.ID, f.origin(artifacts.ReferenceError), f.hours(9)); codeOf(err) != model.Conflict {
		t.Fatalf("a reference of a map whose references lapsed: %v", err)
	}
}

// 09.04-W5 (detection gap): a ledger removed together with its own entry in the project index used
// to read as "this map never had references". The anchor over the index bytes tells; every map of
// the project then fails closed (retention, GC, references, reads), and the original state
// restores service.
func TestLifecycleLedgerAndIndexEntryRemovalIsDetected(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	write := f.scope(t, auth.ArtifactWrite)
	a, b := f.put(t, "removed", false), f.put(t, "sibling", false)
	f.ref(t, a, f.origin(artifacts.ReferenceError), f.hours(4))
	f.ref(t, b, f.origin(artifacts.ReferenceBuild), f.hours(6))

	var good map[string]json.RawMessage
	if err := f.app.Control.View(ctx, func(st model.ControlState) error {
		good = map[string]json.RawMessage{}
		for k, v := range st.Orgs[f.org.String()].Settings {
			good[k] = append(json.RawMessage(nil), v...)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	set := func(mut func(map[string]json.RawMessage)) {
		t.Helper()
		if err := f.app.Control.Update(ctx, func(st *model.ControlState) error {
			o := st.Orgs[f.org.String()]
			settings := map[string]json.RawMessage{}
			for k, v := range good {
				settings[k] = v
			}
			mut(settings)
			o.Settings = settings
			st.Orgs[f.org.String()] = o
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	sameShard := a.ID[0] == b.ID[0] // the anchor of an index shard covers the roots of that shard
	expectFailClosed := func(name string) {
		t.Helper()
		calls := map[string]func() error{
			"LatestReference(removed)": func() error { _, e := f.life.LatestReference(ctx, f.candidate(a)); return e },
			"GC(removed)":              func() error { _, e := f.life.GC(ctx, write, a.ID); return e },
			"Reference(removed)": func() error {
				return f.life.Reference(ctx, write, a.ID, f.origin(artifacts.ReferenceError), f.hours(7))
			},
			"Unreference(removed)": func() error { return f.life.Unreference(ctx, write, a.ID, f.origin(artifacts.ReferenceError), 0) },
			"Lookup(removed)":      func() error { _, e := f.app.Artifacts.Lookup(ctx, f.scope(t, auth.ArtifactRead), a.ID); return e },
		}
		if sameShard {
			calls["LatestReference(sibling)"] = func() error { _, e := f.life.LatestReference(ctx, f.candidate(b)); return e }
			calls["Reference(sibling)"] = func() error {
				return f.life.Reference(ctx, write, b.ID, f.origin(artifacts.ReferenceError), f.hours(7))
			}
			calls["Unreference(sibling)"] = func() error {
				return f.life.Unreference(ctx, write, b.ID, f.origin(artifacts.ReferenceError), 0)
			}
			calls["Get(sibling)"] = func() error { _, e := f.app.Artifacts.Get(ctx, f.scope(t, auth.ArtifactRead), b.ID); return e }
		}
		for what, call := range calls {
			if err := call(); codeOf(err) != model.Corrupt {
				t.Errorf("%s: %s answered %v, want corrupt", name, what, err)
			}
		}
	}
	shardOf := func(settings map[string]json.RawMessage) map[string]refledger.IndexEntry {
		var idx map[string]refledger.IndexEntry
		if err := json.Unmarshal(settings[refledger.ShardIndexKey(f.project, a.ID)], &idx); err != nil {
			t.Fatal(err)
		}
		return idx
	}
	set(func(s map[string]json.RawMessage) {
		delete(s, refledger.LedgerKey(f.project, a.ID))
		idx := shardOf(s)
		delete(idx, a.ID.String())
		raw, err := json.Marshal(idx)
		if err != nil {
			t.Fatal(err)
		}
		s[refledger.ShardIndexKey(f.project, a.ID)] = raw
	})
	expectFailClosed("ledger and its index entry removed")

	set(func(s map[string]json.RawMessage) {
		delete(s, refledger.LedgerKey(f.project, a.ID))
		delete(s, refledger.ShardIndexKey(f.project, a.ID))
	})
	expectFailClosed("ledger and the whole index shard removed")

	set(func(s map[string]json.RawMessage) {
		idx := shardOf(s)
		idx[model.NewID().String()] = refledger.IndexEntry{Seq: 1}
		raw, _ := json.Marshal(idx)
		s[refledger.ShardIndexKey(f.project, a.ID)] = raw
	})
	expectFailClosed("an index entry added by hand")

	set(func(map[string]json.RawMessage) {})
	if got := f.latest(t, a); got < f.hours(4)-model.UnixNano(time.Minute) {
		t.Fatalf("the restored state is not honoured: %d", got)
	}
	if err := f.life.Reference(ctx, write, b.ID, f.origin(artifacts.ReferenceError), f.hours(7)); err != nil {
		t.Fatalf("service did not resume after the restore: %v", err)
	}
}
