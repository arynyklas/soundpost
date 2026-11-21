// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/artifacts/refledger"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// validateWithLedger runs the pure read/write predicate over the real control state with the
// organization's settings replaced by a private copy that mut may change; the stored state is
// never touched.
func (f *artifactDeletionFx) validateWithLedger(t *testing.T, scope auth.Scope, m model.BlobManifest, write bool, mut func(*model.ControlOrg)) error {
	t.Helper()
	var out error
	if err := f.app.Control.View(context.Background(), func(st model.ControlState) error {
		orgs := maps.Clone(st.Orgs)
		o := orgs[f.org.String()]
		o.Settings = maps.Clone(o.Settings)
		if mut != nil {
			mut(&o)
		}
		orgs[f.org.String()] = o
		st.Orgs = orgs
		out = scope.ValidateArtifactState(st, m, write)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func detailOf(err error) string {
	var fault *model.Fault
	if errors.As(err, &fault) {
		return fault.SafeDetail
	}
	return ""
}

// D-new C07 (owner decision, 10.09-W2): the read gate uses the artifact's EFFECTIVE retention,
// the later of the upload's own deadline and every unreleased reference, not the deadline stored
// in its manifest. Each case runs the very predicate every reader meets (Lookup, byte reads,
// symbolication, export, native profiles) against a real organization's control state with one
// artifact (map plus private sources) and a hand-built reference ledger.
func TestArtifactReadGateUsesEffectiveRetention(t *testing.T) {
	f := newArtifactDeletionFx(t)
	read, write := f.scope(t, auth.ArtifactRead), f.scope(t, auth.ArtifactWrite)
	now := time.Now()
	past := model.UnixNano(now.Add(-time.Minute).UnixNano())
	future := model.UnixNano(now.Add(48 * time.Hour).UnixNano())
	elapsed := func(m model.BlobManifest) model.BlobManifest { m.RetainUntil = past; return m }
	ledger := func(m model.BlobManifest, l refledger.Ledger) func(*model.ControlOrg) {
		return func(o *model.ControlOrg) {
			l.Project, l.Root, l.Seq = m.Project, m.Root, 1
			if err := refledger.Store(o, m.Project, &l); err != nil {
				t.Fatal(err)
			}
		}
	}
	entry := func(kind string, until model.UnixNano, released bool) refledger.Entry {
		c := model.Cursor{Group: model.NewID(), Index: 1}
		if kind == refledger.KindIssue {
			c.Index = 0
			released = false
		}
		return refledger.Entry{Kind: kind, Cursor: c, RetainUntil: until, Released: released}
	}
	type want struct {
		allowed bool
		code    model.Code
		detail  string
	}
	allowed := want{allowed: true}
	elapsedReason := want{code: model.NotFound, detail: auth.ArtifactRetentionElapsed}
	for _, blob := range []struct {
		name string
		m    model.BlobManifest
	}{{"map", f.art.Map.Manifest}, {"private sources", f.art.Sources.Manifest}} {
		m := blob.m
		for _, tc := range []struct {
			name string
			m    model.BlobManifest
			mut  func(*model.ControlOrg)
			want want
		}{
			{"within the upload's retention, no ledger", m, nil, allowed},
			{"upload retention elapsed, no ledger", elapsed(m), nil, elapsedReason},
			{"elapsed upload, live error reference", elapsed(m), ledger(m, refledger.Ledger{Entries: []refledger.Entry{entry(refledger.KindError, future, false)}}), allowed},
			{"elapsed upload, live build reference", elapsed(m), ledger(m, refledger.Ledger{Entries: []refledger.Entry{entry(refledger.KindBuild, future, false)}}), allowed},
			{"elapsed upload, live profile reference", elapsed(m), ledger(m, refledger.Ledger{Entries: []refledger.Entry{entry(refledger.KindProfile, future, false)}}), allowed},
			{"elapsed upload, open issue hold", elapsed(m), ledger(m, refledger.Ledger{Entries: []refledger.Entry{entry(refledger.KindIssue, future, false)}}), allowed},
			{"elapsed upload, the reference lapsed too", elapsed(m), ledger(m, refledger.Ledger{Entries: []refledger.Entry{entry(refledger.KindError, past, false)}}), elapsedReason},
			{"elapsed upload, the only reference was released", elapsed(m), ledger(m, refledger.Ledger{Entries: []refledger.Entry{entry(refledger.KindError, future, true)}}), elapsedReason},
			{"elapsed upload, one released and one live", elapsed(m), ledger(m, refledger.Ledger{Entries: []refledger.Entry{entry(refledger.KindError, future, true), entry(refledger.KindBuild, future, false)}}), allowed},
			{"elapsed upload, folded references keep a floor", elapsed(m), ledger(m, refledger.Ledger{Floor: future}), allowed},
			{"elapsed upload, an expired floor", elapsed(m), ledger(m, refledger.Ledger{Floor: past}), elapsedReason},
			{"a live reference never shortens a live upload", m, ledger(m, refledger.Ledger{Entries: []refledger.Entry{entry(refledger.KindError, past, false)}}), allowed},
			{"the GC fence refuses a live upload with live references", m, ledger(m, refledger.Ledger{Retired: true, Entries: []refledger.Entry{entry(refledger.KindError, future, false)}}), want{code: model.NotFound, detail: string(model.NotFound)}},
			{"a ledger that does not verify refuses even a live upload", m, func(o *model.ControlOrg) {
				o.Settings[refledger.LedgerKey(m.Project, m.Root)] = json.RawMessage(`{"Version":1}`)
			}, want{code: model.Corrupt, detail: string(model.Corrupt)}},
			{"another root's ledger extends nothing", elapsed(m), func(o *model.ControlOrg) {
				other := m
				other.Root = model.NewID()
				ledger(other, refledger.Ledger{Entries: []refledger.Entry{entry(refledger.KindError, future, false)}})(o)
			}, elapsedReason},
		} {
			err := f.validateWithLedger(t, read, tc.m, false, tc.mut)
			switch {
			case tc.want.allowed && err != nil:
				t.Errorf("%s / %s: refused: %v", blob.name, tc.name, err)
			case !tc.want.allowed && (faultCode(err) != tc.want.code || detailOf(err) != tc.want.detail):
				t.Errorf("%s / %s: got %v (code %q, detail %q), want code %q detail %q", blob.name, tc.name, err, faultCode(err), detailOf(err), tc.want.code, tc.want.detail)
			}
		}
	}

	// Writes are not read-gated: reserving, publishing and cleaning up do not consult the
	// reference ledger or the retention of an existing manifest.
	m := f.art.Map.Manifest
	broken := func(o *model.ControlOrg) {
		o.Settings[refledger.LedgerKey(m.Project, m.Root)] = json.RawMessage(`{"Version":1}`)
	}
	if err := f.validateWithLedger(t, write, m, true, broken); err != nil {
		t.Errorf("a write was refused by the reference ledger: %v", err)
	}
	if err := f.validateWithLedger(t, write, elapsed(m), true, nil); err != nil {
		t.Errorf("a write was refused by an elapsed manifest: %v", err)
	}

	// An elapsed map is only ever "retention elapsed" to a caller the scope covers; to anyone
	// else the artifact is simply absent, whatever its ledger says.
	foreign := m
	foreign.Org = model.NewID()
	if err := f.validateWithLedger(t, read, elapsed(foreign), false, broken); faultCode(err) != model.NotFound || detailOf(err) != string(model.NotFound) {
		t.Errorf("a manifest outside the scope answered %v (detail %q)", err, detailOf(err))
	}
}
