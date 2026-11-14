// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package releases_test

import (
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/releases"
	"strings"
	"testing"
)

type releaseTestClock struct{ at model.UnixNano }

func (c *releaseTestClock) Now() model.UnixNano { return c.at }

func TestReleaseAuditUsesActionClockAndRequestCorrelation(t *testing.T) {
	f := setupReleaseFixture(t)
	clock := &releaseTestClock{at: 1000}
	service, e := releases.New(f.app.Control, f.app.Auth, clock)
	if e != nil {
		t.Fatal(e)
	}
	release := releases.Release{ID: model.NewID(), Org: f.org, Project: f.project, BuildID: model.NewID(), BuildTime: 0, DisplayLabel: "original"}
	command, request := model.NewID(), model.NewID()
	ctx := model.WithRequestID(context.Background(), request)
	release, e = service.Register(ctx, f.scope, release, f.revision(t), command)
	if e != nil {
		t.Fatal(e)
	}
	clock.at = 2000
	renameCommand, renameRequest := model.NewID(), model.NewID()
	release.DisplayLabel = "renamed"
	if _, e = service.Register(model.WithRequestID(context.Background(), renameRequest), f.scope, release, f.revision(t), renameCommand); e != nil {
		t.Fatal(e)
	}
	old := model.GroupingIssue{ID: model.NewID(), Org: f.org, Project: f.project, GroupingVersion: 1, Fingerprint: model.Hash{1}, Workflow: "open", Revision: 1}
	if e = f.app.Control.Update(ctx, func(st *model.ControlState) error {
		if st.GroupingIssues == nil {
			st.GroupingIssues = map[string]model.GroupingIssue{}
		}
		st.GroupingIssues[model.ReleaseScopeKey(f.org, f.project, old.ID)] = old
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	clock.at = 3000
	migrationCommand, migrationRequest := model.NewID(), model.NewID()
	migration := model.GroupingMigration{ID: model.NewID(), Org: f.org, Project: f.project, From: old.ID, To: model.NewID(), FromRevision: 1, GroupingVersion: 2, Fingerprint: model.Hash{2}, Reason: "audited grouping upgrade", At: 25}
	if _, e = service.MigrateGrouping(model.WithRequestID(context.Background(), migrationRequest), f.scope, migration, f.revision(t), migrationCommand); e != nil {
		t.Fatal(e)
	}
	clock.at = 4000
	if _, e = service.MigrateGrouping(context.Background(), f.scope, migration, 0, migrationCommand); e != nil {
		t.Fatal(e)
	}
	expected := map[model.ID]struct {
		at      int64
		request model.ID
		action  string
	}{command: {1000, request, "releases.register"}, renameCommand: {2000, renameRequest, "releases.register"}, migrationCommand: {3000, migrationRequest, "issues.grouping_migration"}}
	seen := map[model.ID]bool{}
	if e = f.app.Control.View(ctx, func(st model.ControlState) error {
		for _, audit := range st.Audits {
			want, ok := expected[audit.ID]
			if !ok {
				continue
			}
			if seen[audit.ID] {
				t.Fatal("command replay duplicated an action audit")
			}
			seen[audit.ID] = true
			if audit.Time != want.at || audit.RequestID != want.request || audit.Action != want.action {
				t.Fatalf("action audit misdated/miscorrelated: %#v want %#v", audit, want)
			}
		}
		if len(seen) != len(expected) {
			t.Fatalf("missing action audits: got %d want %d", len(seen), len(expected))
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

func TestReleaseLeafDigestsUseCanonicalHex(t *testing.T) {
	id := model.NewID()
	digest := model.Hash{0xab}
	for _, fixture := range []struct {
		value any
		field string
	}{
		{model.ReleaseDebugArtifact{ArtifactID: id, SHA256: digest}, "sha256"},
		{model.GroupingEvidence{OccurrenceID: id, RecordID: id, Origin: model.Cursor{Group: id}, Fingerprint: digest}, "fingerprint"},
		{model.GroupingIssue{ID: id, Org: id, Project: id, Fingerprint: digest}, "fingerprint"},
		{model.GroupingMigration{ID: id, Org: id, Project: id, From: id, To: id, Fingerprint: digest}, "fingerprint"},
	} {
		encoded, e := json.Marshal(fixture.value)
		if e != nil {
			t.Fatal(e)
		}
		var object map[string]json.RawMessage
		if e = json.Unmarshal(encoded, &object); e != nil {
			t.Fatal(e)
		}
		var got string
		if e = json.Unmarshal(object[fixture.field], &got); e != nil {
			t.Fatalf("digest was not a hex string: %s", object[fixture.field])
		}
		if got != "ab"+strings.Repeat("0", 62) {
			t.Fatalf("noncanonical digest: %s", got)
		}
	}
}
