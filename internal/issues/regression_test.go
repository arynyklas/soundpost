// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package issues_test

import (
	"reflect"
	"soundpost/internal/issues"
	"soundpost/internal/model"
	"soundpost/internal/releases"
	"strings"
	"testing"
)

func TestRegressionDecision(t *testing.T) {
	org, project := model.NewID(), model.NewID()
	a, b, c, d, missing, foreign := model.NewID(), model.NewID(), model.NewID(), model.NewID(), model.NewID(), model.NewID()
	rel := func(id model.ID, project model.ID, parents ...model.ID) releases.Release {
		return releases.Release{ID: id, Org: org, Project: project, BuildID: id, Parents: parents}
	}
	graph := releases.Graph{a: rel(a, project), b: rel(b, project, a), c: rel(c, project, b), d: rel(d, project, a), foreign: rel(foreign, model.NewID())}
	resolvedAt := model.UnixNano(100)
	resolved := func(frontier, fixed []model.ID) issues.Issue {
		return issues.Issue{ID: model.NewID(), Org: org, Project: project, Workflow: "resolved", ResolutionTime: &resolvedAt, ResolutionFrontier: frontier, FixedDescendants: fixed}
	}
	evidence := func(release *model.ID, ancestry string, at model.UnixNano) issues.Evidence {
		return issues.Evidence{OccurrenceID: model.NewID(), RecordID: model.NewID(), Origin: model.Cursor{Group: model.NewID(), Index: 1}, EventTime: at, ReleaseID: release, Ancestry: ancestry}
	}
	for _, tt := range []struct {
		name          string
		issue         issues.Issue
		evidence      issues.Evidence
		eligible      bool
		ancestryKnown bool
		frontier      []model.ID
		reason        string
	}{
		{"open issue", issues.Issue{Workflow: "open"}, evidence(&c, "known", 150), false, true, nil, "not resolved"},
		{"ignored issue", issues.Issue{Workflow: "ignored"}, evidence(&c, "known", 150), false, true, nil, "ignored"},
		{"at the boundary is history", resolved([]model.ID{a}, []model.ID{b}), evidence(&c, "known", 100), false, true, []model.ID{b}, "boundary"},
		{"before the boundary is history", resolved([]model.ID{a}, []model.ID{b}), evidence(&c, "known", 90), false, true, []model.ID{b}, "boundary"},
		{"older than the fix frontier", resolved([]model.ID{a}, []model.ID{b}), evidence(&a, "known", 150), false, true, []model.ID{b}, "fix"},
		{"concurrent with the fix frontier", resolved([]model.ID{a}, []model.ID{b}), evidence(&d, "known", 150), false, true, []model.ID{b}, "fix"},
		{"the fix release itself", resolved([]model.ID{a}, []model.ID{b}), evidence(&b, "known", 150), true, true, []model.ID{b}, "fix"},
		{"descendant of the fix", resolved([]model.ID{a}, []model.ID{b}), evidence(&c, "known", 150), true, true, []model.ID{b}, "fix"},
		{"ancestor of a later fix", resolved([]model.ID{a}, []model.ID{c}), evidence(&b, "known", 150), false, true, []model.ID{c}, "fix"},
		{"no fix frontier: observed release recurs", resolved([]model.ID{a}, nil), evidence(&a, "known", 150), true, true, []model.ID{a}, "observed"},
		{"no fix frontier: descendant of observed", resolved([]model.ID{a}, nil), evidence(&c, "known", 150), true, true, []model.ID{a}, "observed"},
		{"no fix frontier: concurrent of observed", resolved([]model.ID{c}, nil), evidence(&d, "known", 150), false, true, []model.ID{c}, "observed"},
		{"release missing from the graph", resolved([]model.ID{a}, []model.ID{b}), evidence(&missing, "known", 150), true, false, []model.ID{b}, "ancestry unknown"},
		{"release of another project", resolved([]model.ID{a}, []model.ID{b}), evidence(&foreign, "known", 150), true, false, []model.ID{b}, "ancestry unknown"},
		{"source says ancestry unknown", resolved([]model.ID{a}, []model.ID{b}), evidence(&c, "unknown", 150), true, false, []model.ID{b}, "ancestry unknown"},
		{"unversioned evidence", resolved([]model.ID{a}, []model.ID{b}), evidence(nil, "unknown", 150), true, false, []model.ID{b}, "ancestry unknown"},
		{"unknown ancestry before the boundary", resolved([]model.ID{a}, []model.ID{b}), evidence(&missing, "known", 90), false, false, []model.ID{b}, "boundary"},
		{"no frontier at all follows the boundary", resolved(nil, nil), evidence(&c, "known", 150), true, false, nil, "ancestry unknown"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := issues.Regresses(tt.issue, tt.evidence, graph)
			if got.Eligible != tt.eligible || got.AncestryKnown != tt.ancestryKnown || !strings.Contains(got.Reason, tt.reason) || !(len(got.Frontier) == 0 && len(tt.frontier) == 0 || reflect.DeepEqual(got.Frontier, tt.frontier)) {
				t.Fatalf("decision %+v, want eligible=%v known=%v frontier=%v reason containing %q", got, tt.eligible, tt.ancestryKnown, tt.frontier, tt.reason)
			}
		})
	}
	// The decision is a pure function of stored facts: lexical or time order of release IDs never matters.
	first := issues.Regresses(resolved([]model.ID{a}, []model.ID{b}), evidence(&c, "known", 150), graph)
	second := issues.Regresses(resolved([]model.ID{a}, []model.ID{b}), evidence(&c, "known", 150), graph)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("decision is not deterministic")
	}
	// The decision must not alias the issue's own frontier slice.
	issue := resolved([]model.ID{a}, []model.ID{b})
	got := issues.Regresses(issue, evidence(&c, "known", 150), graph)
	got.Frontier[0] = model.NewID()
	if issue.FixedDescendants[0] != b {
		t.Fatal("decision aliased issue state")
	}
}
