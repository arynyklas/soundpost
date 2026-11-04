// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package releases_test

import (
	"soundpost/internal/model"
	"soundpost/internal/releases"
	"testing"
)

func TestReleasePartialOrder(t *testing.T) {
	org, project := model.NewID(), model.NewID()
	root, left, right, missing, unknown := model.NewID(), model.NewID(), model.NewID(), model.NewID(), model.NewID()
	graph := releases.Graph{
		root:    {ID: root, Org: org, Project: project, BuildID: root, DisplayLabel: "v9"},
		left:    {ID: left, Org: org, Project: project, BuildID: left, Parents: []model.ID{root}, DisplayLabel: "v10"},
		right:   {ID: right, Org: org, Project: project, BuildID: right, Parents: []model.ID{root}},
		unknown: {ID: unknown, Org: org, Project: project, BuildID: unknown, Parents: []model.ID{missing}},
	}
	for _, tt := range []struct {
		a, b model.ID
		want releases.Order
	}{{root, root, releases.Same}, {root, left, releases.Ancestor}, {left, root, releases.Descendant}, {left, right, releases.Concurrent}, {root, missing, releases.Unknown}, {root, unknown, releases.Unknown}, {missing, missing, releases.Unknown}} {
		if got := releases.Relation(graph, tt.a, tt.b); got != tt.want {
			t.Fatalf("relation(%s,%s)=%s want %s", tt.a, tt.b, got, tt.want)
		}
	}
	foreign := graph[right]
	foreign.Project = model.NewID()
	graph[right] = foreign
	if releases.Relation(graph, left, right) != releases.Unknown {
		t.Fatal("cross-project graph lookup disclosed relation")
	}
	graph[root] = releases.Release{ID: root, Org: org, Project: project, BuildID: root, Parents: []model.ID{left}}
	if releases.Relation(graph, root, left) != releases.Unknown {
		t.Fatal("corrupt cycle asserted ancestry")
	}
}
