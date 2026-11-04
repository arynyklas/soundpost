// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package releases

import "soundpost/internal/model"

type Release = model.Release
type DebugArtifact = model.ReleaseDebugArtifact
type Graph map[model.ID]Release
type Order string

const (
	Same       Order = "same"
	Ancestor   Order = "ancestor"
	Descendant Order = "descendant"
	Concurrent Order = "concurrent"
	Unknown    Order = "unknown"
)

// Relation uses only immutable parent edges within one scope. Missing ancestors
// and corrupt cycles remain unknown, never lexical/time-based order.
func Relation(graph Graph, a, b model.ID) Order {
	left, ok := graph[a]
	if !ok || left.ID != a {
		return Unknown
	}
	right, ok := graph[b]
	if !ok || right.ID != b || left.Org != right.Org || left.Project != right.Project || left.Org == (model.ID{}) || left.Project == (model.ID{}) {
		return Unknown
	}
	aa, ok := ancestors(graph, a, left.Org, left.Project)
	if !ok {
		return Unknown
	}
	bb, ok := ancestors(graph, b, left.Org, left.Project)
	if !ok {
		return Unknown
	}
	if a == b {
		return Same
	}
	if bb[a] {
		return Ancestor
	}
	if aa[b] {
		return Descendant
	}
	return Concurrent
}
func ancestors(graph Graph, start, org, project model.ID) (map[model.ID]bool, bool) {
	type visit struct {
		id   model.ID
		exit bool
	}
	stack := []visit{{id: start}}
	colors := map[model.ID]uint8{}
	out := map[model.ID]bool{}
	for len(stack) > 0 {
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if item.exit {
			colors[item.id] = 2
			continue
		}
		if colors[item.id] == 1 {
			return nil, false
		}
		if colors[item.id] == 2 {
			continue
		}
		release, ok := graph[item.id]
		if !ok || release.ID != item.id || release.Org != org || release.Project != project {
			return nil, false
		}
		colors[item.id] = 1
		out[item.id] = true
		stack = append(stack, visit{id: item.id, exit: true})
		for _, parent := range release.Parents {
			stack = append(stack, visit{id: parent})
		}
	}
	return out, true
}
