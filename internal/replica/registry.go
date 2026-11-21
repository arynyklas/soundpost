// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"github.com/arynyklas/soundpost/internal/model"
)

// Node is the injected consensus facade shared by storage, control and workers;
// each operation routes to the one installed Group, never another data backend.
type Node struct{ groups map[model.ID]*Group }

func NewNode(groups []*Group) (*Node, error) {
	node := &Node{groups: make(map[model.ID]*Group, len(groups))}
	for _, group := range groups {
		if group == nil || node.groups[group.group] != nil {
			return nil, ErrInvalid
		}
		node.groups[group.group] = group
	}
	return node, nil
}
func (n *Node) Group(id model.ID) (*Group, error) {
	if n == nil || n.groups[id] == nil {
		return nil, ErrUnavailable
	}
	return n.groups[id], nil
}
func (n *Node) Propose(ctx context.Context, id model.ID, entry Entry) (CommittedEntry, error) {
	group, err := n.Group(id)
	if err != nil {
		return CommittedEntry{}, err
	}
	return group.Propose(ctx, entry)
}
func (n *Node) ReadIndex(ctx context.Context, id model.ID) (model.Cursor, error) {
	group, err := n.Group(id)
	if err != nil {
		return model.Cursor{}, err
	}
	return group.ReadIndex(ctx)
}
func (n *Node) ChangeMembers(ctx context.Context, id model.ID, expected model.Revision, next Members) error {
	group, err := n.Group(id)
	if err != nil {
		return err
	}
	return group.ChangeMembers(ctx, expected, next)
}
