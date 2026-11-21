// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	raft "go.etcd.io/raft/v3"
	pb "go.etcd.io/raft/v3/raftpb"
)

type Member struct {
	ID            uint64 `json:"id,string"`
	Address       string `json:"address"`
	NodeIdentity  string `json:"node_identity"`
	FailureDomain string `json:"failure_domain"`
	Learner       bool   `json:"learner,omitempty"`
}
type Members struct {
	Revision model.Revision `json:"revision"`
	Nodes    []Member       `json:"nodes"`
}

func cloneMembers(m Members) Members {
	return Members{Revision: m.Revision, Nodes: append([]Member(nil), m.Nodes...)}
}

// FailureDomain is an operator-attested disk/node fault domain, not evidence that
// three processes on one host became three physical machines.
func ValidateMembers(m Members) error {
	if m.Revision == 0 || len(m.Nodes) == 0 || len(m.Nodes) > 9 {
		return ErrInvalid
	}
	ids := map[uint64]bool{}
	names := map[string]bool{}
	addresses := map[string]bool{}
	for _, n := range m.Nodes {
		u, err := url.Parse(n.Address)
		if n.ID == 0 || ids[n.ID] || n.NodeIdentity == "" || names[n.NodeIdentity] || n.FailureDomain == "" || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || addresses[n.Address] {
			return ErrInvalid
		}
		ids[n.ID] = true
		names[n.NodeIdentity] = true
		addresses[n.Address] = true
	}
	return ValidateFailureDomains(m)
}

// ValidateFailureDomains checks placement attestations independently of identity
// and URL parsing. It cannot manufacture physical-hardware qualification.
func ValidateFailureDomains(m Members) error {
	domains := map[string]bool{}
	voters := 0
	for _, member := range m.Nodes {
		if member.Learner {
			continue
		}
		voters++
		if member.FailureDomain == "" || domains[member.FailureDomain] {
			return ErrInvalid
		}
		domains[member.FailureDomain] = true
	}
	if voters != 1 && voters != 3 {
		return ErrInvalid
	}
	return nil
}

// ChangeMembers enters explicit joint consensus, waits for both voter sets to
// apply, and then leaves joint consensus. New voters must first be installed as
// learners and caught up through the current barrier (including source fences).
func (g *Group) ChangeMembers(ctx context.Context, expected model.Revision, next Members) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := ValidateMembers(next); err != nil {
		return err
	}
	if _, err := g.ReadIndex(ctx); err != nil {
		return err
	}
	g.mu.Lock()
	if g.members.Revision == next.Revision {
		old, _ := json.Marshal(sortedMembers(g.members))
		desired, _ := json.Marshal(sortedMembers(next))
		if !equalPayload(old, desired) {
			g.mu.Unlock()
			return ErrConflict
		}
		if len(g.conf.GetVotersOutgoing()) == 0 {
			g.mu.Unlock()
			return nil
		}
		if g.raw.BasicStatus().Lead != g.id {
			g.mu.Unlock()
			return ErrUnavailable
		}
		err := g.raw.ProposeConfChange(&pb.ConfChangeV2{})
		if err == nil {
			err = g.processReady()
		}
		g.mu.Unlock()
		if err != nil {
			return err
		}
		return g.waitMembership(ctx, next.Revision, false)
	}
	g.mu.Unlock()
	readiness := map[uint64]uint64{}
	before := g.Status()
	oldMembers := map[uint64]Member{}
	for _, member := range before.Members.Nodes {
		oldMembers[member.ID] = member
	}
	for _, member := range next.Nodes {
		old, exists := oldMembers[member.ID]
		if !member.Learner && (!exists || old.Learner) {
			if !exists || !old.Learner {
				return ErrStale
			}
			checker, ok := g.transport.(interface {
				CheckReadiness(context.Context, model.ID, uint64) (uint64, error)
			})
			if !ok {
				return ErrUnavailable
			}
			applied, err := checker.CheckReadiness(ctx, g.group, member.ID)
			if err != nil {
				return err
			}
			readiness[member.ID] = applied
		}
	}
	if err := ValidateMembers(next); err != nil {
		return err
	}
	_, err := g.ReadIndex(ctx)
	if err != nil {
		return err
	}
	g.mu.Lock()
	if g.failed || g.closed || g.members.Revision != expected || next.Revision != expected+1 || g.raw.BasicStatus().RaftState != raft.StateLeader || len(g.conf.GetVotersOutgoing()) != 0 {
		g.mu.Unlock()
		return ErrConflict
	}
	current := map[uint64]Member{}
	for _, n := range g.members.Nodes {
		current[n.ID] = n
	}
	desired := map[uint64]Member{}
	status := g.raw.Status()
	physicalCut := status.HardState.GetCommit()
	changes := []*pb.ConfChangeSingle{}
	for _, n := range next.Nodes {
		desired[n.ID] = n
		old, exists := current[n.ID]
		if exists && (old.NodeIdentity != n.NodeIdentity || old.FailureDomain != n.FailureDomain) {
			g.mu.Unlock()
			return ErrConflict
		}
		if !n.Learner && (!exists || old.Learner) {
			p, ok := status.Progress[n.ID]
			if !ok || p.Match < physicalCut || readiness[n.ID] < physicalCut {
				g.mu.Unlock()
				return ErrStale
			}
		}
		if !exists || old.Learner != n.Learner {
			typ := pb.ConfChangeAddNode
			if n.Learner {
				typ = pb.ConfChangeAddLearnerNode
			}
			changes = append(changes, &pb.ConfChangeSingle{Type: typ.Enum(), NodeId: new(n.ID)})
		}
	}
	for id := range current {
		if _, ok := desired[id]; !ok {
			changes = append(changes, &pb.ConfChangeSingle{Type: pb.ConfChangeRemoveNode.Enum(), NodeId: new(id)})
		}
	}
	if len(changes) == 0 {
		g.mu.Unlock()
		return ErrInvalid
	}
	raw, err := json.Marshal(next)
	if err != nil {
		g.mu.Unlock()
		return err
	}
	err = g.raw.ProposeConfChange(&pb.ConfChangeV2{Transition: pb.ConfChangeTransitionJointExplicit.Enum(), Changes: changes, Context: raw})
	if err == nil {
		err = g.processReady()
	}
	g.mu.Unlock()
	if err != nil {
		return err
	}
	if err = g.waitMembership(ctx, next.Revision, true); err != nil {
		return err
	}
	g.mu.Lock()
	if g.raw.BasicStatus().RaftState != raft.StateLeader {
		g.mu.Unlock()
		return ErrUnavailable
	}
	err = g.raw.ProposeConfChange(&pb.ConfChangeV2{})
	if err == nil {
		err = g.processReady()
	}
	g.mu.Unlock()
	if err != nil {
		return err
	}
	return g.waitMembership(ctx, next.Revision, false)
}
func (g *Group) waitMembership(ctx context.Context, revision model.Revision, joint bool) error {
	for {
		g.mu.Lock()
		if g.failed || g.closed {
			g.mu.Unlock()
			return ErrUnavailable
		}
		if g.members.Revision == revision && (len(g.conf.GetVotersOutgoing()) > 0) == joint {
			g.mu.Unlock()
			return nil
		}
		changed := g.changed
		g.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ErrStale
		}
	}
}
func (g *Group) Ready(ctx context.Context) error { _, err := g.ReadIndex(ctx); return err }
func sortedMembers(m Members) Members {
	out := cloneMembers(m)
	sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].ID < out.Nodes[j].ID })
	return out
}
