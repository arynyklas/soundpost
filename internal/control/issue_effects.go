// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"sort"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// IssueOpAck is the acknowledgement arm of the issue lifecycle: effect intents a
// consumer has acted on leave the project's book. The book holds at most
// maxIssueEffects intents and a commit that would exceed it is refused as quota,
// so intents that are never acknowledged would wedge the regression commits that
// mint new ones.
const IssueOpAck = "ack_effects"

// IssueAck is the closed payload of the acknowledgement arm. There is no
// expected revision: an acknowledgement removes intents by ID inside the
// transaction and touches nothing else (no issue, ledger, checkpoint, command
// record or project revision), so it commutes with evidence commits.
type IssueAck struct {
	Operation string     `json:"operation"`
	Project   model.ID   `json:"project"`
	Ack       []model.ID `json:"ack"`
}

// applyIssueAck removes the named effect intents from the project's book. The
// scope is admitted exactly as an evidence commit is (issues.write on the
// project, or an organization administrator as a person), before anything about
// the book is looked up. An intent that is not in the book is skipped (a retried
// acknowledgement, or one erased by a deletion), so the arm is idempotent.
func applyIssueAck(scope auth.Scope, st *State, cmd Command) (Effect, error) {
	var c IssueAck
	if err := strictPayload(cmd.Payload, &c); err != nil {
		return Effect{}, err
	}
	if err := issueWriteScope(scope, st, c.Project); err != nil {
		return Effect{}, err
	}
	if len(c.Ack) == 0 || len(c.Ack) > maxIssueEffectsCommand || cmd.CommandID != IssueCommandID(cmd.Payload) {
		return Effect{}, model.Fail(model.Invalid)
	}
	named := make(map[model.ID]bool, len(c.Ack))
	for _, id := range c.Ack {
		if id == (model.ID{}) || named[id] {
			return Effect{}, model.Fail(model.Invalid)
		}
		named[id] = true
	}
	org := scope.OrgID()
	book, found, err := loadIssueBook(st, org, c.Project)
	if err != nil {
		return Effect{}, err
	}
	var removed []model.ID
	kept := make([]IssueEffect, 0, len(book.Effects))
	for _, e := range book.Effects {
		if named[e.ID] {
			removed = append(removed, e.ID)
			continue
		}
		kept = append(kept, e)
	}
	if !found || len(removed) == 0 {
		return Effect{AffectedIDs: []model.ID{}, Phase: "unchanged"}, nil
	}
	book.Effects = kept
	if len(kept) == 0 {
		book.Effects = nil
	}
	raw, err := json.Marshal(book)
	if err != nil {
		return Effect{}, model.Fail(model.Invalid)
	}
	st.IssueBooks[issueBookKey(org, c.Project)] = raw
	sort.Slice(removed, func(i, j int) bool { return string(removed[i][:]) < string(removed[j][:]) })
	return Effect{AffectedIDs: removed, Phase: "acked"}, nil
}
