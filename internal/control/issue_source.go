// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"encoding/json"
	"sync/atomic"

	"github.com/arynyklas/soundpost/internal/model"
)

// The issues of one project as an issue commit reads and writes them (D84).
//
// A commit names the issues it changes (at most maxIssueRecords). Judging it needs those as they were, and of
// the other issues of the project three facts: how many there are (the per-project count), whether one of
// them already accounts for an occurrence the commit gives to a changed issue (one occurrence, one issue),
// and what they weigh together (the per-project byte bound). The whole-state funnel has every issue in memory
// and answers from the map; the sparse plan holds the project's issues as the records of the ledger and
// answers without decoding or encoding any issue it was not given: the count is a count of keys, the weight
// is the sum of the record lengths, and the occurrence is looked up in the raw bytes of the other records (its
// 32 hex digits, which only a record that accounts for it, or names it as something else, contains) and only
// a record that contains them is decoded. What one commit costs therefore follows the issues it writes, not
// the number or the size of the issues of its project.

type issueSource interface {
	// get returns the issue stored under key, decoded.
	get(key string) (model.GroupingIssue, bool, error)
	// size is how many issues the project holds.
	size() (int, error)
	// holder says which issue, other than the ones at the changed keys, accounts for the occurrence.
	holder(id model.ID, changed map[string]bool) (model.ID, bool, error)
	// otherBytes is the encoded size of the project's issues other than the ones at the changed keys.
	otherBytes(changed map[string]bool) (int, error)
	// put writes the issue at key; raw is its encoding.
	put(key string, gi model.GroupingIssue, raw []byte)
}

// issueDecodes and issueMarshals count the issue records a commit decoded and encoded (read by the tests that
// bound what a commit costs).
var issueDecodes, issueMarshals atomic.Uint64

func decodeIssue(raw []byte) (model.GroupingIssue, error) {
	issueDecodes.Add(1)
	var gi model.GroupingIssue
	if err := json.Unmarshal(raw, &gi); err != nil {
		return model.GroupingIssue{}, model.Fail(model.Corrupt)
	}
	return gi, nil
}

func marshalIssue(gi model.GroupingIssue) ([]byte, error) {
	issueMarshals.Add(1)
	return json.Marshal(gi)
}

// stateIssues is the project's issues in the decoded state (the whole-state funnel).
type stateIssues struct {
	st     *State
	issues map[string]model.GroupingIssue
	held   map[model.ID]model.ID
}

func newStateIssues(st *State, org, project model.ID) *stateIssues {
	return &stateIssues{st: st, issues: projectIssues(st, org, project)}
}

func (s *stateIssues) get(key string) (model.GroupingIssue, bool, error) {
	gi, ok := s.issues[key]
	return gi, ok, nil
}

func (s *stateIssues) size() (int, error) { return len(s.issues), nil }

func (s *stateIssues) holder(id model.ID, changed map[string]bool) (model.ID, bool, error) {
	if s.held == nil {
		s.held = map[model.ID]model.ID{}
		for key, gi := range s.issues {
			if changed[key] {
				continue
			}
			issueHeldIDs(gi, func(held model.ID) bool {
				s.held[held] = gi.ID
				return true
			})
		}
	}
	h, ok := s.held[id]
	return h, ok, nil
}

func (s *stateIssues) otherBytes(changed map[string]bool) (int, error) {
	total := 0
	for key, gi := range s.issues {
		if changed[key] {
			continue
		}
		raw, err := marshalIssue(gi)
		if err != nil {
			return 0, model.Fail(model.Invalid)
		}
		total += len(raw)
	}
	return total, nil
}

func (s *stateIssues) put(key string, gi model.GroupingIssue, _ []byte) {
	if s.st.GroupingIssues == nil {
		s.st.GroupingIssues = map[string]model.GroupingIssue{}
	}
	s.st.GroupingIssues[key] = gi
}

// ledgerIssues is the project's issues as records of the ledger (the sparse plan). prior keeps the bytes of
// each issue get decoded, so that the plan writes only what changed; written is what the commit put.
type ledgerIssues struct {
	l       *ledgerTx
	prefix  []byte
	org     model.ID
	project model.ID
	count   int
	counted bool
	prior   map[string][]byte
	written map[string][]byte
}

func newLedgerIssues(l *ledgerTx, org, project model.ID) *ledgerIssues {
	return &ledgerIssues{l: l, prefix: []byte(org.String() + ":" + project.String() + ":"), org: org, project: project, prior: map[string][]byte{}, written: map[string][]byte{}}
}

func (s *ledgerIssues) get(key string) (model.GroupingIssue, bool, error) {
	raw := s.l.t[tableGroupingIssues].Get([]byte(key))
	if raw == nil {
		return model.GroupingIssue{}, false, nil
	}
	gi, err := decodeIssue(raw)
	if err != nil {
		return model.GroupingIssue{}, false, err
	}
	if gi.Org != s.org || gi.Project != s.project {
		return model.GroupingIssue{}, false, nil
	}
	s.prior[key] = raw
	return gi, true, nil
}

func (s *ledgerIssues) size() (int, error) {
	if !s.counted {
		s.l.each(tableGroupingIssues, s.prefix, func(_, _ []byte) bool {
			s.count++
			return true
		})
		s.counted = true
	}
	return s.count, nil
}

func (s *ledgerIssues) holder(id model.ID, changed map[string]bool) (model.ID, bool, error) {
	needle := []byte(id.String())
	var (
		found   model.ID
		ok      bool
		corrupt bool
	)
	s.l.each(tableGroupingIssues, s.prefix, func(k, v []byte) bool {
		if changed[string(k)] || !bytes.Contains(v, needle) {
			return true
		}
		gi, err := decodeIssue(v)
		if err != nil {
			corrupt = true
			return false
		}
		if gi.Org != s.org || gi.Project != s.project {
			return true
		}
		issueHeldIDs(gi, func(held model.ID) bool {
			ok = held == id
			return !ok
		})
		if ok {
			found = gi.ID
			return false
		}
		return true
	})
	if corrupt {
		return model.ID{}, false, model.Fail(model.Corrupt)
	}
	return found, ok, nil
}

func (s *ledgerIssues) otherBytes(changed map[string]bool) (int, error) {
	total := 0
	s.l.each(tableGroupingIssues, s.prefix, func(k, v []byte) bool {
		if !changed[string(k)] {
			total += len(v)
		}
		return true
	})
	return total, nil
}

func (s *ledgerIssues) put(key string, _ model.GroupingIssue, raw []byte) {
	s.written[key] = raw
}
