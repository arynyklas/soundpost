// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"

	"soundpost/internal/model"
)

// eraseIssueBooks is the issues half of the deletion hook (eraseControlBooks
// calls it once per transition). Issue evidence is error-signal evidence: every
// occurrence and late-history item of State.GroupingIssues was derived from an
// error record, and State.IssueBooks holds what hangs off them (regression
// explanations, effect intents). The rules, all deterministic (sorted
// iteration, no clock) and idempotent:
//
//   - retire_project / retire_org: every issue and the book of every covered
//     project are removed (DropRetiredIssueBooks); the retirement marker and the
//     audits stay.
//   - historical_range: when the predicate covers the error signal, exactly the
//     occurrences and late-history items whose EventTime is in [Start,End) are
//     dropped. An issue left without evidence is removed entirely; a partially
//     covered issue keeps its surviving evidence, its ObservedReleases are
//     re-derived from the survivors, and a surviving denominator whose window
//     overlaps the range (its count was measured over deleted data) is dropped.
//   - entity: evidence names no replay/profile root except by ID, so the only
//     attribution available is an ID link: evidence whose record, occurrence,
//     build, release or producer-epoch ID is a named entity is dropped (the
//     predicate's replay/profile signal narrowing selects which chunks of the
//     root are deleted; the link to the root is the same, so it is ignored). Origin
//     cursors and denominator cursors name a data-group position, never an
//     entity, so cursor-only evidence cannot be attributed and is kept, the same
//     rule as the incident and condition books.
//
// An issue that lost evidence gets Revision+1 and the book Revision+1, so a
// stale committer (it holds the old record revision / book revision)
// conflicts. Regression explanations are stored in a closed format with an
// occurrence ID: those naming a dropped occurrence are dropped, and a list that
// cannot be read is dropped whole (unattributable). Effect intents naming a
// dropped occurrence or a removed issue are dropped. Identities, checkpoints,
// command digests and recorded gaps stay: they carry no telemetry content. An
// unreadable book of a covered project is dropped whole; one of a project the
// deletion does not cover is left in place.
//
// What a service consumer sees: a fully erased issue is gone (not found); a
// partially erased one loads with fewer occurrences and without the erased
// explanations. The returned count is the number of payloads dropped.
func eraseIssueBooks(st *State, p model.DeletePredicate, at model.UnixNano) (dropped int, err error) {
	retire := p.Mode == model.DeleteRetireOrg || p.Mode == model.DeleteRetireProject
	type project struct{ org, project model.ID }
	seen := map[string]project{}
	for _, gi := range st.GroupingIssues {
		seen[issueBookKey(gi.Org, gi.Project)] = project{gi.Org, gi.Project}
	}
	var unreadable []string
	for key, raw := range st.IssueBooks {
		var b IssueBook
		if json.Unmarshal(raw, &b) != nil {
			unreadable = append(unreadable, key)
			continue
		}
		seen[issueBookKey(b.Org, b.Project)] = project{b.Org, b.Project}
	}
	// An unreadable book cannot be attributed from its content, but its key names
	// its organization and project: it is dropped whole only when the predicate
	// covers that project (an organization retirement covers every project of the
	// organization). A book of a project the deletion does not cover is left in
	// place: reads of it fail closed (loadIssueBook answers Corrupt), and another
	// project's deletion must not cost it its checkpoints, command records, gaps,
	// effect intents and revision. A key that names no project is attributable to
	// nothing and stays too.
	sort.Strings(unreadable)
	for _, key := range unreadable {
		if org, project, ok := issueBookKeyOwner(key); !ok || !p.CoversProject(org, project) {
			continue
		}
		delete(st.IssueBooks, key)
		dropped++
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		pr := seen[k]
		if !p.CoversProject(pr.org, pr.project) {
			continue
		}
		if retire {
			ids, book := DropRetiredIssueBooks(st, pr.org, pr.project)
			dropped += len(ids)
			if book {
				dropped++
			}
			continue
		}
		n, err := eraseIssueEvidence(st, p, pr.org, pr.project)
		if err != nil {
			return 0, err
		}
		dropped += n
	}
	return dropped, nil
}

// issueBookKeyOwner is the inverse of issueBookKey: the organization and project
// a key names, ok false for a key that names none.
func issueBookKeyOwner(key string) (org, project model.ID, ok bool) {
	o, p, found := strings.Cut(key, ":")
	if !found {
		return org, project, false
	}
	var err error
	if org, err = model.ParseID(o); err != nil {
		return model.ID{}, model.ID{}, false
	}
	if project, err = model.ParseID(p); err != nil {
		return model.ID{}, model.ID{}, false
	}
	return org, project, true
}

// issueEvidenceCovered says whether one evidence item is covered by a range or
// entity predicate (never called for a retirement).
func issueEvidenceCovered(p model.DeletePredicate, e model.GroupingEvidence) bool {
	switch p.Mode {
	case model.DeleteHistoricalRange:
		return kindCovered(p.Signals, model.ErrorKind) && e.EventTime >= p.Start && e.EventTime < p.End
	case model.DeleteEntity:
		for _, entity := range p.Entities {
			if e.RecordID == entity || e.OccurrenceID == entity || issueIDIs(e.BuildID, entity) || issueIDIs(e.ReleaseID, entity) || issueIDIs(e.ProducerEpoch, entity) {
				return true
			}
		}
	}
	return false
}

// kindCovered: a range must name the kind (an empty list is never "all").
func kindCovered(signals []model.Kind, kind model.Kind) bool {
	for _, s := range signals {
		if s == kind {
			return true
		}
	}
	return false
}

func issueIDIs(p *model.ID, id model.ID) bool { return p != nil && *p == id }

// issueDenominatorTainted: a denominator counts records over its window; one
// that overlaps a covered range was measured over deleted telemetry.
func issueDenominatorTainted(p model.DeletePredicate, d *model.GroupingDenominator) bool {
	return d != nil && p.Mode == model.DeleteHistoricalRange && kindCovered(p.Signals, model.ErrorKind) && d.Start < p.End && d.End >= p.Start
}

func eraseIssueEvidence(st *State, p model.DeletePredicate, org, projectID model.ID) (int, error) {
	issues := projectIssues(st, org, projectID)
	keys := make([]string, 0, len(issues))
	for k := range issues {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	droppedOccurrences := map[model.ID]bool{}
	removed := map[model.ID]bool{}
	modified := map[model.ID]bool{}
	dropped := 0
	for _, key := range keys {
		gi := issues[key]
		next := gi
		next.Occurrences, next.LateHistory = nil, nil
		lost, tainted := 0, false
		keep := func(list []model.GroupingEvidence) []model.GroupingEvidence {
			var out []model.GroupingEvidence
			for _, e := range list {
				if issueEvidenceCovered(p, e) {
					droppedOccurrences[e.OccurrenceID] = true
					lost++
					continue
				}
				if issueDenominatorTainted(p, e.Denominator) {
					e.Denominator = nil
					tainted = true
				}
				out = append(out, e)
			}
			return out
		}
		next.Occurrences, next.LateHistory = keep(gi.Occurrences), keep(gi.LateHistory)
		switch {
		case lost > 0 && len(next.Occurrences)+len(next.LateHistory) == 0:
			delete(st.GroupingIssues, key)
			removed[gi.ID] = true
			dropped += lost + 1
		case lost > 0 || tainted:
			var observed []model.ID
			for _, id := range gi.ObservedReleases {
				if issueSurvivorNames(next, id) {
					observed = append(observed, id)
				}
			}
			next.ObservedReleases = observed
			next.Revision = gi.Revision + 1
			st.GroupingIssues[key] = next
			modified[gi.ID] = true
			dropped += lost
			if tainted {
				dropped++
			}
		}
	}
	if len(removed)+len(modified) == 0 {
		return dropped, nil
	}
	book, _, err := loadIssueBook(st, org, projectID)
	if err != nil {
		return 0, err
	}
	explanations := make(map[string]json.RawMessage, len(book.Explanations))
	ids := make([]string, 0, len(book.Explanations))
	for id := range book.Explanations {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	byID := map[string]model.ID{}
	for id := range removed {
		byID[id.String()] = id
	}
	for id := range modified {
		byID[id.String()] = id
	}
	for _, id := range ids {
		raw := book.Explanations[id]
		if _, touched := byID[id]; !touched {
			explanations[id] = raw
			continue
		}
		if removed[byID[id]] {
			dropped++
			continue
		}
		kept, n := filterIssueExplanations(raw, droppedOccurrences)
		dropped += n
		if kept != nil {
			explanations[id] = kept
		}
	}
	effects := book.Effects[:0:0]
	for _, e := range book.Effects {
		if removed[e.Issue] || droppedOccurrences[e.Occurrence] {
			dropped++
			continue
		}
		effects = append(effects, e)
	}
	book.Effects = effects
	if len(book.Effects) == 0 {
		book.Effects = nil
	}
	book.Explanations = explanations
	if len(explanations) == 0 {
		book.Explanations = nil
	}
	book.Revision++
	raw, err := json.Marshal(book)
	if err != nil {
		return 0, model.Fail(model.Invalid)
	}
	if st.IssueBooks == nil {
		st.IssueBooks = map[string]json.RawMessage{}
	}
	st.IssueBooks[issueBookKey(org, projectID)] = raw
	return dropped, nil
}

func issueSurvivorNames(gi model.GroupingIssue, release model.ID) bool {
	for _, list := range [][]model.GroupingEvidence{gi.Occurrences, gi.LateHistory} {
		for _, e := range list {
			if issueIDIs(e.ReleaseID, release) {
				return true
			}
		}
	}
	return false
}

// filterIssueExplanations keeps the explanations that do not name a dropped
// occurrence. The stored form is a JSON array whose elements carry
// "occurrence_id"; a list or element that cannot be read is dropped (nil
// result), never kept. n is how many explanations were dropped.
func filterIssueExplanations(raw json.RawMessage, gone map[model.ID]bool) (kept json.RawMessage, n int) {
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) != nil {
		return nil, 1
	}
	var out []json.RawMessage
	for _, item := range list {
		var head struct {
			Occurrence *model.ID `json:"occurrence_id"`
		}
		if json.Unmarshal(item, &head) != nil || head.Occurrence == nil || gone[*head.Occurrence] {
			n++
			continue
		}
		out = append(out, item)
	}
	if len(out) == 0 {
		return nil, n
	}
	if n == 0 {
		return raw, 0
	}
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, item := range out {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(item)
	}
	buf.WriteByte(']')
	return json.RawMessage(buf.Bytes()), n
}
