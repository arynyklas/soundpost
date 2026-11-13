// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"sort"

	"soundpost/internal/model"
)

// controlTextErased replaces the free text of a control record that a deletion
// covered (CD-8, decision D6). It is a fixed non-empty token so every invariant
// that requires a reason keeps holding, and a reader sees that text was removed
// rather than that none was ever written.
const controlTextErased = "erased"

// textErased reports whether a free-text field is already redacted or is a
// closed system reason (a fixed token the control package itself writes, no
// text a person typed or the pipeline derived from telemetry): such a field is
// neither rewritten nor counted again, which keeps the erasure idempotent.
func textErased(text string) bool {
	return text == "" || text == controlTextErased || text == ruleRetiredReason
}

// intervalMeets reports whether the half-open interval [from,to) of a record
// meets the half-open range [start,end); an empty or inverted interval is the
// instant from.
func intervalMeets(from, to, start, end model.UnixNano) bool {
	if to <= from {
		return from >= start && from < end
	}
	return from < end && to > start
}

// eraseControlText redacts, in the caller's transition, the free-text fields of
// the control records a deletion covers, and returns how many fields it
// redacted. Redacting rewrites the record in place, so the pages that held the
// old text are free pages of control.db like those of any erased payload: the
// count joins the erasure's, and an erasure that redacted text owes the scrub.
//
// The fields (found by the 01.08 review's field sweep, none of them a hash, a
// cursor or a counter, which the design keeps as evidence):
//
//   - RuleOutput.Reason: consumer text and data-derived text such as
//     series_conflict:<n>, redacted with the output (eraseRuleFacts);
//   - RuleBook.Replays[].Reason: operator text, redacted for the books and
//     replay windows the deletion covers (eraseRuleFacts);
//   - IssueBook.Gaps[].Reason: the evidence-gap reason of a range deletion (a
//     retirement drops the whole book);
//   - State.GroupingMigrations[].Reason: operator text;
//   - State.Releases[].DisplayLabel and its History: the labels of a retired
//     project's releases.
//
// A retirement covers every record of its projects. A range covers a record
// whose time (and signal, where it has one) it selects: a release is not
// time-bound, so only a retirement redacts its labels. An entity deletion covers
// no record of these books. State.EvidenceGaps keeps its reason: the backup
// attestation binds the committed gap fact and the data plane's declared gap to
// that text (backup.GapDigest), so redacting it would break the restore proof;
// it is a closed vocabulary the retention worker writes. Audits stay as the
// append-only evidence of who did what.
func eraseControlText(st *State, p model.DeletePredicate) (n int, err error) {
	retire := p.Mode == model.DeleteRetireOrg || p.Mode == model.DeleteRetireProject
	ranged := p.Mode == model.DeleteHistoricalRange
	if !retire && !ranged {
		return 0, nil
	}
	migrations := make([]string, 0, len(st.GroupingMigrations))
	for key := range st.GroupingMigrations {
		migrations = append(migrations, key)
	}
	sort.Strings(migrations)
	for _, key := range migrations {
		m := st.GroupingMigrations[key]
		if textErased(m.Reason) || !p.CoversProject(m.Org, m.Project) {
			continue
		}
		if ranged && !(signalIn(p.Signals, model.ErrorKind) && m.At >= p.Start && m.At < p.End) {
			continue
		}
		m.Reason = controlTextErased
		st.GroupingMigrations[key] = m
		n++
	}
	if retire {
		releases := make([]string, 0, len(st.Releases))
		for key := range st.Releases {
			releases = append(releases, key)
		}
		sort.Strings(releases)
		for _, key := range releases {
			r := st.Releases[key]
			if !p.CoversProject(r.Org, r.Project) {
				continue
			}
			history := make([]model.ReleaseLabelRevision, len(r.History))
			copy(history, r.History)
			changed := false
			if !textErased(r.DisplayLabel) {
				r.DisplayLabel, changed = controlTextErased, true
				n++
			}
			for i := range history {
				if !textErased(history[i].DisplayLabel) {
					history[i].DisplayLabel, changed = controlTextErased, true
					n++
				}
			}
			if changed {
				r.History = history
				st.Releases[key] = r
			}
		}
		return n, nil
	}
	books := make([]string, 0, len(st.IssueBooks))
	for key := range st.IssueBooks {
		books = append(books, key)
	}
	sort.Strings(books)
	for _, key := range books {
		org, project, ok := issueBookKeyOwner(key)
		if !ok || !p.CoversProject(org, project) {
			continue
		}
		var b IssueBook
		if json.Unmarshal(st.IssueBooks[key], &b) != nil {
			continue // unreadable: eraseIssueBooks drops it whole when the project is covered
		}
		changed := false
		for i := range b.Gaps {
			g := &b.Gaps[i]
			if textErased(g.Reason) || !gapInRange(*g, p) {
				continue
			}
			g.Reason, changed = controlTextErased, true
			n++
		}
		if !changed {
			continue
		}
		raw, err := json.Marshal(b)
		if err != nil {
			return 0, model.Fail(model.Corrupt)
		}
		st.IssueBooks[key] = raw
	}
	return n, nil
}

// gapInRange reports whether an evidence gap lies inside a range deletion: its
// closed interval [Start,End] meets [start,end) and it concerns a signal the
// range names (a gap that names none concerns every signal).
func gapInRange(g model.EvidenceGap, p model.DeletePredicate) bool {
	if g.End < p.Start || g.Start >= p.End {
		return false
	}
	if len(g.Signals) == 0 {
		return true
	}
	for _, k := range g.Signals {
		if signalIn(p.Signals, k) {
			return true
		}
	}
	return false
}
