// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// D84 / ControlLane round 3: an issue commit is judged on the issues it names. It decoded every issue of its
// project, the handler encoded them all again for the project byte bound and the plan once more to find the
// ones that changed, all under the lock every control writer shares: 3 ms per commit early in a run and 33 ms
// late, from the same code, because the issues of the project only grow.

// seedProject commits n issues of perIssue occurrences each (30 to a command); revision is the book's.
func seedProject(f *issFx, n, perIssue int, revision *uint64) {
	for done := 0; done < n; {
		batch := min(30, n-done)
		var recs []control.IssueRecordChange
		for i := 1; i <= batch; i++ {
			fp := byte(done + i)
			recs = append(recs, f.record(f.issue(fp, 1, f.ledger(fp, 1, perIssue)...)))
		}
		f.must(control.IssueCommand{ExpectedRevision: model.Revision(*revision), Records: recs})
		*revision++
		done += batch
	}
}

// appendCommits commits commits appends of one occurrence to issue 1 and answers what they cost.
func appendCommits(f *issFx, revision *uint64, issueRevision *uint64, ledger *int, commits int) (decodes, marshals uint64, hold time.Duration) {
	d0, m0 := f.store.IssueCodecCountsForTest()
	hold, _ = lockHold(f.fenceFx, func() {
		for range commits {
			*ledger++
			*issueRevision++
			f.must(control.IssueCommand{ExpectedRevision: model.Revision(*revision), Records: []control.IssueRecordChange{f.record(f.issue(1, *issueRevision, f.ledger(1, 1, *ledger)...))}})
			*revision++
		}
	})
	d1, m1 := f.store.IssueCodecCountsForTest()
	return d1 - d0, m1 - m0, hold
}

func TestIssueCommitCostDoesNotGrowWithTheProject(t *testing.T) {
	const commits, perIssue = 20, 40
	run := func(issues int) (decodes, marshals uint64, hold time.Duration) {
		f := newIssFxOn(t, newFenceFxPatch(t))
		var revision, issueRevision uint64
		seedProject(f, issues, perIssue, &revision)
		issueRevision, ledger := uint64(1), perIssue
		sparse := f.store.SparseCommitsForTest()
		decodes, marshals, hold = appendCommits(f, &revision, &issueRevision, &ledger, commits)
		if got := f.store.SparseCommitsForTest() - sparse; got != commits {
			t.Errorf("%d issues: %d of %d commits were committed as records", issues, got, commits)
		}
		if s := f.snap(); len(s.Issues) != issues {
			t.Errorf("the project holds %d issues, want %d", len(s.Issues), issues)
		}
		return
	}
	smallD, smallM, small := run(8)
	largeD, largeM, large := run(240)
	t.Logf("8 issues: %d decodes, %d encodes, lock %v per %d commits; 240 issues: %d decodes, %d encodes, lock %v", smallD, smallM, small, commits, largeD, largeM, large)
	// The issue the commit changes is read once and written once; the others are not decoded or encoded at all.
	if smallD != largeD || largeD > commits || smallM != largeM || largeM > commits {
		t.Errorf("a commit decodes and encodes what it changes, whatever the project holds: 8 issues %d/%d, 240 issues %d/%d (decodes/encodes for %d commits, at most %d each)", smallD, smallM, largeD, largeM, commits, commits)
	}
	if large > 3*small+commits*time.Millisecond {
		t.Errorf("%d commits held the lock %v in a project of 8 issues and %v in one of 240: the cost follows the project", commits, small, large)
	}
}

func faultOf(err error) (model.Code, string) {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.Code, f.SafeDetail
	}
	if err != nil {
		return "", err.Error()
	}
	return "", ""
}

// What the commit used to learn from the occurrence index of the whole project it still learns, from the
// records of the others: an occurrence another issue accounts for is refused, an effect names an occurrence
// of its own issue, written or not.
func TestIssueCommitJudgesTheOtherIssuesOfTheProjectByTheirRecords(t *testing.T) {
	f := newIssFxOn(t, newFenceFxPatch(t))
	var revision uint64
	seedProject(f, 3, 12, &revision)
	one, two := f.ledger(1, 1, 12), f.ledger(2, 1, 12)
	try := func(c control.IssueCommand) error {
		c.ExpectedRevision = model.Revision(revision)
		_, err := f.commit(c)
		if err == nil {
			revision++
		}
		return err
	}
	stolen := f.evidence(2, 13)
	stolen.OccurrenceID = one[4].OccurrenceID
	if code, detail := faultOf(try(control.IssueCommand{Records: []control.IssueRecordChange{f.record(f.issue(2, 2, append(append([]model.GroupingEvidence(nil), two...), stolen)...))}})); code != model.Conflict || detail != "issue_record_conflict" {
		t.Errorf("an occurrence another issue holds: %q %q, want the record conflict", code, detail)
	}
	// An occurrence of the written issue's own record is not another issue's.
	if err := try(control.IssueCommand{Records: []control.IssueRecordChange{f.record(f.issue(2, 2, append(append([]model.GroupingEvidence(nil), two...), f.evidence(2, 13))...))}}); err != nil {
		t.Fatalf("a fresh occurrence: %v", err)
	}
	two = append(two, f.evidence(2, 13))
	// An effect names an occurrence of an issue the command does not write ...
	eff := func(id byte, issue byte, occ model.ID) control.IssueEffect {
		return control.IssueEffect{ID: model.ID{0xf1, id}, Kind: "issue_regressed", Issue: f.issueID(issue), Occurrence: occ}
	}
	fresh := f.evidence(2, 14)
	record2 := func() control.IssueRecordChange {
		return f.record(f.issue(2, 3, append(append([]model.GroupingEvidence(nil), two...), fresh)...))
	}
	if code, _ := faultOf(try(control.IssueCommand{Records: []control.IssueRecordChange{record2()}, Effects: []control.IssueEffect{eff(1, 1, two[3].OccurrenceID)}})); code != model.Invalid {
		t.Errorf("an effect naming another issue's occurrence: %q, want invalid", code)
	}
	if code, _ := faultOf(try(control.IssueCommand{Records: []control.IssueRecordChange{record2()}, Effects: []control.IssueEffect{eff(2, 3, one[3].OccurrenceID)}})); code != model.Invalid {
		t.Errorf("an effect naming an occurrence of an issue that does not hold it: %q, want invalid", code)
	}
	if err := try(control.IssueCommand{Records: []control.IssueRecordChange{record2()}, Effects: []control.IssueEffect{eff(3, 1, one[3].OccurrenceID), eff(4, 2, fresh.OccurrenceID)}}); err != nil {
		t.Fatalf("effects naming an occurrence of an unwritten issue and of a written one: %v", err)
	}
	if got := len(f.snap().Effects); got != 2 {
		t.Errorf("the book holds %d effects, want 2", got)
	}
}

// One random sequence of commits judged by the whole-state funnel and by the sparse plan: the same
// answers, the same issues and book.
func TestIssueCommitsAnswerTheSameOnTheSparsePathAndTheFunnel(t *testing.T) {
	rnd := rand.New(rand.NewPCG(84, 1))
	fixtures := []*issFx{newIssFxOn(t, newFenceFx(t)), newIssFxOn(t, newFenceFxPatch(t))}
	funnel, sparse := fixtures[0], fixtures[1]
	var fps []byte // the issues committed, in creation order
	ledgers := map[byte]int{}
	rev := map[byte]uint64{}
	var book uint64
	pick := func() byte { return fps[rnd.IntN(len(fps))] }
	for step := range 160 {
		var (
			records func(f *issFx) []control.IssueRecordChange
			effects func(f *issFx) []control.IssueEffect
			stale   bool
			commit  func()
		)
		kind := rnd.IntN(6)
		if len(fps) == 0 {
			kind = 0
		}
		switch kind {
		case 0:
			fp, count := byte(len(fps)+1), 1+rnd.IntN(3)
			records = func(f *issFx) []control.IssueRecordChange {
				return []control.IssueRecordChange{f.record(f.issue(fp, 1, f.ledger(fp, 1, count)...))}
			}
			commit = func() { fps, ledgers[fp], rev[fp] = append(fps, fp), count, 1 }
		case 1: // an occurrence another issue holds
			fp := pick()
			steal := pick()
			if steal == fp {
				continue
			}
			records = func(f *issFx) []control.IssueRecordChange {
				ev := f.evidence(fp, uint64(ledgers[fp]+1))
				ev.OccurrenceID = f.evidence(steal, 1).OccurrenceID
				return []control.IssueRecordChange{f.record(f.issue(fp, rev[fp]+1, append(f.ledger(fp, 1, ledgers[fp]), ev)...))}
			}
		case 2: // a lost book revision
			stale = true
			fp := pick()
			records = func(f *issFx) []control.IssueRecordChange {
				return []control.IssueRecordChange{f.record(f.issue(fp, rev[fp]+1, f.ledger(fp, 1, ledgers[fp]+1)...))}
			}
		default: // an append, with an effect that names some issue's occurrence
			fp, target := pick(), pick()
			occ := 1 + rnd.IntN(ledgers[target]+1)
			records = func(f *issFx) []control.IssueRecordChange {
				return []control.IssueRecordChange{f.record(f.issue(fp, rev[fp]+1, f.ledger(fp, 1, ledgers[fp]+1)...))}
			}
			effects = func(f *issFx) []control.IssueEffect {
				return []control.IssueEffect{{ID: model.ID{0xf1, byte(step), byte(step >> 8)}, Kind: "issue_regressed", Issue: f.issueID(target), Occurrence: f.evidence(target, uint64(occ)).OccurrenceID}}
			}
			commit = func() { ledgers[fp]++; rev[fp]++ }
		}
		var outcome [2]string
		for i, f := range fixtures {
			c := control.IssueCommand{ExpectedRevision: model.Revision(book), Records: records(f)}
			if stale {
				c.ExpectedRevision = model.Revision(book + 1)
			}
			if effects != nil {
				c.Effects = effects(f)
			}
			_, err := f.commit(c)
			code, detail := faultOf(err)
			outcome[i] = fmt.Sprintf("%v/%s", code, detail)
			if err == nil {
				outcome[i] = "ok"
			}
		}
		if outcome[0] != outcome[1] {
			t.Fatalf("step %d: the funnel answered %q and the sparse plan %q", step, outcome[0], outcome[1])
		}
		if outcome[0] == "ok" {
			book++
			if commit != nil {
				commit()
			}
		}
	}
	if book < 40 {
		t.Fatalf("only %d of 160 commits were accepted: the sequence does not exercise the paths", book)
	}
	if funnel.semantic() != sparse.semantic() {
		t.Errorf("the funnel and the sparse plan left different issues and books\nfunnel: %.600s\nsparse: %.600s", funnel.semantic(), sparse.semantic())
	}
	if sparse.store.SparseCommitsForTest() < book {
		t.Errorf("%d of %d commits ran as records", sparse.store.SparseCommitsForTest(), book)
	}
}
