// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"errors"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// Fairness of admission toward every other writer.
//
// A control command is one compare-and-swap on the application index: the proposal that names the
// revision the group is at wins, every other one is refused as stale and its proposer reads and proposes
// again. An admission command (a state patch that writes ledger records and steps the revision) costs
// one record write and takes a fraction of a millisecond to propose; the command of any other writer
// (a deletion Begin, an admin command, a rule or job step) is computed from the whole of the state
// without the ledger and takes a few times that between its read and its proposal. With admission
// saturating the group on every voter the revision moves several times in that window, so such a
// command loses almost every attempt: TestBeginIsNotRefusedByLostProposalsFromAnyVoterUnderSaturatingIntake
// refused 4 of 12 Begins from the leader and 6 to 10 of 12 from the other voters once an admission cost
// a few hundred microseconds, though the Begin retried 64 times (measured: 16,888 intake proposals in
// 12 s, 59 % of them lost among themselves, a Begin attempt taking 0.6 ms between its read and its
// proposal).
//
// The leader sees every proposal, and sees a command that is not admission lose the race (it is
// refused in Validate). That is the signal: the loser reads again at once, so for a short window
// (admissionYield) the leader refuses the admission commands that come in as stale as well, and the
// loser's next attempt meets a group whose revision does not move. A window opens at most once in
// admissionYieldEvery, so admission keeps at least four fifths of the time whatever the other writers
// do. An admission proposer that is refused retries (admissionUpdate), so the yield costs intake a few
// milliseconds of latency and never an error.
const (
	admissionYield      = 8 * time.Millisecond
	admissionYieldEvery = 40 * time.Millisecond
)

// ledgerOnlyPatch says whether every op of p writes a record of the ledger or steps the revision and its
// clock, and the patch is an admission command: one that writes a record of the admission books or none of
// the workers'. A write of the job or issue books alone is a writer's, not admission's; a round of the group
// commit that carries both (the sparse transitions ride in the admission rounds, sparse.go) is admission's: it
// is as cheap to propose as an admission round and held for a writer that lost like one.
func ledgerOnlyPatch(p *statePatch) bool {
	if len(p.Ops) == 0 {
		return false
	}
	books, admission := false, false
	for _, op := range p.Ops {
		if len(op.Path) == 0 {
			return false
		}
		if ledgerRoot(op.Path[0]) {
			if bookRoot(op.Path[0]) {
				books = true
			} else {
				admission = true
			}
			continue
		}
		if len(op.Path) == 1 && op.Op == opSet && (op.Path[0] == "Revision" || op.Path[0] == "revision_clock") {
			continue
		}
		return false
	}
	return admission || !books
}

// admissionYielding says whether the leader is holding admission commands for a writer that lost.
func (s *Store) admissionYielding(now time.Time) bool {
	return now.UnixNano() < s.admissionYieldUntil.Load()
}

// noteWriterLost opens a window when none was opened in the last admissionYieldEvery. Both durations are
// stretched by the store's admissionYieldScale, which is 1 in production: only a test whose writers run
// several times slower than the window was sized for (a race detector) sets it, so that its writer's next
// attempt still meets a window that is open (SetAdmissionYieldScaleForTest).
func (s *Store) noteWriterLost(now time.Time) {
	n := now.UnixNano()
	if n < s.admissionYieldNext.Load() {
		return
	}
	scale := max(1, s.admissionYieldScale.Load())
	s.admissionYieldNext.Store(n + int64(admissionYieldEvery)*scale)
	s.admissionYieldUntil.Store(n + int64(admissionYield)*scale)
}

func isStale(err error) bool {
	var fault *model.Fault
	return errors.As(err, &fault) && fault.Code == model.Stale
}
