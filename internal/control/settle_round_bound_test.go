// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// TestARoundCarriesOneSettlementCommandAtMost is the red test of the tail of the acknowledgements' latency (admit report, round 6):
// the passes of the 64 data groups ask for a settlement at once, and a round took every command that waited, three of them at 5,000
// records/s (204 KB, a propose of 67 ms where a round without one takes 24 ms), so the reserve or finalize that waited behind such a
// round paid for all of them. A round carries one settlement command; the others wait for the next round, and every command is
// still committed: every row of every group is settled afterwards.
func TestARoundCarriesOneSettlementCommandAtMost(t *testing.T) {
	if os.Getenv("SOUNDPOST_TEST_SETTLE_UNBOUNDED") != "" {
		old := control.SetMaxSettleCommandsPerRoundForTest(1 << 30) // the red run: every command that waits rides in the round
		t.Cleanup(func() { control.SetMaxSettleCommandsPerRoundForTest(old) })
	}
	f := newFenceFxCompact(t)
	if err := f.store.BindAdmissionOwner(&reconcileOwner{}); err != nil {
		t.Fatal(err)
	}
	const groups, span, windows = 8, 4, 16 // one group's windows are 64 rows: one settlement command
	scope := sourceScopeOf(f)
	type row struct {
		r      model.AdmissionReservation
		cursor model.Cursor
	}
	ids := make([]model.ID, groups)
	rows := make([][]row, groups)
	for g := range groups {
		ids[g] = model.NewID()
		rows[g] = make([]row, span*windows)
	}
	var wg sync.WaitGroup
	errs := make(chan error, groups*span*windows)
	for g := range groups {
		for w := range windows {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for k := range span {
					i := w*span + k
					r, err := reserveBatchOf(f, []string{fmt.Sprintf("settle_bound_series_%02d_%04d", g, i)})
					if err != nil {
						errs <- err
						return
					}
					cursor := model.Cursor{Group: ids[g], Index: model.Uint64(i + 1)}
					if err = f.store.FinalizeAdmission(f.ctx, scope, model.FinalizeAdmission{ReservationID: r.ID, Cursor: cursor}); err != nil {
						errs <- err
						return
					}
					r.State, r.Cursor = "consumed", &cursor
					rows[g][i] = row{r, cursor}
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal("admit:", err)
	}
	candidates := make([][]model.SettleCandidate, groups)
	for g := range groups {
		for n := range windows {
			var items []model.ChargeItem
			for _, x := range rows[g][n*span : n*span+span] {
				items = append(items, model.ChargeOf(x.r))
			}
			candidates[g] = append(candidates[g], model.SettleCandidate{Group: ids[g], N: uint64(n), Span: span, Batches: span, Charge: model.ChargeDigest(items)})
		}
	}
	roundsBefore, commandsBefore := f.store.SettleRoundStatsForTest()
	submittedBefore := f.store.SubmittedAdmissionsForTest()
	// (the passes below ask together)
	reports := make([]uint64, groups)
	var ended atomic.Int32 // the passes that returned: none can while the update lock is held, unless it failed or found nothing
	start := make(chan struct{})
	for g := range groups {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer ended.Add(1)
			<-start
			rep, err := f.store.SettleAdmissions(f.ctx, candidates[g])
			if err != nil {
				t.Error("settle:", err)
				return
			}
			reports[g] = uint64(rep.Reservations)
		}()
	}
	// The passes ask while the update lock is held, so no round can commit. A pass queues its command and waits for it. The runner
	// takes the commands that are queued when its round starts: one, or several when other passes queued before it ran (a loaded
	// host runs it late), and that round waits for the lock with them. Either way the commands of every pass meet the lock together,
	// in the first round or in the queue behind it, which is what the bound of a round is tested against: wait until every pass has
	// submitted its command, not until a number of them are still queued (the runner may have taken more than the first).
	release := f.store.HoldUpdatesForTest()
	close(start)
	for f.store.SubmittedAdmissionsForTest()-submittedBefore < groups && ended.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	submitted, returned := f.store.SubmittedAdmissionsForTest()-submittedBefore, ended.Load()
	release()
	wg.Wait()
	if returned != 0 {
		t.Fatalf("%d settlement passes returned while the update lock was held and nothing could commit (%d of %d had submitted)", returned, submitted, groups)
	}
	var total uint64
	for _, n := range reports {
		total += n
	}
	rounds, commands := f.store.SettleRoundStatsForTest()
	rounds, commands = rounds-roundsBefore, commands-commandsBefore
	t.Logf("%d rows settled by %d settlement commands in %d rounds", total, commands, rounds)
	if total != groups*span*windows {
		t.Errorf("%d rows settled, want %d: a command that waited for a later round was lost", total, groups*span*windows)
	}
	if commands != groups {
		t.Errorf("%d settlement commands committed for %d groups of one command each", commands, groups)
	}
	if rounds != commands {
		t.Errorf("%d settlement commands rode in %d rounds: a round carried more than one", commands, rounds)
	}
}
