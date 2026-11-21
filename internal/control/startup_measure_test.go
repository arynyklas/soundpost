// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// Open-to-ready of the control store grows with the control Raft journal it replays: the journal is
// parsed, indexed (rebuildKnown) and its committed tail applied through the machine before the
// store serves. These helpers build a journal of a chosen size with real control commands through
// the real replicated store and time reopening it.

// openPhases is where one open of a replicated control store spent its time.
type openPhases struct {
	store    time.Duration // Open: the bolt state file
	enable   time.Duration // EnableReplication: WAL parse, snapshot restore, rebuildKnown, replay of the tail
	campaign time.Duration // single-voter election
	ready    time.Duration // one ReadIndex round
}

func (p openPhases) total() time.Duration { return p.store + p.enable + p.campaign + p.ready }

// stateShape is the size of the whole state one commit carries: Owners command-owner strings and
// Results applied-command results (nested objects, which cost more to decode per byte).
type stateShape struct{ Owners, Results int }

// commitShape commits one control command whose whole next state carries the shape: the same form
// as every folding control commit, which carries the whole state.
func commitShape(t testing.TB, s *Store, i int, shape stateShape) {
	t.Helper()
	if err := s.Update(context.Background(), func(st *State) error {
		if st.CommandOwners == nil {
			st.CommandOwners = map[string]string{}
		}
		if st.Commands == nil {
			st.Commands = map[string]model.ControlResult{}
		}
		for n := range shape.Owners {
			st.CommandOwners[fmt.Sprintf("storm:%05d", n)] = fmt.Sprintf("owner-%012d", i)
		}
		for n := range shape.Results {
			st.Commands[fmt.Sprintf("storm:%05d", n)] = model.ControlResult{Revision: model.Revision(i), AffectedIDs: []model.ID{model.NewID(), model.NewID()}, Cursor: model.Cursor{Group: st.Installation, Index: model.Uint64(i)}}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func journalSize(t testing.TB, raft string) int64 {
	t.Helper()
	info, err := os.Stat(filepath.Join(raft, "ready.wal"))
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

// openTimed opens the control store under dir with its replicated group and times the phases.
func openTimed(t testing.TB, dir string, cadence replica.Cadence) (*Store, openPhases) {
	t.Helper()
	began := time.Now()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	opened := time.Since(began)
	p := enableSingleTimed(t, s, filepath.Join(dir, "raft-control"), cadence)
	p.store = opened
	return s, p
}

// buildJournal commits until stop(journal bytes, commands) holds, then closes the store. It returns
// the journal size and the number of commands.
func buildJournal(t testing.TB, dir string, cadence replica.Cadence, shape stateShape, stop func(int64, int) bool) (int64, int) {
	t.Helper()
	s, _ := openTimed(t, dir, cadence)
	raft := filepath.Join(dir, "raft-control")
	commands := 0
	for !stop(journalSize(t, raft), commands) {
		commitShape(t, s, commands, shape)
		commands++
	}
	time.Sleep(500 * time.Millisecond) // a cut that is still running would move the journal under the reopen
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return journalSize(t, raft), commands
}

// TestControlStartupMeasure prints one MEASURE line per reopen of a control journal:
//
//	SOUNDPOST_CTL_JOURNAL_MB=8,30 go test ./internal/control -run TestControlStartupMeasure -v
//
// For each size in SOUNDPOST_CTL_JOURNAL_MB it builds a journal that is never cut (the pre-D4
// behaviour) until ready.wal holds that many MB and reopens it, then commits the same number of
// commands at DefaultJournalCadence and reopens that. SOUNDPOST_CTL_OWNERS and
// SOUNDPOST_CTL_RESULTS (defaults 200 and 0) set the state each commit carries,
// SOUNDPOST_CTL_REOPENS the repetitions (default 3). Reopen CPU samples carry the pprof label
// phase=reopen, so -cpuprofile plus `pprof -tagfocus=phase=reopen` splits the replay.
func TestControlStartupMeasure(t *testing.T) {
	spec := os.Getenv("SOUNDPOST_CTL_JOURNAL_MB")
	if spec == "" {
		t.Skip("measurement only: set SOUNDPOST_CTL_JOURNAL_MB=8,30")
	}
	env := func(name string, def int) int {
		if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v >= 0 && os.Getenv(name) != "" {
			return v
		}
		return def
	}
	shape, reopens := stateShape{Owners: env("SOUNDPOST_CTL_OWNERS", 200), Results: env("SOUNDPOST_CTL_RESULTS", 0)}, env("SOUNDPOST_CTL_REOPENS", 3)
	uncut := replica.Cadence{Commands: ^uint64(0), Bytes: 1 << 62}
	measure := func(label string, cadence replica.Cadence, stop func(int64, int) bool) {
		dir := t.TempDir()
		built := time.Now()
		bytes, commands := buildJournal(t, dir, cadence, shape, stop)
		t.Logf("%s: built %d commands, ready.wal %d bytes in %v (shape %+v, cadence %+v)", label, commands, bytes, time.Since(built).Round(time.Millisecond), shape, cadence)
		var totals []time.Duration
		for run := range reopens {
			var s *Store
			var p openPhases
			pprof.Do(context.Background(), pprof.Labels("phase", "reopen"), func(context.Context) { s, p = openTimed(t, dir, cadence) })
			totals = append(totals, p.total())
			t.Logf("MEASURE %s journal=%dB commands=%d run=%d race=%v total=%dms store=%dms enable=%dms campaign=%dms ready=%dms", label, journalSize(t, filepath.Join(dir, "raft-control")), commands, run+1, raceBuild, p.total().Milliseconds(), p.store.Milliseconds(), p.enable.Milliseconds(), p.campaign.Milliseconds(), p.ready.Milliseconds())
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
		}
		slices.Sort(totals)
		t.Logf("MEASURE %s journal=%dB commands=%d race=%v median=%dms", label, bytes, commands, raceBuild, totals[len(totals)/2].Milliseconds())
	}
	for _, field := range strings.Split(spec, ",") {
		mb, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil || mb <= 0 {
			t.Fatalf("SOUNDPOST_CTL_JOURNAL_MB: %q", field)
		}
		var commands int
		measure(fmt.Sprintf("before-%dMB", mb), uncut, func(size int64, n int) bool { commands = n; return size >= int64(mb)<<20 })
		measure(fmt.Sprintf("after-%dMB-history", mb), DefaultJournalCadence, func(_ int64, n int) bool { return n >= commands })
	}
}
