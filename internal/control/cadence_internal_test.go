// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// Decision D4. The control journal is cut onto a snapshot and compacted every 4096 commands or
// 64 MiB, independent of any deletion. Before it, a store that never erased anything kept every
// command it ever committed (every control command carries the whole next state): measured on a
// 682-command history, a 269 MB raft log.

func TestControlJournalCadenceIsTheApprovedOne(t *testing.T) {
	if DefaultJournalCadence.Commands != 4096 || DefaultJournalCadence.Bytes != 64<<20 {
		t.Fatalf("D4: 4096 commands or 64 MiB, have %+v", DefaultJournalCadence)
	}
}

// enableSingleWith is EnableSingle with the journal cadence chosen by the caller.
func enableSingleWith(t *testing.T, s *Store, directory string, cadence replica.Cadence) {
	t.Helper()
	var id model.ID
	if err := s.View(context.Background(), func(st State) error { id = st.Installation; return nil }); err != nil {
		t.Fatal(err)
	}
	local := replica.NewLoopback()
	group, err := s.EnableReplication(replica.Config{ID: 1, Group: id, Directory: directory, Transport: local, Cadence: cadence, Members: replica.Members{Revision: 1, Nodes: []replica.Member{{ID: 1, Address: "https://single.invalid", NodeIdentity: "single", FailureDomain: "local-disk"}}}})
	if err != nil {
		local.Close()
		t.Fatal(err)
	}
	s.repl.local = local
	if err = local.Register(group); err == nil {
		err = group.Campaign()
	}
	if err == nil {
		err = group.Ready(context.Background())
	}
	if err != nil {
		t.Fatal(err)
	}
}

type stormResult struct {
	journal   int64 // ready.wal at the end
	peak      int64 // largest ready.wal seen
	first     uint64
	committed int
}

func procStatus(field string) string {
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "n/a"
	}
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(l, field+":") {
			return strings.TrimSpace(strings.TrimPrefix(l, field+":"))
		}
	}
	return "n/a"
}

// storm commits `commands` control commands, each carrying a state of about 3 KB, and reports the
// journal. With a bounded cadence it waits for the background cut after the last command.
func storm(t *testing.T, commands int, cadence replica.Cadence, wait bool) stormResult {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	raft := filepath.Join(dir, "raft-control")
	enableSingleWith(t, s, raft, cadence)
	g := s.ReplicaGroup()
	var res stormResult
	start, _ := g.JournalRange()
	size := func() int64 {
		info, err := os.Stat(filepath.Join(raft, "ready.wal"))
		if err != nil {
			t.Fatal(err)
		}
		return info.Size()
	}
	for i := range commands {
		if err := s.Update(context.Background(), func(st *State) error {
			if st.CommandOwners == nil {
				st.CommandOwners = map[string]string{}
			}
			for n := range 100 {
				st.CommandOwners[fmt.Sprintf("storm:%03d", n)] = fmt.Sprintf("owner-%012d", i)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		res.committed++
		if i%64 == 0 {
			res.peak = max(res.peak, size())
		}
	}
	if wait {
		first0 := start
		deadline := time.Now().Add(60 * time.Second)
		for {
			if first, _ := g.JournalRange(); first > first0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%d commands at the approved cadence left the journal uncut", commands)
			}
			time.Sleep(50 * time.Millisecond)
		}
		time.Sleep(200 * time.Millisecond)
	}
	res.journal = size()
	res.peak = max(res.peak, res.journal)
	res.first, _ = g.JournalRange()
	return res
}

// The same storm at a cadence of 100 commands (the in-suite size; the approved 4096 / 64 MiB run
// is TestControlCommitStormMeasure).
func TestControlCommitStormJournalIsBoundedWithoutAnyDeletion(t *testing.T) {
	const commands = 130
	cadence := replica.Cadence{Commands: 100}
	unbounded := storm(t, commands, replica.Cadence{Commands: ^uint64(0)}, false)
	bounded := storm(t, commands, cadence, true)
	t.Logf("%d commands: ready.wal %d bytes uncut, %d bytes at a cadence of %d (first index %d)", commands, unbounded.journal, bounded.journal, cadence.Commands, bounded.first)
	if bounded.first <= 1 {
		t.Fatal("the journal was never compacted")
	}
	if bounded.journal*2 > unbounded.journal {
		t.Fatalf("the journal after the cut is %d bytes, uncut %d: not bounded by the cadence", bounded.journal, unbounded.journal)
	}
}

func TestControlStoreDefaultsToTheApprovedJournalCadence(t *testing.T) {
	f := newInstallFx(t)
	if got := f.s.ReplicaGroup().Cadence(); got != DefaultJournalCadence {
		t.Fatalf("the control group runs with cadence %+v, want %+v", got, DefaultJournalCadence)
	}
}

// TestControlCommitStormMeasure reports the journal and the process's peak RSS of one storm per
// process: go test -run 'TestControlCommitStormMeasure/before' (and /after), with
// SOUNDPOST_STORM_MEASURE=1. VmHWM is per process, so each variant needs its own run.
func TestControlCommitStormMeasure(t *testing.T) {
	if os.Getenv("SOUNDPOST_STORM_MEASURE") == "" {
		t.Skip("measurement only: set SOUNDPOST_STORM_MEASURE=1 and select one subtest")
	}
	const commands = 4300
	for name, cadence := range map[string]replica.Cadence{"before": {Commands: ^uint64(0)}, "after": DefaultJournalCadence} {
		t.Run(name, func(t *testing.T) {
			res := storm(t, commands, cadence, name == "after")
			t.Logf("MEASURE %s: %d commands, ready.wal %d bytes (peak %d), first index %d, VmHWM %s, VmRSS %s", name, commands, res.journal, res.peak, res.first, procStatus("VmHWM"), procStatus("VmRSS"))
		})
	}
}
