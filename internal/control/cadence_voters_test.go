// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/replica"
)

// 10.13-W1 and 11.05-W2. The journal cadence (decision D4) was measured on one voter. This drives
// the real three-voter control group (three stores, three journals, one in-process network) through
// a storm of commands with one voter cut off, then lets that voter back: its journal position is by
// then compacted away on the leader, so it can only catch up by installing a snapshot.

const stormVoter = 3 // the follower that lags

type voterStorm struct {
	commands    int
	cutLog      []string
	data        int64         // entry data bytes the cadence counts per command
	longestCut  time.Duration // the longest cadence cut the leader made
	cutsOnLeads uint64
	finalWAL    map[uint64]int64 // ready.wal of every voter at the end of the storm
	peakWAL     map[uint64]int64 // largest ready.wal seen on a voter while it ran
	headWAL     int64            // ready.wal of the leader before the storm (the seed snapshot record, the fixture's commits)
	command     int64            // journal bytes one command adds
	snapshots   int              // snapshot messages the lagging voter installed
	peakRSS     string           // VmHWM at the end
	rssNow      string
	peakHeap    uint64 // largest runtime HeapInuse sampled
	peakSys     uint64
	stormTime   time.Duration
	catchUp     time.Duration
}

func walSize(t *testing.T, dir string) int64 {
	t.Helper()
	info, err := os.Stat(filepath.Join(dir, "raft-control", "ready.wal"))
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

func procField(field string) string {
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

// runVoterStorm commits `commands` control commands, each carrying a state of about 3 KB, through
// the leader (voter 1) while voter 3 is cut off, waits for the leader's cadence to have cut at
// least minCuts times, then reconnects voter 3 and waits for it to reach the leader's revision.
func runVoterStorm(t *testing.T, cadence replica.Cadence, commands int, minCuts uint64) voterStorm {
	t.Helper()
	v := newControlVotersCadence(t, cadence)
	leader := v.stores[1]
	res := voterStorm{commands: commands, finalWAL: map[uint64]int64{}, peakWAL: map[uint64]int64{}}
	res.headWAL = walSize(t, v.dirs[1])
	commit := func(i int) {
		if err := leader.Update(context.Background(), func(st *control.State) error {
			if st.CommandOwners == nil {
				st.CommandOwners = map[string]string{}
			}
			for n := range 100 {
				st.CommandOwners[fmt.Sprintf("storm:%03d", n)] = fmt.Sprintf("owner-%012d", i)
			}
			return nil
		}); err != nil {
			t.Fatalf("command %d: %v", i, err)
		}
	}
	commit(0)
	commit(1)
	g := leader.ReplicaGroup()
	res.command = walSize(t, v.dirs[1])
	data := g.AppliedDataBytes()
	commit(2)
	res.command = walSize(t, v.dirs[1]) - res.command
	res.data = int64(g.AppliedDataBytes() - data)

	// The sampler: RSS high-water mark is the kernel's (VmHWM), the Go heap is read every 20 ms.
	v.mesh.cut(stormVoter, true)
	stop, done := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	go func() {
		defer close(done)
		var ms runtime.MemStats
		for {
			runtime.ReadMemStats(&ms)
			mu.Lock()
			res.peakHeap, res.peakSys = max(res.peakHeap, ms.HeapInuse), max(res.peakSys, ms.Sys)
			for id := uint64(1); id <= 2; id++ {
				if info, err := os.Stat(filepath.Join(v.dirs[id], "raft-control", "ready.wal")); err == nil {
					res.peakWAL[id] = max(res.peakWAL[id], info.Size())
				}
			}
			mu.Unlock()
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}()
	began := time.Now()
	var seen uint64
	for i := 3; i < commands; i++ {
		commit(i)
		if c := g.CadenceCuts(); c != seen {
			seen = c
			res.cutLog = append(res.cutLog, fmt.Sprintf("cut %d seen after command %d, ready.wal %d", c, i, walSize(t, v.dirs[1])))
		}
	}
	res.stormTime = time.Since(began)
	deadline := time.Now().Add(120 * time.Second)
	for g.CadenceCuts() < minCuts {
		if time.Now().After(deadline) {
			t.Fatalf("%d commands at cadence %+v: the leader cut %d times, want %d", commands, g.Cadence(), g.CadenceCuts(), minCuts)
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // a cut that began with the last command ends
	res.cutsOnLeads, res.longestCut = g.CadenceCuts(), g.CadenceLongestCut()
	if before := func() int { v.mesh.mu.Lock(); defer v.mesh.mu.Unlock(); return v.mesh.snaps[stormVoter] }(); before != 0 {
		t.Fatalf("voter %d was handed %d snapshots while it was cut off", stormVoter, before)
	}

	// The lagging voter comes back: it can only learn the commands from the snapshot.
	rev := v.mustRevision(1)
	began = time.Now()
	v.mesh.cut(stormVoter, false)
	v.await(stormVoter, rev)
	res.catchUp = time.Since(began)
	close(stop)
	<-done
	v.mesh.mu.Lock()
	res.snapshots = v.mesh.snaps[stormVoter]
	v.mesh.mu.Unlock()
	for id := uint64(1); id <= 3; id++ {
		res.finalWAL[id] = walSize(t, v.dirs[id])
	}
	res.peakWAL[3] = max(res.peakWAL[3], res.finalWAL[3])
	res.peakRSS, res.rssNow = procField("VmHWM"), procField("VmRSS")

	// The follower holds the leader's state, not a prefix of it.
	want := fmt.Sprintf("owner-%012d", commands-1)
	for id := uint64(1); id <= 3; id++ {
		if err := v.stores[id].View(context.Background(), func(st control.State) error {
			if got := st.CommandOwners["storm:099"]; got != want {
				return fmt.Errorf("voter %d holds %q, want %q", id, got, want)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	return res
}

func (r voterStorm) log(t *testing.T, label string) {
	t.Helper()
	t.Logf("MEASURE %s: %d commands (%d journal bytes each, leader's head %d), leader cut %d times (longest %v), snapshots installed on voter %d: %d, ready.wal at the end %v (peak %v), RSS high-water %s, RSS now %s, Go heap-in-use peak %d kB, Go sys peak %d kB, storm %v, catch-up %v",
		label, r.commands, r.command, r.headWAL, r.cutsOnLeads, r.longestCut.Round(time.Millisecond), stormVoter, r.snapshots, r.finalWAL, r.peakWAL, r.peakRSS, r.rssNow, r.peakHeap>>10, r.peakSys>>10, r.stormTime.Round(time.Millisecond), r.catchUp.Round(time.Millisecond))
	for _, l := range r.cutLog {
		t.Log(l)
	}
}

// requireBounded holds every voter's journal to what a cadence of `bytes` of applied entry data
// allows, in journal bytes (head: the journal's own start, the seed snapshot record and the commands
// before the storm):
//   - at rest, 1.5 x the bound plus the head: the cadence counts entry data and the journal holds it
//     base64-encoded with a record around every append, which is 1.4 x at the trigger (measured:
//     r.command journal bytes for r.data counted bytes);
//   - while the storm runs, 2 x the bound plus the head: the journal is at its 1.4 x when the cut
//     triggers and keeps growing at the storm's rate (an unthrottled storm, a quorum of three
//     voters committing as fast as they can) until the cut compacts it. The measured excess is
//     logged as a multiple of the bound; the leader's longest cut and the commit interval of the
//     storm tell how many commands that is.
func (r voterStorm) requireBounded(t *testing.T, bytes int64) {
	t.Helper()
	interval := r.stormTime / time.Duration(max(r.commands-3, 1))
	during := int64(r.longestCut / max(interval, time.Microsecond))
	atTrigger := bytes/r.data + 1 // commands whose data adds up to the bound
	atRest, running := bytes*3/2+r.headWAL, bytes*2+r.headWAL
	for id, size := range r.peakWAL {
		t.Logf("voter %d: peak ready.wal %d bytes = %.2f x the %d-byte cadence (%d commands of %d journal bytes at the trigger, about %d more in the longest cut, head %d)", id, size, float64(size)/float64(bytes), bytes, atTrigger, r.command, during, r.headWAL)
		if size > running {
			t.Errorf("voter %d: ready.wal reached %d bytes while the storm ran, more than the %d a cadence of %d bytes allows", id, size, running, bytes)
		}
		if end := r.finalWAL[id]; end > atRest {
			t.Errorf("voter %d: ready.wal is %d bytes at rest, more than the %d a cadence of %d bytes allows", id, end, atRest, bytes)
		}
	}
	if r.snapshots < 1 {
		t.Errorf("voter %d caught up without installing a snapshot", stormVoter)
	}
}

// The shipped cadence (4096 commands or 8 MiB, whichever first) on the three voters, beyond the
// 4096-command bound: the byte bound is the one a command of this size reaches first, so the
// leader cuts several times; the voter that was cut off for the whole storm installs a snapshot
// when it returns and holds the leader's state; no journal leaves what the cadence allows. The
// numbers (RSS high-water, ready.wal, cuts, catch-up) are logged: run it with -v. VmHWM is per
// process: run it alone for a measurement of the group (-run TestControlVotersStorm).
func TestControlVotersStormBeyondTheCommandBoundWithALaggingFollower(t *testing.T) {
	commands := 4400 // beyond DefaultJournalCadence.Commands
	if raceEnabled {
		commands = 1500 // the race detector makes a command several times slower; the byte bound still cuts
	}
	r := runVoterStorm(t, replica.Cadence{}, commands, 1)
	r.log(t, "defaults")
	// Each cut accounts for DefaultJournalCadence.Bytes of entry data (measured per command, r.data);
	// the cut in flight when the storm ends is not counted.
	total := int64(r.commands) * r.data
	if want := uint64(total/control.DefaultJournalCadence.Bytes) - 1; r.cutsOnLeads < want {
		t.Errorf("the leader cut %d times, want at least %d for %d bytes of entry data at a cadence of %d bytes", r.cutsOnLeads, want, total, control.DefaultJournalCadence.Bytes)
	}
	r.requireBounded(t, control.DefaultJournalCadence.Bytes)
}
