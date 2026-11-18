// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/artifacts/refledger"
	"github.com/arynyklas/soundpost/internal/model"
)

// The structural rules the real-binary scenarios apply to a stored organization, on values the product's own
// writers make (refledger.Store, refledger.Contract) and on values that were damaged.
func TestStoredLayoutRulesOfBothPhases(t *testing.T) {
	project := model.NewID()
	o := model.ControlOrg{Settings: map[string]json.RawMessage{}}
	var roots []model.ID
	for range 6 {
		l := &refledger.Ledger{Project: project, Root: model.NewID(), Seq: 1}
		if err := refledger.Store(&o, project, l); err != nil {
			t.Fatal(err)
		}
		roots = append(roots, l.Root)
	}
	// Replays: a checkpoint index and its pin in the whole-project map, as the previous release (and the
	// expand phase) keep them, and the replay's own pin.
	addReplay := func(settings map[string]json.RawMessage, own bool) model.ID {
		replay := model.NewID()
		head := model.HashCanonical([]byte(replay.String()))
		g, _ := json.Marshal(storedGroup{Seq: 1, Head: head})
		settings[model.ReplayIndexKeyPrefix+project.String()+":"+replay.String()] = g
		pins := map[string]storedPin{}
		if raw, ok := settings[model.ReplayPinKeyPrefix+project.String()]; ok {
			_ = json.Unmarshal(raw, &pins)
		}
		pins[replay.String()] = storedPin{Seq: 1, Head: head, RetainUntil: 5}
		raw, _ := json.Marshal(pins)
		settings[model.ReplayPinKeyPrefix+project.String()] = raw
		if own {
			p, _ := json.Marshal(storedPin{Seq: 1, Head: head, RetainUntil: 5})
			settings[model.ReplayPinKeyPrefix+project.String()+":"+replay.String()] = p
		}
		return replay
	}
	addReplay(o.Settings, true)

	expanded := parseLayout(o.Settings, project)
	if problems := expanded.requireExpanded(true, true); len(problems) > 0 {
		t.Fatalf("a layout the expand phase writes has problems: %v", problems)
	}
	if got := len(expanded.perProjectKeys()); got != 3 {
		t.Fatalf("per-project values %v", expanded.perProjectKeys())
	}

	// damage: a ledger the whole-project index does not know, an index entry with no ledger, a pin map that does
	// not pin the replay's checkpoint index.
	damaged := cloneSettings(o.Settings)
	delete(damaged, refledger.LedgerKey(project, roots[0]))
	if problems := parseLayout(damaged, project).problems(false); len(problems) == 0 {
		t.Fatal("a removed ledger went unnoticed")
	}
	damaged = cloneSettings(o.Settings)
	delete(damaged, model.ReplayPinKeyPrefix+project.String())
	if problems := parseLayout(damaged, project).problems(false); len(problems) == 0 {
		t.Fatal("a removed whole-project pin map went unnoticed")
	}
	damaged = cloneSettings(o.Settings)
	damaged[model.ReplayPinKeyPrefix+project.String()] = json.RawMessage(`{}`)
	if problems := parseLayout(damaged, project).problems(false); len(problems) == 0 {
		t.Fatal("a pin map without the replay went unnoticed")
	}
	damaged = cloneSettings(o.Settings)
	delete(damaged, refledger.LegacyAnchorKey(project))
	if problems := parseLayout(damaged, project).problems(false); len(problems) == 0 {
		t.Fatal("a removed anchor went unnoticed")
	}
	if problems := expanded.problems(true); len(problems) == 0 {
		t.Fatal("an expanded layout passed the contracted rules")
	}

	// contract: the product's own step, then the pins by hand (replays.ContractPins is the product's, here only
	// the shape matters).
	if _, err := refledger.Contract(&o); err != nil {
		t.Fatal(err)
	}
	delete(o.Settings, model.ReplayPinKeyPrefix+project.String())
	contracted := parseLayout(o.Settings, project)
	if problems := contracted.problems(true); len(problems) > 0 {
		t.Fatalf("a contracted layout has problems: %v", problems)
	}
	if got := contracted.perProjectKeys(); len(got) != 0 {
		t.Fatalf("per-project values after the contraction: %v", got)
	}
	if problems := contracted.problems(false); len(problems) == 0 {
		t.Fatal("a contracted layout passed the expand rules")
	}
	// after the contraction a write leaves no per-project value
	l := &refledger.Ledger{Project: project, Root: model.NewID(), Seq: 1}
	if err := refledger.Store(&o, project, l); err != nil {
		t.Fatal(err)
	}
	if problems := parseLayout(cloneSettings(o.Settings), project).problems(true); len(problems) > 0 {
		t.Fatalf("a write after the contraction: %v", problems)
	}
	// a stray per-project value after the contraction is caught
	stray := cloneSettings(o.Settings)
	stray[refledger.LegacyIndexKey(project)] = json.RawMessage(`{}`)
	if problems := parseLayout(stray, project).problems(true); len(problems) == 0 {
		t.Fatal("a per-project value after the contraction went unnoticed")
	}
}

func cloneSettings(in map[string]json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// TestExpandPhaseCrashRecovery runs the candidate on a real data directory under load (artifact uploads named by
// error occurrences, which the issue producer turns into ledger writes, and new replays), kills it with SIGKILL
// at a random moment (no graceful stop), and after every kill
//
//   - checks the stored state: the whole-project index names exactly the stored ledgers, the whole-project pin map
//     pins every replay's checkpoint index, every shard is anchored (a crash cannot tear a write);
//   - starts the PREVIOUS release on the directory: it is ready and reads every acknowledged ledger and replay
//     (no corrupt);
//   - starts the candidate again: it reads everything and writes again.
//
// The cycle repeats (SOUNDPOST_CRASH_CYCLES, default 5). Environment: SOUNDPOST_UPGRADE_OLD_RELEASE and
// SOUNDPOST_UPGRADE_NEW_RELEASE (release directories with linux-amd64/soundpost, as
// TestUpgradeRollbackOfProducedBinaries), SOUNDPOST_CRASH_SEED (the random kill moments; default the clock),
// SOUNDPOST_CRASH_REPORT (a JSON report).
func TestExpandPhaseCrashRecovery(t *testing.T) {
	oldRel, newRel := os.Getenv("SOUNDPOST_UPGRADE_OLD_RELEASE"), os.Getenv("SOUNDPOST_UPGRADE_NEW_RELEASE")
	if oldRel == "" || newRel == "" {
		t.Skip("set SOUNDPOST_UPGRADE_OLD_RELEASE and SOUNDPOST_UPGRADE_NEW_RELEASE to release directories")
	}
	cycles := 5
	if v := os.Getenv("SOUNDPOST_CRASH_CYCLES"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			t.Fatalf("SOUNDPOST_CRASH_CYCLES=%q", v)
		}
		cycles = n
	}
	seed := time.Now().UnixNano()
	if v := os.Getenv("SOUNDPOST_CRASH_SEED"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			t.Fatalf("SOUNDPOST_CRASH_SEED=%q", v)
		}
		seed = n
	}
	rng := rand.New(rand.NewPCG(uint64(seed), 1))
	t.Logf("seed %d, %d kill cycles", seed, cycles)
	report := map[string]any{"seed": seed, "cycles": cycles}
	var cycleReports []map[string]any
	defer func() {
		report["cycle_reports"] = cycleReports
		if out := os.Getenv("SOUNDPOST_CRASH_REPORT"); out != "" {
			raw, _ := json.MarshalIndent(report, "", "  ")
			_ = os.WriteFile(out, raw, 0o644)
		}
	}()
	fail := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	oldHostI, err := newBinaryHost(filepath.Join(oldRel, "linux-amd64", "soundpost"), oldRel, map[string]any{})
	fail(err)
	oldHost := oldHostI.(*binaryHost)
	defer oldHost.cleanup()
	newHostI, err := newBinaryHost(filepath.Join(newRel, "linux-amd64", "soundpost"), newRel, map[string]any{})
	fail(err)
	newHost := newHostI.(*binaryHost)
	newHost.cleanup() // only its identity is used: it runs on the old host's directory
	newHost.dir, newHost.holdDir = oldHost.dir, oldHost.holdDir
	dir := oldHost.dir

	// the installation is made by the candidate itself
	run, err := newHost.start()
	fail(err)
	defer func() { run.kill() }()
	cert, err := run.waitCertificate()
	fail(err)
	site := newInstallSite(run.url(), cert)
	fail(run.release())
	fail(run.waitReady(90 * time.Second))
	token, err := run.bootstrapToken()
	fail(err)
	fx, err := bootstrapInstallation(site, token)
	fail(err)
	owner, err := loginOwner(site, fx)
	fail(err)
	analyst, err := provisionAnalyst(owner, site, fx)
	fail(err)

	var acked []expandWrite
	layoutOf := func() storedLayout {
		t.Helper()
		l, err := readStoredLayout(dir, fx.org, fx.project)
		fail(err)
		return l
	}
	for cycle := 1; cycle <= cycles; cycle++ {
		cr := map[string]any{"cycle": cycle}
		cycleReports = append(cycleReports, cr)

		// ---- load on the candidate, then kill -9 at a random moment ----
		var mu sync.Mutex
		var stopped atomic.Bool
		var wg sync.WaitGroup
		var fresh []expandWrite
		var sent atomic.Int64
		loadSite := *site
		worker := func(w int) {
			defer wg.Done()
			for i := 0; !stopped.Load(); i++ {
				if w%2 == 0 {
					status, a, _, err := tryUploadArtifact(&loadSite, analyst, fx, fmt.Sprintf("c%d-w%d-%d", cycle, w, i))
					if err != nil || status != 200 {
						time.Sleep(20 * time.Millisecond)
						continue
					}
					mu.Lock()
					fresh = append(fresh, expandWrite{artifact: a})
					mu.Unlock()
					sent.Add(1)
					tryIngestRecord(&loadSite, fx, namingRecord(fx, a.root()))
				} else {
					rec, id := replayRecord(fx)
					if !tryIngestRecord(&loadSite, fx, rec) {
						time.Sleep(20 * time.Millisecond)
						continue
					}
					mu.Lock()
					fresh = append(fresh, expandWrite{replay: id})
					mu.Unlock()
					sent.Add(1)
				}
			}
		}
		for w := range 4 {
			wg.Add(1)
			go worker(w)
		}
		delay := time.Duration(1500+rng.IntN(5000)) * time.Millisecond
		time.Sleep(delay)
		fail(run.kill()) // SIGKILL: no graceful stop
		stopped.Store(true)
		wg.Wait()
		mu.Lock()
		acked = append(acked, fresh...)
		cr["kill_after_ms"], cr["acknowledged_in_cycle"], cr["acknowledged_total"] = delay.Milliseconds(), len(fresh), len(acked)
		mu.Unlock()

		// ---- the stored state of the killed node ----
		l := layoutOf()
		cr["state_after_kill"] = l.summary()
		t.Logf("cycle %d: killed after %s with %d acknowledged writes in the cycle (%d in all); %s", cycle, delay, len(fresh), len(acked), l.summary())
		if problems := l.problems(false); len(problems) > 0 {
			fail(expandProblem("crash_state", "stored_state_torn", problems))
		}
		if len(l.Ledgers) == 0 && cycle > 1 {
			t.Fatalf("cycle %d: no ledger was ever stored", cycle)
		}

		// ---- the previous release on the killed directory ----
		r, err := startOn(oldHost, site, "old")
		fail(err)
		fail(analyst.login(site))
		fail(requireReads(site, analyst, fx, "old_after_kill", acked))
		cr["old_reads_all_acknowledged"] = true
		fail(r.stop())

		// ---- the candidate again: reads everything, writes again ----
		run, err = startOn(newHost, site, "new")
		fail(err)
		fail(analyst.login(site))
		fail(requireReads(site, analyst, fx, "new_after_kill", acked))
		w, err := writeLedgerAndReplay(site, analyst, fx, dir, fmt.Sprintf("after-kill-%d", cycle))
		fail(err)
		acked = append(acked, w)
		fail(requireReads(site, analyst, fx, "new_after_write", acked))
		l = layoutOf()
		if problems := l.problems(false); len(problems) > 0 {
			fail(expandProblem("crash_state_after_write", "stored_state_wrong", problems))
		}
		cr["new_reads_all_and_writes"] = l.summary()
	}
	fail(run.stop())
	l := layoutOf()
	if problems := l.requireExpanded(true, true); len(problems) > 0 {
		fail(expandProblem("crash_final_state", "stored_state_wrong", problems))
	}
	report["final_state"] = l.summary()
	t.Logf("final: %s; %d acknowledged writes", l.summary(), len(acked))
}
