// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// pinnedMachine is a ledgerMachine whose cut can be pinned (CutPinner): PinCut copies what the applied index fixes
// (the rows and the fences, no derivation), and the pinned cut derives the state, the ledger and the files slowly,
// the way a storage slot machine derives its window table from commands that no later command changes. Its own
// CompactSnapshot, DeletionLedger and PinFiles answer the same questions at the index the machine has now: they
// are what a group that does not pin asks under its locks.
type pinnedMachine struct {
	*ledgerMachine
	// step is called at the start of every derivation step; a test makes it sleep or wait.
	step      func(name string)
	pinned    atomic.Int32          // PinFiles calls that pinned
	releases  atomic.Int32          // releases of what they pinned
	pinFail   atomic.Pointer[error] // PinFiles of a pinned cut fails with it
	badLedger atomic.Bool           // the ledger of a pinned cut has no entries list: it is not one
	live      atomic.Bool           // the pinned cut derives its ledger from the machine's state at the time it is asked, not at the pin
}

func newPinnedMachine(group model.ID, dir string) *pinnedMachine {
	return &pinnedMachine{ledgerMachine: newLedgerMachine(group, dir)}
}

type pinnedCut struct {
	m     *pinnedMachine
	state ledgerState
}

func (m *pinnedMachine) PinCut() (PinnedCut, error) { return m.cutNow(), nil }

func (m *pinnedMachine) cutNow() *pinnedCut {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := make(map[string]string, len(m.rows))
	for k, v := range m.rows {
		rows[k] = v
	}
	return &pinnedCut{m: m, state: ledgerState{Rows: rows, Fences: append([]LedgerEntry{}, m.fences...), Generation: m.generation}}
}

func (c *pinnedCut) at(step string) {
	if c.m.step != nil {
		c.m.step(step)
	}
}

func (c *pinnedCut) CompactSnapshot() ([]byte, error) {
	c.at("state")
	return json.Marshal(c.state)
}

func (c *pinnedCut) DeletionLedger() (Ledger, error) {
	c.at("ledger")
	if c.m.live.Load() { // a machine that did not pin: it answers from what it holds now
		c = c.m.cutNow()
	}
	if c.m.badLedger.Load() {
		return Ledger{Version: 1, Group: c.m.group, Generation: c.state.Generation}, nil // entries absent: not a ledger
	}
	return Ledger{Version: 1, Group: c.m.group, Generation: c.state.Generation, Entries: append([]LedgerEntry{}, c.state.Fences...)}, nil
}

func (c *pinnedCut) PinFiles() ([]PinnedFile, func(), error) {
	c.at("files")
	if err := c.m.pinFail.Load(); err != nil {
		return nil, nil, *err
	}
	c.m.pinned.Add(1)
	return nil, func() { c.m.releases.Add(1) }, nil
}

func (m *pinnedMachine) CompactSnapshot() ([]byte, error) { return m.cutNow().CompactSnapshot() }
func (m *pinnedMachine) DeletionLedger() (Ledger, error)  { return m.cutNow().DeletionLedger() }
func (m *pinnedMachine) PinFiles() ([]PinnedFile, func(), error) {
	return m.cutNow().PinFiles()
}

var (
	_ CutPinner      = (*pinnedMachine)(nil)
	_ PinnedCut      = (*pinnedCut)(nil)
	_ LedgerMachine  = (*pinnedMachine)(nil)
	_ CompactMachine = (*pinnedMachine)(nil)
	_ FileMachine    = (*pinnedMachine)(nil)
)

func openPinned(t *testing.T, m *pinnedMachine, cfg Config) *Group {
	t.Helper()
	transport := NewLoopback()
	cfg.ID, cfg.Group, cfg.Directory, cfg.Transport, cfg.Members, cfg.Machine = 1, m.group, filepath.Join(t.TempDir(), "raft"), transport, soloMembers(), m
	g, err := Open(cfg)
	if err != nil {
		transport.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close(); transport.Close() })
	if err = transport.Register(g); err == nil {
		err = g.Campaign()
	}
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func proposeRow(t *testing.T, g *Group, kind Kind, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := g.Propose(ctx, Entry{ID: model.NewID(), Kind: kind, Payload: []byte(name)}); err != nil {
		t.Fatalf("propose %s: %v", name, err)
	}
}

func cutAtNow(g *Group) (Snapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return g.CreateSnapshot(ctx, g.Status().ApplicationCursor)
}

// A snapshot cut held the ready stage and the group lock for the whole of what the machine derives: a group that holds
// them runs no cycle (no proposal is persisted or applied, no heartbeat leaves) and takes no tick or step, so a
// leader that cuts is silent for as long as the machine takes, and its followers' election timers run. What the
// applied index fixes is the index and term, the members, the retry table and the machine's state at it; the machine
// is asked to pin that (CutPinner) and derives the rest after the locks are released.
func TestCutHoldsTheGroupLocksOnlyToPinTheMachine(t *testing.T) {
	const slow = 150 * time.Millisecond
	m := newPinnedMachine(model.NewID(), t.TempDir())
	m.step = func(string) { time.Sleep(slow) }
	g := openPinned(t, m, Config{})
	for i := range 5 {
		proposeRow(t, g, Data, fmt.Sprintf("row-%d", i))
	}
	proposeRow(t, g, Barrier, "tombstone")
	g.PhaseMaxima()
	began := time.Now()
	snap, err := cutAtNow(g)
	if err != nil {
		t.Fatal(err)
	}
	whole := time.Since(began)
	_, held, _, _ := g.PhaseMaxima()
	t.Logf("a cut whose machine takes 3 x %v: whole %v, group locks held %v", slow, whole, time.Duration(held))
	if whole < 3*slow {
		t.Fatalf("fixture invalid: the cut took %v, the machine's three steps take %v", whole, 3*slow)
	}
	if got := time.Duration(held); got > slow/3 {
		t.Fatalf("the cut held the group locks for %v while the machine derived its state, want at most %v (the capture only)", got, slow/3)
	}
	if snap.Manifest.Ledger.Count != 1 {
		t.Fatalf("the ledger of the cut holds %d entries, want the fence", snap.Manifest.Ledger.Count)
	}
}

// The cycle (a proposal persisted and applied) and the readers of the group (Status takes the group lock, as every tick and
// step does) make progress while the machine derives a cut, and the cut is still the state at the index it was taken at:
// the proposals that commit during it are in the journal and the machine, not in the snapshot.
func TestGroupProgressesWhileTheMachineDerivesACut(t *testing.T) {
	for _, stage := range []string{"state", "ledger", "files"} {
		t.Run(stage, func(t *testing.T) {
			m := newPinnedMachine(model.NewID(), t.TempDir())
			blocked, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			m.step = func(name string) {
				if name == stage {
					once.Do(func() { close(blocked) })
					<-release
				}
			}
			g := openPinned(t, m, Config{})
			for i := range 4 {
				proposeRow(t, g, Data, fmt.Sprintf("before-%d", i))
			}
			proposeRow(t, g, Barrier, "tombstone-before")
			cursor := g.Status().ApplicationCursor
			done := make(chan error, 1)
			var snap Snapshot
			go func() {
				var err error
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				snap, err = g.CreateSnapshot(ctx, cursor)
				done <- err
			}()
			select {
			case <-blocked:
			case <-time.After(10 * time.Second):
				t.Fatalf("the cut never reached the %s step", stage)
			}
			progress := make(chan error, 1)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				for i := range 3 {
					if _, err := g.Propose(ctx, Entry{ID: model.NewID(), Kind: Data, Payload: []byte(fmt.Sprintf("during-%d", i))}); err != nil {
						progress <- err
						return
					}
				}
				if _, err := g.Propose(ctx, Entry{ID: model.NewID(), Kind: Barrier, Payload: []byte("tombstone-during")}); err != nil {
					progress <- err
					return
				}
				g.Status()
				progress <- nil
			}()
			select {
			case err := <-progress:
				if err != nil {
					close(release)
					<-done
					t.Fatalf("a proposal made while the machine derived the %s step of a cut: %v", stage, err)
				}
			case <-time.After(10 * time.Second):
				close(release)
				<-done
				t.Fatalf("the group made no progress for 10 s while the machine derived the %s step of a cut", stage)
			}
			close(release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if snap.Manifest.Cursor != cursor {
				t.Fatalf("the cut is at %+v, want the index it was taken at, %+v", snap.Manifest.Cursor, cursor)
			}
			if snap.Manifest.Ledger.Count != 1 {
				t.Fatalf("the ledger of the cut holds %d fences, want the one that was applied at its index (the one committed during the cut is after it)", snap.Manifest.Ledger.Count)
			}
			raw, err := snap.MachineState()
			if err != nil {
				t.Fatal(err)
			}
			var state ledgerState
			if err = json.Unmarshal(raw, &state); err != nil {
				t.Fatal(err)
			}
			if len(state.Rows) != 5 || len(state.Fences) != 1 {
				t.Fatalf("the state of the cut holds %d rows and %d fences, want the 5 and 1 of its index", len(state.Rows), len(state.Fences))
			}
			if pinned, released := m.pinned.Load(), m.releases.Load(); pinned != 1 || released != 1 {
				t.Fatalf("the cut pinned %d times and released %d times, want once each", pinned, released)
			}
		})
	}
}

// A cut that fails after the machine pinned its files releases them (here: the ledger the machine derived is not one), and
// one whose machine fails to pin leaves the group usable and the next cut whole.
func TestPinnedCutReleasesItsFilesAndAFailedCutLeavesTheGroupUsable(t *testing.T) {
	m := newPinnedMachine(model.NewID(), t.TempDir())
	g := openPinned(t, m, Config{})
	proposeRow(t, g, Data, "row")
	m.badLedger.Store(true)
	if _, err := cutAtNow(g); !errors.Is(err, ErrNoLedger) {
		t.Fatalf("a cut whose ledger is not one returned %v, want ErrNoLedger", err)
	}
	if pinned, released := m.pinned.Load(), m.releases.Load(); pinned != 1 || released != 1 {
		t.Fatalf("the failed cut pinned %d times and released %d times, want once each: the files of a cut that failed after pinning are released", pinned, released)
	}
	m.badLedger.Store(false)
	pinErr := errors.New("machine cannot pin")
	m.pinFail.Store(&pinErr)
	if _, err := cutAtNow(g); !errors.Is(err, pinErr) {
		t.Fatalf("a cut whose machine failed to pin its files returned %v, want %v", err, pinErr)
	}
	proposeRow(t, g, Data, "row-after")
	m.pinFail.Store(nil)
	snap, err := cutAtNow(g)
	if err != nil {
		t.Fatalf("the cut after the failures: %v", err)
	}
	if snap.Manifest.Cursor != g.Status().ApplicationCursor {
		t.Fatalf("the cut after the failures is at %+v, want %+v", snap.Manifest.Cursor, g.Status().ApplicationCursor)
	}
	if pinned, released := m.pinned.Load(), m.releases.Load(); pinned != 2 || released != 2 {
		t.Fatalf("%d pins and %d releases after three cuts of which one failed to pin, want 2 and 2", pinned, released)
	}
}

// What the machine derives after the locks are released is checked against the index the group captured: a ledger that
// names a command after it is not a ledger of that cut.
func TestPinnedCutRefusesALedgerBeyondItsIndex(t *testing.T) {
	m := newPinnedMachine(model.NewID(), t.TempDir())
	g := openPinned(t, m, Config{})
	proposeRow(t, g, Data, "row")
	cursor := g.Status().ApplicationCursor
	m.live.Store(true)
	m.step = func(name string) {
		if name != "state" {
			return
		}
		// A command applied after the index the cut was taken at, which a machine that did not pin would show in its ledger.
		// A group that holds its locks through the derivation cannot apply it: the proposer is not waited for beyond 5 s.
		proposed := make(chan error, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err := g.Propose(ctx, Entry{ID: model.NewID(), Kind: Barrier, Payload: []byte("tombstone-after")})
			proposed <- err
		}()
		select {
		case err := <-proposed:
			if err != nil {
				t.Errorf("a command proposed while the machine derived the cut: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("a command proposed while the machine derived the cut was not applied within 5 s: the group holds its locks through the derivation")
		}
	}
	if _, err := g.CreateSnapshot(t.Context(), cursor); !errors.Is(err, ErrNoLedger) {
		t.Fatalf("a cut whose ledger names a command after its index returned %v, want ErrNoLedger", err)
	}
}
