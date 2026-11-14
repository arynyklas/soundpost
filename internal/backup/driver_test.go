// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/backup"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/storage"
)

// ---- fakes: the real engine is exercised by restore_test.go; these pin the
// driver's own obligations (always seal-or-abort, durable attempt markers, only
// committed control gaps) without needing a failure to happen inside storage.

type fakePlane struct {
	groups   []model.ID
	applied  []model.Cursor
	begins   int
	aborts   int
	seals    int
	cut      storage.ControlCut
	gaps     []storage.DeclaredGap
	beginErr error
	sealErr  error
	onBegin  func()
	onSeal   func()
}

func newFakePlane() *fakePlane {
	p := &fakePlane{}
	for i := range 64 {
		g := model.NewID()
		p.groups = append(p.groups, g)
		p.applied = append(p.applied, model.Cursor{Group: g, Index: model.Uint64(100 + i)})
	}
	return p
}
func (p *fakePlane) Applied() []model.Cursor { return append([]model.Cursor(nil), p.applied...) }
func (p *fakePlane) Begin(ctx context.Context, cut storage.ControlCut) (backup.PlaneSession, error) {
	p.begins++
	p.cut = cut
	if p.onBegin != nil {
		p.onBegin()
	}
	if p.beginErr != nil {
		return nil, p.beginErr
	}
	return &fakeSession{p: p}, nil
}

type fakeSession struct {
	p       *fakePlane
	aborted bool
}

func (s *fakeSession) Seal(ctx context.Context, gaps []storage.DeclaredGap) (storage.SealedBackup, error) {
	s.p.seals++
	s.p.gaps = append([]storage.DeclaredGap(nil), gaps...)
	if s.p.onSeal != nil {
		s.p.onSeal()
	}
	return storage.SealedBackup{}, s.p.sealErr
}
func (s *fakeSession) Abort() { s.p.aborts++ }

type fakeControl struct {
	state model.ControlState
	seed  []byte
	rev   uint64
	err   error
	views int
}

func newFakeControl(t *testing.T, plane *fakePlane) *fakeControl {
	t.Helper()
	c := &fakeControl{state: model.ControlState{Installation: model.NewID(), Revision: 42, Reservations: map[string]model.AdmissionReservation{}, EvidenceGaps: map[string]model.EvidenceGap{}}}
	c.refresh(t)
	return c
}
func (c *fakeControl) refresh(t *testing.T) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"state": c.state, "keys": map[string][]byte{"envelope.key": []byte("0123456789abcdef0123456789abcdef")}, "metadata": map[string][]byte{}})
	if err != nil {
		t.Fatal(err)
	}
	c.seed, c.rev = raw, uint64(c.state.Revision)
}
func (c *fakeControl) View(ctx context.Context, fn func(model.ControlState) error) error {
	c.views++
	if c.err != nil {
		return c.err
	}
	return fn(c.state)
}
func (c *fakeControl) ReplicationSeed() ([]byte, uint64, error) { return c.seed, c.rev, nil }

type fakeLedger struct {
	cur backup.CurrentDeletion
	err error
}

func (l *fakeLedger) Current(ctx context.Context) (backup.CurrentDeletion, error) {
	return l.cur, l.err
}

type fakeAuthorizer struct {
	err   error
	calls int
}

func (a *fakeAuthorizer) RevalidateInstance(ctx context.Context, scope auth.Scope) error {
	a.calls++
	return a.err
}

type fakePins struct {
	pins    []backup.Pin
	dropped []string
	failOn  string
}

func (p *fakePins) Pins() ([]backup.Pin, error) { return append([]backup.Pin(nil), p.pins...), nil }
func (p *fakePins) DropPin(id string) error {
	if id == p.failOn {
		return errors.New("pin busy")
	}
	p.dropped = append(p.dropped, id)
	for i, pin := range p.pins {
		if pin.ID == id {
			p.pins = append(p.pins[:i], p.pins[i+1:]...)
			break
		}
	}
	return nil
}

type driverFixture struct {
	t       *testing.T
	plane   *fakePlane
	control *fakeControl
	ledger  *fakeLedger
	authz   *fakeAuthorizer
	attempt backup.DirAttempts
	pins    *fakePins
	svc     *backup.Service
	dest    *backup.LocalDestination
	destDir string
}

func newDriverFixture(t *testing.T) *driverFixture {
	t.Helper()
	f := &driverFixture{t: t, plane: newFakePlane(), authz: &fakeAuthorizer{}, pins: &fakePins{}}
	f.control = newFakeControl(t, f.plane)
	authority := model.NewID()
	f.ledger = &fakeLedger{cur: backup.CurrentDeletion{Installation: f.control.state.Installation, Head: backup.AuthorityHead{Authority: authority, Sequence: 0}, Ledger: replica.Ledger{Version: 1, Group: f.control.state.Installation, Entries: []replica.LedgerEntry{}}}}
	f.attempt = backup.DirAttempts(filepath.Join(t.TempDir(), "attempts"))
	f.destDir = t.TempDir()
	var err error
	if f.dest, err = backup.NewLocalDestination(f.destDir); err != nil {
		t.Fatal(err)
	}
	keys := backup.StaticKeys{}
	for _, id := range []string{"data-kek", "secret-kek"} {
		k, err := backup.GenerateKey(id)
		if err != nil {
			t.Fatal(err)
		}
		keys[id] = k
	}
	f.svc, err = backup.New(backup.Config{Control: f.control, Data: f.plane, Processed: backup.AppliedProcessed(f.plane), Authority: f.ledger, Authorizer: f.authz, Keys: keys, DataKEK: "data-kek", SecretKEK: "secret-kek", Attempts: f.attempt, Pins: f.pins, Clock: func() time.Time { return time.Unix(1_800_000_000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *driverFixture) destObjects() []string {
	names, _ := f.dest.List(context.Background(), "")
	return names
}

func TestBackupAlwaysSealsOrAborts(t *testing.T) {
	ctx := context.Background()
	t.Run("a failing seal aborts the pins and finishes the attempt", func(t *testing.T) {
		f := newDriverFixture(t)
		f.plane.sealErr = errors.New("seal failed")
		if _, err := f.svc.Run(ctx, auth.Scope{}, f.dest); err == nil {
			t.Fatal("run succeeded although the seal failed")
		}
		if f.plane.begins != 1 || f.plane.aborts != 1 {
			t.Fatalf("begins=%d aborts=%d: pins would leak", f.plane.begins, f.plane.aborts)
		}
		if open, _ := f.attempt.Incomplete(ctx); len(open) != 0 {
			t.Fatalf("attempt left incomplete: %v", open)
		}
		if got := f.destObjects(); len(got) != 0 {
			t.Fatalf("a failed backup published objects: %v", got)
		}
	})
	t.Run("a panic during the seal still aborts", func(t *testing.T) {
		f := newDriverFixture(t)
		f.plane.onSeal = func() { panic("boom") }
		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("the panic was swallowed")
				}
			}()
			_, _ = f.svc.Run(ctx, auth.Scope{}, f.dest)
		}()
		if f.plane.aborts != 1 {
			t.Fatalf("a panicking seal leaked its pins (aborts=%d)", f.plane.aborts)
		}
		if open, _ := f.attempt.Incomplete(ctx); len(open) != 0 {
			t.Fatal("a panicking backup left its attempt incomplete in this process")
		}
		done, _ := filepath.Glob(filepath.Join(string(f.attempt), "*.done"))
		if len(done) != 1 {
			t.Fatalf("%d attempt outcomes recorded", len(done))
		}
		if raw, _ := os.ReadFile(done[0]); string(raw) != "aborted" {
			t.Fatalf("a panicking backup was recorded as %q", raw)
		}
	})
	t.Run("a cancelled context aborts", func(t *testing.T) {
		f := newDriverFixture(t)
		cancelled, cancel := context.WithCancel(ctx)
		f.plane.onSeal = cancel
		f.plane.sealErr = context.Canceled
		if _, err := f.svc.Run(cancelled, auth.Scope{}, f.dest); err == nil || f.plane.aborts != 1 {
			t.Fatalf("cancel: err=%v aborts=%d", err, f.plane.aborts)
		}
	})
	t.Run("a refused begin never starts and still closes the attempt", func(t *testing.T) {
		f := newDriverFixture(t)
		f.plane.beginErr = errors.New("group unavailable")
		if _, err := f.svc.Run(ctx, auth.Scope{}, f.dest); err == nil {
			t.Fatal("run succeeded without pins")
		}
		if open, _ := f.attempt.Incomplete(ctx); len(open) != 0 {
			t.Fatalf("attempt left incomplete after a refused begin: %v", open)
		}
	})
	t.Run("a deletion that aborts the backup restarts it from a new cut", func(t *testing.T) {
		f := newDriverFixture(t)
		calls := 0
		f.plane.onSeal = func() {
			calls++
			if calls == 1 {
				f.plane.sealErr = model.Fail(model.Conflict) // storage: a deletion touched pinned evidence
			} else {
				f.plane.sealErr = errors.New("second attempt stops here")
			}
		}
		_, err := f.svc.Run(ctx, auth.Scope{}, f.dest)
		if err == nil || f.plane.begins != 2 || f.plane.aborts != 2 {
			t.Fatalf("restart after deletion: err=%v begins=%d aborts=%d", err, f.plane.begins, f.plane.aborts)
		}
	})
}

func TestAttemptMarkerIsDurableBeforeBeginBackup(t *testing.T) {
	ctx := context.Background()
	f := newDriverFixture(t)
	var seenDuringBegin []backup.Attempt
	var files []string
	f.plane.onBegin = func() {
		seenDuringBegin, _ = f.attempt.Incomplete(ctx)
		// A restarted process sees the same marker: it is on disk, not in memory.
		entries, _ := os.ReadDir(string(f.attempt))
		for _, e := range entries {
			files = append(files, e.Name())
		}
	}
	f.plane.sealErr = errors.New("stop")
	_, _ = f.svc.Run(ctx, auth.Scope{}, f.dest)
	if len(seenDuringBegin) != 1 || len(files) != 1 {
		t.Fatalf("no durable attempt marker when BeginBackup ran: %v %v", seenDuringBegin, files)
	}
	if seenDuringBegin[0].ControlRevision != 42 || seenDuringBegin[0].StartedAt != model.UnixNano(1_800_000_000*int64(time.Second)) {
		t.Fatalf("marker content: %+v", seenDuringBegin[0])
	}
}

func TestStartupReaperDropsPinsOfAttemptsThatNeverCompleted(t *testing.T) {
	ctx := context.Background()
	f := newDriverFixture(t)
	// A process died between BeginBackup and Seal/Abort: marker on disk, pins pinned, no Finish.
	died := backup.Attempt{ID: model.NewID(), StartedAt: 1, ControlRevision: 7}
	if err := f.attempt.Begin(ctx, died); err != nil {
		t.Fatal(err)
	}
	finished := backup.Attempt{ID: model.NewID(), StartedAt: 2, ControlRevision: 8}
	if err := f.attempt.Begin(ctx, finished); err != nil {
		t.Fatal(err)
	}
	if err := f.attempt.Finish(ctx, finished.ID, "completed"); err != nil {
		t.Fatal(err)
	}
	f.pins.pins = []backup.Pin{{ID: "pin-slot-0", Group: "g0"}, {ID: "pin-slot-1", Group: "g1"}}
	// A fresh Service instance is the restarted process.
	report, err := f.svc.Reap(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(f.pins.dropped)
	if report.Attempts != 1 || report.Dropped != 2 || len(f.pins.dropped) != 2 || len(f.pins.pins) != 0 {
		t.Fatalf("reap: %+v dropped=%v remaining=%v", report, f.pins.dropped, f.pins.pins)
	}
	if open, _ := f.attempt.Incomplete(ctx); len(open) != 0 {
		t.Fatalf("reaped attempt still incomplete: %v", open)
	}
	// Idempotent.
	if again, err := f.svc.Reap(ctx); err != nil || again.Attempts != 0 || again.Dropped != 0 {
		t.Fatalf("second reap: %+v %v", again, err)
	}
	t.Run("pins without a marker are reported, never dropped", func(t *testing.T) {
		g := newDriverFixture(t)
		g.pins.pins = []backup.Pin{{ID: "pin-unowned", Group: "g0"}}
		report, err := g.svc.Reap(ctx)
		if err != nil || report.Unowned != 1 || report.Dropped != 0 || len(g.pins.dropped) != 0 {
			t.Fatalf("unowned pin handling: %+v %v", report, err)
		}
	})
	t.Run("a pin that cannot be dropped keeps the attempt open and fails loudly", func(t *testing.T) {
		g := newDriverFixture(t)
		if err := g.attempt.Begin(ctx, backup.Attempt{ID: model.NewID(), StartedAt: 3, ControlRevision: 9}); err != nil {
			t.Fatal(err)
		}
		g.pins.pins = []backup.Pin{{ID: "pin-a"}, {ID: "pin-stuck"}}
		g.pins.failOn = "pin-stuck"
		if _, err := g.svc.Reap(ctx); err == nil {
			t.Fatal("a stuck pin was reported as reaped")
		}
		if open, _ := g.attempt.Incomplete(ctx); len(open) != 1 {
			t.Fatal("the attempt was closed while a pin was still held")
		}
	})
	t.Run("without a reaper the attempt stays open", func(t *testing.T) {
		g := newDriverFixture(t)
		svc, err := backup.New(backup.Config{Control: g.control, Data: g.plane, Processed: backup.AppliedProcessed(g.plane), Authority: g.ledger, Authorizer: g.authz, Keys: backup.StaticKeys{}, DataKEK: "data-kek", SecretKEK: "secret-kek", Attempts: g.attempt})
		if err != nil {
			t.Fatal(err)
		}
		if err = g.attempt.Begin(ctx, backup.Attempt{ID: model.NewID(), StartedAt: 4, ControlRevision: 1}); err != nil {
			t.Fatal(err)
		}
		report, err := svc.Reap(ctx)
		if err == nil && report.Attempts != 0 {
			t.Fatal("attempts were closed without any ability to drop pins")
		}
		if open, _ := g.attempt.Incomplete(ctx); len(open) != 1 {
			t.Fatal("attempt closed without a reaper")
		}
	})
}

func TestDriverDeclaresOnlyCommittedControlGaps(t *testing.T) {
	ctx := context.Background()
	f := newDriverFixture(t)
	org, project := model.NewID(), model.NewID()
	g1, g2 := f.plane.groups[3], f.plane.groups[40]
	f.control.state.EvidenceGaps = map[string]model.EvidenceGap{}
	for _, gap := range []model.EvidenceGap{
		{ID: model.NewID(), Org: org, Project: project, Group: g1, After: 10, Through: 12, Count: 2, Reason: "unprocessed_expiry", RecordedAt: 5},
		{ID: model.NewID(), Org: org, Project: project, Group: g2, After: 20, Through: 25, Count: 5, Reason: "unprocessed_expiry", RecordedAt: 6},
	} {
		f.control.state.EvidenceGaps[gap.ID.String()] = gap
	}
	f.control.refresh(t)
	f.plane.sealErr = errors.New("stop after seal")
	_, _ = f.svc.Run(ctx, auth.Scope{}, f.dest)
	if f.plane.seals != 1 {
		t.Fatal("seal never ran")
	}
	want := map[storage.DeclaredGap]bool{
		{Group: g1, After: 10, Through: 12, Reason: "unprocessed_expiry"}: true,
		{Group: g2, After: 20, Through: 25, Reason: "unprocessed_expiry"}: true,
	}
	if len(f.plane.gaps) != 2 {
		t.Fatalf("driver declared %d gaps, control committed 2: %+v", len(f.plane.gaps), f.plane.gaps)
	}
	for _, g := range f.plane.gaps {
		if !want[g] {
			t.Fatalf("driver declared a gap control never committed: %+v", g)
		}
	}
	// No committed fact, no declared gap: the seal must fail on a hole instead.
	g := newDriverFixture(t)
	g.plane.sealErr = errors.New("stop")
	_, _ = g.svc.Run(ctx, auth.Scope{}, g.dest)
	if len(g.plane.gaps) != 0 {
		t.Fatalf("gaps declared with no control fact: %+v", g.plane.gaps)
	}
	// A fact naming a group the installation does not own is a corrupt control state.
	h := newDriverFixture(t)
	foreign := model.EvidenceGap{ID: model.NewID(), Org: org, Project: project, Group: model.NewID(), After: 1, Through: 3, Count: 2, Reason: "unprocessed_expiry", RecordedAt: 5}
	h.control.state.EvidenceGaps = map[string]model.EvidenceGap{foreign.ID.String(): foreign}
	h.control.refresh(t)
	if _, err := h.svc.Run(ctx, auth.Scope{}, h.dest); err == nil || h.plane.begins != 0 {
		t.Fatalf("a gap for a foreign group did not stop the backup before it pinned anything (err=%v begins=%d)", err, h.plane.begins)
	}
}

func TestDriverBindsTheCutToTheSeedItStores(t *testing.T) {
	ctx := context.Background()
	f := newDriverFixture(t)
	reserved := model.AdmissionReservation{ID: model.NewID(), Org: model.NewID(), Project: model.NewID(), Source: model.NewID(), Producer: model.NewID(), Batch: model.NewID(), Slot: 3, Bytes: 10, State: "reserved"}
	f.control.state.Reservations[reserved.ID.String()] = reserved
	f.control.state.Revision = 77
	f.control.refresh(t)
	f.plane.sealErr = errors.New("stop")
	_, _ = f.svc.Run(ctx, auth.Scope{}, f.dest)
	cut := f.plane.cut
	if cut.Revision != 77 || len(cut.Reservations) != 1 || cut.Reservations[reserved.ID.String()].ID != reserved.ID || len(cut.Processed) != 64 {
		t.Fatalf("cut: revision=%d reservations=%d processed=%d", cut.Revision, len(cut.Reservations), len(cut.Processed))
	}
	for i, c := range cut.Processed {
		if c != f.plane.applied[i] {
			t.Fatal("AppliedProcessed must report each group's applied cursor in slot order")
		}
	}
	// A seed whose revision disagrees with the state inside it is never used.
	g := newDriverFixture(t)
	g.control.rev = 1
	if _, err := g.svc.Run(ctx, auth.Scope{}, g.dest); err == nil || g.plane.begins != 0 {
		t.Fatalf("an inconsistent control seed started a backup (err=%v)", err)
	}
}

func TestDriverRefusesWithoutAuthorityOrAuthorization(t *testing.T) {
	ctx := context.Background()
	f := newDriverFixture(t)
	f.authz.err = model.Fail(model.Forbidden)
	if _, err := f.svc.Run(ctx, auth.Scope{}, f.dest); err == nil || f.plane.begins != 0 || f.control.views != 0 {
		t.Fatalf("an unauthorized caller reached the control plane: err=%v", err)
	}
	g := newDriverFixture(t)
	g.ledger.err = model.Fail(model.Unavailable)
	if _, err := g.svc.Run(ctx, auth.Scope{}, g.dest); err == nil || g.plane.begins != 0 {
		t.Fatalf("a backup was taken without a verifiable deletion authority (err=%v begins=%d)", err, g.plane.begins)
	}
	if open, _ := g.attempt.Incomplete(ctx); len(open) != 0 {
		t.Fatal("a refused backup left an attempt marker behind")
	}
	if _, err := backup.New(backup.Config{Control: g.control, Data: g.plane, Processed: backup.AppliedProcessed(g.plane), Authorizer: g.authz, Keys: backup.StaticKeys{}, DataKEK: "d", SecretKEK: "s", Attempts: g.attempt}); err == nil {
		t.Fatal("a backup service without a deletion authority was constructed")
	}
	if _, err := backup.New(backup.Config{Control: g.control, Data: g.plane, Authority: g.ledger, Authorizer: g.authz, Keys: backup.StaticKeys{}, DataKEK: "d", SecretKEK: "s", Attempts: g.attempt}); err == nil {
		t.Fatal("a backup service without a processed-highwater source was constructed")
	}
}
