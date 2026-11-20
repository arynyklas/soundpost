//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
)

// Pins for the ProfileSource wrapper (l4w33 mutation battery A).

type stoppableSource struct {
	sweepingSource
	stopErr error
	stopped int
}

func (s *stoppableSource) Stop() error { s.stopped++; return s.stopErr }

// Next returns the event of an item, the error of the source, and refuses a proof (a caller that wants proofs asks
// NextItem).
func TestProfileSourceNextReturnsEventsErrorsAndRefusesProofs(t *testing.T) {
	proof := AcquisitionProof{Domain: ClockDomain{HostID: "host", BootID: "boot"}, CPUs: []uint32{0}, Through: 50}
	src := &sweepingSource{items: []AcquisitionItem{sidebandSample(100), {Proof: &proof}}}
	s := &ProfileSource{source: src, domain: ClockDomain{HostID: "host", BootID: "boot"}}
	e, err := s.Next(context.Background())
	if err != nil || e.Kind != EventCPU || e.Time != 100 || e.Sequence != 1 {
		t.Fatalf("%+v %v", e, err)
	}
	if e, err = s.Next(context.Background()); !errors.Is(err, ErrProgressRequired) || e.Kind != "" {
		t.Fatalf("%+v %v", e, err)
	}
	if e, err = s.Next(context.Background()); !errors.Is(err, ErrSourceComplete) || e.Kind != "" {
		t.Fatalf("%+v %v", e, err)
	}
}

// An event the source cannot validate after numbering is the capture's failure, never published.
func TestProfileSourceNeverPublishesAnInvalidEvent(t *testing.T) {
	bad := sidebandSample(100)
	bad.Event.Task.Generation = 0
	s := &ProfileSource{source: &sweepingSource{items: []AcquisitionItem{bad}}, domain: ClockDomain{HostID: "host", BootID: "boot"}}
	if item, err := s.NextItem(context.Background()); !errors.Is(err, ErrAcquisitionFailed) || item.Event != nil {
		t.Fatalf("%+v %v", item, err)
	}
}

// Stop of a closed source is a closed error; a source that cannot stop says so; the final reconciliation is owed only
// after the wrapped acquisition stopped.
func TestProfileSourceStopOwesTheFinalReconciliationOnlyAfterTheAcquisitionStopped(t *testing.T) {
	unlocked := func(s *ProfileSource, what string) {
		t.Helper()
		if !s.mu.TryLock() {
			t.Fatalf("%s left the source locked", what)
		}
		s.mu.Unlock()
	}
	closed := &ProfileSource{closed: true, source: &stoppableSource{}}
	if err := closed.Stop(); !errors.Is(err, ErrAcquisitionClosed) {
		t.Fatalf("%v", err)
	}
	unlocked(closed, "Stop of a closed source")
	cannot := &ProfileSource{source: &sweepingSource{}}
	if err := cannot.Stop(); err == nil {
		t.Fatal("a source that cannot stop was reported stopped")
	} else if ce := (*CapabilityError)(nil); !errors.As(err, &ce) || ce.Status != Unsupported || ce.Reason != ReasonEvent {
		t.Fatalf("%v", err)
	}
	unlocked(cannot, "Stop of a source that cannot stop")
	ok := &stoppableSource{}
	s := &ProfileSource{source: ok}
	if err := s.Stop(); err != nil || ok.stopped != 1 || !s.finalDue {
		t.Fatalf("%v stopped %d finalDue %v", err, ok.stopped, s.finalDue)
	}
	unlocked(s, "Stop")
	want := errors.New("stop failed")
	failing := &stoppableSource{stopErr: want}
	f := &ProfileSource{source: failing}
	if err := f.Stop(); !errors.Is(err, want) || f.finalDue {
		t.Fatalf("%v finalDue %v", err, f.finalDue)
	}
	unlocked(f, "a failed Stop")
}

// NewProfileAcquisition refuses before it opens anything: a context that has ended wins over every argument error,
// and the policy must be the revision of the capture.
func TestNewProfileAcquisitionRefusesBeforeItOpensAnything(t *testing.T) {
	cfg := DefaultConfig(1)
	a := AuthorizedTargets{targets: []Target{{TGID: 1, PIDNamespace: 2, ProcessStart: 3}}, mode: ModeCPU}
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewProfileAcquisition(ended, a, cfg, nil, SymbolPolicy{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("an ended context: %v", err)
	}
	b := NewResourceBudget()
	r, err := b.Reserve(a, cfg, Topology{CPUs: 1, FDLimit: 1024, PageBytes: 4096}, MemoryUsage{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err = NewProfileAcquisition(context.Background(), a, cfg, r, DefaultSymbolPolicy(2)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a policy of another revision: %v", err)
	}
	if _, err = NewProfileAcquisition(context.Background(), a, cfg, nil, DefaultSymbolPolicy(1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no reservation: %v", err)
	}
	if _, err = NewProfileAcquisition(context.Background(), AuthorizedTargets{mode: ModeCPU}, cfg, r, DefaultSymbolPolicy(1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no targets: %v", err)
	}
	if b.memory != r.Memory || b.fds != r.FDs {
		t.Fatalf("a refused request leaked a lease: budget %d/%d, reservation %d/%d", b.memory, b.fds, r.Memory, r.FDs)
	}
}

// endsAfter is a context that reports cancellation from its n-th Err call on.
type endsAfter struct {
	context.Context
	left atomic.Int32
}

func (c *endsAfter) Err() error {
	if c.left.Add(-1) < 0 {
		return context.Canceled
	}
	return nil
}

// A context that ends while the targets are being opened ends the request there, with its own error, before any
// target is read.
func TestNewProfileAcquisitionStopsBetweenTargetsWhenItsContextEnds(t *testing.T) {
	if _, err := localCPUDomain(); err != nil {
		t.Skipf("no host identity here: %v", err)
	}
	cfg := DefaultConfig(1)
	a := AuthorizedTargets{targets: []Target{{TGID: 1, PIDNamespace: 2, ProcessStart: 3}}, mode: ModeCPU}
	b := NewResourceBudget()
	r, err := b.Reserve(a, cfg, Topology{CPUs: 1, FDLimit: 1024, PageBytes: 4096}, MemoryUsage{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx := &endsAfter{Context: context.Background()}
	ctx.left.Store(1) // the entry check passes, the check before the first target does not
	if _, err = NewProfileAcquisition(ctx, a, cfg, r, DefaultSymbolPolicy(1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
	if b.memory != r.Memory || b.fds != r.FDs {
		t.Fatalf("leases leaked: budget %d/%d, reservation %d/%d", b.memory, b.fds, r.Memory, r.FDs)
	}
}

// The three leases are exactly: the map-read scratch with 3 descriptors per target and 6 more, then two leases that
// hold no descriptor. With room for no more than that, the request gets past admission and fails only on the target it
// cannot open; with one descriptor less it is refused as a resource error.
func TestNewProfileAcquisitionLeasesExactlyTheDescriptorsItNeeds(t *testing.T) {
	cfg := DefaultConfig(1)
	a := AuthorizedTargets{targets: []Target{{TGID: 1, PIDNamespace: 2, ProcessStart: 3}}, mode: ModeCPU}
	for _, c := range []struct {
		name string
		room uint64
		want func(error) bool
	}{
		{"exact room", 9, func(err error) bool { return err != nil && !errors.Is(err, ErrResources) }},
		{"one descriptor short", 8, func(err error) bool { return errors.Is(err, ErrResources) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := NewResourceBudget()
			r, err := b.Reserve(a, cfg, Topology{CPUs: 1, FDLimit: 1024, PageBytes: 4096}, MemoryUsage{})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			r.fdCeiling = r.FDs + c.room
			if _, err = NewProfileAcquisition(context.Background(), a, cfg, r, DefaultSymbolPolicy(1)); !c.want(err) {
				t.Fatalf("room for %d descriptors: %v", c.room, err)
			}
			if b.memory != r.Memory || b.fds != r.FDs {
				t.Fatalf("a failed request leaked a lease: budget %d/%d, reservation %d/%d", b.memory, b.fds, r.Memory, r.FDs)
			}
		})
	}
}

const hostIdentityChildEnv = "L4W33_NO_HOST_IDENTITY_CHILD"

// noHostIdentityRefused is the contract on a host whose identity cannot be read: the request is refused as an identity
// failure before any target is opened, and holds no lease afterwards.
func noHostIdentityRefused(t *testing.T) {
	t.Helper()
	cfg := DefaultConfig(1)
	a := AuthorizedTargets{targets: []Target{{TGID: 1, PIDNamespace: 2, ProcessStart: 3}}, mode: ModeCPU}
	b := NewResourceBudget()
	r, err := b.Reserve(a, cfg, Topology{CPUs: 1, FDLimit: 1024, PageBytes: 4096}, MemoryUsage{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err = NewProfileAcquisition(context.Background(), a, cfg, r, DefaultSymbolPolicy(1)); !errors.Is(err, ErrTargetIdentity) {
		t.Fatalf("a host without an identity: %v", err)
	}
	if b.memory != r.Memory || b.fds != r.FDs {
		t.Fatalf("leases leaked: budget %d/%d, reservation %d/%d", b.memory, b.fds, r.Memory, r.FDs)
	}
}

// TestNewProfileAcquisitionHostIdentityChild is the body of the re-execution below; it does nothing otherwise.
func TestNewProfileAcquisitionHostIdentityChild(t *testing.T) {
	if os.Getenv(hostIdentityChildEnv) == "" {
		t.Skip("helper of TestNewProfileAcquisitionRefusesAHostWithoutAnIdentity")
	}
	noHostIdentityRefused(t)
}

// A host whose machine identity cannot be read is refused. Where this host has one, root runs the check once more in a
// private mount namespace in which the file is empty.
func TestNewProfileAcquisitionRefusesAHostWithoutAnIdentity(t *testing.T) {
	if _, err := localCPUDomain(); err != nil {
		noHostIdentityRefused(t)
		return
	}
	if os.Getuid() != 0 {
		t.Skip("needs root for a private mount namespace")
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("no unshare(1)")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	cmd := exec.Command("unshare", "--mount", "--propagation", "private", "sh", "-c",
		`mount --bind /dev/null /etc/machine-id && exec "$0" -test.run=^TestNewProfileAcquisitionHostIdentityChild$ -test.v -test.count=1`, exe)
	cmd.Env = append(os.Environ(), hostIdentityChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	text := string(out)
	if strings.Contains(text, "--- FAIL") || strings.Contains(text, "panic:") {
		t.Fatalf("the child failed:\n%s", text)
	}
	if !strings.Contains(text, "--- PASS: TestNewProfileAcquisitionHostIdentityChild") {
		if err != nil {
			t.Skipf("the private mount namespace is not available here: %v\n%s", err, text)
		}
		t.Fatalf("the child did not run:\n%s", text)
	}
}
