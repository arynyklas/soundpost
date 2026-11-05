// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"soundpost/internal/model"
	"soundpost/internal/replica"
	"soundpost/internal/retention"
)

type authFixture struct {
	t            *testing.T
	dir          string
	dest         *LocalDestination
	keys         AuthorityKeys
	clock        time.Time
	a            *Authority
	installation model.ID
}

func newAuthFixture(t *testing.T) *authFixture {
	t.Helper()
	f := &authFixture{t: t, dir: t.TempDir(), clock: time.Unix(1_800_000_000, 0), installation: model.NewID()}
	var err error
	if f.dest, err = NewLocalDestination(f.dir); err != nil {
		t.Fatal(err)
	}
	if f.keys, err = GenerateAuthorityKeys("authority-key-1"); err != nil {
		t.Fatal(err)
	}
	f.a = f.open(f.dest, f.keys)
	return f
}
func (f *authFixture) open(dest Destination, keys AuthorityKeys) *Authority {
	f.t.Helper()
	a, err := NewAuthority(dest, keys, func() time.Time { return f.clock })
	if err != nil {
		f.t.Fatal(err)
	}
	return a
}
func (f *authFixture) initialize() {
	f.t.Helper()
	if _, err := f.a.Initialize(context.Background(), f.installation); err != nil {
		f.t.Fatal(err)
	}
}

func tombstone(org, project model.ID, start, end int64) model.DeletePredicate {
	return model.DeletePredicate{Operation: model.NewID(), Org: org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{project}, Signals: []model.Kind{model.Metric}, Start: model.UnixNano(start), End: model.UnixNano(end), Generation: 1}
}
func generation(installation model.ID, n uint64, tombs ...model.DeletePredicate) retention.LedgerGeneration {
	ledger := replica.Ledger{Version: 1, Group: installation, Generation: n, Entries: []replica.LedgerEntry{}}
	for i, p := range tombs {
		ledger.Entries = append(ledger.Entries, replica.LedgerEntry{Index: uint64(i + 1), Kind: p.Mode, Hash: p.Digest()})
	}
	return retention.LedgerGeneration{Generation: n, Ledger: ledger, Tombstones: append([]model.DeletePredicate(nil), tombs...)}
}
func headNames(t *testing.T, d Destination) []string {
	t.Helper()
	names, err := d.List(context.Background(), "authority/head/")
	if err != nil {
		t.Fatal(err)
	}
	return names
}
func faultCode(err error) model.Code {
	var fault *model.Fault
	if errors.As(err, &fault) {
		return fault.Code
	}
	return ""
}

func TestAuthorityIsFailClosedUntilInitialized(t *testing.T) {
	f := newAuthFixture(t)
	ctx := context.Background()
	if _, err := f.a.Current(ctx); err == nil {
		t.Fatal("an empty destination was read as an authority with no deletions")
	}
	if _, err := f.a.CurrentDeletionLedger(ctx); err == nil {
		t.Fatal("CurrentDeletionLedger answered for an uninitialized authority")
	}
	if _, err := f.a.CheckpointDeletion(ctx, generation(f.installation, 1, tombstone(model.NewID(), model.NewID(), 1, 2))); err == nil {
		t.Fatal("a checkpoint was accepted without an initialized authority")
	}
	id, err := f.a.Initialize(ctx, f.installation)
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.a.Initialize(ctx, f.installation)
	if err != nil || again != id {
		t.Fatalf("initialize is not idempotent: %v", err)
	}
	if _, err = f.a.Initialize(ctx, model.NewID()); faultCode(err) != model.Conflict {
		t.Fatalf("a different installation re-initialized the authority: %v", err)
	}
	cur, err := f.a.Current(ctx)
	if err != nil || cur.Head.Sequence != 0 || cur.Head.Generation != 0 || cur.Head.Authority != id || cur.Installation != f.installation || len(cur.Tombstones) != 0 || cur.Ledger.Group != f.installation || cur.Ledger.Entries == nil {
		t.Fatalf("fresh authority head: %+v %v", cur, err)
	}
	// Deleting ROOT turns the authority into an unverifiable one, never an empty one.
	if err = os.Remove(filepath.Join(f.dir, "authority", "ROOT")); err != nil {
		t.Fatal(err)
	}
	if _, err = f.a.Current(ctx); err == nil {
		t.Fatal("an authority whose root was removed answered")
	}
}

func TestCheckpointAdvancesAMonotonicSignedHead(t *testing.T) {
	f := newAuthFixture(t)
	f.initialize()
	ctx := context.Background()
	org, project := model.NewID(), model.NewID()
	t1, t2 := tombstone(org, project, 10, 20), tombstone(org, project, 30, 40)
	f.clock = f.clock.Add(time.Minute)
	r1, err := f.a.CheckpointDeletion(ctx, generation(f.installation, 5, t1))
	if err != nil {
		t.Fatal(err)
	}
	if r1.Generation != 5 || r1.At != model.UnixNano(f.clock.UnixNano()) || r1.Head == (model.Hash{}) {
		t.Fatalf("receipt: %+v", r1)
	}
	f.clock = f.clock.Add(time.Minute)
	r2, err := f.a.CheckpointDeletion(ctx, generation(f.installation, 6, t1, t2))
	if err != nil {
		t.Fatal(err)
	}
	cur, err := f.a.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cur.Head.Sequence != 2 || cur.Head.Generation != 6 || cur.Head.Digest != r2.Head || len(cur.Chain) != 2 || cur.Chain[0] != r1.Head || cur.Chain[1] != r2.Head {
		t.Fatalf("head does not bind the receipts: %+v", cur.Head)
	}
	if len(cur.Tombstones) != 2 || cur.Tombstones[0].Digest() != t1.Digest() || cur.Tombstones[1].Digest() != t2.Digest() || cur.Ledger.Generation != 6 || len(cur.Ledger.Entries) != 2 {
		t.Fatal("the current ledger/tombstones are not the last checkpoint")
	}
	ledger, err := f.a.CurrentDeletionLedger(ctx)
	tombs, err2 := f.a.CurrentDeletionTombstones(ctx)
	if err != nil || err2 != nil || ledger.Generation != 6 || len(tombs) != 2 {
		t.Fatal("the retention interfaces disagree with Current")
	}
	if got := headNames(t, f.dest); len(got) != 2 {
		t.Fatalf("immutable generations not retained: %v", got)
	}
}

func TestCheckpointIsIdempotentNeverRegressesAndRejectsForks(t *testing.T) {
	f := newAuthFixture(t)
	f.initialize()
	ctx := context.Background()
	org, project := model.NewID(), model.NewID()
	t1, t2, t3 := tombstone(org, project, 1, 2), tombstone(org, project, 3, 4), tombstone(org, project, 5, 6)
	first, err := f.a.CheckpointDeletion(ctx, generation(f.installation, 3, t1, t2))
	if err != nil {
		t.Fatal(err)
	}
	// A retry returns the same receipt without a new record.
	retry, err := f.a.CheckpointDeletion(ctx, generation(f.installation, 3, t1, t2))
	if err != nil || retry.Head != first.Head || retry.Generation != first.Generation {
		t.Fatalf("retry: %+v %v", retry, err)
	}
	// An older ledger the head already covers is satisfied by the head (no regression).
	older, err := f.a.CheckpointDeletion(ctx, generation(f.installation, 2, t1))
	if err != nil || older.Head != first.Head || older.Generation != 3 {
		t.Fatalf("subsumed checkpoint: %+v %v", older, err)
	}
	if n := len(headNames(t, f.dest)); n != 1 {
		t.Fatalf("idempotent/subsumed checkpoints wrote %d records", n)
	}
	// Same deletions, higher generation (e.g. after physical erasure): a new head.
	bumped, err := f.a.CheckpointDeletion(ctx, generation(f.installation, 4, t1, t2))
	if err != nil || bumped.Head == first.Head || bumped.Generation != 4 {
		t.Fatalf("generation bump: %+v %v", bumped, err)
	}
	// A ledger that forgets an existing tombstone is refused however high its generation.
	if _, err = f.a.CheckpointDeletion(ctx, generation(f.installation, 99, t1, t3)); faultCode(err) != model.Conflict {
		t.Fatalf("a ledger dropping a tombstone was accepted: %v", err)
	}
	if _, err = f.a.CheckpointDeletion(ctx, generation(f.installation, 99)); faultCode(err) != model.Conflict {
		t.Fatalf("an empty ledger over existing deletions was accepted: %v", err)
	}
	// Malformed ledgers never reach the store.
	bad := generation(f.installation, 9, t1, t2, t3)
	bad.Ledger.Entries[1].Hash[0] ^= 1
	if _, err = f.a.CheckpointDeletion(ctx, bad); faultCode(err) == "" {
		t.Fatal("a ledger whose digests do not match its tombstones was accepted")
	}
	wrongGroup := generation(model.NewID(), 9, t1, t2, t3)
	if _, err = f.a.CheckpointDeletion(ctx, wrongGroup); err == nil {
		t.Fatal("a ledger of another installation was accepted")
	}
	mismatch := generation(f.installation, 9, t1, t2, t3)
	mismatch.Generation = 8
	if _, err = f.a.CheckpointDeletion(ctx, mismatch); err == nil {
		t.Fatal("a generation that disagrees with its ledger was accepted")
	}
	dup := generation(f.installation, 9, t1, t1)
	if _, err = f.a.CheckpointDeletion(ctx, dup); err == nil {
		t.Fatal("a duplicated tombstone was accepted")
	}
	if cur, _ := f.a.Current(ctx); cur.Head.Generation != 4 || cur.Head.Sequence != 2 {
		t.Fatalf("rejected checkpoints moved the head: %+v", cur.Head)
	}
}

func TestCheckpointRacesHaveExactlyOneWinnerPerSequence(t *testing.T) {
	f := newAuthFixture(t)
	f.initialize()
	ctx := context.Background()
	org, project := model.NewID(), model.NewID()
	other, err := NewAuthority(f.dest, f.keys, func() time.Time { return f.clock })
	if err != nil {
		t.Fatal(err)
	}
	a, b := tombstone(org, project, 1, 2), tombstone(org, project, 3, 4)
	// Two writers each believe they are advancing from the same head with different ledgers.
	errs := make(chan error, 2)
	go func() { _, err := f.a.CheckpointDeletion(ctx, generation(f.installation, 1, a)); errs <- err }()
	go func() { _, err := other.CheckpointDeletion(ctx, generation(f.installation, 1, b)); errs <- err }()
	e1, e2 := <-errs, <-errs
	if (e1 == nil) == (e2 == nil) {
		t.Fatalf("two writers racing for one sequence must leave exactly one winner, got %v / %v", e1, e2)
	}
	cur, err := f.a.Current(ctx)
	if err != nil || cur.Head.Sequence != 1 || len(cur.Tombstones) != 1 {
		t.Fatalf("head after a race: %+v %v", cur.Head, err)
	}
}

// tamperTargets are the stored bytes whose alteration must never be read as authority.
func TestAuthorityDetectsTamperingGapsForeignSignersAndWrongKeys(t *testing.T) {
	ctx := context.Background()
	build := func(t *testing.T) (*authFixture, string) {
		f := newAuthFixture(t)
		f.initialize()
		org, project := model.NewID(), model.NewID()
		for i := range 3 {
			prev := []model.DeletePredicate{}
			if cur, err := f.a.Current(ctx); err == nil {
				prev = cur.Tombstones
			}
			if _, err := f.a.CheckpointDeletion(ctx, generation(f.installation, uint64(i+1), append(prev, tombstone(org, project, int64(10*i), int64(10*i+5)))...)); err != nil {
				t.Fatal(err)
			}
		}
		return f, filepath.Join(f.dir, "authority", "head")
	}
	t.Run("flipping any region of any stored record", func(t *testing.T) {
		f, heads := build(t)
		entries, _ := os.ReadDir(heads)
		for _, e := range entries {
			path := filepath.Join(heads, e.Name())
			orig := mustRead(t, path)
			for _, at := range []int{0, len(orig) / 4, len(orig) / 2, 3 * len(orig) / 4, len(orig) - 2} {
				flipped := bytes.Clone(orig)
				flipped[at] ^= 0x20
				if err := os.WriteFile(path, flipped, 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := f.a.Current(ctx); err == nil {
					t.Fatalf("flipped byte %d of %s was accepted as authority", at, e.Name())
				}
			}
			_ = os.WriteFile(path, orig, 0600)
		}
		if _, err := f.a.Current(ctx); err != nil {
			t.Fatalf("restored bytes no longer verify: %v", err)
		}
	})
	t.Run("a missing middle generation", func(t *testing.T) {
		f, heads := build(t)
		entries, _ := os.ReadDir(heads)
		if err := os.Remove(filepath.Join(heads, entries[1].Name())); err != nil {
			t.Fatal(err)
		}
		if _, err := f.a.Current(ctx); err == nil {
			t.Fatal("a chain with a missing generation answered")
		}
	})
	t.Run("a record from another authority's chain", func(t *testing.T) {
		f, heads := build(t)
		foreign := newAuthFixture(t)
		foreign.installation = f.installation
		foreign.initialize()
		if _, err := foreign.a.CheckpointDeletion(ctx, generation(f.installation, 3, tombstone(model.NewID(), model.NewID(), 1, 2))); err != nil {
			t.Fatal(err)
		}
		entries, _ := os.ReadDir(heads)
		last := filepath.Join(heads, entries[len(entries)-1].Name())
		if err := os.WriteFile(last, mustRead(t, filepath.Join(foreign.dir, "authority", "head", "00000000000000000001")), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := f.a.Current(ctx); err == nil {
			t.Fatal("a record signed under another authority was accepted")
		}
	})
	t.Run("reader with the wrong keys", func(t *testing.T) {
		f, _ := build(t)
		wrong, _ := GenerateAuthorityKeys("authority-key-1")
		if _, err := f.open(f.dest, wrong).Current(ctx); err == nil {
			t.Fatal("different keys with the same id read the authority")
		}
		// The sealing key alone, without the signing identity, cannot validate anything.
		sealOnly := f.keys
		sealOnly.public = wrong.public
		if _, err := f.open(f.dest, sealOnly).Current(ctx); err == nil {
			t.Fatal("a reader trusting a different public key accepted the chain")
		}
	})
	t.Run("rolling the head back is visible to a manifest binding", func(t *testing.T) {
		f, heads := build(t)
		before, _ := f.a.Current(ctx)
		entries, _ := os.ReadDir(heads)
		if err := os.Remove(filepath.Join(heads, entries[len(entries)-1].Name())); err != nil {
			t.Fatal(err)
		}
		after, err := f.a.Current(ctx)
		if err != nil {
			t.Fatalf("a consistent prefix is a valid (older) chain: %v", err)
		}
		if after.Head.Sequence >= before.Head.Sequence {
			t.Fatal("rollback not reflected")
		}
		// The chain digests let a restore notice that the head it was promised is gone.
		if len(after.Chain) != len(before.Chain)-1 || after.Chain[len(after.Chain)-1] == before.Chain[len(before.Chain)-1] {
			t.Fatal("chain does not expose the rollback")
		}
	})
}

type flakyDest struct {
	Destination
	failCreate func(name string) error
	drop       func(name string) bool // report success but store nothing
	corrupt    func(name string) bool // store, but read back different bytes
}

func (d *flakyDest) Create(ctx context.Context, name string, r io.Reader, size int64) error {
	if d.failCreate != nil {
		if err := d.failCreate(name); err != nil {
			return err
		}
	}
	if d.drop != nil && d.drop(name) {
		_, _ = io.Copy(io.Discard, r)
		return nil
	}
	return d.Destination.Create(ctx, name, r, size)
}
func (d *flakyDest) Open(ctx context.Context, name string) (io.ReadCloser, error) {
	rc, err := d.Destination.Open(ctx, name)
	if err != nil || d.corrupt == nil || !d.corrupt(name) {
		return rc, err
	}
	raw, _ := io.ReadAll(rc)
	rc.Close()
	raw[len(raw)/2] ^= 1
	return io.NopCloser(bytes.NewReader(raw)), nil
}

func TestAuthorityFailureIsNeverAReceipt(t *testing.T) {
	ctx := context.Background()
	f := newAuthFixture(t)
	f.initialize()
	flaky := &flakyDest{Destination: f.dest}
	a := f.open(flaky, f.keys)
	org, project := model.NewID(), model.NewID()
	t1 := tombstone(org, project, 1, 2)
	isHead := func(name string) bool { return strings.HasPrefix(name, "authority/head/") }
	t.Run("destination refuses the write", func(t *testing.T) {
		flaky.failCreate = func(n string) error {
			if isHead(n) {
				return errors.New("disk full")
			}
			return nil
		}
		if r, err := a.CheckpointDeletion(ctx, generation(f.installation, 1, t1)); err == nil || r.Head != (model.Hash{}) {
			t.Fatalf("a failed write produced a receipt: %+v %v", r, err)
		}
		if cur, _ := f.a.Current(ctx); cur.Head.Sequence != 0 {
			t.Fatal("a failed write advanced the head")
		}
	})
	t.Run("destination claims success but stored nothing", func(t *testing.T) {
		flaky.failCreate = nil
		flaky.drop = isHead
		if r, err := a.CheckpointDeletion(ctx, generation(f.installation, 1, t1)); err == nil || r.Head != (model.Hash{}) {
			t.Fatalf("an unverified write produced a receipt: %+v %v", r, err)
		}
	})
	t.Run("destination returns different bytes than it stored", func(t *testing.T) {
		flaky.drop = nil
		flaky.corrupt = isHead
		if r, err := a.CheckpointDeletion(ctx, generation(f.installation, 1, t1)); err == nil || r.Head != (model.Hash{}) {
			t.Fatalf("a read-back mismatch produced a receipt: %+v %v", r, err)
		}
		flaky.corrupt = nil
	})
	t.Run("a healed destination completes the same checkpoint", func(t *testing.T) {
		receipt, err := a.CheckpointDeletion(ctx, generation(f.installation, 1, t1))
		if err != nil || receipt.Generation != 1 {
			t.Fatalf("retry after healing: %+v %v", receipt, err)
		}
		cur, err := f.a.Current(ctx)
		if err != nil || cur.Head.Digest != receipt.Head || cur.Head.Sequence != 1 {
			t.Fatalf("head after healing: %+v %v", cur.Head, err)
		}
	})
}

func TestAuthorityRecordsAreSealedAndRestrictedKeysCannotWrite(t *testing.T) {
	ctx := context.Background()
	f := newAuthFixture(t)
	f.initialize()
	org, project := model.NewID(), model.NewID()
	if _, err := f.a.CheckpointDeletion(ctx, generation(f.installation, 1, tombstone(org, project, 1, 2))); err != nil {
		t.Fatal(err)
	}
	_ = filepath.WalkDir(f.dir, func(path string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return nil
		}
		raw := mustRead(t, path)
		for _, secret := range []string{org.String(), project.String()} {
			if bytes.Contains(raw, []byte(secret)) {
				t.Fatalf("%s carries a deleted scope identifier in the clear", path)
			}
		}
		return nil
	})
	restricted := f.open(f.dest, f.keys.Restricted())
	cur, err := restricted.Current(ctx)
	if err != nil || len(cur.Tombstones) != 1 {
		t.Fatalf("restricted keys cannot verify and read: %v", err)
	}
	if _, err = restricted.CheckpointDeletion(ctx, generation(f.installation, 2, cur.Tombstones[0], tombstone(org, project, 5, 6))); faultCode(err) != model.Forbidden {
		t.Fatalf("a verification-only key checkpointed: %v", err)
	}
	if _, err = restricted.Initialize(ctx, f.installation); err != nil && faultCode(err) != model.Forbidden {
		t.Fatalf("restricted initialize: %v", err)
	}
}

func TestPinnedAuthorityAnswersOneHeadAndNeverWrites(t *testing.T) {
	ctx := context.Background()
	f := newAuthFixture(t)
	f.initialize()
	org, project := model.NewID(), model.NewID()
	tomb := tombstone(org, project, 1, 2)
	if _, err := f.a.CheckpointDeletion(ctx, generation(f.installation, 1, tomb)); err != nil {
		t.Fatal(err)
	}
	cur, err := f.a.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pinned := cur.AsAuthority()
	ledger, err := pinned.CurrentDeletionLedger(ctx)
	if err != nil || ledger.Generation != 1 || len(ledger.Entries) != 1 {
		t.Fatalf("pinned ledger: %v", err)
	}
	source, ok := pinned.(retention.TombstoneSource)
	if !ok {
		t.Fatal("pinned authority is not a TombstoneSource")
	}
	tombs, err := source.CurrentDeletionTombstones(ctx)
	if err != nil || len(tombs) != 1 || tombs[0].Digest() != tomb.Digest() {
		t.Fatalf("pinned tombstones: %v", err)
	}
	if _, err = pinned.CheckpointDeletion(ctx, generation(f.installation, 2, tomb)); err == nil {
		t.Fatal("a pinned (restore-time) authority accepted a checkpoint")
	}
	// Later checkpoints do not change what the pinned view answers.
	if _, err = f.a.CheckpointDeletion(ctx, generation(f.installation, 2, tomb, tombstone(org, project, 5, 6))); err != nil {
		t.Fatal(err)
	}
	if l, _ := pinned.CurrentDeletionLedger(ctx); l.Generation != 1 {
		t.Fatal("the pinned view moved")
	}
}

func TestAuthorityKeyFilesArePrivateAndRestrictedFilesCarryNoSigner(t *testing.T) {
	dir := t.TempDir()
	keys, err := GenerateAuthorityKeys("authority-key-1")
	if err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(dir, "authority.json")
	if err = WriteAuthorityKeys(full, keys); err != nil {
		t.Fatal(err)
	}
	if err = WriteAuthorityKeys(full, keys); err == nil {
		t.Fatal("an authority key file was overwritten")
	}
	got, err := ReadAuthorityKeys(full)
	if err != nil || got.ID != keys.ID || got.signer == nil {
		t.Fatalf("round trip: %v", err)
	}
	restricted := filepath.Join(dir, "restricted.json")
	if err = WriteAuthorityKeys(restricted, keys.Restricted()); err != nil {
		t.Fatal(err)
	}
	r, err := ReadAuthorityKeys(restricted)
	if err != nil || r.signer != nil || r.seal.b != keys.seal.b {
		t.Fatalf("restricted key file: %v", err)
	}
	if bytes.Contains(mustRead(t, restricted), []byte("signing")) {
		t.Fatal("the restricted key file carries a signing key")
	}
	if runtime.GOOS != "windows" {
		if err = os.Chmod(full, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err = ReadAuthorityKeys(full); err == nil {
			t.Fatal("a world-readable authority key file was accepted")
		}
	}
}

// The same journal over an S3-compatible bucket: signed requests, create-only
// writes, a multi-page listing, and a chain that verifies end to end.
func TestAuthorityRunsOverAnS3CompatibleDestination(t *testing.T) {
	ctx := context.Background()
	fake, server := newFakeS3("SECRETKEY-MUST-NEVER-LEAK")
	defer server.Close()
	dest := newS3(t, server, "authority-prefix")
	keys, err := GenerateAuthorityKeys("authority-key-1")
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAuthority(dest, keys, func() time.Time { return time.Unix(1_800_000_000, 0) })
	if err != nil {
		t.Fatal(err)
	}
	installation := model.NewID()
	if _, err = a.Initialize(ctx, installation); err != nil {
		t.Fatal(err)
	}
	org, project := model.NewID(), model.NewID()
	var tombs []model.DeletePredicate
	var last retention.AuthorityReceipt
	for i := range 5 { // more records than one listing page (the fake pages two keys at a time)
		tombs = append(tombs, tombstone(org, project, int64(10*i), int64(10*i+5)))
		if last, err = a.CheckpointDeletion(ctx, generation(installation, uint64(i+1), tombs...)); err != nil {
			t.Fatal(err)
		}
	}
	cur, err := a.Current(ctx)
	if err != nil || cur.Head.Sequence != 5 || cur.Head.Digest != last.Head || len(cur.Tombstones) != 5 || len(cur.Chain) != 5 {
		t.Fatalf("journal over S3: %+v %v", cur.Head, err)
	}
	// A restricted reader on another process sees the same verified head.
	reader, _ := NewAuthority(dest, keys.Restricted(), time.Now)
	if got, err := reader.Current(ctx); err != nil || got.Head.Digest != cur.Head.Digest {
		t.Fatalf("restricted reader: %v", err)
	}
	// Stored objects are sealed: no scope identifier in any stored body.
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for key, body := range fake.objects {
		if bytes.Contains(body, []byte(org.String())) || bytes.Contains(body, []byte(project.String())) {
			t.Fatalf("%s carries a deleted scope identifier in the clear", key)
		}
	}
}
