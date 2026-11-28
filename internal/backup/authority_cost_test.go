// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/retention"
)

// The first journal format (authorityFormat) stores the WHOLE tombstone ledger in every record, so
// it is O(D^2) bytes in D completed deletions, and Current (run by every checkpoint twice, by
// every backup and by every restore) fetches, decrypts, verifies and re-validates all of it. The
// current format (authorityDelta) stores the tombstones each record appends, with a whole-ledger
// checkpoint at every power-of-two sequence, which is linear. The benchmarks measure both; they
// are not run by `go test` (see docs/operations/backup-restore.md):
//
//	go test ./internal/backup -run '^$' -bench 'AuthorityCurrent' -benchtime=1x
//
// Journals are forged directly (no per-record verification) because writing one through
// CheckpointDeletion costs O(D) per record.

// forgeRecord writes one signed, sealed head record of the FIRST format (the whole ledger) without the read-back.
func (a *Authority) forgeRecord(ctx context.Context, tb testing.TB, authority model.ID, sequence uint64, prev model.Hash, installation model.ID, tombstones []model.DeletePredicate) model.Hash {
	tb.Helper()
	g := generation(installation, sequence, tombstones...)
	plain, err := json.Marshal(headPayload{Ledger: g.Ledger, Tombstones: g.Tombstones})
	if err != nil {
		tb.Fatal(err)
	}
	aead, err := a.keys.seal.aead()
	if err != nil {
		tb.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		tb.Fatal(err)
	}
	rec := headRecord{Version: authorityFormat, Authority: authority, Sequence: sequence, Prev: prev, Generation: g.Generation, Tombstones: uint64(len(tombstones)), Payload: digestOf(plain), At: model.UnixNano(a.now().UnixNano()), KeyID: a.keys.ID, Nonce: nonce}
	rec.Sealed = aead.Seal(nil, nonce, plain, payloadAAD(authority, sequence, prev, g.Generation))
	if rec.Signature, err = a.sign(rec); err != nil {
		tb.Fatal(err)
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		tb.Fatal(err)
	}
	if err = a.dest.Create(ctx, headName(sequence), bytes.NewReader(raw), int64(len(raw))); err != nil {
		tb.Fatal(err)
	}
	return digestOf(raw)
}

// forgeJournal builds a journal whose record i (1-based) holds counts[i-1] tombstones.
func forgeJournal(b *testing.B, counts []int) (*Authority, string) {
	b.Helper()
	ctx := context.Background()
	dir := b.TempDir()
	dest, err := NewLocalDestination(dir)
	if err != nil {
		b.Fatal(err)
	}
	keys, err := GenerateAuthorityKeys("authority-key-1")
	if err != nil {
		b.Fatal(err)
	}
	a, err := NewAuthority(dest, keys, nil)
	if err != nil {
		b.Fatal(err)
	}
	installation := model.NewID()
	if _, err = a.Initialize(ctx, installation); err != nil {
		b.Fatal(err)
	}
	cur, err := a.Current(ctx)
	if err != nil {
		b.Fatal(err)
	}
	most := 0
	for _, n := range counts {
		most = max(most, n)
	}
	all := make([]model.DeletePredicate, most)
	org, project := model.NewID(), model.NewID()
	for i := range all {
		all[i] = tombstone(org, project, int64(10*i), int64(10*i+5))
	}
	prev := cur.Head.Digest
	for i, n := range counts {
		prev = a.forgeRecord(ctx, b, cur.Head.Authority, uint64(i+1), prev, installation, all[:n])
	}
	return a, dir
}

func journalBytes(b *testing.B, dir string) int64 {
	b.Helper()
	var total int64
	entries, err := os.ReadDir(filepath.Join(dir, "authority", "head"))
	if err != nil {
		b.Fatal(err)
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			b.Fatal(err)
		}
		total += info.Size()
	}
	return total
}

// BenchmarkAuthorityCurrentWholeJournal: D records, record i holding i tombstones
// (the shape CheckpointDeletion produces: one more deletion per record).
func BenchmarkAuthorityCurrentWholeJournal(b *testing.B) {
	for _, d := range []int{100, 250, 500, 1000, 2000} {
		b.Run(fmt.Sprintf("tombstones=%d", d), func(b *testing.B) {
			counts := make([]int, d)
			for i := range counts {
				counts[i] = i + 1
			}
			a, dir := forgeJournal(b, counts)
			size := journalBytes(b, dir)
			b.ResetTimer()
			for range b.N {
				if _, err := a.Current(context.Background()); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(size)/(1<<20), "MiB/read")
		})
	}
}

// BenchmarkAuthorityCurrentOneRecord: a journal of a single record holding n
// tombstones. The record cost is linear in n, so the whole-journal cost for D
// deletions is about D * (cost of an average record) = D * cost(n=D) / 2.
func BenchmarkAuthorityCurrentOneRecord(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		b.Run(fmt.Sprintf("tombstones=%d", n), func(b *testing.B) {
			a, dir := forgeJournal(b, []int{n})
			size := journalBytes(b, dir)
			b.ResetTimer()
			for range b.N {
				if _, err := a.Current(context.Background()); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(size)/(1<<20), "MiB/record")
		})
	}
}

// ---- the delta format ----------------------------------------------------------------------------

// countingDest counts the bytes a reader pulls out of the destination.
type countingDest struct {
	Destination
	read atomic.Int64
}

type countedReader struct {
	io.ReadCloser
	n *atomic.Int64
}

func (r countedReader) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	r.n.Add(int64(n))
	return n, err
}

func (c *countingDest) Open(ctx context.Context, name string) (io.ReadCloser, error) {
	rc, err := c.Destination.Open(ctx, name)
	if err != nil {
		return rc, err
	}
	return countedReader{rc, &c.read}, nil
}

// forgedDeltas is a journal of d records of the current format, record i appending one tombstone.
type forgedDeltas struct {
	keys         AuthorityKeys
	dir          string
	installation model.ID
	authority    model.ID
	root         model.Hash
	tombstones   []model.DeletePredicate
	entries      []replica.LedgerEntry
}

func forgeDeltaJournal(tb testing.TB, d int) forgedDeltas {
	tb.Helper()
	ctx := context.Background()
	f := forgedDeltas{dir: tb.TempDir(), installation: model.NewID()}
	dest, err := NewLocalDestination(f.dir)
	if err != nil {
		tb.Fatal(err)
	}
	if f.keys, err = GenerateAuthorityKeys("authority-key-1"); err != nil {
		tb.Fatal(err)
	}
	a, err := NewAuthority(dest, f.keys, nil)
	if err != nil {
		tb.Fatal(err)
	}
	if _, err = a.Initialize(ctx, f.installation); err != nil {
		tb.Fatal(err)
	}
	cur, err := a.Current(ctx)
	if err != nil {
		tb.Fatal(err)
	}
	f.authority, f.root = cur.Head.Authority, cur.Head.Digest
	org, project := model.NewID(), model.NewID()
	for i := range d {
		t := tombstone(org, project, int64(10*i), int64(10*i+5))
		f.tombstones = append(f.tombstones, t)
		f.entries = append(f.entries, replica.LedgerEntry{Index: uint64(i + 1), Kind: t.Mode, Hash: t.Digest()})
	}
	prev := f.root
	for i := range d {
		n := i + 1
		g := retention.LedgerGeneration{Generation: uint64(n), Ledger: replica.Ledger{Version: 1, Group: f.installation, Generation: uint64(n), Entries: f.entries[:n]}, Tombstones: f.tombstones[:n]}
		_, raw, err := a.sealRecord(f.authority, uint64(n), prev, g, i)
		if err != nil {
			tb.Fatal(err)
		}
		if err = dest.Create(ctx, headName(uint64(n)), bytes.NewReader(raw), int64(len(raw))); err != nil {
			tb.Fatal(err)
		}
		prev = digestOf(raw)
	}
	return f
}

// read opens the journal through a counting destination and reads the whole of it once.
func (f forgedDeltas) read(tb testing.TB) (CurrentDeletion, int64) {
	tb.Helper()
	dest, err := NewLocalDestination(f.dir)
	if err != nil {
		tb.Fatal(err)
	}
	counted := &countingDest{Destination: dest}
	a, err := NewAuthority(counted, f.keys, nil)
	if err != nil {
		tb.Fatal(err)
	}
	cur, err := a.Current(context.Background())
	if err != nil {
		tb.Fatal(err)
	}
	return cur, counted.read.Load()
}

// Reading the journal must cost what the journal is, and the journal must grow with the number of
// deletions: 4x the deletions is about 4x the bytes read, where the first format read 16x (1,000
// deletions were 224 MiB, ten seconds). A writer that stores the whole ledger in every record
// (checkpoint at every sequence) fails the ratio and the size bound.
func TestAuthorityReadCostIsLinearInDeletions(t *testing.T) {
	small, large := forgeDeltaJournal(t, 250), forgeDeltaJournal(t, 1000)
	cs, bytesSmall := small.read(t)
	cl, bytesLarge := large.read(t)
	for _, c := range []struct {
		cur  CurrentDeletion
		want int
	}{{cs, 250}, {cl, 1000}} {
		if len(c.cur.Tombstones) != c.want || len(c.cur.Ledger.Entries) != c.want || c.cur.Head.Sequence != uint64(c.want) || len(c.cur.Chain) != c.want {
			t.Fatalf("a journal of %d deletions reads back as %d tombstones at sequence %d", c.want, len(c.cur.Tombstones), c.cur.Head.Sequence)
		}
	}
	ratio := float64(bytesLarge) / float64(bytesSmall)
	t.Logf("bytes read: 250 deletions %d, 1000 deletions %d (x%.2f for x4 deletions)", bytesSmall, bytesLarge, ratio)
	if ratio > 6 {
		t.Fatalf("read cost grew x%.1f for x4 deletions: not linear", ratio)
	}
	if bytesLarge > 8<<20 {
		t.Fatalf("1000 deletions read %d bytes (the first format read 224 MiB)", bytesLarge)
	}
}

func readHead(t *testing.T, a *Authority, sequence uint64) headRecord {
	t.Helper()
	raw, err := a.read(context.Background(), headName(sequence))
	if err != nil {
		t.Fatal(err)
	}
	var rec headRecord
	if err = json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

// A checkpoint at every power-of-two sequence, deltas between: the writer produced by
// CheckpointDeletion, and a reader that agrees with it.
func TestAuthorityWritesDeltasAndCheckpointsAtPowersOfTwo(t *testing.T) {
	f := newAuthFixture(t)
	f.initialize()
	ctx := context.Background()
	org, project := model.NewID(), model.NewID()
	var all []model.DeletePredicate
	for n := 1; n <= 9; n++ {
		all = append(all, tombstone(org, project, int64(10*n), int64(10*n+5)))
		if _, err := f.a.CheckpointDeletion(ctx, generation(f.installation, uint64(n), all...)); err != nil {
			t.Fatal(n, err)
		}
	}
	for n := uint64(1); n <= 9; n++ {
		rec := readHead(t, f.a, n)
		want := kindDelta
		if n == 2 || n == 4 || n == 8 {
			want = kindCheckpoint
		}
		if rec.Version != authorityDelta || rec.Kind != want || rec.Tombstones != n {
			t.Fatalf("record %d: version %d kind %q total %d, want kind %q", n, rec.Version, rec.Kind, rec.Tombstones, want)
		}
	}
	// A delta holds one tombstone however long the ledger is.
	if one, seven := readHead(t, f.a, 1), readHead(t, f.a, 7); len(seven.Sealed) > 2*len(one.Sealed) {
		t.Fatalf("record 7 seals %d bytes, record 1 %d: a delta grows with the ledger", len(seven.Sealed), len(one.Sealed))
	}
	cur, err := f.a.Current(ctx)
	if err != nil || len(cur.Tombstones) != 9 || cur.Head.Sequence != 9 || cur.Head.Generation != 9 || len(cur.Ledger.Entries) != 9 || cur.Ledger.Generation != 9 {
		t.Fatalf("current: %+v %v", cur.Head, err)
	}
	for i, p := range all {
		if cur.Tombstones[i].Digest() != p.Digest() || cur.Ledger.Entries[i].Index != uint64(i+1) || cur.Ledger.Entries[i].Hash != p.Digest() {
			t.Fatalf("tombstone %d is not the one appended", i+1)
		}
	}
	// The ledger is append-only: the same tombstones in another order are a fork, not a delta.
	reordered := generation(f.installation, 10, append([]model.DeletePredicate{all[1], all[0]}, all[2:]...)...)
	if _, err = f.a.CheckpointDeletion(ctx, reordered); faultCode(err) != model.Conflict {
		t.Fatalf("a reordered ledger was appended: %v", err)
	}
}

// Journals written before the delta format hold the whole ledger in every record. They stay readable,
// and a writer appends the new format after them, whose checkpoint is checked against that ledger.
func TestAuthorityReadsAFirstFormatJournalAndAppendsDeltasToIt(t *testing.T) {
	f := newAuthFixture(t)
	f.initialize()
	ctx := context.Background()
	cur, err := f.a.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	org, project := model.NewID(), model.NewID()
	var all []model.DeletePredicate
	for n := 1; n <= 6; n++ {
		all = append(all, tombstone(org, project, int64(10*n), int64(10*n+5)))
	}
	prev := cur.Head.Digest
	for n := 1; n <= 3; n++ {
		prev = f.a.forgeRecord(ctx, t, cur.Head.Authority, uint64(n), prev, f.installation, all[:n])
	}
	if old, err := f.a.Current(ctx); err != nil || len(old.Tombstones) != 3 || old.Head.Sequence != 3 {
		t.Fatalf("a first-format journal does not read: %+v %v", old.Head, err)
	}
	// Record 4 is a checkpoint over the first-format ledger, record 5 a delta.
	for n := 4; n <= 5; n++ {
		if _, err = f.a.CheckpointDeletion(ctx, generation(f.installation, uint64(n), all[:n+1]...)); err != nil {
			t.Fatal(n, err)
		}
	}
	if rec := readHead(t, f.a, 4); rec.Version != authorityDelta || rec.Kind != kindCheckpoint {
		t.Fatalf("record 4: %+v", rec)
	}
	if rec := readHead(t, f.a, 5); rec.Version != authorityDelta || rec.Kind != kindDelta {
		t.Fatalf("record 5: %+v", rec)
	}
	got, err := f.a.Current(ctx)
	if err != nil || len(got.Tombstones) != 6 || got.Head.Sequence != 5 || len(got.Ledger.Entries) != 6 {
		t.Fatalf("mixed journal: %+v %v", got.Head, err)
	}
}

// The reader holds every record to the ledger it has replayed: a checkpoint that is not exactly that
// ledger, a delta that skips an index or repeats an operation, and an unknown kind are all corrupt,
// even when signed by the authority's own key.
func TestAuthorityRejectsRecordsThatDisagreeWithTheLedgerTheyExtend(t *testing.T) {
	org, project := model.NewID(), model.NewID()
	t1, t2, t3 := tombstone(org, project, 10, 15), tombstone(org, project, 20, 25), tombstone(org, project, 30, 35)
	entry := func(i uint64, t model.DeletePredicate) replica.LedgerEntry {
		return replica.LedgerEntry{Index: i, Kind: t.Mode, Hash: t.Digest()}
	}
	cases := map[string]struct {
		kind    string
		total   uint64
		payload deltaPayload
	}{
		"a checkpoint that names another tombstone": {kindCheckpoint, 1, deltaPayload{Entries: []replica.LedgerEntry{entry(1, t2)}, Tombstones: []model.DeletePredicate{t2}}},
		"a checkpoint that forgot a tombstone":      {kindCheckpoint, 0, deltaPayload{Entries: []replica.LedgerEntry{}, Tombstones: []model.DeletePredicate{}}},
		"a delta that skips an index":               {kindDelta, 2, deltaPayload{Entries: []replica.LedgerEntry{entry(3, t2)}, Tombstones: []model.DeletePredicate{t2}}},
		"a delta that repeats an operation":         {kindDelta, 2, deltaPayload{Entries: []replica.LedgerEntry{entry(2, t1)}, Tombstones: []model.DeletePredicate{t1}}},
		"a delta whose total is wrong":              {kindDelta, 3, deltaPayload{Entries: []replica.LedgerEntry{entry(2, t3)}, Tombstones: []model.DeletePredicate{t3}}},
		"a record of an unknown kind":               {"rewrite", 2, deltaPayload{Entries: []replica.LedgerEntry{entry(2, t3)}, Tombstones: []model.DeletePredicate{t3}}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newAuthFixture(t)
			f.initialize()
			ctx := context.Background()
			if _, err := f.a.CheckpointDeletion(ctx, generation(f.installation, 1, t1)); err != nil {
				t.Fatal(err)
			}
			head, err := f.a.Current(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, raw, err := f.a.sealPayload(head.Head.Authority, 2, head.Head.Digest, 2, c.kind, c.total, c.payload)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.dest.Create(ctx, headName(2), bytes.NewReader(raw), int64(len(raw))); err != nil {
				t.Fatal(err)
			}
			if _, err = f.a.Current(ctx); faultCode(err) != model.Corrupt {
				t.Fatalf("%s was read as authority: %v", name, err)
			}
		})
	}
}

// BenchmarkAuthorityCurrentDeltaJournal is the current format at the sizes the first format was
// measured at (224 MiB and ten seconds at 1,000 deletions).
func BenchmarkAuthorityCurrentDeltaJournal(b *testing.B) {
	for _, d := range []int{100, 250, 500, 1000, 2000, 10000} {
		b.Run(fmt.Sprintf("tombstones=%d", d), func(b *testing.B) {
			f := forgeDeltaJournal(b, d)
			_, size := f.read(b)
			b.ResetTimer()
			for range b.N {
				f.read(b)
			}
			b.ReportMetric(float64(size)/(1<<20), "MiB/read")
		})
	}
}
