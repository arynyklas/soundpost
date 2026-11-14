// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// The authority journal stores the WHOLE tombstone ledger in every record, so it
// is O(D^2) bytes in D completed deletions, and Current (run by every checkpoint
// twice, by every backup and by every restore) fetches, decrypts, verifies and
// re-validates all of it. These benchmarks measure that cost; they are not run by
// `go test` (see docs/operations/backup-restore.md, "Not verified / open items"):
//
//	go test ./internal/backup -run '^$' -bench 'AuthorityCurrent' -benchtime=1x
//
// Journals are forged directly (no per-record verification) because writing one
// through CheckpointDeletion would itself cost O(D^3).

// forgeRecord writes one signed, sealed head record exactly as advance does, without the read-back.
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
