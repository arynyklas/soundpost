// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"sort"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

func metricCandidates(x *eraseEnv, seen *int) eraseSelector {
	return eraseSelector{
		record: func(_, _ model.ID, r model.Record, _ model.Receipt) (bool, model.UnixNano) {
			*seen++
			return r.Kind == model.Metric, 0
		},
		blob: func(model.BlobManifest) (bool, model.UnixNano) { return false, 0 },
	}
}

func cursorsOf(jobs []eraseBatchJob) []uint64 {
	var out []uint64
	for _, j := range jobs {
		out = append(out, uint64(j.slot)<<48|j.index)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// The read of the stored commands that finds what an expiry or an erasure may touch (the journal-expiry plan every quarter hour, the
// retention pass) walked every command of the history in ONE read transaction. A read transaction blocks the remap of the apply
// database, and a write that has to grow the mapping waits for it and holds every new transaction behind it: at the single-host load the
// plan of the 15th minute held one for 40 s, the second for 80 s, and every acknowledgement stopped for as long
// (L2w20Admission22: 6,000 timeouts and 20,000 shed requests in the first one). The read now takes its transactions in chunks of
// eraseScanChunk commands and resumes after the last key it saw, so none lasts longer than a chunk.
func TestCandidateScanReadsInShortTransactions(t *testing.T) {
	old := eraseScanChunk
	eraseScanChunk = 3
	t.Cleanup(func() { eraseScanChunk = old })
	x := newEraseEnv(t)
	for range 10 {
		x.appendMixed(eraseCanary, bothDeadlines)
	}
	guard := func(context.Context, EraseCandidate) (bool, error) { return true, nil }
	var seen int
	before := x.e.db.views.Load()
	jobs, _, _, err := x.e.eraseCandidates(context.Background(), metricCandidates(x, &seen), guard)
	if err != nil {
		t.Fatal(err)
	}
	if views := x.e.db.views.Load() - before; views < 4 {
		t.Fatalf("10 commands read in chunks of 3 took %d read transactions: the scan holds one across the history", views)
	}
	if seen != 30 || len(jobs) != 10 {
		t.Fatalf("saw %d records of 10 batches, %d candidate commands", seen, len(jobs))
	}
	// The same commands as one chunk, whatever the chunking.
	eraseScanChunk = 1 << 20
	var all int
	whole, _, _, err := x.e.eraseCandidates(context.Background(), metricCandidates(x, &all), guard)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cursorsOf(jobs), cursorsOf(whole); len(got) != len(want) {
		t.Fatalf("chunked scan found %v, one transaction found %v", got, want)
	} else {
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("chunked scan found %v, one transaction found %v", got, want)
			}
		}
	}
}

// A selector that can tell from the stored bytes that a command holds nothing it looks for spares the decode of the command.
func TestCandidateScanSkipsCommandsTheSelectorRulesOutFromTheirBytes(t *testing.T) {
	x := newEraseEnv(t)
	for range 5 {
		x.appendMixed(eraseCanary, bothDeadlines)
	}
	var seen, hinted int
	sel := metricCandidates(x, &seen)
	sel.skip = func(raw []byte) bool {
		hinted++
		return true
	}
	guard := func(context.Context, EraseCandidate) (bool, error) { return true, nil }
	jobs, _, _, err := x.e.eraseCandidates(context.Background(), sel, guard)
	if err != nil {
		t.Fatal(err)
	}
	if hinted != 5 || seen != 0 || len(jobs) != 0 {
		t.Fatalf("hinted %d commands, decoded %d records, %d candidates", hinted, seen, len(jobs))
	}
	sel.skip = func(raw []byte) bool { return !bytes.Contains(raw, []byte(`"kind":"metric"`)) }
	seen = 0
	if jobs, _, _, err = x.e.eraseCandidates(context.Background(), sel, guard); err != nil || len(jobs) != 5 || seen != 15 {
		t.Fatalf("a hint that keeps the commands: %d candidates, %d records seen (%v)", len(jobs), seen, err)
	}
}
