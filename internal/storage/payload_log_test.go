// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// openPayloadEngine is openTestEngine on a file that has adopted the payload layout (the installation is contracted).
func openPayloadEngine(t *testing.T, dir string, store *control.Store, service Revalidator) *Engine {
	t.Helper()
	e, err := openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.adoptRunsLayout(); err == nil {
		err = e.adoptPayloadLayout()
	}
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func payloadFilesBytes(t *testing.T, dir string) (files int, bytes int64) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, payloadDirName))
	if errors.Is(err, os.ErrNotExist) {
		return 0, 0
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		fi, err := en.Info()
		if err != nil {
			t.Fatal(err)
		}
		files++
		bytes += fi.Size()
	}
	return files, bytes
}

// TestPayloadLogRoundTrip: what is appended is read back verified, across files, after a reopen (the tail of a file that ends in
// the middle of a record is dead space the next append continues after), and a record that was scrubbed or damaged is refused.
func TestPayloadLogRoundTrip(t *testing.T) {
	old := payloadFileLimit
	payloadFileLimit = 4 << 10
	defer func() { payloadFileLimit = old }()
	dir := filepath.Join(t.TempDir(), payloadDirName)
	l, err := openPayloadLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	var refs [][]byte
	var want [][]byte
	for i := range 20 {
		b := bytes.Repeat([]byte{byte('a' + i)}, 700+i)
		ref, err := l.append(b)
		if err != nil {
			t.Fatal(err)
		}
		if !isPayloadRef(ref) || len(ref) != payloadRefLen {
			t.Fatalf("reference %x is not a reference", ref)
		}
		refs, want = append(refs, ref), append(want, b)
	}
	if err = l.sync(); err != nil {
		t.Fatal(err)
	}
	if n, _ := payloadFilesBytes(t, filepath.Dir(dir)); n < 3 {
		t.Fatalf("20 records of 700 bytes in files of 4 KiB made %d files", n)
	}
	for i, ref := range refs {
		got, err := l.read(ref)
		if err != nil || !bytes.Equal(got, want[i]) {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	// A torn tail: bytes after the last record, as a crash in the middle of an append leaves them.
	f, err := os.OpenFile(filepath.Join(dir, payloadFileName(l.seq)), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("SPL1\x00\x00\x03\xe8partial")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err = l.close(); err != nil {
		t.Fatal(err)
	}
	l, err = openPayloadLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.close()
	ref, err := l.append([]byte(strings.Repeat("z", 300)))
	if err != nil {
		t.Fatal(err)
	}
	if err = l.sync(); err != nil {
		t.Fatal(err)
	}
	for i, r := range append(refs, ref) {
		got, err := l.read(r)
		if err != nil {
			t.Fatalf("record %d after the reopen: %v", i, err)
		}
		if i < len(want) && !bytes.Equal(got, want[i]) {
			t.Fatalf("record %d changed", i)
		}
	}
	// Damage is refused, never returned.
	seq, off, _, _, _ := parsePayloadRef(refs[3])
	p := filepath.Join(dir, payloadFileName(seq))
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	raw[off+payloadHeaderLen+5] ^= 0xff
	if err = os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = l.read(refs[3]); err == nil {
		t.Fatal("a damaged record was read")
	}
	if err = l.scrub(refs[4]); err != nil {
		t.Fatal(err)
	}
	if _, err = l.read(refs[4]); err == nil {
		t.Fatal("a scrubbed record was read")
	}
}

// TestPayloadLayoutKeepsAppliedBytesOutOfBolt is the red test of D89: after one hour at 2,000 records/s apply.db was 30 GB, about 18 KB
// a batch of which most was payload (the command, the stored records, the hot page), and the working set outgrew the page cache of
// the host. Once the installation is contracted the engine keeps that payload in the owned log and bolt holds references: what a
// batch leaves in bolt is bounded, whatever the history, and the log holds the payload.
func TestPayloadLayoutKeepsAppliedBytesOutOfBolt(t *testing.T) {
	store, service, cred, desc := fixture(t)
	dir := t.TempDir()
	e := openPayloadEngine(t, dir, store, service)
	if err := store.BindAdmissionOwner(e); err != nil {
		t.Fatal(err)
	}
	const total, window = 600, 200
	batches := make([]preparedAppend, total)
	for i := range batches {
		batches[i].scope, batches[i].batch = settleBatch(t, store, service, cred, desc, model.NewID(), 1, fmt.Sprintf("series_%d", i))
	}
	perBatch := func(m map[string]int64) (sum float64) {
		for _, v := range m {
			sum += float64(v)
		}
		return
	}
	var early, late float64
	var before float64
	for from := 0; from < total; from += window {
		pageNodesPerAck(t, e, batches[from:from+window], 1)
		now := perBatch(storedBytes(t, e))
		got := (now - before) / window
		before = now
		t.Logf("batches %d-%d: %.0f logical bytes of bolt per batch", from, from+window, got)
		if from == 0 {
			early = got
		}
		late = got
	}
	sizes := storedBytes(t, e)
	for _, name := range []string{"bucket:replica_commands", "rows:batches", "rows:scan_pages"} {
		if per := float64(sizes[name]) / total; per > 520 {
			t.Errorf("%s holds %.0f bytes per batch: the payload is still in bolt (a reference is %d bytes)", name, per, payloadRefLen)
		}
	}
	if sum := perBatch(sizes) / total; sum > 4400 {
		t.Errorf("bolt holds %.0f logical bytes per batch after %d batches, more than the 4400 the references, the indexes and the receipts need (6,327 before the log)", sum, total)
	}
	if late > early*1.2+200 {
		t.Errorf("what a batch leaves in bolt grew with the history: %.0f bytes for the first %d batches, %.0f for the last", early, window, late)
	}
	files, logged := payloadFilesBytes(t, dir)
	t.Logf("payload log: %d file(s), %.0f bytes per batch", files, float64(logged)/total)
	if float64(logged)/total < 1500 {
		t.Errorf("the payload log holds %.0f bytes per batch: the command, the records and the page are not in it", float64(logged)/total)
	}
	if sizes["bucket:replica_commands"] == 0 {
		t.Fatal("no commands stored")
	}
}

// TestPayloadLayoutReadsWhatItStoredAfterARestart: the commands, the stored records and the pages of the log layout are what the
// engine reads after a restart, and an engine that only had the previous layout's values reads both forms.
func TestPayloadLayoutReadsWhatItStoredAfterARestart(t *testing.T) {
	withoutPayloadToggle(t)
	store, service, cred, desc := fixture(t)
	dir := t.TempDir()
	e, err := openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.BindAdmissionOwner(e); err != nil {
		t.Fatal(err)
	}
	// The merger migrates inline values to the log by itself once the layout is adopted (migrateInlinePayload, a tick every 200 ms):
	// on a loaded machine it would move the first batch's command before this test counts the inline ones. The migration is
	// covered by payload_migrate_test.go; this test is about the file holding both forms.
	e.stopIndexMerger()
	// One batch before the layout (stored inline), one after (stored in the log).
	scope1, b1 := settleBatch(t, store, service, cred, desc, model.NewID(), 1, "series_before")
	r1, err := e.Append(context.Background(), scope1, b1)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.adoptRunsLayout(); err == nil {
		err = e.adoptPayloadLayout()
	}
	if err != nil {
		t.Fatal(err)
	}
	scope2, b2 := settleBatch(t, store, service, cred, desc, model.NewID(), 1, "series_after")
	r2, err := e.Append(context.Background(), scope2, b2)
	if err != nil {
		t.Fatal(err)
	}
	var inline, logged int
	if err = e.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("replica_commands")).ForEach(func(_, v []byte) error {
			if isPayloadRef(v) {
				logged++
			} else if len(v) >= payloadMinBytes {
				inline++
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	if inline == 0 || logged == 0 {
		t.Fatalf("%d inline and %d logged commands: both forms must be in the file", inline, logged)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	e2, err := openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatalf("reopening a file with payload references: %v", err)
	}
	if !e2.payloadOn.Load() {
		t.Fatal("the reopened file lost the layout")
	}
	for i, c := range []struct {
		scope auth.Scope
		b     model.NormalizedBatch
		r     model.Receipt
	}{{scope1, b1, r1}, {scope2, b2, r2}} {
		got, err := e2.Append(context.Background(), c.scope, c.b)
		if err != nil {
			t.Fatalf("retry of batch %d: %v", i+1, err)
		}
		if string(mustJSON(t, got)) != string(mustJSON(t, c.r)) {
			t.Fatalf("batch %d: the receipt after the restart is not the original", i+1)
		}
	}
	history, err := func() ([]string, error) {
		e2.mu.Lock()
		defer e2.mu.Unlock()
		var out []string
		for slot := range uint16(64) {
			h, err := e2.historyLocked(slot)
			if err != nil {
				return nil, err
			}
			for _, raw := range h {
				out = append(out, string(raw))
			}
		}
		return out, nil
	}()
	if err != nil {
		t.Fatal(err)
	}
	var found int
	for _, raw := range history {
		entry, err := decodeWAL([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if entry.Batch != nil && (entry.Batch.ID == b1.ID || entry.Batch.ID == b2.ID) {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("the history of the slots holds %d of the 2 batches: a stored command was not read through its reference", found)
	}
}
