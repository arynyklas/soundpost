// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	pb "go.etcd.io/raft/v3/raftpb"
)

func entryDecodeCorpus(t *testing.T) map[string][]byte {
	t.Helper()
	id := model.NewID()
	res := model.NewID()
	good := func(e Entry) []byte {
		raw, err := json.Marshal(e) // the encoding the journal and the proposer have always used
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	plain := Entry{ID: id, Kind: Artifact, Payload: []byte(`{"type":"artifact_fragment"}`), ApplicationIndex: 7}
	withRes := Entry{ID: id, Kind: Data, Payload: bytes.Repeat([]byte("<&>\u00e9"), 5000), ReservationID: &res, ApplicationIndex: 1 << 40}
	orig := model.HashCanonical([]byte("x"))
	redacted := Entry{ID: id, Kind: Data, Payload: []byte("r"), Original: &orig, ApplicationIndex: 3}
	idText := id.String()
	return map[string][]byte{
		"plain":            good(plain),
		"reservation":      good(withRes),
		"redacted":         good(redacted),
		"padded":           append([]byte(" \n"), append(good(plain), ' ', '\n')...),
		"unknown field":    []byte(`{"id":"` + idText + `","kind":"artifact","payload":"eA==","application_index":"1","extra":1}`),
		"duplicate key":    []byte(`{"id":"` + idText + `","id":"` + idText + `","kind":"artifact","payload":"eA==","application_index":"1"}`),
		"numeric index":    []byte(`{"id":"` + idText + `","kind":"artifact","payload":"eA==","application_index":1}`),
		"leading zero":     []byte(`{"id":"` + idText + `","kind":"artifact","payload":"eA==","application_index":"01"}`),
		"bad base64":       []byte(`{"id":"` + idText + `","kind":"artifact","payload":"e","application_index":"1"}`),
		"trailing data":    append(good(plain), []byte(` {}`)...),
		"trailing garbage": append(good(plain), 'x'),
		"truncated":        good(plain)[:20],
		"null":             []byte(`null`),
		"array":            []byte(`[]`),
		"empty":            []byte(``),
		"bad utf8":         []byte("{\"id\":\"" + idText + "\",\"kind\":\"ar\xfftifact\",\"payload\":\"eA==\",\"application_index\":\"1\"}"),
		"lone surrogate":   []byte(`{"id":"` + idText + `","kind":"\ud800","payload":"eA==","application_index":"1"}`),
		"deep":             []byte(strings.Repeat(`[`, 70) + strings.Repeat(`]`, 70)),
		"unknown kind":     []byte(`{"id":"` + idText + `","kind":"nope","payload":"eA==","application_index":"1"}`),
		"zero id":          []byte(`{"id":"00000000000000000000000000000000","kind":"artifact","payload":"eA==","application_index":"1"}`),
		"empty payload":    []byte(`{"id":"` + idText + `","kind":"artifact","payload":"","application_index":"1"}`),
	}
}

// decodeEntry must accept and refuse exactly what model.StrictJSON(data, &Entry) does, and return
// the same Entry for what it accepts.
func TestDecodeEntryMatchesNestedStrictJSON(t *testing.T) {
	accepted := 0
	for name, raw := range entryDecodeCorpus(t) {
		var want Entry
		wantErr := model.StrictJSON(raw, &want)
		got, gotErr := decodeEntry(raw)
		if (wantErr == nil) != (gotErr == nil) {
			t.Fatalf("%s: reference err=%v, decodeEntry err=%v", name, wantErr, gotErr)
		}
		if wantErr != nil {
			continue
		}
		accepted++
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("%s: decodeEntry differs from the reference\n got  %+v\n want %+v", name, got, want)
		}
		g := &Group{}
		cached, cerr := g.decodeEntry(raw)
		if (cerr == nil) != want.valid() || cerr == nil && !reflect.DeepEqual(cached, want) {
			t.Fatalf("%s: Group.decodeEntry err=%v valid=%v", name, cerr, want.valid())
		}
	}
	if accepted < 4 {
		t.Fatalf("the corpus accepted only %d inputs: it no longer proves equality", accepted)
	}
}

// The reuse is keyed by the identity of the Raft data slice. A different slice with the same
// length and different (or corrupt) bytes is decoded and refused on its own.
func TestGroupDecodeEntryReuseIsByIdentityOnly(t *testing.T) {
	good := entryDecodeCorpus(t)["plain"]
	g := &Group{}
	first, err := g.decodeEntry(good)
	if err != nil {
		t.Fatal(err)
	}
	again, err := g.decodeEntry(good)
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatalf("same slice: %v", err)
	}
	// Same length, same first byte address class, but a corrupt copy.
	corrupt := bytes.Clone(good)
	corrupt[len(corrupt)/2] ^= 0x01
	if _, err = g.decodeEntry(corrupt); err == nil {
		if bytes.Equal(corrupt, good) {
			t.Fatal("test did not corrupt")
		}
		var ref Entry
		if model.StrictJSON(corrupt, &ref) != nil || !ref.valid() {
			t.Fatal("a corrupt entry was served from the reuse slot")
		}
	}
	// A refusal must not poison the slot: the corrupt bytes are refused every time.
	bad := entryDecodeCorpus(t)["unknown field"]
	for range 2 {
		if _, err = g.decodeEntry(bad); err == nil {
			t.Fatal("an entry with an unknown field was accepted")
		}
	}
	// A different valid entry of the same length is not answered with the first one.
	other := bytes.Clone(good)
	other[bytes.Index(other, []byte(`"application_index":"7"`))+len(`"application_index":"`)] = '8'
	got, err := g.decodeEntry(other)
	if err != nil || got.ApplicationIndex != 8 {
		t.Fatalf("same-length different entry: index %d err %v", got.ApplicationIndex, err)
	}
}

// goldenDir is a control group's raft directory written by the binary of commit e805349 (the
// writer that kept the retry table by digest), not by this tree: ready.wal, one sealed snapshot
// (CURRENT, MANIFEST, envelope, ledger, raft.conf) and one journal-pin archive. It was produced by
// a generator test run in a clean `git archive e805349` tree, which committed three whole-state
// control commands, pinned the journal, committed three more, cut and compacted, committed two
// more and closed. expected.json records what that run observed (the commands, the receipts it
// acknowledged them with, the final state and the SHA-256 of every file).
const goldenDir = "testdata/e805349"

type goldenRow struct {
	Entry json.RawMessage `json:"entry"`
	Acked CommittedEntry  `json:"acked"`
}

type goldenExpected struct {
	Group      model.ID          `json:"group"`
	Pin        model.ID          `json:"pin"`
	Rows       []goldenRow       `json:"rows"`
	FinalRev   uint64            `json:"final_rev"`
	FinalState wholeState        `json:"final_state"`
	Files      map[string]string `json:"file_sha256"`
}

// copyGolden copies the golden raft directory into dir/raft after proving its bytes are the ones
// the old writer produced (the recorded SHA-256 of every file).
func copyGolden(t *testing.T, dir string) goldenExpected {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(goldenDir, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ex goldenExpected
	if err = json.Unmarshal(raw, &ex); err != nil {
		t.Fatal(err)
	}
	if len(ex.Files) < 7 || len(ex.Rows) != 8 {
		t.Fatalf("golden metadata is incomplete: %d files, %d rows", len(ex.Files), len(ex.Rows))
	}
	for rel, want := range ex.Files {
		data, err := os.ReadFile(filepath.Join(goldenDir, "raft", filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != want {
			t.Fatalf("%s no longer has the bytes e805349 wrote", rel)
		}
		dst := filepath.Join(dir, "raft", filepath.FromSlash(rel))
		if err = os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(dst, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return ex
}

func (ex goldenExpected) wholeRows(t *testing.T) []wholeRow {
	t.Helper()
	rows := make([]wholeRow, len(ex.Rows))
	for i, r := range ex.Rows {
		var e Entry
		if err := json.Unmarshal(r.Entry, &e); err != nil {
			t.Fatal(err)
		}
		rows[i] = wholeRow{entry: e, acked: r.Acked}
	}
	return rows
}

// The current code opens the directory the old binary left: the sealed snapshot is restored, the
// ready.wal suffix is replayed to the same final state, every command the old binary
// acknowledged is still answered with its original receipt (the digest-kept retry table of the
// snapshot and the journal's own entries), and the pin's archive is read back.
func TestGoldenRaftDirectoryOfE805349ReadsBack(t *testing.T) {
	dir := t.TempDir()
	ex := copyGolden(t, dir)
	s := openDigest(t, dir, ex.Group)
	if _, err := s.group.ReadIndex(s.ctx()); err != nil {
		t.Fatal(err)
	}
	state := s.machine.current()
	if state.Rev != ex.FinalRev || !reflect.DeepEqual(state, ex.FinalState) {
		t.Fatalf("state after replaying the old directory: rev %d %v, want rev %d %v", state.Rev, state.Books, ex.FinalRev, ex.FinalState.Books)
	}
	rows := ex.wholeRows(t)
	requireOriginalReceipts(t, s, "golden e805349", rows)

	pins, err := s.group.Pins()
	if err != nil || len(pins) != 1 || pins[0].ID != ex.Pin || !pins[0].Orphaned {
		t.Fatalf("the old pin was not reloaded as an orphan: %+v %v", pins, err)
	}
	archive, err := readPinArchive(filepath.Join(dir, "raft", "pins", ex.Pin.String()+".pin"))
	if err != nil || archive.header.ID != ex.Pin || archive.header.After == 0 {
		t.Fatalf("pin archive header: %+v %v", archive.header, err)
	}
	archived := map[model.ID]bool{}
	for _, ent := range archive.entries {
		if len(ent.GetData()) == 0 {
			continue
		}
		e, err := decodeEntry(ent.GetData())
		if err != nil {
			t.Fatalf("an archived entry the old binary wrote no longer decodes: %v", err)
		}
		archived[e.ID] = true
	}
	for i := 3; i < 6; i++ {
		if !archived[rows[i].entry.ID] {
			t.Fatalf("command %d, committed after the pin and before the compaction, is not in the archive", i+1)
		}
	}

	var scanned int
	wal, err := os.Open(filepath.Join(dir, "raft", "ready.wal"))
	if err != nil {
		t.Fatal(err)
	}
	defer wal.Close()
	err = scanJournalEntries(wal, func(ent *pb.Entry) error {
		if len(ent.GetData()) == 0 {
			return nil
		}
		if _, err := decodeEntry(ent.GetData()); err != nil {
			return err
		}
		scanned++
		return nil
	})
	if err != nil || scanned == 0 {
		t.Fatalf("the old ready.wal does not scan: %d entries, %v", scanned, err)
	}
}
