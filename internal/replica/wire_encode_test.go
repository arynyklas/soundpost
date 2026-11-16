// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	raft "go.etcd.io/raft/v3"
	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

// jsonFields lists the JSON members of a struct in declaration order: name, then the full tag.
func jsonFields(t reflect.Type) []string {
	var out []string
	for i := range t.NumField() {
		f := t.Field(i)
		out = append(out, f.Name+" "+f.Type.String()+" `"+string(f.Tag)+"`")
	}
	return out
}

// encodeEntry assembles the bytes of an Entry from a head and a tail; an Entry that gains a member
// has to gain it there too, or the journal would silently stop carrying it.
func TestEntryJSONHeadAndTailCoverEntry(t *testing.T) {
	want := jsonFields(reflect.TypeOf(Entry{}))
	got := append(jsonFields(reflect.TypeOf(entryHead{})), want[2]) // the payload member in between
	got = append(got, jsonFields(reflect.TypeOf(entryTail{}))...)
	// The member names differ in nothing but the receiver type, which is the same.
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("Entry members\n%q\nare not entryHead + payload + entryTail\n%q", want, got)
	}
}

// encodeEntry must write exactly the bytes json.Marshal does: they are the journal of every group.
func TestEncodeEntryMatchesJSONMarshal(t *testing.T) {
	res, orig := model.NewID(), model.HashCanonical([]byte("original"))
	cs := &CommitSetWatermark{Group: model.NewID(), Term: 3, PhysicalCommit: 9, PhysicalLast: 10, ApplicationApplied: 8, Reservation: res}
	big := bytes.Repeat([]byte{0, 1, 2, 0xff, '<', '&', '>', 0xe2, 0x80, 0xa8}, 30000)
	for name, e := range map[string]Entry{
		"minimal":        {ID: model.NewID(), Kind: Data, Payload: []byte("p"), ApplicationIndex: 1},
		"nil payload":    {ID: model.NewID(), Kind: Control, ApplicationIndex: 2},
		"empty payload":  {ID: model.NewID(), Kind: Control, Payload: []byte{}, ApplicationIndex: 2},
		"large":          {ID: model.NewID(), Kind: Artifact, Payload: big, ApplicationIndex: 1 << 40},
		"all members":    {ID: model.NewID(), Kind: Cancellation, Payload: []byte("<&>\u2028"), ReservationID: &res, ApplicationIndex: 7, CommitSet: cs, Original: &orig, Proposer: &Proposer{Node: 3, Identity: "node-<3>&\u00e9"}, At: 1731600000123456789},
		"redacted":       {ID: model.NewID(), Kind: Data, Payload: []byte("r"), Original: &orig, ApplicationIndex: 3},
		"max index":      {ID: model.NewID(), Kind: Barrier, Payload: []byte("b"), ApplicationIndex: ^uint64(0), At: 5},
		"base64 padding": {ID: model.NewID(), Kind: ArtifactGC, Payload: []byte("ab"), ApplicationIndex: 4},
		// A leader whose clock reads before 1970 stamps a negative At into the entry it orders; its own
		// applier must be able to read the entry back (Entry.At is signed).
		"negative at": {ID: model.NewID(), Kind: Data, Payload: []byte("n"), ApplicationIndex: 6, At: -1},
		"min at":      {ID: model.NewID(), Kind: Data, Payload: []byte("m"), ApplicationIndex: 6, At: math.MinInt64},
		"max at":      {ID: model.NewID(), Kind: Data, Payload: []byte("x"), ApplicationIndex: 6, At: math.MaxInt64},
	} {
		want, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := encodeEntry(e)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s: encodeEntry differs from json.Marshal (len %d vs %d, %v)", name, len(got), len(want), err)
		}
		if cap(got) != len(got) {
			t.Fatalf("%s: output buffer is %d for %d bytes of text: it was not assembled at its size", name, cap(got), len(got))
		}
		back, err := decodeEntry(got)
		if err != nil || !reflect.DeepEqual(normalized(back), normalized(e)) {
			t.Fatalf("%s: encodeEntry output does not decode back: %v", name, err)
		}
	}
}

// Entry.At is a signed Unix-nanosecond stamp: a leader whose clock reads before 1970 (a dead RTC)
// stamps a negative one into the entry it orders, and its own applier decodes the entry it just
// committed. The wire bytes of a positive stamp are the ones every journal already holds.
func TestEntryAtIsSignedOnTheWire(t *testing.T) {
	id := model.NewID()
	for _, tc := range []struct {
		at   int64
		text string
	}{
		{1731600000123456789, `"at":"1731600000123456789"`},
		{-1, `"at":"-1"`},
		{math.MinInt64, `"at":"-9223372036854775808"`},
		{math.MaxInt64, `"at":"9223372036854775807"`},
	} {
		e := Entry{ID: id, Kind: Data, Payload: []byte("p"), ApplicationIndex: 1, At: tc.at}
		raw, err := encodeEntry(e)
		if err != nil || !bytes.Contains(raw, []byte(tc.text)) || !bytes.HasSuffix(raw, []byte(tc.text+"}")) {
			t.Fatalf("At %d encodes as %s (%v), want ...%s}", tc.at, raw, err, tc.text)
		}
		back, err := decodeEntry(raw)
		if err != nil || back.At != tc.at {
			t.Fatalf("At %d does not decode back (got %d, %v)", tc.at, back.At, err)
		}
		var viaJSON Entry
		if err := json.Unmarshal(raw, &viaJSON); err != nil || viaJSON.At != tc.at {
			t.Fatalf("At %d through Entry.UnmarshalJSON: got %d, %v", tc.at, viaJSON.At, err)
		}
	}
	for _, bad := range []string{`"-0"`, `"-"`, `"-9223372036854775809"`, `"9223372036854775808"`, `-1`} {
		raw := []byte(`{"id":"` + id.String() + `","kind":"data","payload":"cA==","application_index":"1","at":` + bad + `}`)
		if _, err := decodeEntry(raw); err == nil {
			t.Fatalf("At %s was accepted", bad)
		}
	}
}

// normalized is e as the decoder returns it: an empty or nil payload decodes as nil.
func normalized(e Entry) Entry {
	if len(e.Payload) == 0 {
		e.Payload = nil
	}
	return e
}

// readyRecordFixture is a journal record's worth of everything raft hands to persist.
func readyRecordFixture(payload int, entries int) raft.Ready {
	rd := raft.Ready{
		HardState: &pb.HardState{Term: new(uint64(4)), Vote: new(uint64(1)), Commit: new(uint64(12))},
		Snapshot:  &pb.Snapshot{Data: bytes.Repeat([]byte("s"), 100), Metadata: &pb.SnapshotMetadata{Index: new(uint64(11)), Term: new(uint64(3))}},
	}
	for i := range entries {
		rd.Entries = append(rd.Entries, &pb.Entry{Term: new(uint64(4)), Index: new(uint64(13 + i)), Data: bytes.Repeat([]byte{byte(i), 0xfe, '"', '\\'}, payload)})
	}
	return rd
}

func marshalReady(t *testing.T, w *readyWAL, rd raft.Ready) []byte {
	t.Helper()
	r := readyRecord{Group: w.group, Node: w.node, Members: cloneMembers(w.members)}
	var err error
	if rd.HardState != nil {
		if r.Hard, err = proto.Marshal(rd.HardState); err != nil {
			t.Fatal(err)
		}
	}
	if rd.Snapshot != nil {
		if r.Snapshot, err = proto.Marshal(rd.Snapshot); err != nil {
			t.Fatal(err)
		}
	}
	for _, ent := range rd.Entries {
		raw, err := proto.Marshal(ent)
		if err != nil {
			t.Fatal(err)
		}
		r.Entries = append(r.Entries, raw)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The journal record writer builds the bytes of json.Marshal(readyRecord) without its copies, for
// every combination of hard state, snapshot and entries, and across reuse of one buffer.
func TestReadyRecordWriterMatchesJSONMarshal(t *testing.T) {
	members := Members{Revision: 2, Nodes: []Member{{ID: 1, Address: "a:1", NodeIdentity: "n<1>", FailureDomain: "d1"}, {ID: 2, Address: "b:1", NodeIdentity: "n2", FailureDomain: "d2", Learner: true}}}
	w := &readyWAL{group: model.NewID(), node: 2, members: members}
	buf := new(readyBuffer)
	cases := map[string]raft.Ready{
		"empty":           {},
		"hard only":       {HardState: readyRecordFixture(1, 0).HardState},
		"zero hard state": {HardState: &pb.HardState{}},
		"snapshot only":   {Snapshot: readyRecordFixture(1, 0).Snapshot},
		"one entry":       readyRecordFixture(1, 1),
		"three entries":   readyRecordFixture(50000, 3),
		"zero entry":      {Entries: []*pb.Entry{{}}},
		"small after big": readyRecordFixture(2, 2),
		"everything":      readyRecordFixture(3, 5),
	}
	for _, name := range []string{"empty", "hard only", "zero hard state", "snapshot only", "one entry", "three entries", "zero entry", "small after big", "everything"} {
		rd := cases[name]
		want := marshalReady(t, w, rd)
		got, err := w.appendRecord(buf, rd)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s: record differs from json.Marshal (len %d vs %d, %v)", name, len(got), len(want), err)
		}
		var back readyRecord
		if err := model.StrictJSON(got, &back); err != nil || back.Group != w.group || back.Node != w.node || len(back.Entries) != len(rd.Entries) {
			t.Fatalf("%s: record does not read back: %v", name, err)
		}
	}
}

// readyHead carries the leading members of readyRecord; the writer appends the rest by hand.
func TestReadyRecordHeadCoversReadyRecord(t *testing.T) {
	want := jsonFields(reflect.TypeOf(readyRecord{}))
	got := append(jsonFields(reflect.TypeOf(readyHead{})), want[3:]...)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("readyRecord members\n%q\nare not readyHead + hard, snapshot, entries\n%q", want, got)
	}
	if !strings.Contains(want[3], "hard") || !strings.Contains(want[4], "snapshot") || !strings.Contains(want[5], "entries") {
		t.Fatalf("the writer appends hard, snapshot and entries in this order; readyRecord now has %q", want[3:])
	}
}

// A record is built in a pooled buffer; a buffer left over from a larger record must not leak its tail.
func TestReadyBufferReuseDoesNotLeakEarlierRecords(t *testing.T) {
	w := &readyWAL{group: model.NewID(), node: 1, members: Members{Revision: 1, Nodes: []Member{{ID: 1, Address: "a", NodeIdentity: "n", FailureDomain: "d"}}}}
	big, small := readyRecordFixture(40000, 2), readyRecordFixture(1, 1)
	buf := new(readyBuffer)
	first, err := w.appendRecord(buf, big)
	if err != nil {
		t.Fatal(err)
	}
	first = bytes.Clone(first)
	second, err := w.appendRecord(buf, small)
	if err != nil || !bytes.Equal(second, marshalReady(t, w, small)) {
		t.Fatalf("a small record built after a big one differs: %v", err)
	}
	if len(second) >= len(first) {
		t.Fatalf("fixture: the second record (%d) is not smaller than the first (%d)", len(second), len(first))
	}
}
