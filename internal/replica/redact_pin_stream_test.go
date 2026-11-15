// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

// tornTail is a record header that promises more bytes than the file holds.
var tornTail = []byte{0, 0, 1, 0, 0, 0, 0, 0, 9, 9}

// writePinArchive writes a pin archive of n data commands with payloads of size bytes and returns
// the command IDs.
func writePinArchive(t *testing.T, path string, n, size int, tail []byte) []model.ID {
	t.Helper()
	var out bytes.Buffer
	ids := make([]model.ID, n)
	payload := bytes.Repeat([]byte{'p'}, size)
	for i := range ids {
		ids[i] = model.NewID()
		data, err := json.Marshal(Entry{ID: ids[i], Kind: Data, Payload: payload, ApplicationIndex: uint64(i + 1)})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := proto.Marshal(&pb.Entry{Index: new(uint64(i + 1)), Term: new(uint64(1)), Type: pb.EntryNormal.Enum(), Data: data})
		if err != nil {
			t.Fatal(err)
		}
		record, err := json.Marshal(pinRecord{Entry: raw})
		if err != nil {
			t.Fatal(err)
		}
		var h [8]byte
		binary.BigEndian.PutUint32(h[:4], uint32(len(record)))
		binary.BigEndian.PutUint32(h[4:], crc32.Checksum(record, readyCRC))
		out.Write(h[:])
		out.Write(record)
	}
	out.Write(tail)
	if err := os.WriteFile(path, out.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return ids
}

// IM-5: rewriting a pin archive holds one record in memory, not the archive twice, and the
// result is what the whole-file rewrite produced: the targeted command replaced, every other
// record byte-identical, a torn tail dropped, nothing left beside the archive.
func TestRedactPinArchiveStreamsAndKeepsEveryOtherRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pin-a.archive")
	const n, size = 8192, 8 << 10 // 64 MiB of payload
	ids := writePinArchive(t, path, n, size, tornTail)
	want := ids[n/2]
	targets := map[model.ID]*redactTarget{want: {replacement: []byte("redacted")}}

	// The peak heap while the archive is rewritten, sampled; garbage included, so the bound is
	// generous against a whole-archive read (64 MiB, twice with a second copy) and tight against
	// one record at a time.
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var peak uint64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		var m runtime.MemStats
		for {
			runtime.ReadMemStats(&m)
			peak = max(peak, m.HeapAlloc)
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()
	rewritten, err := redactPinArchive(path, targets)
	close(stop)
	<-done
	if err != nil || rewritten != 1 {
		t.Fatalf("rewritten %d, err %v", rewritten, err)
	}
	if grown := int64(peak) - int64(base.HeapAlloc); grown > 24<<20 {
		t.Fatalf("redacting a %d MiB archive grew the heap by %d MiB: the archive is read whole", n*size>>20, grown>>20)
	}
	var seen []model.ID
	if err = scanPinArchive(path, func(ent *pb.Entry) error {
		e, ok := parseEntry(ent)
		if !ok {
			t.Fatal("unparseable entry in the rewritten archive")
		}
		seen = append(seen, e.ID)
		if e.ID == want {
			if string(e.Payload) != "redacted" || e.Original == nil {
				t.Fatalf("target not redacted: %q original %v", e.Payload[:min(8, len(e.Payload))], e.Original)
			}
		} else if len(e.Payload) != size {
			t.Fatalf("an untargeted record changed: %d bytes", len(e.Payload))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != n {
		t.Fatalf("%d records after the rewrite, want %d", len(seen), n)
	}
	for i := range ids {
		if seen[i] != ids[i] {
			t.Fatalf("record %d reordered", i)
		}
	}
	if raw, _ := os.ReadFile(path); len(raw) > 0 {
		if tailPresent := bytes.HasSuffix(raw, tornTail); tailPresent {
			t.Fatal("the torn tail survived the rewrite")
		}
	}
	if _, err = os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file left behind: %v", err)
	}
}

// An archive with nothing to redact is not rewritten and leaves no temp file.
func TestRedactPinArchiveLeavesAnUntargetedArchiveAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pin-b.archive")
	writePinArchive(t, path, 16, 1024, nil)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rewritten, err := redactPinArchive(path, map[model.ID]*redactTarget{model.NewID(): {replacement: []byte("x")}})
	if err != nil || rewritten != 0 {
		t.Fatalf("rewritten %d, err %v", rewritten, err)
	}
	if now, _ := os.ReadFile(path); !bytes.Equal(now, original) {
		t.Fatal("an archive with nothing to redact was changed")
	}
	if _, err = os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file left behind: %v", err)
	}
}
