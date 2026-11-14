// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	raft "go.etcd.io/raft/v3"
	pb "go.etcd.io/raft/v3/raftpb"
)

// tornFixture is a journal of the seed record plus two further records, closed cleanly. It returns
// the directory, the group, the exact bytes of the journal and the offset at which the last record
// starts.
func tornFixture(t *testing.T) (dir string, group model.ID, good []byte, lastStart int) {
	t.Helper()
	dir, group = t.TempDir(), model.NewID()
	w, _, err := openReadyWAL(dir, group, 1, soloMembers(), []byte("seed"), 0, 1, 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for term := uint64(2); term <= 3; term++ {
		if term == 3 {
			info, e := os.Stat(filepath.Join(dir, "ready.wal"))
			if e != nil {
				t.Fatal(e)
			}
			lastStart = int(info.Size())
		}
		if err = w.persist(raft.Ready{HardState: &pb.HardState{Term: new(term), Commit: new(uint64(1))}}); err != nil {
			t.Fatal(err)
		}
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	good, err = os.ReadFile(filepath.Join(dir, "ready.wal"))
	if err != nil {
		t.Fatal(err)
	}
	return dir, group, good, lastStart
}

func reopenTorn(t *testing.T, dir string, group model.ID, content []byte) error {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "ready.wal"), content, 0600); err != nil {
		t.Fatal(err)
	}
	w, _, err := openReadyWAL(dir, group, 1, soloMembers(), nil, 0, 0, 0, nil, nil)
	if err == nil {
		w.Close()
	}
	return err
}

func frameOf(payload []byte, corruptPayloadCRC bool) []byte {
	var header [16]byte
	copy(header[:4], "SPR1")
	binary.BigEndian.PutUint32(header[4:8], uint32(len(payload)))
	sum := crc32.Checksum(payload, readyCRC)
	if corruptPayloadCRC {
		sum++
	}
	binary.BigEndian.PutUint32(header[8:12], sum)
	binary.BigEndian.PutUint32(header[12:], crc32.Checksum(header[:12], readyCRC))
	return append(header[:], payload...)
}

// Decision D16: a final record that provably never reached the disk whole is dropped and the
// journal opens: a zero filled tail, an all-zero header sector, or a record with an unwritten
// (all-zero, 512-byte aligned) sector. Nothing verifiable follows it.
func TestATornFinalRecordIsTruncatedAndTheJournalOpens(t *testing.T) {
	dir, group, good, lastStart := tornFixture(t)
	big := bytes.Repeat([]byte{'x'}, 4096)
	partial := frameOf(big, false)
	for i := 100; i < len(partial); i++ { // the first 100 bytes landed, the rest never did
		partial[i] = 0
	}
	torn := map[string][]byte{
		"zero filled tail":                    make([]byte, 700),
		"all-zero header sector":              make([]byte, 40),
		"complete length, unwritten sectors":  partial,
		"header written, payload sector zero": append(frameOf(big, false)[:16], make([]byte, 4096)...),
	}
	for name, tail := range torn {
		t.Run(name, func(t *testing.T) {
			if err := reopenTorn(t, dir, group, append(bytes.Clone(good), tail...)); err != nil {
				t.Fatalf("reopen with a torn final record: %v", err)
			}
			after, err := os.ReadFile(filepath.Join(dir, "ready.wal"))
			if err != nil || !bytes.Equal(after, good) {
				t.Fatalf("journal after reopen is not the verified prefix: %d bytes (err %v), want %d", len(after), err, len(good))
			}
		})
	}
	_ = lastStart
}

// D16: a complete final record with nonzero sectors that fails its checksum is corruption, not a
// tear: it was synced and may have been acknowledged. It is refused with ErrInvalid and the file
// is left as it is.
func TestACompleteFinalRecordWithABadChecksumIsRefused(t *testing.T) {
	dir, group, good, lastStart := tornFixture(t)
	flipped := bytes.Clone(good)
	flipped[len(flipped)-3] ^= 0x01 // one bit in the complete, synced final record's payload
	cases := map[string][]byte{
		"one flipped bit in the final record": flipped,
		"final record with every byte changed": func() []byte {
			b := bytes.Clone(good)
			for i := lastStart + 20; i < len(b); i++ {
				b[i] ^= 0xff
			}
			return b
		}(),
		"complete extra frame, bad payload crc": append(bytes.Clone(good), frameOf(bytes.Repeat([]byte{'x'}, 300), true)...),
		"nonzero unreadable header at the end":  append(bytes.Clone(good), []byte("not a record header at all, torn")...),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if err := reopenTorn(t, dir, group, content); !errors.Is(err, ErrInvalid) {
				t.Fatalf("reopen = %v, want ErrInvalid", err)
			}
			after, _ := os.ReadFile(filepath.Join(dir, "ready.wal"))
			if !bytes.Equal(after, content) {
				t.Fatal("a refused journal was modified")
			}
		})
	}
}

// A bad record with intact records after it is not a torn tail: it is corruption inside the
// journal, which a node never repairs by dropping history.
func TestACorruptRecordInsideTheJournalIsStillRefused(t *testing.T) {
	dir, group, good, lastStart := tornFixture(t)
	for name, mutate := range map[string]func([]byte){
		"middle record payload":  func(b []byte) { b[lastStart-5] ^= 0xff },
		"middle record header":   func(b []byte) { b[lastStart-len(b)/3] ^= 0xff },
		"first record signature": func(b []byte) { b[0] = 'X' },
	} {
		t.Run(name, func(t *testing.T) {
			damaged := bytes.Clone(good)
			mutate(damaged)
			if err := reopenTorn(t, dir, group, damaged); !errors.Is(err, ErrInvalid) {
				t.Fatalf("reopen with %s damaged = %v, want ErrInvalid", name, err)
			}
			after, _ := os.ReadFile(filepath.Join(dir, "ready.wal"))
			if !bytes.Equal(after, damaged) {
				t.Fatal("a refused journal was modified")
			}
		})
	}
	t.Run("bad final frame followed by an intact frame", func(t *testing.T) {
		bad := frameOf(bytes.Repeat([]byte{'y'}, 64), true)
		next := good[lastStart:]
		content := append(append(bytes.Clone(good), bad...), next...)
		if err := reopenTorn(t, dir, group, content); !errors.Is(err, ErrInvalid) {
			t.Fatalf("reopen = %v, want ErrInvalid", err)
		}
	})
	t.Run("a journal whose only record is torn is refused", func(t *testing.T) {
		first := good[:16]
		if err := reopenTorn(t, dir, group, append(bytes.Clone(first), 0, 0, 0)); err == nil {
			t.Fatal("a journal without one verified record was accepted")
		}
	})
}
