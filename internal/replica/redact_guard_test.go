// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

// rawEntry is a normal raft entry (the raftpb fields are pointers).
func rawEntry(index, term uint64, data []byte) *pb.Entry {
	return &pb.Entry{Type: pb.EntryNormal.Enum(), Index: proto.Uint64(index), Term: proto.Uint64(term), Data: data}
}

// The guard that decides whether a staged rewrite may be installed compares every part of what
// the plan read. A real group changes several parts at once (a commit moves the applied index, the
// retained log and the journal length), so each part is changed alone here, under the group lock,
// and each one alone must be enough to refuse the staged copy.
func TestRedactPlanIsCurrentOnlyWhileEveryPartOfItIsUnchanged(t *testing.T) {
	type mutation struct {
		name    string
		journal bool // the change must be seen by the journal inputs (false: by the pin plan)
		apply   func(t *testing.T, g *Group, pin *JournalPin)
	}
	appendToFile := func(t *testing.T, path string) {
		t.Helper()
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err = f.Write([]byte{0}); err != nil {
			t.Fatal(err)
		}
	}
	replaceFile := func(t *testing.T, path string) { // the same bytes under another file
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path+".other", raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.Rename(path+".other", path); err != nil {
			t.Fatal(err)
		}
	}
	mutations := []mutation{
		{"nothing changes", true, func(*testing.T, *Group, *JournalPin) {}},
		{"an entry is applied", true, func(t *testing.T, g *Group, _ *JournalPin) { g.applied++ }},
		{"an entry is appended to the retained log", true, func(t *testing.T, g *Group, _ *JournalPin) {
			last, _ := g.memory.LastIndex()
			if err := g.memory.Append([]*pb.Entry{rawEntry(last+1, 1, []byte("x"))}); err != nil {
				t.Fatal(err)
			}
		}},
		{"an entry of the retained log is replaced", true, func(t *testing.T, g *Group, _ *JournalPin) {
			last, _ := g.memory.LastIndex()
			ents, err := g.memory.Entries(last, last+1, ^uint64(0))
			if err != nil || len(ents) != 1 {
				t.Fatalf("last entry: %d %v", len(ents), err)
			}
			replaced := rawEntry(ents[0].GetIndex(), ents[0].GetTerm(), append([]byte("y"), ents[0].GetData()...))
			if err = g.memory.Append([]*pb.Entry{replaced}); err != nil {
				t.Fatal(err)
			}
		}},
		{"the journal grows", true, func(t *testing.T, g *Group, _ *JournalPin) {
			if _, err := g.disk.file.Write([]byte{0}); err != nil {
				t.Fatal(err)
			}
		}},
		{"the journal is replaced by another file", true, func(t *testing.T, g *Group, _ *JournalPin) {
			path := filepath.Join(g.dir, "ready.wal")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			other := path + ".other"
			if err = os.WriteFile(other, raw, 0600); err != nil {
				t.Fatal(err)
			}
			f, err := os.OpenFile(other, os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			g.disk.file = f
		}},
		{"a pin is added", false, func(t *testing.T, g *Group, pin *JournalPin) {
			cp := *pin
			g.pins[model.NewID()] = &cp
		}},
		{"a pin is registered again", false, func(t *testing.T, g *Group, pin *JournalPin) {
			cp := *pin
			g.pins[pin.id] = &cp
		}},
		{"a pin archive grows", false, func(t *testing.T, g *Group, pin *JournalPin) { appendToFile(t, pin.path) }},
		{"a pin archive is replaced by another file", false, func(t *testing.T, g *Group, pin *JournalPin) { replaceFile(t, pin.path) }},
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			s := openSolo(t, t.TempDir(), model.NewID(), nil)
			s.putRow("KEEP-9f52b0d6e183")
			s.putRow("KEEP-0a63c1e7f294")
			pin, err := s.group.PinJournal(0)
			if err != nil {
				t.Fatal(err)
			}
			g := s.group
			g.mu.Lock()
			defer g.mu.Unlock()
			in, err := g.journalInputsLocked()
			if err != nil {
				t.Fatal(err)
			}
			defer in.close()
			pins, err := g.planPinsLocked()
			if err != nil {
				t.Fatal(err)
			}
			verdict := func() (journal, pinSet bool) {
				journal, err := in.currentLocked(g)
				if err != nil {
					t.Fatal(err)
				}
				pinSet, err = pinsCurrentLocked(g, pins)
				if err != nil {
					t.Fatal(err)
				}
				return journal, pinSet
			}
			if journal, pinSet := verdict(); !journal || !pinSet {
				t.Fatalf("a plan is not current right after it was read: journal %v, pins %v", journal, pinSet)
			}
			m.apply(t, g, pin)
			journal, pinSet := verdict()
			switch {
			case m.name == "nothing changes":
				if !journal || !pinSet {
					t.Fatalf("an unchanged group was refused: journal %v, pins %v", journal, pinSet)
				}
			case m.journal && (journal || !pinSet):
				t.Fatalf("a journal change: journal current %v (want false), pins current %v (want true)", journal, pinSet)
			case !m.journal && (!journal || pinSet):
				t.Fatalf("a pin change: journal current %v (want true), pins current %v (want false)", journal, pinSet)
			}
		})
	}
}

// RedactMachineCommands builds its pass without the lock only while the group has no pin (pin
// archives are rewritten under the lock): a pin that appears makes the read pass stale.
func TestMachinePassInputsAreStaleOnceAPinIsLive(t *testing.T) {
	s := openSolo(t, t.TempDir(), model.NewID(), nil)
	s.putRow("KEEP-1b74d2f8a3b5")
	g := s.group
	g.mu.Lock()
	in, err := g.machineInputsLocked()
	if err != nil {
		g.mu.Unlock()
		t.Fatal(err)
	}
	defer in.close()
	if current, err := in.currentLocked(g); err != nil || !current {
		g.mu.Unlock()
		t.Fatalf("inputs not current right after they were read: %v %v", current, err)
	}
	g.mu.Unlock()
	if _, err = g.PinJournal(0); err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	// The pin archived the retained log, which does not change the journal or the log: only the
	// pin check can refuse.
	if current, err := in.currentLocked(g); err != nil || current {
		t.Fatalf("inputs read before a pin appeared are still current: %v %v", current, err)
	}
}
