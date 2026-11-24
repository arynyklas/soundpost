// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// The fault-injecting file system of the crash tests of the payload log, and the recorder that turns one run of the engine into every
// disk a power cut could have left of it.
//
// The engine runs on crashRecorder (the payloadFS of the log) and its apply.db on the real disk. The recorder keeps, in order,
// every operation the log made on its directory: the creation of a file, the directory fsync, every write, every file fsync; and,
// through trackedDB.updateHook, the state of apply.db after every commit that returned. A crash point is a position in that
// sequence. The disk a power cut at that position leaves is computed offline, from the first operation to the crash point, under the
// durability contract of payloadFS and nothing more: only what an fsync covered is there for certain; what was written since is lost,
// kept, torn or reordered (the modes below). Bolt itself is modelled as it promises to be: the file as of the last commit that returned,
// or, while a commit is in flight, that or the commit.

// crashWrite is one write the file system has not yet been told to make durable.
type crashWrite struct {
	off  int64
	data []byte
}

// crashEvent is one operation of the log on its directory.
type crashEvent struct {
	kind string // mkdir, load, create, write, sync, syncdir
	name string // the file, relative to the directory of the log
	off  int64
	data []byte
}

// crashItem is one position of the recorded run: what had happened when it was recorded.
type crashItem struct {
	desc     string
	nev      int  // operations of the log so far
	gen      int  // commits of apply.db that returned so far
	inflight bool // a commit has started and not returned
	mark     int  // index into marks, or -1
}

// crashMark is a fact about the run the test verifies at every later crash point.
type crashMark struct {
	kind    string // "ack" (an append returned: its kept records must read back), "erased" (an erasure returned: the canaries are gone)
	metrics []model.ID
	logs    []model.ID
	canary  []string
}

type crashRecorder struct {
	mu        sync.Mutex
	dir       string
	dirOK     bool
	live      map[string][]byte
	events    []crashEvent
	items     []crashItem
	marks     []crashMark
	snaps     [][]byte
	gen       int
	inflight  bool
	recording bool

	commitMu sync.Mutex
}

func newCrashRecorder() *crashRecorder { return &crashRecorder{live: map[string][]byte{}} }

// hook is payloadFSHook for the engine under test.
func (r *crashRecorder) hook(dir string) payloadFS {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dir = dir
	return r
}

// load makes a file that is on the disk, durably, when the recording starts (a log an earlier crash left).
func (r *crashRecorder) load(name string, data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dirOK = true
	r.live[name] = bytes.Clone(data)
	r.events = append(r.events, crashEvent{kind: "load", name: name, data: bytes.Clone(data)})
}

// addLocked appends an event, and a position of the run when it is being recorded.
func (r *crashRecorder) addLocked(ev crashEvent, desc string) {
	r.events = append(r.events, ev)
	if r.recording {
		r.items = append(r.items, crashItem{desc: desc, nev: len(r.events), gen: r.gen, inflight: r.inflight, mark: -1})
	}
}

func (r *crashRecorder) snapshot(db *trackedDB) []byte {
	var buf bytes.Buffer
	if err := db.DB.View(func(tx *bolt.Tx) error {
		_, err := tx.WriteTo(&buf)
		return err
	}); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// start begins the recording: the state of apply.db now is the state of the first crash point, and every commit from now on is a
// position of the run.
func (r *crashRecorder) start(db *trackedDB) {
	snap := r.snapshot(db)
	r.mu.Lock()
	r.snaps = [][]byte{snap}
	r.recording = true
	r.items = []crashItem{{desc: "start", nev: len(r.events), mark: -1}}
	r.mu.Unlock()
	h := func(run func() error) error {
		r.commitMu.Lock()
		defer r.commitMu.Unlock()
		r.mu.Lock()
		r.inflight = true
		r.addItemLocked("commit start")
		r.mu.Unlock()
		err := run()
		var snap []byte
		if err == nil {
			snap = r.snapshot(db)
		}
		r.mu.Lock()
		if err == nil {
			r.snaps = append(r.snaps, snap)
		} else {
			r.snaps = append(r.snaps, r.snaps[len(r.snaps)-1])
		}
		r.gen++
		r.inflight = false
		r.addItemLocked("commit end")
		r.mu.Unlock()
		return err
	}
	db.updateHook.Store(&h)
}

func (r *crashRecorder) addItemLocked(desc string) {
	r.items = append(r.items, crashItem{desc: desc, nev: len(r.events), gen: r.gen, inflight: r.inflight, mark: -1})
}

// stop ends the recording.
func (r *crashRecorder) stop(db *trackedDB) {
	db.updateHook.Store(nil)
	r.mu.Lock()
	r.recording = false
	r.mu.Unlock()
}

// note records a fact about the run at the current position.
func (r *crashRecorder) note(desc string, m crashMark) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.marks = append(r.marks, m)
	r.items = append(r.items, crashItem{desc: desc, nev: len(r.events), gen: r.gen, inflight: r.inflight, mark: len(r.marks) - 1})
}

// payloadFS of the log.

func (r *crashRecorder) OpenFile(name string, flag int, _ os.FileMode) (payloadFile, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rel := filepath.Base(name)
	_, ok := r.live[rel]
	switch {
	case !ok && flag&os.O_CREATE == 0, !ok && !r.dirOK:
		return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
	case ok && flag&os.O_CREATE != 0 && flag&os.O_EXCL != 0:
		return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrExist}
	case !ok:
		r.live[rel] = nil
		r.addLocked(crashEvent{kind: "create", name: rel}, "create "+rel)
	}
	return &crashHandle{r: r, name: rel}, nil
}

func (r *crashRecorder) Files(dir string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.dirOK {
		return nil, &os.PathError{Op: "open", Path: dir, Err: os.ErrNotExist}
	}
	names := make([]string, 0, len(r.live))
	for n := range r.live {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

func (r *crashRecorder) Size(name string) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.live[filepath.Base(name)]
	if !ok {
		return 0, &os.PathError{Op: "stat", Path: name, Err: os.ErrNotExist}
	}
	return int64(len(d)), nil
}

func (r *crashRecorder) MkdirAll(dir string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.dirOK {
		r.dirOK = true
		r.addLocked(crashEvent{kind: "mkdir"}, "mkdir payload")
	}
	return nil
}

func (r *crashRecorder) SyncDir(dir string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addLocked(crashEvent{kind: "syncdir"}, "fsync payload directory")
	return nil
}

type crashHandle struct {
	r    *crashRecorder
	name string
}

func (h *crashHandle) ReadAt(p []byte, off int64) (int, error) {
	h.r.mu.Lock()
	defer h.r.mu.Unlock()
	d := h.r.live[h.name]
	if off >= int64(len(d)) {
		return 0, io.EOF
	}
	n := copy(p, d[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (h *crashHandle) WriteAt(p []byte, off int64) (int, error) {
	h.r.mu.Lock()
	defer h.r.mu.Unlock()
	h.r.live[h.name] = writeAtCopy(h.r.live[h.name], off, p)
	h.r.addLocked(crashEvent{kind: "write", name: h.name, off: off, data: bytes.Clone(p)}, fmt.Sprintf("write %s @%d +%d", h.name, off, len(p)))
	return len(p), nil
}

func (h *crashHandle) Sync() error {
	h.r.mu.Lock()
	defer h.r.mu.Unlock()
	h.r.addLocked(crashEvent{kind: "sync", name: h.name}, "fsync "+h.name)
	return nil
}

func (h *crashHandle) Close() error { return nil }

func (h *crashHandle) Stat() (os.FileInfo, error) {
	h.r.mu.Lock()
	defer h.r.mu.Unlock()
	return crashInfo{name: h.name, size: int64(len(h.r.live[h.name]))}, nil
}

type crashInfo struct {
	name string
	size int64
}

func (i crashInfo) Name() string       { return i.name }
func (i crashInfo) Size() int64        { return i.size }
func (i crashInfo) Mode() os.FileMode  { return 0600 }
func (i crashInfo) ModTime() time.Time { return time.Time{} }
func (i crashInfo) IsDir() bool        { return false }
func (i crashInfo) Sys() any           { return nil }

// writeAtCopy returns a copy of d with p written at off (zero filled past its end), so that earlier states stay as they were.
func writeAtCopy(d []byte, off int64, p []byte) []byte {
	n := max(int64(len(d)), off+int64(len(p)))
	out := make([]byte, n)
	copy(out, d)
	copy(out[off:], p)
	return out
}

// simFile is a file as the disk would hold it.
type simFile struct {
	vol      []byte // what the process sees
	dur      []byte // what an fsync made durable
	pend     []crashWrite
	entryDur bool // the directory entry is durable (a SyncDir returned after the create)
}

// simulate replays the first nev operations.
func (r *crashRecorder) simulate(nev int) (files map[string]*simFile, dir bool) {
	files = map[string]*simFile{}
	for _, ev := range r.events[:nev] {
		switch ev.kind {
		case "mkdir":
			dir = true
		case "load":
			dir = true
			files[ev.name] = &simFile{vol: ev.data, dur: ev.data, entryDur: true}
		case "create":
			files[ev.name] = &simFile{}
		case "write":
			f := files[ev.name]
			f.vol = writeAtCopy(f.vol, ev.off, ev.data)
			f.pend = append(f.pend, crashWrite{ev.off, ev.data})
		case "sync":
			f := files[ev.name]
			f.dur, f.pend = f.vol, nil
		case "syncdir":
			for _, f := range files {
				f.entryDur = true
			}
		}
	}
	return files, dir
}

// crashMode is what a power cut makes of the writes and the directory entries that no fsync covered.
type crashMode struct {
	name string
	// image is the content of the file after the cut and whether the file exists.
	image func(f *simFile, rng *rand.Rand) ([]byte, bool)
}

func applyWrites(base []byte, ws []crashWrite) []byte {
	out := base
	for _, w := range ws {
		out = writeAtCopy(out, w.off, w.data)
	}
	return out
}

var crashModes = []crashMode{
	// The unsynced writes are gone, and so is a file whose directory entry no SyncDir covered.
	{"unsynced-lost", func(f *simFile, _ *rand.Rand) ([]byte, bool) { return f.dur, f.entryDur }},
	// The unsynced writes are gone, a created file is there (the filesystem happened to commit the directory).
	{"unsynced-lost-entries-kept", func(f *simFile, _ *rand.Rand) ([]byte, bool) { return f.dur, true }},
	// The size reached the disk and the data did not: the file has its length and zeros where the unsynced bytes go.
	{"size-kept-data-zero", func(f *simFile, _ *rand.Rand) ([]byte, bool) {
		out := make([]byte, len(f.vol))
		copy(out, f.dur)
		return out, true
	}},
	// The first half of the unsynced bytes, in the order they were written, reached the disk, the last write cut in the middle.
	{"torn-half", func(f *simFile, _ *rand.Rand) ([]byte, bool) {
		total := 0
		for _, w := range f.pend {
			total += len(w.data)
		}
		budget := total / 2
		var take []crashWrite
		for _, w := range f.pend {
			if budget <= 0 {
				break
			}
			n := min(len(w.data), budget)
			take = append(take, crashWrite{w.off, w.data[:n]})
			budget -= n
		}
		return applyWrites(f.dur, take), true
	}},
	// Any subset of the unsynced writes reached the disk (the disk reorders), and the directory entry may be lost.
	{"random-subset", func(f *simFile, rng *rand.Rand) ([]byte, bool) {
		var take []crashWrite
		for _, w := range f.pend {
			if rng.IntN(2) == 0 {
				take = append(take, w)
			}
		}
		return applyWrites(f.dur, take), f.entryDur || rng.IntN(2) == 0
	}},
	// Every write reached the disk: the process was killed, the machine was not (the control).
	{"all-written", func(f *simFile, _ *rand.Rand) ([]byte, bool) { return f.vol, true }},
}

// crashPoint is a place of the run a power cut is tried at, with the apply.db the disk holds there.
type crashPoint struct {
	item int
	desc string
	snap int
	mode string
	// files and dir are what the log's directory holds.
	files map[string][]byte
	dir   bool
	key   [32]byte
}

// points lists every distinct disk of every crash point and mode. Two points whose disks are byte for byte the same are one.
func (r *crashRecorder) points() []crashPoint {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := map[[32]byte]bool{}
	var out []crashPoint
	for i, it := range r.items {
		sim, dir := r.simulate(it.nev)
		snaps := []int{it.gen}
		if it.inflight {
			snaps = append(snaps, it.gen+1) // the commit may have reached the disk before it returned
		}
		for mi, m := range crashModes {
			rng := rand.New(rand.NewPCG(uint64(i)+1, uint64(mi)+1))
			files := map[string][]byte{}
			names := make([]string, 0, len(sim))
			for n := range sim {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				if data, ok := m.image(sim[n], rng); ok {
					files[n] = data
				}
			}
			for _, s := range snaps {
				h := sha256.New()
				fmt.Fprintf(h, "snap=%d dir=%v\n", s, dir)
				for _, n := range names {
					if d, ok := files[n]; ok {
						fmt.Fprintf(h, "%s %d\n", n, len(d))
						h.Write(d)
					}
				}
				var key [32]byte
				copy(key[:], h.Sum(nil))
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, crashPoint{item: i, desc: it.desc, snap: s, mode: m.name, files: files, dir: dir, key: key})
			}
		}
	}
	return out
}

// writeImage lays the disk of a crash point under dst: apply.db, the log's files, and the journals of the groups (which the engine
// writes and syncs before it applies: the journals are taken whole, and the machine's cursor in apply.db decides what is replayed).
func (r *crashRecorder) writeImage(dst string, p crashPoint, raft map[string][]byte) error {
	if err := os.MkdirAll(dst, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dst, "apply.db"), r.snaps[p.snap], 0600); err != nil {
		return err
	}
	for name, data := range raft {
		path := filepath.Join(dst, "raft", name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			return err
		}
	}
	if p.dir {
		if err := os.MkdirAll(filepath.Join(dst, payloadDirName), 0700); err != nil {
			return err
		}
	}
	for name, data := range p.files {
		if err := os.WriteFile(filepath.Join(dst, payloadDirName, name), data, 0600); err != nil {
			return err
		}
	}
	return nil
}

// readTree reads every file under root into a map keyed by the slash path relative to it.
func readTree(root string) (map[string][]byte, error) {
	out := map[string][]byte{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		rel, _ := filepath.Rel(root, p)
		out[strings.ReplaceAll(rel, `\`, "/")] = raw
		return nil
	})
	return out, err
}
