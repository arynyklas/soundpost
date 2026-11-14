// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/arynyklas/soundpost/internal/durablefs"
	"github.com/arynyklas/soundpost/internal/model"
)

// Crash hooks. Each runs immediately before the named durability step; a hook
// that returns an error simulates process death there and nothing is cleaned up,
// exactly as after a kill. OpenSnapshotStore repairs whatever such a stop left.
const (
	HookSnapshotCut           = "snapshot_cut"
	HookSnapshotPin           = "snapshot_pin"
	HookSnapshotFileWrite     = "snapshot_file_write"
	HookSnapshotFileSync      = "snapshot_file_sync"
	HookSnapshotManifestWrite = "snapshot_manifest_write"
	HookSnapshotDirSync       = "snapshot_dir_sync"
	HookSnapshotSwitch        = "snapshot_switch"
	HookSnapshotRenamed       = "snapshot_renamed"
	HookSnapshotCurrentWrite  = "snapshot_current_write"
	HookSnapshotCurrentSwitch = "snapshot_current_switch"
	HookSnapshotPublished     = "snapshot_published"

	HookInstallBegin         = "install_begin"
	HookInstallFileWrite     = "install_file_write"
	HookInstallFileSync      = "install_file_sync"
	HookInstallManifestWrite = "install_manifest_write"
	HookInstallDirSync       = "install_dir_sync"
	HookInstallSwitch        = "install_switch"
	HookInstallRenamed       = "install_renamed"
	HookInstallCurrentWrite  = "install_current_write"
	HookInstallCurrentSwitch = "install_current_switch"
	HookInstallPublished     = "install_published"
)

const (
	currentName = "CURRENT"
	fenceName   = "FENCE"
)

// crashed marks a hook-induced stop so the unwinding code leaves the disk as is.
type crashed struct{ err error }

func (c crashed) Error() string { return "simulated crash: " + c.err.Error() }
func (c crashed) Unwrap() error { return c.err }

type bundleSource struct {
	name string
	data []byte
	path string
}

type currentPointer struct {
	Version  uint16     `json:"version"`
	Dir      string     `json:"dir"`
	Checksum model.Hash `json:"checksum"`
}

// SnapshotStore owns <group dir>/snapshots. Installation always writes into a
// new directory, fsyncs every file and directory, and only then atomically
// switches the CURRENT pointer, so an interrupted install leaves the previously
// selected valid directory in force.
type SnapshotStore struct {
	mu    sync.Mutex
	root  string
	group model.ID
	fault func(string) error
}

// OpenSnapshotStore opens (creating if needed) the store under directory and
// repairs leftovers of interrupted creation or installation.
func OpenSnapshotStore(directory string, group model.ID, fault func(string) error) (*SnapshotStore, error) {
	if directory == "" || group == (model.ID{}) {
		return nil, ErrInvalid
	}
	s := &SnapshotStore{root: filepath.Join(directory, "snapshots"), group: group, fault: fault}
	if err := durablefs.MkdirAll(s.root); err != nil {
		return nil, err
	}
	if err := s.repair(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SnapshotStore) hook(prefix, step string) error {
	if s.fault == nil {
		return nil
	}
	if err := s.fault(prefix + step); err != nil {
		return crashed{err}
	}
	return nil
}

func dirName(m SnapshotManifest) string {
	return fmt.Sprintf("snap-%020d-%s", m.Index, hex.EncodeToString(m.Checksum[:4]))
}

// Current returns the selected snapshot after structural validation (manifest
// checksum, file presence and sizes). Use Verify for a full byte re-check.
func (s *SnapshotStore) Current() (Snapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, err := s.loadCurrent(false)
	return snap, err == nil
}

func (s *SnapshotStore) loadCurrent(deep bool) (Snapshot, error) {
	raw, err := os.ReadFile(filepath.Join(s.root, currentName))
	if err != nil {
		return Snapshot{}, err
	}
	var p currentPointer
	if model.StrictJSON(raw, &p) != nil || p.Version != 1 || p.Dir != filepath.Base(p.Dir) || !strings.HasPrefix(p.Dir, "snap-") {
		return Snapshot{}, ErrCorrupt
	}
	snap, err := s.loadDir(filepath.Join(s.root, p.Dir), deep)
	if err != nil {
		return Snapshot{}, err
	}
	if snap.Manifest.Checksum != p.Checksum || dirName(snap.Manifest) != p.Dir {
		return Snapshot{}, ErrCorrupt
	}
	return snap, nil
}

// Verify re-reads every byte of the current snapshot against its manifest.
func (s *SnapshotStore) Verify() (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, err := s.loadCurrent(true)
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, ErrNoSnapshot
	}
	return snap, err
}

func (s *SnapshotStore) loadDir(dir string, deep bool) (Snapshot, error) {
	raw, err := os.ReadFile(filepath.Join(dir, fileManifest))
	if err != nil {
		return Snapshot{}, err
	}
	var m SnapshotManifest
	if model.StrictJSON(raw, &m) != nil {
		return Snapshot{}, ErrCorrupt
	}
	if err = m.Validate(); err != nil {
		return Snapshot{}, err
	}
	if m.Group != s.group {
		return Snapshot{}, ErrCorrupt
	}
	if err = checkTree(dir, m, deep); err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Manifest: m, dir: dir}, nil
}

// checkTree requires the directory to hold exactly the manifest's files.
func checkTree(dir string, m SnapshotManifest, deep bool) error {
	expected := map[string]SnapshotFile{}
	for _, f := range m.Files {
		expected[f.Name] = f
	}
	found := 0
	for _, f := range m.Files {
		path := filepath.Join(dir, filepath.FromSlash(f.Name))
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || uint64(info.Size()) != f.Size {
			return ErrCorrupt
		}
		found++
		if deep {
			in, err := os.Open(path)
			if err != nil {
				return ErrCorrupt
			}
			h := sha256.New()
			_, err = io.Copy(h, in)
			in.Close()
			if err != nil || model.Hash(h.Sum(nil)) != f.SHA256 {
				return ErrCorrupt
			}
		}
	}
	var walk func(rel string) error
	extra := 0
	walk = func(rel string) error {
		entries, err := os.ReadDir(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		for _, e := range entries {
			name := strings.TrimPrefix(rel+"/"+e.Name(), "/")
			if e.IsDir() {
				if name != "files" {
					return ErrCorrupt
				}
				if err = walk(name); err != nil {
					return err
				}
				continue
			}
			if name == fileManifest {
				continue
			}
			if _, ok := expected[name]; !ok {
				extra++
			}
		}
		return nil
	}
	if err := walk(""); err != nil {
		return ErrCorrupt
	}
	if extra != 0 || found != len(m.Files) {
		return ErrCorrupt
	}
	return checkContent(dir, m, deep)
}

// checkContent enforces the semantic requirements that make a snapshot ready:
// a present, well-formed deletion ledger bound to the manifest and an envelope
// whose application cursor equals the manifest cursor.
func checkContent(dir string, m SnapshotManifest, envelopeToo bool) error {
	raw, err := os.ReadFile(filepath.Join(dir, fileLedger))
	if err != nil {
		return ErrNoLedger
	}
	var ledger Ledger
	if model.StrictJSON(raw, &ledger) != nil || ledger.Entries == nil || ledger.Version != 1 || ledger.Group != m.Group || ledger.Generation != m.Generation {
		return ErrNoLedger
	}
	if uint64(len(ledger.Entries)) != m.Ledger.Count {
		return ErrNoLedger
	}
	var previous uint64
	for _, e := range ledger.Entries {
		if e.Index <= previous || e.Index > uint64(m.Cursor.Index) || e.Kind == "" {
			return ErrNoLedger
		}
		previous = e.Index
	}
	if !envelopeToo {
		return nil
	}
	raw, err = os.ReadFile(filepath.Join(dir, fileEnvelope))
	if err != nil {
		return ErrCorrupt
	}
	var envelope snapshotEnvelope
	if json.Unmarshal(raw, &envelope) != nil || envelope.Application != uint64(m.Cursor.Index) || ValidateMembers(envelope.Members) != nil {
		return ErrCorrupt
	}
	return nil
}

// RequireGeneration durably refuses every snapshot (including a node's own)
// whose deletion-ledger generation is older than generation. The restore
// authority calls this before any data read.
func (s *SnapshotStore) RequireGeneration(generation uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current := s.fenceLocked(); generation < current {
		return ErrStale
	}
	return s.writeAtomic(fenceName, []byte(strconv.FormatUint(generation, 10)), "")
}

func (s *SnapshotStore) fenceLocked() uint64 {
	raw, err := os.ReadFile(filepath.Join(s.root, fenceName))
	if err != nil {
		return 0
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return ^uint64(0) // an unreadable fence refuses everything rather than nothing
	}
	return v
}

func (s *SnapshotStore) writeAtomic(name string, data []byte, prefix string) error {
	tmp := filepath.Join(s.root, name+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if ce := f.Close(); err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	if prefix != "" {
		if err = s.hook(prefix, "current_switch"); err != nil {
			return err
		}
	}
	return durablefs.Rename(tmp, filepath.Join(s.root, name))
}

func (s *SnapshotStore) admit(m SnapshotManifest) (Snapshot, bool, error) {
	if fence := s.fenceLocked(); m.Generation < fence {
		return Snapshot{}, false, ErrStale
	}
	cur, err := s.loadCurrent(false)
	if err != nil {
		return Snapshot{}, false, nil
	}
	if cur.Manifest.Checksum == m.Checksum {
		return cur, true, nil
	}
	if m.Generation < cur.Manifest.Generation || m.Index < cur.Manifest.Index {
		return Snapshot{}, false, ErrStale
	}
	if m.Index == cur.Manifest.Index {
		return Snapshot{}, false, ErrConflict
	}
	return Snapshot{}, false, nil
}

func randomSuffix() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// copyOut writes one file and returns its description; fsync precedes return.
func (s *SnapshotStore) copyOut(ctx context.Context, prefix, tmp, name string, in io.Reader, want *SnapshotFile) (SnapshotFile, error) {
	path := filepath.Join(tmp, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return SnapshotFile{}, err
	}
	if err := s.hook(prefix, "file_write"); err != nil {
		return SnapshotFile{}, err
	}
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return SnapshotFile{}, err
	}
	h := sha256.New()
	var n int64
	if want != nil {
		n, err = copyContext(ctx, io.MultiWriter(out, h), io.LimitReader(in, int64(want.Size)))
		if err == nil && uint64(n) != want.Size {
			err = ErrCorrupt
		}
	} else {
		n, err = copyContext(ctx, io.MultiWriter(out, h), in)
	}
	if err == nil {
		if err = s.hook(prefix, "file_sync"); err == nil {
			err = out.Sync()
		}
	}
	if ce := out.Close(); err == nil {
		err = ce
	}
	if err != nil {
		return SnapshotFile{}, err
	}
	file := SnapshotFile{Name: name, Size: uint64(n)}
	copy(file.SHA256[:], h.Sum(nil))
	if want != nil && file.SHA256 != want.SHA256 {
		return SnapshotFile{}, ErrCorrupt
	}
	return file, nil
}

func copyContext(ctx context.Context, w io.Writer, r io.Reader) (int64, error) {
	buf := make([]byte, 256<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

func isCrash(err error) bool { var c crashed; return errors.As(err, &c) }

// create publishes a locally cut snapshot.
func (s *SnapshotStore) create(ctx context.Context, m SnapshotManifest, ledgerRaw []byte, sources []bundleSource) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	const prefix = "snapshot_"
	if fence := s.fenceLocked(); m.Generation < fence {
		return Snapshot{}, ErrStale
	}
	if cur, err := s.loadCurrent(false); err == nil && cur.Manifest.Index >= m.Index {
		// Same cut: the retained snapshot is already this state; an older cut is stale.
		if cur.Manifest.Index == m.Index && cur.Manifest.Generation == m.Generation {
			return cur, nil
		}
		return Snapshot{}, ErrStale
	}
	var ledger Ledger
	if model.StrictJSON(ledgerRaw, &ledger) != nil || ledger.Entries == nil {
		return Snapshot{}, ErrNoLedger
	}
	tmp := filepath.Join(s.root, "tmp-"+randomSuffix())
	if err := durablefs.MkdirAll(tmp); err != nil {
		return Snapshot{}, err
	}
	snap, err := s.build(ctx, prefix, tmp, m, uint64(len(ledger.Entries)), func(name string, want *SnapshotFile) (io.ReadCloser, error) {
		for _, src := range sources {
			if src.name != name {
				continue
			}
			if src.path != "" {
				return os.Open(src.path)
			}
			return io.NopCloser(bytes.NewReader(src.data)), nil
		}
		return nil, ErrCorrupt
	}, names(sources), false, nil)
	if err != nil {
		if !isCrash(err) {
			_ = os.RemoveAll(tmp)
		}
		return Snapshot{}, err
	}
	return snap, nil
}

func names(sources []bundleSource) []string {
	out := make([]string, len(sources))
	for i, s := range sources {
		out[i] = s.name
	}
	return out
}

// build writes every named file, seals the manifest and publishes the directory.
// When install is true the manifest m is already complete and each file is
// verified against it as it is copied.
func (s *SnapshotStore) build(ctx context.Context, prefix, tmp string, m SnapshotManifest, ledgerCount uint64, open func(string, *SnapshotFile) (io.ReadCloser, error), order []string, install bool, after func() error) (Snapshot, error) {
	var files []SnapshotFile
	for i, name := range order {
		var want *SnapshotFile
		if install {
			want = &m.Files[i]
		}
		in, err := open(name, want)
		if err != nil {
			return Snapshot{}, err
		}
		file, err := s.copyOut(ctx, prefix, tmp, name, in, want)
		in.Close()
		if err != nil {
			return Snapshot{}, err
		}
		files = append(files, file)
	}
	if after != nil {
		if err := after(); err != nil {
			return Snapshot{}, err
		}
	}
	if !install {
		m.Files = files
		for _, f := range files {
			if f.Name == fileLedger {
				m.Ledger = LedgerSummary{Generation: m.Generation, Count: ledgerCount, Digest: f.SHA256}
			}
		}
		m.Checksum = m.seal()
	}
	if err := m.Validate(); err != nil {
		return Snapshot{}, err
	}
	if err := checkContent(tmp, m, true); err != nil {
		return Snapshot{}, err
	}
	if err := s.hook(prefix, "manifest_write"); err != nil {
		return Snapshot{}, err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return Snapshot{}, err
	}
	if err = writeSynced(filepath.Join(tmp, fileManifest), raw); err != nil {
		return Snapshot{}, err
	}
	if err = s.hook(prefix, "dir_sync"); err != nil {
		return Snapshot{}, err
	}
	if err = syncDirTree(tmp); err != nil {
		return Snapshot{}, err
	}
	if err = s.hook(prefix, "switch"); err != nil {
		return Snapshot{}, err
	}
	target := filepath.Join(s.root, dirName(m))
	if _, err = os.Stat(target); err == nil {
		if err = os.RemoveAll(target); err != nil { // an orphan of an unacknowledged earlier attempt
			return Snapshot{}, err
		}
	}
	if err = durablefs.Rename(tmp, target); err != nil {
		return Snapshot{}, err
	}
	if err = s.hook(prefix, "renamed"); err != nil {
		return Snapshot{}, err
	}
	pointer, err := json.Marshal(currentPointer{Version: 1, Dir: dirName(m), Checksum: m.Checksum})
	if err != nil {
		return Snapshot{}, err
	}
	if err = s.hook(prefix, "current_write"); err != nil {
		return Snapshot{}, err
	}
	if err = s.writeAtomic(currentName, pointer, prefix); err != nil {
		return Snapshot{}, err
	}
	if err = s.hook(prefix, "published"); err != nil {
		return Snapshot{}, err
	}
	if err = s.prune(dirName(m)); err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Manifest: m, dir: target}, nil
}

func writeSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if ce := f.Close(); err == nil {
		err = ce
	}
	return err
}

// InstallSnapshot consumes the stream produced by Snapshot.WriteTo for manifest
// into a fresh directory and selects it only when every checksum, the deletion
// ledger and the generation fence hold. Any failure leaves the previous
// selection untouched.
func (s *SnapshotStore) InstallSnapshot(ctx context.Context, m SnapshotManifest, r io.Reader) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if m.Group != s.group {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	const prefix = "install_"
	if _, same, err := s.admit(m); err != nil {
		return err
	} else if same {
		return nil
	}
	if err := s.hook(prefix, "begin"); err != nil {
		return err
	}
	tmp := filepath.Join(s.root, "install-"+randomSuffix())
	if err := durablefs.MkdirAll(tmp); err != nil {
		return err
	}
	order := make([]string, len(m.Files))
	for i, f := range m.Files {
		order[i] = f.Name
	}
	_, err := s.build(ctx, prefix, tmp, m, m.Ledger.Count, func(name string, want *SnapshotFile) (io.ReadCloser, error) {
		return io.NopCloser(r), nil
	}, order, true, func() error {
		// The sender must have nothing left over: a longer stream is a different snapshot.
		var one [1]byte
		if n, _ := r.Read(one[:]); n != 0 {
			return ErrCorrupt
		}
		return nil
	})
	if err != nil {
		if !isCrash(err) {
			_ = os.RemoveAll(tmp)
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			err = ErrCorrupt
		}
		return err
	}
	return nil
}

// prune keeps the selected directory and the newest previous one.
func (s *SnapshotStore) prune(keep string) error {
	dirs, err := s.snapDirs()
	if err != nil {
		return err
	}
	retained := 0
	for _, d := range dirs {
		if d == keep {
			continue
		}
		if d > keep { // an unreferenced orphan newer than the selection
			if err = os.RemoveAll(filepath.Join(s.root, d)); err != nil {
				return err
			}
			continue
		}
		if retained == 0 {
			retained++
			continue
		}
		if err = os.RemoveAll(filepath.Join(s.root, d)); err != nil {
			return err
		}
	}
	return durablefs.SyncDir(s.root)
}

// snapDirs lists snap-* directories newest first.
func (s *SnapshotStore) snapDirs() ([]string, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "snap-") {
			dirs = append(dirs, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dirs)))
	return dirs, nil
}
