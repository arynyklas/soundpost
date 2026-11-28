//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"bytes"
	"context"
	"github.com/arynyklas/soundpost/internal/model"
	"io"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type executableMap struct {
	start, end, offset, device, inode uint64
	path                              string
	reason                            FrameReason
}

func mapPath(raw string) (string, error) {
	if len(raw) > 4096 {
		return "", ErrInvalid
	}
	var out strings.Builder
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == '\\' {
			if i+3 >= len(raw) {
				return "", ErrInvalid
			}
			escape := raw[i+1 : i+4]
			switch escape {
			case "040":
				c = ' '
			case "011":
				c = '\t'
			case "012":
				c = '\n'
			case "134":
				c = '\\'
			default:
				return "", ErrInvalid
			}
			i += 3
		}
		if c == 0 || c == '\n' || c == '\r' || c == '\t' {
			return "", ErrInvalid
		}
		out.WriteByte(c)
	}
	return out.String(), nil
}
func validMappedPath(path string) bool {
	if len(path) < 2 || len(path) > 4096 || path[0] != '/' || strings.ContainsAny(path, "\x00\n\r\\") {
		return false
	}
	for _, part := range strings.Split(path[1:], "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}
func parseExecutableMaps(b []byte, maxBytes uint64, maxMappings uint32) ([]executableMap, error) {
	if uint64(len(b)) > maxBytes {
		return nil, ErrResourceBudget
	}
	out := make([]executableMap, 0)
	var previousEnd uint64
	for len(b) > 0 {
		end := bytes.IndexByte(b, '\n')
		if end < 0 {
			return nil, ErrInvalid
		}
		line := b[:end]
		b = b[end+1:]
		if len(line) == 0 || len(line) > 8192 {
			return nil, ErrInvalid
		}
		// Only five numeric/permission columns are split; the rest is a transient
		// pathname and never appears in returned diagnostics/export metadata.
		var fields [5][]byte
		rest := line
		for i := range fields {
			rest = bytes.TrimLeft(rest, " \t")
			n := bytes.IndexAny(rest, " \t")
			if n < 0 {
				if i != 4 {
					return nil, ErrInvalid
				}
				fields[i] = rest
				rest = nil
				break
			}
			fields[i] = rest[:n]
			rest = rest[n:]
		}
		rangeParts := bytes.Split(fields[0], []byte{'-'})
		deviceParts := bytes.Split(fields[3], []byte{':'})
		if len(rangeParts) != 2 || len(deviceParts) != 2 || len(fields[1]) != 4 {
			return nil, ErrInvalid
		}
		start, e1 := strconv.ParseUint(string(rangeParts[0]), 16, 64)
		finish, e2 := strconv.ParseUint(string(rangeParts[1]), 16, 64)
		offset, e3 := strconv.ParseUint(string(fields[2]), 16, 64)
		major, e4 := strconv.ParseUint(string(deviceParts[0]), 16, 32)
		minor, e5 := strconv.ParseUint(string(deviceParts[1]), 16, 32)
		inode, e6 := strconv.ParseUint(string(fields[4]), 10, 64)
		perms := fields[1]
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil || start >= finish || start < previousEnd || offset > ^uint64(0)-(finish-start) || (perms[0] != 'r' && perms[0] != '-') || (perms[1] != 'w' && perms[1] != '-') || (perms[2] != 'x' && perms[2] != '-') || (perms[3] != 'p' && perms[3] != 's') {
			return nil, ErrInvalid
		}
		previousEnd = finish
		if perms[2] != 'x' {
			continue
		}
		if uint32(len(out)) >= maxMappings {
			return nil, ErrResourceBudget
		}
		// Linux's gnu_dev_makedev encoding; major/minor were independently parsed.
		device := (minor & 0xff) | ((major & 0xfff) << 8) | ((minor &^ uint64(0xff)) << 12) | ((major &^ uint64(0xfff)) << 32)
		row := executableMap{start: start, end: finish, offset: offset, device: device, inode: inode}
		raw := string(bytes.TrimLeft(rest, " \t"))
		if raw == "" || raw[0] != '/' || inode == 0 {
			row.reason = FrameJITMissing
			out = append(out, row)
			continue
		}
		path, e := mapPath(raw)
		if e != nil {
			return nil, e
		}
		if strings.HasSuffix(path, " (deleted)") {
			row.reason = FrameDeleted
			out = append(out, row)
			continue
		}
		if !validMappedPath(path) {
			return nil, ErrInvalid
		}
		row.path = path
		out = append(out, row)
	}
	return out, nil
}
func openMappedPath(root int, path string) (*os.File, error) {
	if !validMappedPath(path) {
		return nil, ErrInvalid
	}
	current, e := syscall.Dup(root)
	if e != nil {
		return nil, ErrTargetIdentity
	}
	parts := strings.Split(path[1:], "/")
	for i, part := range parts {
		flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= syscall.O_DIRECTORY
		}
		next, e := syscall.Openat(current, part, flags, 0)
		syscall.Close(current)
		if e != nil {
			return nil, ErrTargetIdentity
		}
		current = next
	}
	f := os.NewFile(uintptr(current), "approved-mapped-elf")
	if _, e := fileIdentity(f); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}

// MappingReader is helper-local, scope-bound and not safe to create from an
// ordinary Target alone. Only the existing signed local AuthorizedTargets can
// create it. Explicit generation is the source's epoch, not a guessed hash.
type MappingReader struct {
	mu         sync.Mutex
	handle     *TargetHandle
	authority  AuthorizedTargets
	target     Target
	process    ProcessKey
	epoch      identityEpoch
	policy     SymbolPolicy
	executable executableIdentity
	build      string
	threads    []cpuThread
	domain     ClockDomain
	lastRead   time.Time
	closed     bool
}

func NewMappingReader(a AuthorizedTargets, target Target, generation uint64, policy SymbolPolicy) (*MappingReader, error) {
	if generation == 0 || policy.validate() != nil || target.Validate() != nil || target.CgroupID == 0 || len(target.AllowedBuildIDs) == 0 {
		return nil, ErrInvalid
	}
	found := false
	for _, t := range a.targets {
		if reflect.DeepEqual(t, target) {
			found = true
			break
		}
	}
	if !found {
		return nil, ErrTargetIdentity
	}
	// Copy policy slices/maps to prevent request-side mutation after admission.
	target.AllowedBuildIDs = append([]string(nil), target.AllowedBuildIDs...)
	refs := make(map[string]model.ID, len(policy.Artifacts))
	for k, v := range policy.Artifacts {
		refs[k] = v
	}
	policy.Artifacts = refs
	r := &MappingReader{target: target, policy: policy, epoch: identityEpoch{generation: generation}, handle: &TargetHandle{Target: target}, authority: AuthorizedTargets{targets: []Target{target}, mode: a.mode}}
	fail := func() (*MappingReader, error) { r.Close(); return nil, ErrTargetIdentity }
	fd, _, errno := syscall.Syscall(434, uintptr(target.TGID), 0, 0)
	if errno != 0 {
		return fail()
	}
	r.handle.pidfd = os.NewFile(fd, "mapping-pidfd")
	proc, e := syscall.Open("/proc/"+strconv.FormatUint(uint64(target.TGID), 10), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return fail()
	}
	r.handle.proc = os.NewFile(uintptr(proc), "mapping-proc")
	r.domain, e = localCPUDomain()
	if e != nil {
		return fail()
	}
	r.handle.exe, e = openProcExecutable(proc)
	if e != nil {
		return fail()
	}
	r.executable, e = fileIdentity(r.handle.exe)
	if e != nil {
		return fail()
	}
	r.build, e = executableBuildID(r.handle.exe)
	if e != nil || !approvedBuild(target, r.build) {
		return fail()
	}
	r.process = ProcessKey{BootID: r.domain.BootID, PIDNamespace: target.PIDNamespace, TGID: target.TGID, ProcessStart: target.ProcessStart, Generation: model.Uint64(generation)}
	r.threads, e = snapshotCPUThreads(r.authority, r.domain)
	if e != nil {
		return fail()
	}
	if e = r.guardLocked(); e != nil {
		return fail()
	}
	return r, nil
}
func approvedBuild(t Target, build string) bool {
	for _, id := range t.AllowedBuildIDs {
		if id == build {
			return true
		}
	}
	return false
}
func (r *MappingReader) guardLocked() error {
	if r.closed || r.epoch.check(uint64(r.process.Generation)) != nil {
		return ErrTargetIdentity
	}
	_, _, errno := syscall.Syscall6(424, r.handle.pidfd.Fd(), 0, 0, 0, 0, 0)
	if errno != 0 {
		return ErrTargetIdentity
	}
	task, e := resolveTask(int(r.target.TGID), NamespaceID(r.target.PIDNamespace))
	if e != nil || task.TGID != r.target.TGID || task.ProcessStart != r.target.ProcessStart {
		return ErrTargetIdentity
	}
	executable, e := openProcExecutable(int(r.handle.proc.Fd()))
	if e != nil {
		return ErrTargetIdentity
	}
	defer executable.Close()
	identity, e := fileIdentity(executable)
	if e != nil || identity != r.executable {
		return ErrTargetIdentity
	}
	build, e := executableBuildID(executable)
	if e != nil || build != r.build {
		return ErrTargetIdentity
	}
	cgroup, e := procFile(int(r.handle.proc.Fd()), "cgroup", 65536)
	if e != nil {
		return ErrTargetIdentity
	}
	group, e := cgroupIdentity(cgroup)
	if e != nil || group != uint64(r.target.CgroupID) {
		return ErrTargetIdentity
	}
	threads, e := snapshotCPUThreads(r.authority, r.domain)
	if e != nil || !reflect.DeepEqual(threads, r.threads) {
		return ErrTargetIdentity
	}
	return nil
}
func (r *MappingReader) Guard() error { r.mu.Lock(); defer r.mu.Unlock(); return r.guardLocked() }

// Invalidate must run on COMM_EXEC even for unchanged executable inodes. A
// retired reader never relabels old mappings; restart authorized acquisition.
func (r *MappingReader) Invalidate(nextGeneration uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.epoch.invalidate(nextGeneration)
}
func (r *MappingReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	return r.handle.Close()
}
func (r *MappingReader) Read(ctx context.Context) (MappingTable, error) {
	if e := ctx.Err(); e != nil {
		return MappingTable{}, e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return MappingTable{}, e
	}
	now := time.Now()
	if !r.lastRead.IsZero() && now.Sub(r.lastRead) < r.policy.MinReadInterval {
		return MappingTable{}, ErrResourceBudget
	}
	r.lastRead = now
	if e := r.guardLocked(); e != nil {
		return MappingTable{}, e
	}
	b, e := r.readMaps()
	if e != nil {
		return MappingTable{}, e
	}
	rows, e := parseExecutableMaps(b, r.policy.MaxMapsBytes, r.policy.MaxMappings)
	if e != nil {
		return MappingTable{}, e
	}
	table := MappingTable{process: r.process, policy: r.policy, entries: make([]mappingEntry, 0, len(rows))}
	// root is a fixed kernel proc magic-link. Every subsequent path component is
	// O_NOFOLLOW, regular-file-only, then checked against maps device/inode.
	root, e := syscall.Openat(int(r.handle.proc.Fd()), "root", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if e != nil {
		return MappingTable{}, ErrTargetIdentity
	}
	defer syscall.Close(root)
	for _, row := range rows {
		if e := ctx.Err(); e != nil {
			return MappingTable{}, e
		}
		if uint32(len(table.entries)) >= r.policy.MaxMappings {
			return MappingTable{}, ErrResourceBudget
		}
		entry := mappingEntry{start: row.start, end: row.end, offset: row.offset, reason: row.reason}
		if entry.reason != "" {
			table.entries = append(table.entries, entry)
			continue
		}
		entry.reason = FrameUnapproved
		if !r.policy.AllowMappedELF {
			table.entries = append(table.entries, entry)
			continue
		}
		f, e := openMappedPath(root, row.path)
		if e != nil {
			entry.reason = FrameArtifactUnavailable
			table.entries = append(table.entries, entry)
			continue
		}
		before, e := fileIdentity(f)
		if e != nil || before.device != row.device || before.inode != row.inode || before.size > r.policy.MaxELFBytes {
			f.Close()
			entry.reason = FrameInvalidELF
			table.entries = append(table.entries, entry)
			continue
		}
		parser := boundedELF{ctx: ctx, input: f, max: r.policy.MaxELFBytes}
		layout, e := readELFLayout(&parser)
		after, e2 := fileIdentity(f)
		f.Close()
		if e := ctx.Err(); e != nil {
			return MappingTable{}, e
		}
		if e != nil || e2 != nil || before != after {
			entry.reason = FrameInvalidELF
			table.entries = append(table.entries, entry)
			continue
		}
		if !approvedBuild(r.target, layout.buildID) {
			table.entries = append(table.entries, entry)
			continue
		}
		added := false
		for _, load := range layout.loads {
			low, high := max(row.offset, load.offset), min(row.offset+row.end-row.start, load.offset+load.size)
			if low >= high {
				continue
			}
			if uint32(len(table.entries)) >= r.policy.MaxMappings {
				return MappingTable{}, ErrResourceBudget
			}
			table.entries = append(table.entries, mappingEntry{start: row.start + low - row.offset, end: row.start + high - row.offset, offset: low, module: SafeModule{ID: moduleIdentity(layout.buildID), BuildID: layout.buildID}})
			added = true
		}
		if !added {
			entry.reason = FrameInvalidELF
			table.entries = append(table.entries, entry)
		}
	}
	sort.Slice(table.entries, func(i, j int) bool { return table.entries[i].start < table.entries[j].start })
	for i := 1; i < len(table.entries); i++ {
		if table.entries[i].start < table.entries[i-1].end {
			return MappingTable{}, ErrInvalid
		}
	}
	after, e := r.readMaps()
	if e != nil || !bytes.Equal(b, after) {
		return MappingTable{}, ErrTargetIdentity
	}
	if e := ctx.Err(); e != nil {
		return MappingTable{}, e
	}
	if e = r.guardLocked(); e != nil {
		return MappingTable{}, e
	}
	return table, nil
}
func (r *MappingReader) readMaps() ([]byte, error) {
	fd, e := syscall.Openat(int(r.handle.proc.Fd()), "maps", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrTargetIdentity
	}
	f := os.NewFile(uintptr(fd), "mapping-metadata")
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, int64(r.policy.MaxMapsBytes)+1))
	if e != nil {
		return nil, ErrTargetIdentity
	}
	if uint64(len(b)) > r.policy.MaxMapsBytes {
		return nil, ErrResourceBudget
	}
	return b, nil
}
