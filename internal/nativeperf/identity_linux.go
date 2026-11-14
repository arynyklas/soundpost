//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"github.com/arynyklas/soundpost/internal/model"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

type NamespaceID uint64

func parseTaskStart(b []byte, pid uint32) (uint64, error) {
	if len(b) > 4096 {
		return 0, ErrTargetIdentity
	}
	space := bytes.IndexByte(b, ' ')
	end := bytes.LastIndexByte(b, ')')
	if space < 1 || end <= space || space+1 >= len(b) || b[space+1] != '(' {
		return 0, ErrTargetIdentity
	}
	parsed, e := strconv.ParseUint(string(b[:space]), 10, 32)
	if e != nil || parsed != uint64(pid) {
		return 0, ErrTargetIdentity
	}
	fields := bytes.Fields(b[end+1:])
	if len(fields) < 20 {
		return 0, ErrTargetIdentity
	}
	ticks, e := strconv.ParseUint(string(fields[19]), 10, 64)
	if e != nil || ticks == 0 || ticks > ^uint64(0)/10000000 {
		return 0, ErrTargetIdentity
	}
	return ticks, nil
}
func namespaceInode(f *os.File) (uint64, error) {
	var st syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &st) != nil || st.Ino == 0 {
		return 0, ErrTargetIdentity
	}
	return st.Ino, nil
}
func procFile(dir int, name string, limit int64) ([]byte, error) {
	fd, e := syscall.Openat(dir, name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, ErrTargetIdentity
	}
	f := os.NewFile(uintptr(fd), "identity-metadata")
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, ErrTargetIdentity
	}
	return b, nil
}
func procNamespace(dir int) (uint64, error) {
	// ns/pid is a fixed kernel proc magic-link, never a caller-provided symlink.
	fd, e := syscall.Openat(dir, "ns/pid", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if e != nil {
		return 0, ErrTargetIdentity
	}
	f := os.NewFile(uintptr(fd), "pid-namespace")
	defer f.Close()
	return namespaceInode(f)
}
func parseTGID(status []byte) (uint32, error) {
	var result uint64
	for _, line := range bytes.Split(status, []byte{'\n'}) {
		if !bytes.HasPrefix(line, []byte("Tgid:")) {
			continue
		}
		if result != 0 {
			return 0, ErrTargetIdentity
		}
		n, e := strconv.ParseUint(string(bytes.TrimSpace(line[5:])), 10, 32)
		if e != nil || n == 0 {
			return 0, ErrTargetIdentity
		}
		result = n
	}
	if result == 0 {
		return 0, ErrTargetIdentity
	}
	return uint32(result), nil
}
func taskIdentityDigest(namespace, process, thread, start, threadStart, device, inode uint64) uint64 {
	var b [56]byte
	for i, v := range [...]uint64{namespace, process, thread, start, threadStart, device, inode} {
		binary.LittleEndian.PutUint64(b[i*8:], v)
	}
	sum := sha256.Sum256(b[:])
	out := binary.LittleEndian.Uint64(sum[:])
	if out == 0 {
		return 1
	}
	return out
}

// resolveTask is a bounded local identity snapshot, not authorization. Its
// generation fingerprint distinguishes task starts; acquisition's explicit
// process epoch remains authoritative for joining events/mappings. Same-file
// exec MUST also be rejected through PERF_RECORD_COMM_EXEC by the live source.
func resolveTask(pid int, namespace NamespaceID) (TaskKey, error) {
	if pid <= 0 || uint64(pid) > uint64(^uint32(0)) || namespace == 0 {
		return TaskKey{}, ErrTargetIdentity
	}
	fd, e := syscall.Open("/proc/"+strconv.Itoa(pid), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return TaskKey{}, ErrTargetIdentity
	}
	defer syscall.Close(fd)
	first, e := procFile(fd, "stat", 4096)
	if e != nil {
		return TaskKey{}, e
	}
	threadStart, e := parseTaskStart(first, uint32(pid))
	if e != nil {
		return TaskKey{}, e
	}
	ns, e := procNamespace(fd)
	if e != nil || ns != uint64(namespace) {
		return TaskKey{}, ErrTargetIdentity
	}
	status, e := procFile(fd, "status", 65536)
	if e != nil {
		return TaskKey{}, e
	}
	tgid, e := parseTGID(status)
	if e != nil {
		return TaskKey{}, e
	}
	processFD, e := syscall.Open("/proc/"+strconv.FormatUint(uint64(tgid), 10), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return TaskKey{}, ErrTargetIdentity
	}
	defer syscall.Close(processFD)
	processStat, e := procFile(processFD, "stat", 4096)
	if e != nil {
		return TaskKey{}, e
	}
	start, e := parseTaskStart(processStat, tgid)
	if e != nil {
		return TaskKey{}, e
	}
	processNS, e := procNamespace(processFD)
	if e != nil || processNS != ns {
		return TaskKey{}, ErrTargetIdentity
	}
	exe, e := openProcExecutable(processFD)
	if e != nil {
		return TaskKey{}, e
	}
	defer exe.Close()
	before, e := fileIdentity(exe)
	if e != nil {
		return TaskKey{}, e
	}
	domain, e := localCPUDomain()
	if e != nil {
		return TaskKey{}, e
	}
	last, e := procFile(fd, "stat", 4096)
	if e != nil {
		return TaskKey{}, e
	}
	lastStart, e := parseTaskStart(last, uint32(pid))
	if e != nil || threadStart != lastStart {
		return TaskKey{}, ErrTargetIdentity
	}
	lastNS, e := procNamespace(fd)
	if e != nil || ns != lastNS {
		return TaskKey{}, ErrTargetIdentity
	}
	again, e := openProcExecutable(processFD)
	if e != nil {
		return TaskKey{}, e
	}
	defer again.Close()
	after, e := fileIdentity(again)
	if e != nil || before != after {
		return TaskKey{}, ErrTargetIdentity
	}
	lastProcess, e := procFile(processFD, "stat", 4096)
	if e != nil {
		return TaskKey{}, e
	}
	lastProcessStart, e := parseTaskStart(lastProcess, tgid)
	if e != nil || start != lastProcessStart {
		return TaskKey{}, ErrTargetIdentity
	}
	return TaskKey{BootID: domain.BootID, PIDNamespace: model.Uint64(ns), TGID: tgid, TID: uint32(pid), ProcessStart: model.MonoNano(start * 10000000), Generation: model.Uint64(taskIdentityDigest(ns, uint64(tgid), uint64(pid), start, threadStart, before.device, before.inode))}, nil
}

// ResolveTask exposes the checked snapshot for fixture/integration use. This
// does not create an AuthorizedTargets value or grant access to mapped files.
func ResolveTask(pid int, namespace NamespaceID) (TaskKey, error) { return resolveTask(pid, namespace) }

type executableIdentity struct {
	device, inode, size                  uint64
	mtimeSec, mtimeNS, ctimeSec, ctimeNS int64
}

func fileIdentity(f *os.File) (executableIdentity, error) {
	var st syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Size < 0 {
		return executableIdentity{}, ErrTargetIdentity
	}
	return executableIdentity{uint64(st.Dev), st.Ino, uint64(st.Size), st.Mtim.Sec, st.Mtim.Nsec, st.Ctim.Sec, st.Ctim.Nsec}, nil
}
func openProcExecutable(proc int) (*os.File, error) {
	// Readlink is used only to reject a deleted executable; its raw result is
	// transient, never returned, logged, hashed into module names or persisted.
	path := "/proc/self/fd/" + strconv.Itoa(proc) + "/exe"
	link, e := os.Readlink(path)
	if e != nil || len(link) > 4096 || strings.HasSuffix(link, " (deleted)") {
		return nil, ErrTargetIdentity
	}
	fd, e := syscall.Openat(proc, "exe", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrTargetIdentity
	}
	return os.NewFile(uintptr(fd), "checked-executable"), nil
}

type identityEpoch struct {
	generation uint64
	invalid    bool
}

func (g *identityEpoch) invalidate(next uint64) error {
	if next <= g.generation {
		return ErrTargetIdentity
	}
	g.generation = next
	g.invalid = true
	return nil
}
func (g identityEpoch) check(expected uint64) error {
	if g.invalid || expected == 0 || expected != g.generation {
		return ErrTargetIdentity
	}
	return nil
}
