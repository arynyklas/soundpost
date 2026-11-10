//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// TargetHandle pins process lifetime with pidfd and holds checked metadata FDs.
// No /proc memory, stack, arguments, environment or target-selected files are read.
type TargetHandle struct {
	pidfd, proc, exe *os.File
	Target           Target
}

func (h *TargetHandle) Close() error {
	if h.exe != nil {
		h.exe.Close()
	}
	if h.proc != nil {
		h.proc.Close()
	}
	if h.pidfd != nil {
		return h.pidfd.Close()
	}
	return nil
}
func openCheckedTarget(t Target) (*TargetHandle, error) {
	h := &TargetHandle{Target: t}
	fail := func() (*TargetHandle, error) { h.Close(); return nil, ErrTargetIdentity }
	// pidfd_open is syscall 434 on supported Linux amd64 and arm64.
	fd, _, errno := syscall.Syscall(434, uintptr(t.TGID), 0, 0)
	if errno != 0 {
		return fail()
	}
	h.pidfd = os.NewFile(fd, "pidfd")
	p, e := syscall.Open("/proc/"+strconv.FormatUint(uint64(t.TGID), 10), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return fail()
	}
	h.proc = os.NewFile(uintptr(p), "proc")
	before, e := ResolveLocalTarget(int(t.TGID))
	var denied *CapabilityError
	if errors.As(e, &denied) && denied.Status == Denied {
		h.Close()
		return nil, e
	}
	if e != nil || before.PIDNamespace != t.PIDNamespace || before.ProcessStart != t.ProcessStart {
		return fail()
	}
	// exe is the kernel-owned proc magic link, not a request-supplied path.
	x, e := syscall.Openat(p, "exe", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if e != nil {
		if d := permissionDenied(e); d != nil {
			h.Close()
			return nil, d
		}
		return fail()
	}
	h.exe = os.NewFile(uintptr(x), "executable")
	if len(t.AllowedBuildIDs) == 0 {
		return fail()
	}
	id, e := executableBuildID(h.exe)
	if e != nil {
		return fail()
	}
	found := false
	for _, allowed := range t.AllowedBuildIDs {
		if string(allowed) == id {
			found = true
		}
	}
	if !found {
		return fail()
	}
	c, e := readProcMetadata(p, "cgroup")
	if e != nil {
		return fail()
	}
	cg, e := cgroupIdentity(c)
	if e != nil || cg != uint64(t.CgroupID) {
		return fail()
	}
	again, e := syscall.Openat(p, "exe", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if e != nil {
		return fail()
	}
	var firstStat, lastStat syscall.Stat_t
	firstErr := syscall.Fstat(x, &firstStat)
	lastErr := syscall.Fstat(again, &lastStat)
	syscall.Close(again)
	if firstErr != nil || lastErr != nil || firstStat.Dev != lastStat.Dev || firstStat.Ino != lastStat.Ino {
		return fail()
	}
	c2, e := readProcMetadata(p, "cgroup")
	if e != nil || !bytes.Equal(c, c2) {
		return fail()
	}
	after, e := ResolveLocalTarget(int(t.TGID))
	if e != nil || before.PIDNamespace != after.PIDNamespace || before.ProcessStart != after.ProcessStart || before.TGID != after.TGID {
		return fail()
	}
	// signal 0 through pidfd rejects an exited/reused process without signalling it.
	_, _, errno = syscall.Syscall6(424, fd, 0, 0, 0, 0, 0)
	if errno != 0 {
		return fail()
	}
	return h, nil
}
func readProcMetadata(dir int, name string) ([]byte, error) {
	fd, e := syscall.Openat(dir, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	if len(b) > 65536 {
		return nil, ErrInvalid
	}
	return b, e
}
func cgroupIdentity(b []byte) (uint64, error) {
	path := ""
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "0::/") {
			path = strings.TrimPrefix(line, "0::")
			break
		}
	}
	if path == "" {
		return 0, ErrAuthorization
	}
	fd, e := syscall.Open("/sys/fs/cgroup", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return 0, e
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		if part == "." || part == ".." {
			syscall.Close(fd)
			return 0, ErrAuthorization
		}
		next, e := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if e != nil {
			return 0, e
		}
		fd = next
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if e := syscall.Fstat(fd, &st); e != nil {
		return 0, e
	}
	return st.Ino, nil
}
func executableBuildID(f *os.File) (string, error) {
	var header [64]byte
	if _, e := f.ReadAt(header[:], 0); e != nil {
		return "", e
	}
	if !bytes.Equal(header[:4], []byte{0x7f, 'E', 'L', 'F'}) || header[4] != 2 || header[5] != 1 {
		return "", ErrAuthorization
	}
	order := binary.LittleEndian
	offset, count, size := order.Uint64(header[32:]), order.Uint16(header[56:]), order.Uint16(header[54:])
	if count == 0 || count > 128 || size != 56 || offset > 1<<30 {
		return "", ErrAuthorization
	}
	var ph [56]byte
	var scratch [65536]byte
	for i := uint16(0); i < count; i++ {
		if _, e := f.ReadAt(ph[:], int64(offset)+int64(i)*56); e != nil {
			return "", e
		}
		if order.Uint32(ph[:]) != 4 {
			continue
		}
		start, length := order.Uint64(ph[8:]), order.Uint64(ph[32:])
		if length > 65536 || start > 1<<40 {
			return "", ErrAuthorization
		}
		b := scratch[:int(length)]
		if _, e := f.ReadAt(b, int64(start)); e != nil {
			return "", e
		}
		for len(b) >= 12 {
			n, d, typ := order.Uint32(b), order.Uint32(b[4:]), order.Uint32(b[8:])
			b = b[12:]
			nn, dd := (uint64(n)+3)&^3, (uint64(d)+3)&^3
			if nn+dd > uint64(len(b)) {
				return "", ErrInvalid
			}
			if typ == 3 && bytes.Equal(bytes.TrimRight(b[:n], "\x00"), []byte("GNU")) && d > 0 && d <= 64 {
				return hex.EncodeToString(b[nn : nn+uint64(d)]), nil
			}
			b = b[nn+dd:]
		}
	}
	return "", ErrAuthorization
}

// Revalidate is the acquisition boundary check for exec/exit/cgroup changes.
// Acquisition must additionally bind every emitted event to its generation.
func (a AuthorizedTargets) Revalidate() error {
	for _, t := range a.targets {
		h, e := openCheckedTarget(t)
		if e != nil {
			return e
		}
		h.Close()
	}
	return nil
}
