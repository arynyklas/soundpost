//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"os"
	"syscall"
)

// Filesystem magic numbers (linux/magic.h, statfs f_type) of the local filesystems whose
// modification and status-change times are set by the kernel alone, on every write, truncate,
// rename and attribute change, so that a rewrite that restores the old mtime still moves the
// ctime. A filesystem not listed here (a FUSE mount, a network or 9p share, anything unknown)
// answers timestamps from a server or a daemon that may set them to any value, mtime and ctime
// included: a rewrite there can leave the whole identity unchanged, so the hash is read every
// time instead of reused.
const (
	magicExt4      = 0xEF53
	magicXFS       = 0x58465342
	magicBtrfs     = 0x9123683E
	magicTmpfs     = 0x01021994
	magicRamfs     = 0x858458F6
	magicOverlayfs = 0x794C7630
	magicF2fs      = 0xF2F52010
	magicSquashfs  = 0x73717368
	magicErofs     = 0xE0F5E1E2
	magicZfs       = 0x2FC12FC1
	magicBcachefs  = 0xCA451A4E
)

// kernelTimestamps reports whether the filesystem type keeps ctime out of user space's reach.
func kernelTimestamps(fsType uint32) bool {
	switch fsType {
	case magicExt4, magicXFS, magicBtrfs, magicTmpfs, magicRamfs, magicOverlayfs, magicF2fs, magicSquashfs, magicErofs, magicZfs, magicBcachefs:
		return true
	}
	return false
}

// onKernelTimestamps asks the filesystem of the open file.
func onKernelTimestamps(f *os.File) bool {
	rc, e := f.SyscallConn()
	if e != nil {
		return false
	}
	var sfs syscall.Statfs_t
	var serr error
	if e = rc.Control(func(fd uintptr) { serr = syscall.Fstatfs(int(fd), &sfs) }); e != nil || serr != nil {
		return false
	}
	// f_type is a signed or unsigned word of varying width; the magic numbers fit 32 bits.
	return kernelTimestamps(uint32(sfs.Type))
}

// identityOf reads the identity of the open file; ok is false for anything that is not a
// regular file on a filesystem with kernel-maintained timestamps, which is then never cached.
func identityOf(f *os.File) (fileIdentity, bool) {
	fi, e := f.Stat()
	if e != nil || !fi.Mode().IsRegular() {
		return fileIdentity{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !onKernelTimestamps(f) {
		return fileIdentity{}, false
	}
	return fileIdentity{dev: uint64(st.Dev), ino: uint64(st.Ino), size: st.Size, mtime: st.Mtim.Nano(), ctime: st.Ctim.Nano()}, true
}
