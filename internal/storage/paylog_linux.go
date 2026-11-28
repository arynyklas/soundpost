//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"os"

	"golang.org/x/sys/unix"
)

var osPageSize = int64(os.Getpagesize())

// dropPayloadRange asks the kernel to forget the clean cached pages that [off, off+n) of a payload file touches (a page that holds the
// end of one record and the start of the next goes with either: the kernel forgets only whole pages of the range it is given, and a
// record of a few hundred bytes, which is most of the log, covers none). The log is written once and read rarely (a window cut, a
// snapshot, an erasure, the verification), so its pages are not what the page cache of a node that takes 2,000 records a second
// should hold: they push out the pages of apply.db that every append touches. Advice only.
func dropPayloadRange(f *os.File, off, n int64) {
	start := off &^ (osPageSize - 1)
	end := (off + n + osPageSize - 1) &^ (osPageSize - 1)
	_ = unix.Fadvise(int(f.Fd()), start, end-start, unix.FADV_DONTNEED)
}

// adviseRandomReads switches off the kernel's readahead for the file. The log is read by record, and the records that lie next to one
// another belong to different groups and to different moments (64 groups append to one log): a read that brings the following 128 KiB
// or more into the page cache with it fills the cache with records that nobody asked for, and the page cache of the scope is what
// keeps apply.db fast (L2w20Admission35). Advice only.
func adviseRandomReads(f *os.File) {
	_ = unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_RANDOM)
}
