// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/arynyklas/soundpost/internal/durablefs"
)

// payloadFile is what the payload log uses of an open file. *os.File is one.
type payloadFile interface {
	ReadAt(p []byte, off int64) (int, error)
	WriteAt(p []byte, off int64) (int, error)
	Sync() error
	Close() error
	Stat() (os.FileInfo, error)
}

// payloadFS is every operation the payload log makes on its directory: the seam through which a test loses what a power cut loses
// (a write that no Sync followed, a created file whose directory was never synced). The product runs on osPayloadFS.
//
// The durability contract the log relies on, and the test fs enforces: bytes written to a file are durable once Sync of that file
// returned; a file that was created is there after a crash once SyncDir of its directory returned (MkdirAll publishes the directory it
// creates the same way); nothing else is promised.
type payloadFS interface {
	// OpenFile opens name with the flags of os.OpenFile (a missing file is os.ErrNotExist, an existing one with O_EXCL os.ErrExist).
	OpenFile(name string, flag int, perm os.FileMode) (payloadFile, error)
	// Files lists the names of the files (not directories) of dir, ascending; a missing dir is os.ErrNotExist.
	Files(dir string) ([]string, error)
	// Size is the size of the file name.
	Size(name string) (int64, error)
	// MkdirAll creates dir and its parents and makes their entries durable.
	MkdirAll(dir string) error
	// SyncDir makes the entries of dir durable.
	SyncDir(dir string) error
}

type osPayloadFS struct{}

func (osPayloadFS) OpenFile(name string, flag int, perm os.FileMode) (payloadFile, error) {
	f, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (osPayloadFS) Files(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, en := range entries {
		if !en.IsDir() {
			out = append(out, en.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

func (osPayloadFS) Size(name string) (int64, error) {
	fi, err := os.Stat(name)
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

func (osPayloadFS) MkdirAll(dir string) error { return durablefs.MkdirAll(dir) }
func (osPayloadFS) SyncDir(dir string) error  { return durablefs.SyncDir(dir) }

// payloadFSOf is the file system a log of dir runs on: the real one, unless a test installed another (payloadFSHook).
func payloadFSOf(dir string) payloadFS {
	if hook := payloadFSHook; hook != nil {
		if fs := hook(dir); fs != nil {
			return fs
		}
	}
	return osPayloadFS{}
}

// payloadFSHook is set by the crash tests only, before an engine opens, and never while an engine of another test runs.
var payloadFSHook func(dir string) payloadFS

// payloadPath is the path of file seq of the log of dir.
func payloadPath(dir string, seq uint32) string { return filepath.Join(dir, payloadFileName(seq)) }

// adviseRandom and dropRange are the kernel advice of the helpers of paylog_linux.go, for a file that is a real one.
func adviseRandom(f payloadFile) {
	if of, ok := f.(*os.File); ok {
		adviseRandomReads(of)
	}
}

func dropRange(f payloadFile, off, n int64) {
	if of, ok := f.(*os.File); ok {
		dropPayloadRange(of, off, n)
	}
}
