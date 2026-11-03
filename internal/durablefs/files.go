// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package durablefs

import (
	"io"
	"os"
	"path/filepath"
)

// MkdirAll publishes each newly created directory before any dependent authority.
func MkdirAll(dir string) error {
	dir = filepath.Clean(dir)
	if st, e := os.Stat(dir); e == nil {
		if !st.IsDir() {
			return os.ErrInvalid
		}
		return SyncDir(dir)
	} else if !os.IsNotExist(e) {
		return e
	}
	parent := filepath.Dir(dir)
	if parent == dir {
		return os.ErrInvalid
	}
	if e := MkdirAll(parent); e != nil {
		return e
	}
	if e := os.Mkdir(dir, 0700); e != nil && !os.IsExist(e) {
		return e
	}
	if e := SyncDir(dir); e != nil {
		return e
	}
	return SyncDir(parent)
}
func Exclusive(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	n, e := f.Write(b)
	if e == nil && n != len(b) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = SyncDir(filepath.Dir(path))
	}
	return e
}
func SyncFileAndDir(path string) error {
	f, e := os.OpenFile(path, os.O_RDWR, 0)
	if e != nil {
		return e
	}
	e = f.Sync()
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = SyncDir(filepath.Dir(path))
	}
	return e
}
func Remove(path string) error {
	if e := os.Remove(path); e != nil && !os.IsNotExist(e) {
		return e
	}
	return SyncDir(filepath.Dir(path))
}
func Rename(from, to string) error {
	if e := rename(from, to); e != nil {
		return e
	}
	return SyncDir(filepath.Dir(to))
}
