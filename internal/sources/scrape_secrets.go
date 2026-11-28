// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// Secret reference syntax is closed: a reference is a plain file name of the
// private secrets directory. It can not name a path, a hidden file or a parent.
const scrapeSecretMaxBytes = 4096

// Secret failure reasons. They are static codes: never a path, a reference or
// an operating-system error.
const (
	SecretBadReference = "bad_reference"
	SecretNotFound     = "not_found"
	SecretNotRegular   = "not_regular"
	SecretSymlink      = "symlink"
	SecretInsecureMode = "insecure_mode"
	SecretTooLarge     = "too_large"
	SecretUnreadable   = "unreadable"
	SecretEmpty        = "empty"
	SecretDirInvalid   = "dir_invalid"
	SecretDirInsecure  = "dir_insecure"
)

// SecretError is the only error a DirSecretReader returns. Its text carries
// the static reason and nothing the operator or the secret supplied.
type SecretError struct{ Reason string }

func (e *SecretError) Error() string { return "sources: secret unavailable (" + e.Reason + ")" }

func secretFail(reason string) error { return &SecretError{Reason: reason} }

// ErrSecretUnavailable matches every SecretError through errors.Is.
var ErrSecretUnavailable = errors.New("sources: secret unavailable")

func (e *SecretError) Is(target error) bool { return target == ErrSecretUnavailable }

// DirSecretReader reads secrets by reference from a private directory: one
// regular file per secret, named by its reference, readable by its owner only.
// Every read opens the file again; nothing is cached, logged or retained, and
// the returned bytes belong to the caller, which zeroes them (FetchScrape does).
type DirSecretReader struct {
	dir string
}

// ValidSecretRef reports whether ref is a well-formed reference.
func ValidSecretRef(ref SecretRef) bool {
	return scrapeAliasRE.MatchString(string(ref)) && !containsDotDot(string(ref))
}

func containsDotDot(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '.' && s[i+1] == '.' {
			return true
		}
	}
	return false
}

// NewDirSecretReader checks the directory once at construction: it must be a
// real directory (not a symbolic link) that no other user can enter or list.
// POSIX modes say nothing about Windows ACLs, so the mode check does not apply
// there (the same limit as the data directory check).
func NewDirSecretReader(dir string) (*DirSecretReader, error) {
	if dir == "" {
		return nil, secretFail(SecretDirInvalid)
	}
	dir = filepath.Clean(dir)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return nil, secretFail(SecretDirInvalid)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, secretFail(SecretDirInsecure)
	}
	return &DirSecretReader{dir: dir}, nil
}

// ReadSecret implements SecretReader. A single trailing line feed (or CR LF)
// that an editor or `echo` leaves behind is not part of the secret.
func (r *DirSecretReader) ReadSecret(ctx context.Context, ref SecretRef) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !ValidSecretRef(ref) {
		return nil, secretFail(SecretBadReference)
	}
	name := filepath.Join(r.dir, string(ref))
	before, err := os.Lstat(name)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, secretFail(SecretNotFound)
	case err != nil:
		return nil, secretFail(SecretUnreadable)
	case before.Mode()&os.ModeSymlink != 0:
		return nil, secretFail(SecretSymlink)
	case !before.Mode().IsRegular():
		return nil, secretFail(SecretNotRegular)
	case runtime.GOOS != "windows" && before.Mode().Perm()&0o077 != 0:
		return nil, secretFail(SecretInsecureMode)
	case before.Size() > scrapeSecretMaxBytes:
		return nil, secretFail(SecretTooLarge)
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, secretFail(SecretUnreadable)
	}
	defer f.Close()
	// The open file must be the file that was checked (a swap between the check
	// and the open is a refusal, not a read).
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, secretFail(SecretUnreadable)
	}
	buf, err := io.ReadAll(io.LimitReader(f, scrapeSecretMaxBytes+1))
	if err != nil {
		scrapeZero(buf)
		return nil, secretFail(SecretUnreadable)
	}
	if len(buf) > scrapeSecretMaxBytes {
		scrapeZero(buf)
		return nil, secretFail(SecretTooLarge)
	}
	switch n := len(buf); {
	case n >= 2 && buf[n-2] == '\r' && buf[n-1] == '\n':
		buf[n-2], buf[n-1] = 0, 0
		buf = buf[:n-2]
	case n >= 1 && buf[n-1] == '\n':
		buf[n-1] = 0
		buf = buf[:n-1]
	}
	if len(buf) == 0 {
		return nil, secretFail(SecretEmpty)
	}
	return buf, nil
}
