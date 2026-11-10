// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"soundpost/internal/durablefs"
)

// errInsecureMode means a directory or key that must be private is reachable by other users.
var errInsecureMode = errors.New("insecure file mode")

// preparePrivate makes sure the data directory exists as a private (0700) directory. A
// directory this process may chmod (a hand-made or volume-provided 0755 one) is tightened to
// 0700; one it cannot make private is refused, and so is an operator-supplied TLS private
// key that group or other users can read (it is shared material this process must not chmod).
// The files the process creates itself (envelope keys, bootstrap.token, generated server.key)
// are already 0600; the directory mode is what keeps them unreachable. POSIX modes say nothing
// about Windows ACLs, so the check does not apply there (docs/operations/bootstrap.md).
func preparePrivate(dir, tlsKey string) error {
	if err := durablefs.MkdirAll(dir); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	dir = filepath.Clean(dir)
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err = os.Chmod(dir, 0o700); err != nil {
			return errInsecureMode
		}
		if info, err = os.Stat(dir); err != nil {
			return err
		}
		if info.Mode().Perm()&0o077 != 0 {
			return errInsecureMode
		}
	}
	if tlsKey != "" {
		keyInfo, err := os.Stat(tlsKey)
		if err != nil {
			return err
		}
		if keyInfo.Mode().Perm()&0o077 != 0 {
			return errInsecureMode
		}
	}
	return nil
}
