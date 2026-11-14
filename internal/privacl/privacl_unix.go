// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package privacl

import "os"

func check(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return ErrNotPrivate
	}
	return nil
}

func restrict(path string) error { return os.Chmod(path, 0o700) }
