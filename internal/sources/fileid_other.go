//go:build !windows

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"syscall"
)

// fileID is an opaque identity token of an open file: a hash of device and
// inode. It never carries (or reveals) a path.
func fileID(f *os.File) (string, error) {
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("no file identity")
	}
	sum := sha256.Sum256([]byte(strconv.FormatUint(uint64(sys.Dev), 10) + ":" + strconv.FormatUint(uint64(sys.Ino), 10)))
	return hex.EncodeToString(sum[:16]), nil
}
