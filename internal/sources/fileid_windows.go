// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strconv"

	"golang.org/x/sys/windows"
)

// fileID is an opaque identity token of an open file: a hash of the volume
// serial number and the 64-bit file index. It never carries a path.
func fileID(f *os.File) (string, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		return "", err
	}
	text := strconv.FormatUint(uint64(info.VolumeSerialNumber), 10) + ":" + strconv.FormatUint(uint64(info.FileIndexHigh), 10) + ":" + strconv.FormatUint(uint64(info.FileIndexLow), 10)
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:16]), nil
}
