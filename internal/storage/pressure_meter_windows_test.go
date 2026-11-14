// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package storage

import (
	"os"
	"testing"
)

// Windows paths reach the meter relative, with trailing separators and
// forward slashes (the engine passes filepath.Join(dir, "data")); the volume
// answer must be the same for all of them.
func TestWindowsMeterAcceptsEveryPathSpelling(t *testing.T) {
	dir := t.TempDir()
	want, err := HostMeter().Usage(dir)
	if err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir + `\`, dir + `\.`, wd, "."} {
		got, err := HostMeter().Usage(p)
		if err != nil {
			t.Fatalf("%q: %v", p, err)
		}
		if got.TotalBytes == 0 || got.UsedBytes > got.TotalBytes {
			t.Fatalf("%q: %+v", p, got)
		}
	}
	if want.TotalBytes == 0 {
		t.Fatal("empty volume")
	}
}
