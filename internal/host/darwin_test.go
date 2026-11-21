// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package host

import (
	"encoding/binary"
	"testing"
)

// Compiled and vetted for darwin only; it has not been run on a Mac.
func TestDarwinLoadavgDecoding(t *testing.T) {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b[0:], 1024)
	binary.LittleEndian.PutUint32(b[4:], 2560)
	binary.LittleEndian.PutUint32(b[8:], 512)
	binary.LittleEndian.PutUint64(b[16:], 2048)
	got, ok := loadavgFromSysctl(b)
	if !ok || got != [3]float64{0.5, 1.25, 0.25} {
		t.Fatalf("got %v %v", got, ok)
	}
	if _, ok := loadavgFromSysctl(b[:23]); ok {
		t.Fatal("short buffer accepted")
	}
	binary.LittleEndian.PutUint64(b[16:], 0)
	if _, ok := loadavgFromSysctl(b); ok {
		t.Fatal("zero fscale accepted")
	}
}
