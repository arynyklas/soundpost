// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package value

import (
	"testing"
	"unsafe"
)

// Review 02.03-07 M4: the engines retain samples in slices that grow by append,
// and the account charges SampleBytes per retained sample, not the capacity the
// runtime allocates. The charge stays honest only while the fixed part of
// SampleBytes covers the struct plus the steady-state append slack (Go grows
// large slices by at most 1.25x, so half a struct of slack per sample is the
// accepted margin). A larger Sample or a smaller fixed charge must revisit the
// accounting, so this pins the relation.
func TestSampleBytesCoversTheStructAndItsAppendSlack(t *testing.T) {
	slot := int64(unsafe.Sizeof(Sample{}))
	if charged := SampleBytes(Sample{}); charged < slot+slot/2 {
		t.Fatalf("SampleBytes charges %d bytes for a %d-byte slot: the fixed charge no longer covers the append slack", charged, slot)
	}
}
