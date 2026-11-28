//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"math"
	"testing"
)

// The plan reads the commands cold: the pages of the log it reads are not left in the page cache of the scope.
func TestExpiringErrorEvidenceLeavesNoPageOfThePayloadLogInTheCache(t *testing.T) {
	holdBackgroundVerification(t)
	noKeep(t)
	x := newEraseEnv(t)
	x.adoptPayload()
	for i := range 40 {
		x.appendError(100)
		x.appendMixed("plan", bothDeadlines)
		_ = i
	}
	// The merger of the query indexes appends to this log and reads its blocks (a merge is due after the appends above, and it ticks
	// every 200 ms): a page it writes or reads after the eviction is resident whatever the plan does. It is not what the test measures.
	x.e.stopIndexMerger()
	if err := x.e.payload.sync(); err != nil {
		t.Fatal(err)
	}
	paths := payloadFilePaths(t, x.dir)
	if len(paths) == 0 {
		t.Fatal("no payload file")
	}
	for _, p := range paths {
		if !evictFile(t, p) {
			t.Skip("this file system keeps the pages of a file whatever is asked")
		}
	}
	nreads := x.e.payload.nreads.Load()
	list, err := x.e.ExpiringErrorEvidence(context.Background(), math.MaxInt64)
	if err != nil || len(list) != 40 {
		t.Fatalf("%d entries (%v)", len(list), err)
	}
	if x.e.payload.nreads.Load() == nreads {
		t.Fatal("the plan read no record of the log: the test measures nothing")
	}
	var resident int64
	for _, p := range paths {
		resident += residentBytes(t, p)
	}
	if resident > 16<<10 {
		t.Fatalf("%d bytes of the payload log are cached after the plan", resident)
	}
}
