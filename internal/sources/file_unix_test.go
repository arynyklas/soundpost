//go:build !windows

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"context"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO or a directory is never opened as a log file: opening a FIFO blocks
// forever, which would hang the whole agent cycle.
func TestRotatedFileRefusesNonRegularSources(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "app.log")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}
	for name, path := range map[string]string{"fifo": fifo, "directory": dir} {
		store, _ := mustStore(t)
		pump := newPump(t, baseFilePolicy(t, path), store, newRecorder())
		done := make(chan error, 1)
		go func() { _, err := pump.Cycle(context.Background()); done <- err }()
		select {
		case err := <-done:
			if se, ok := AsError(err); !ok || se.Status != StatusUnknown || se.Reason != ReasonReadFailed {
				t.Fatalf("%s: got %v, want unknown/read_failed", name, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: the cycle blocked on a non-regular file", name)
		}
	}
}
