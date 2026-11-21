//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package nativeperf

import (
	"errors"
	"os/exec"
	"testing"
	"time"
)

// A task-scoped perf event reports POLLHUP once its task has exited, which is before the TID can be handed to another
// process: asking the event is the whole identity question of one published scheduler record, with no /proc read.
// (The task is a child process's main thread: a Go runtime thread's exit is not under the test's control.)
func TestRingReportsTheExitOfItsTask(t *testing.T) {
	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Skipf("no child process: %v", err)
	}
	reaped := false
	defer func() {
		if !reaped {
			child.Process.Kill()
			child.Wait()
		}
	}()
	ring, err := openThreadCPU(TaskKey{TID: uint32(child.Process.Pid)}, DefaultConfig(1), MethodSoftwareCPUClock)
	if err != nil {
		var capability *CapabilityError
		if errors.As(err, &capability) {
			t.Skipf("no perf event for a child process here: %v", err)
		}
		t.Fatal(err)
	}
	defer ring.Close()
	if e := enableCPU(ring); e != nil { // the product enables every thread event before it publishes anything
		t.Fatal(e)
	}
	if gone, e := ring.exited(); e != nil || gone {
		t.Fatalf("a live task reported exited=%v err=%v", gone, e)
	}
	child.Process.Kill()
	child.Wait() // reaped: the TID is free to be reused from here on
	reaped = true
	deadline := time.Now().Add(5 * time.Second)
	for {
		gone, e := ring.exited()
		if e != nil {
			t.Fatal(e)
		}
		if gone {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the exit of the task was not reported by its perf event")
		}
		time.Sleep(time.Millisecond)
	}
	ring.Close()
	if _, e := ring.exited(); !errors.Is(e, ErrAcquisitionClosed) {
		t.Fatalf("a closed ring answered: %v", e)
	}
}
