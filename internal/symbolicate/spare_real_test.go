//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// A worker that finished its handshake and then waited longer than the 100 ms
// processing bound for its request (what a warm spare does) still answers: the
// bound covers the request, not the idle wait. Real worker, either sandbox mode.
func TestAHandshakenWorkerThatWaitsStillAnswersItsRequest(t *testing.T) {
	c := sandboxConfig(t)
	s := &Service{config: c}
	ctx, cancel := context.WithTimeout(context.Background(), ProcessTimeout)
	defer cancel()
	p, reason := s.startWorker(ctx)
	if reason != "" {
		t.Fatalf("worker did not start: %s", reason)
	}
	defer p.cleanup()
	time.Sleep(5 * FrameTimeout)
	lines := []uint32{1, 5, 7}
	in := batchInput(lineMap(20), lines...)
	go func() { json.NewEncoder(p.input).Encode(in); p.input.Close() }()
	var out []workerOutput
	if err := decodeClosed(p.output, &out, MaxOutputBytes); err != nil {
		t.Fatalf("a worker idle for %s did not answer: %v (exit code %d)", 5*FrameTimeout, err, p.cmd.ProcessState.ExitCode())
	}
	if err := p.cmd.Wait(); err != nil {
		t.Fatalf("worker exit: %v", err)
	}
	for i, l := range lines {
		if out[i].Reason != Resolved || out[i].Position == nil || out[i].Position.Line != l {
			t.Fatalf("position %d: %+v", i, out[i])
		}
	}
}

// The warm spare of a real OCI runtime is handed a request after it has idled
// past the 100 ms bound and answers it (the request's own bound is unchanged).
func TestWarmSpareOfARealRuntimeServesAfterIdling(t *testing.T) {
	c := realOCIConfig(t)
	c.WarmSpare = true
	s, err := New(&unusedReader{}, unusedGenerations{}, c)
	if err != nil {
		t.Fatal(err)
	}
	before := workerContainers(t, c)
	if got := s.run(context.Background(), batchInput(lineMap(20), 1)); len(got) != 1 {
		t.Fatalf("cold request: %+v", got)
	}
	s.spares.started.Wait()
	time.Sleep(5 * FrameTimeout)
	start := time.Now()
	got := s.run(context.Background(), batchInput(lineMap(20), 2, 9))
	t.Logf("request served by a spare that idled %s: %s", 5*FrameTimeout, time.Since(start))
	if len(got) != 2 || got[0].Reason != Resolved || got[1].Reason != Resolved {
		t.Fatalf("spare-served request: %+v", got)
	}
	s.spares.started.Wait()
	time.Sleep(spareMaxAge + time.Second)
	removeRetries.Wait()
	for name := range workerContainers(t, c) {
		if !before[name] {
			t.Errorf("worker container %s left behind", name)
		}
	}
}
