// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"time"
)

// TestLoadWaitsForTheKill9RestartToAnswer: the read-back that follows a kill -9 run met a node still in its start-up gate (every route
// answers the retryable 503) because the run ended while the restart was in progress; the run ends only when the restart answered.
func TestLoadWaitsForTheKill9RestartToAnswer(t *testing.T) {
	done := make(chan struct{})
	go func() { time.Sleep(150 * time.Millisecond); close(done) }()
	began := time.Now()
	if err := awaitKill9Restart(done, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if time.Since(began) < 140*time.Millisecond {
		t.Fatalf("returned after %s, before the restart answered", time.Since(began))
	}
	if err := awaitKill9Restart(make(chan struct{}), 50*time.Millisecond); err == nil {
		t.Fatal("a restart that never answers must fail the run")
	}
}
