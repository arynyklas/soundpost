// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// A node that refuses to start says why in a closed vocabulary, and never with the text of the
// error: that text can carry the data directory, the key path or a credential.
func TestStartupFailureCarriesAClosedReasonNeverText(t *testing.T) {
	serve := []string{"soundpost", "serve"}
	for name, c := range map[string]struct {
		err  error
		want string
	}{
		"typed fault":          {model.Fail(model.Stale), "soundpost: startup or service failed (reason=stale)"},
		"wrapped typed fault":  {fmt.Errorf("open /secret/dir: %w", model.Fail(model.Corrupt)), "soundpost: startup or service failed (reason=corrupt)"},
		"replication error":    {fmt.Errorf("group /secret/dir: %w", replica.ErrUnavailable), "soundpost: startup or service failed (reason=unavailable)"},
		"file system failure":  {&fs.PathError{Op: "sync", Path: "/secret/dir/ready.wal", Err: syscall.EIO}, "soundpost: startup or service failed (reason=io_error)"},
		"untyped error":        {errors.New("flag provided but not defined: -/secret"), "soundpost: startup or service failed"},
		"insecure data folder": {errInsecureMode, "soundpost: the data directory or TLS private key is accessible to other users; it must be mode 0700 and the key 0600"},
	} {
		got := failureLine(serve, c.err)
		if got != c.want {
			t.Errorf("%s: printed %q, want %q", name, got, c.want)
		}
		if strings.Contains(got, "secret") {
			t.Errorf("%s: the line carries error text: %q", name, got)
		}
	}
	if got := failureLine([]string{"soundpost", "ready"}, model.Fail(model.Stale)); got != "soundpost: not ready" {
		t.Errorf("ready printed %q", got)
	}
}

// A node whose storage failed must say so with a closed reason and nothing else: the generic
// startup line would hide the cause, and the underlying error can carry paths.
func TestStorageFailStopIsReportedWithAClosedReason(t *testing.T) {
	group := model.NewID()
	err := &storageFailStopError{failure: replica.FailStop{Group: group, Reason: replica.FailJournal}}
	line := failureLine([]string{"soundpost", "serve"}, err)
	if line != "soundpost: storage failure, node stopped: journal_write_failed" {
		t.Fatalf("serve failure printed %q", line)
	}
	logged := storageFailStopLine(err.failure)
	for _, want := range []string{"reason=journal_write_failed", "group=" + group.String(), "failed closed"} {
		if !strings.Contains(logged, want) {
			t.Fatalf("fail-stop log line %q lacks %q", logged, want)
		}
	}
	if strings.Contains(logged, "/") {
		t.Fatalf("fail-stop log line carries a path: %q", logged)
	}
}

// The watcher stops `serve` as soon as the node's domain reports a failure, and remembers why.
func TestWatchFailStopCancelsServeAndRemembersTheReason(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	want := replica.FailStop{Group: model.NewID(), Reason: replica.FailApply}
	failed := watchFailStop(ctx, done, func() (replica.FailStop, bool) { return want, true }, stop)
	if failed.Load() != nil {
		t.Fatal("a healthy node reported a failure")
	}
	close(done)
	select {
	case <-served.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("serve was not stopped by the fail-stop")
	}
	deadline := time.Now().Add(2 * time.Second)
	for failed.Load() == nil {
		if time.Now().After(deadline) {
			t.Fatal("the failure reason was not remembered")
		}
		time.Sleep(time.Millisecond)
	}
	if got := *failed.Load(); got != want {
		t.Fatalf("remembered %+v, want %+v", got, want)
	}
}
