// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync/atomic"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// startupReason names, in a closed vocabulary, why `serve` could not start or stopped serving: the
// code of a typed fault (invalid, corrupt, unavailable, stale, conflict, ...), the replication
// layer's typed errors, or io_error for a file system call that failed. It is "" for any other
// error, which keeps the generic line: those can carry operator-supplied paths. The text of an
// error is never part of it.
func startupReason(err error) string {
	var fault *model.Fault
	var pathErr *fs.PathError
	switch {
	case errors.Is(err, replica.ErrJournalBehind):
		return replica.ReasonJournalBehind
	case errors.As(err, &fault):
		return string(fault.Code)
	case errors.Is(err, replica.ErrStale):
		return string(model.Stale)
	case errors.Is(err, replica.ErrUnavailable):
		return string(model.Unavailable)
	case errors.Is(err, replica.ErrConflict):
		return string(model.Conflict)
	case errors.Is(err, replica.ErrInvalid):
		return string(model.Invalid)
	case errors.As(err, &pathErr):
		return "io_error"
	}
	return ""
}

// storageFailStopError ends `serve` when the storage of the node failed (a Ready journal write or
// fsync, an apply, an engine commit). The replication layer has already failed every group of the
// node closed, so it neither leads nor votes and the other voters elect among themselves; the
// process exits non-zero so its supervisor (systemd Restart=on-failure, a container restart
// policy) restarts it, and the restart verifies the journal before the node serves again. Only a
// closed reason and a group identifier are ever printed: the underlying error can carry paths.
type storageFailStopError struct{ failure replica.FailStop }

func (e *storageFailStopError) Error() string {
	return "soundpost: storage failure, node stopped: " + string(e.failure.Reason)
}

// storageFailStopLine is the one line logged at the moment of a fail-stop.
func storageFailStopLine(f replica.FailStop) string {
	return fmt.Sprintf("soundpost: storage failure (reason=%s group=%s): every replication group of this node is failed closed and the process exits for a supervised restart; the restart verifies the journal before this node serves", f.Reason, f.Group)
}

// watchStorage cancels `serve` once the node's storage failed (done closed), logs the closed reason
// and remembers it for the exit error.
func watchStorage(ctx context.Context, core *appcore.App, cancel context.CancelFunc) *atomic.Pointer[replica.FailStop] {
	return watchFailStop(ctx, core.StorageFailStop(), core.StorageFailure, cancel)
}

func watchFailStop(ctx context.Context, done <-chan struct{}, failure func() (replica.FailStop, bool), cancel context.CancelFunc) *atomic.Pointer[replica.FailStop] {
	var failed atomic.Pointer[replica.FailStop]
	go func() {
		select {
		case <-done:
			f, _ := failure()
			failed.Store(&f)
			fmt.Fprintln(os.Stderr, storageFailStopLine(f))
			cancel()
		case <-ctx.Done():
		}
	}()
	return &failed
}
