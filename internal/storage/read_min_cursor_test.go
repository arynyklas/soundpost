// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// A read that names a cursor (an ingest receipt's min_cursor, a finalization's cursor) waits for the group
// that owns it to apply that command, up to the documented 5 seconds, and fails with a freshness error only
// after that. It does not fail at once with the cut the group answered while the command was still being
// applied: the cursor is not ahead of the group, the group has not caught up with its own Apply yet.
func TestMinCursorOfACommitThatIsStillBeingAppliedWaitsForItsGroup(t *testing.T) {
	for _, tc := range []struct {
		name string
		read func(e *Engine, ctx context.Context, c model.Cursor) error
	}{
		{"read fence", func(e *Engine, ctx context.Context, c model.Cursor) error {
			marks, _, err := e.replicaReadFence(ctx, []model.Cursor{c}, false)
			if err == nil {
				for _, m := range marks {
					if m.Group == c.Group && m.Index < c.Index {
						t.Errorf("the fence answered %v for min_cursor %v", m, c)
					}
				}
			}
			return err
		}},
		{"before cursor", func(e *Engine, ctx context.Context, c model.Cursor) error { return e.replicaBeforeCursor(ctx, c) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, a, c, d := fixture(t)
			write, b := normalized(t, store, a, c, d)
			e, err := openTestEngine(t, t.TempDir(), a, store)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			before, _, err := e.replicaReadFence(context.Background(), nil, false)
			if err != nil || len(before) != 64 {
				t.Fatalf("fence: %d marks, %v", len(before), err)
			}

			published := make(chan struct{})
			release := make(chan struct{})
			armed := true
			e.mu.Lock()
			e.afterApplyPublished = func() {
				if !armed {
					return
				}
				armed = false
				close(published)
				<-release // the group is held between its machine's Apply and its own record of the command
			}
			e.mu.Unlock()
			appended := make(chan error, 1)
			go func() {
				_, err := e.Append(context.Background(), write, b)
				appended <- err
			}()
			select {
			case <-published:
			case <-time.After(10 * time.Second):
				close(release)
				t.Fatal("the commit never reached the slot machine's Apply")
			}

			// The cursor of the command being applied: the slot whose index moved past its group's cut.
			var inFlight model.Cursor
			e.mu.Lock()
			for slot, mark := range before {
				if e.indexes[slot] > uint64(mark.Index) {
					inFlight = model.Cursor{Group: mark.Group, Index: model.Uint64(e.indexes[slot])}
				}
			}
			e.mu.Unlock()
			if inFlight == (model.Cursor{}) {
				close(release)
				t.Fatal("no slot has a command in flight")
			}

			read := make(chan error, 1)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				read <- tc.read(e, ctx, inFlight)
			}()
			select {
			case err := <-read:
				close(release)
				t.Fatalf("a read with min_cursor %v answered %v while its group had not recorded the command as applied: it must wait", inFlight, err)
			case <-time.After(300 * time.Millisecond): // waiting for the group, as it must
			}
			close(release)
			if err := <-read; err != nil {
				t.Fatalf("the read with min_cursor %v failed once its group applied the command: %v", inFlight, err)
			}
			if err = <-appended; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// An ingest acknowledgement followed at once by a read that names its receipt's cursor sees the record, and
// so does the default read: no stale, no false absence.
func TestReadRightAfterAnAcknowledgementSeesTheAcknowledgedRecord(t *testing.T) {
	store, a, c, d := fixture(t)
	write, b := normalized(t, store, a, c, d)
	read := scanScope(t, store, a, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	receipt, err := e.Append(context.Background(), write, b)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.replicaBeforeCursor(context.Background(), receipt.Cursor); err != nil {
		t.Fatalf("the receipt's cursor was refused right after the acknowledgement: %v", err)
	}
	for name, fence := range map[string]ReadFence{"min_cursor": {Min: []model.Cursor{receipt.Cursor}}, "default": {}} {
		rows := collectPages(t, e, read, ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: 100, Fence: fence})
		if len(rows) != 1 {
			t.Fatalf("%s read right after the acknowledgement saw %d rows, want 1", name, len(rows))
		}
	}
}
