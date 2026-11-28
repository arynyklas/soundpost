// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// A restart replays the journal of each of the 64 data groups since its last cut. Without a cadence the
// groups cut only on the worker's hourly schedule, so the journal (1.3 GB after 35 minutes of the
// single-host load) grows with the time since the last cut and so does the restart (99-139 s,
// L2w20Admission7). Every group must cut and compact by itself once its bound is reached, and the
// bound a production engine carries must keep the replay small.
func TestDataGroupsCutAndCompactOnTheirOwnCadence(t *testing.T) {
	if c := DefaultSlotCadence; !c.Enabled() || c.Bytes <= 0 || c.Bytes > 16<<20 || c.Commands == 0 || c.Commands > 4096 {
		t.Fatalf("the default cadence of a data group is %+v: want a bound of at most 4096 commands (one window) and 16 MiB", c)
	}
	old := DefaultSlotCadence
	DefaultSlotCadence = replica.Cadence{Commands: 6}
	t.Cleanup(func() { DefaultSlotCadence = old })
	store, service, cred, desc := fixture(t)
	e, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.BindAdmissionOwner(e); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 400; i++ {
		scope, batch := settleBatch(t, store, service, cred, desc, model.NewID(), 1, fmt.Sprintf("series_%d", i))
		if _, err = e.Append(context.Background(), scope, batch); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	cuts := func() (n uint64) {
		for _, g := range e.repl.groups {
			n += g.CadenceCuts()
		}
		return n
	}
	deadline := time.Now().Add(30 * time.Second)
	for cuts() == 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if cuts() == 0 {
		t.Fatal("after 400 appends no data group cut a snapshot on its cadence")
	}
}
