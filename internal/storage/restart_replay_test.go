// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"fmt"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// A restart replays the journal of each data group since its last cut: every committed entry reaches the
// machine again, and the machine's answer for an entry its store already holds is "nothing to write". It
// used to decode the command twice and encode it once to prove the store held that very command: 47 s of CPU
// of the 79 s restart after four minutes of the single-host load (L2w20Admission8/r6). A batch held byte
// for byte is proven by the bytes: the restart decodes none of the batches it replays.
func TestRestartDoesNotDecodeTheBatchesItReplays(t *testing.T) {
	store, service, cred, desc := fixture(t)
	dir := t.TempDir()
	const appended = 150
	e, err := openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	var all []preparedAppend
	for i := 0; i < appended; i++ {
		p := preparedAppend{}
		p.scope, p.batch = settleBatch(t, store, service, cred, desc, model.NewID(), 1, fmt.Sprintf("series_%d", i))
		if _, err = e.Append(context.Background(), p.scope, p.batch); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		all = append(all, p)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	before := walDecodes.Load()
	e, err = openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	decoded := walDecodes.Load() - before
	t.Logf("a restart over %d journaled batches decoded %d commands", appended, decoded)
	if decoded > appended/10 {
		t.Fatalf("a restart over %d journaled batches decoded %d commands: the replay proves each stored command by decoding it", appended, decoded)
	}
	for i, p := range all { // the replay left the store as it was: a retry answers with the stored receipt
		if _, err = e.Append(context.Background(), p.scope, p.batch); err != nil {
			t.Fatalf("retry %d after the restart: %v", i, err)
		}
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
}
