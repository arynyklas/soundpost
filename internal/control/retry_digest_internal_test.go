// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"fmt"
	"testing"
)

// Task 10.13. Every control command carries the whole control state, so a retry table that keeps
// each applied command's payload retains O(commands x state) bytes for the life of the group, and
// every snapshot envelope serializes all of it (measured: the retry table, the log index and the
// in-memory snapshot were 3.3x the sum of all payloads ever committed, and the redaction pass's
// snapshot cut and journal compaction released none of it). The control machine asks the group
// to keep a digest and the receipt instead (replica.DigestRetryMachine).

func TestControlRetryTableDoesNotCarryEveryCommandsWholeState(t *testing.T) {
	const commands = 30
	const perCommand = 1024 // the receipt fields, digest and ids of one retry-table entry, with margin
	f := newInstallFx(t)
	for i := range commands {
		if err := f.s.Update(f.ctx, func(st *State) error {
			if st.CommandOwners == nil {
				st.CommandOwners = map[string]string{}
			}
			for n := range 400 {
				st.CommandOwners[fmt.Sprintf("retry:%03d", n)] = fmt.Sprintf("owner-%012d", i)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	state, _, err := f.s.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	g := f.s.ReplicaGroup()
	snap, err := g.CreateSnapshot(f.ctx, g.Status().ApplicationCursor)
	if err != nil {
		t.Fatal(err)
	}
	size := -1
	for _, file := range snap.Manifest.Files {
		if file.Name == "envelope.json" {
			size = int(file.Size)
		}
	}
	if size < 0 {
		t.Fatal("snapshot has no envelope")
	}
	// The envelope holds the state once (base64) and a fixed-size record per command.
	if bound := 2*len(state) + commands*perCommand + 16<<10; size > bound {
		t.Fatalf("the snapshot envelope is %d bytes after %d commands that each carry a state of %d bytes: bound %d = 2 x state + %d x %d + 16 KiB; a retry table that keeps every payload is about %d",
			size, commands, len(state), bound, commands, perCommand, commands*len(state)*4/3)
	}
}
