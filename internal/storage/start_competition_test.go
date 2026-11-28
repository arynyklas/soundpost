// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// The cold start of the single-host gate's node was 28 s at the end of the hour (D91 allows 20 s). What it did, measured on the data the
// hour left (L2w20Admission30): the first full pass of the background verification began at once and read every index entry and every
// record of the payload log (10 of the 39 CPU seconds of the first 13 s, and as much disk as the start itself), while the 64 groups
// replayed their journals from the same cold disk, and each replayed entry read its command back from the payload log, one random read
// each, under the engine lock. The node's start is complete when EnableReplication returns; the pass is background maintenance (no
// readiness waits for it: nothing outside storage reads VerifyFailure or calls VerifyFull) and has no reason to run before that.

// payloadNode builds a node on the payload layout with n acknowledged batches and returns the image of its directory as a crash leaves
// it (a copy taken while the engine runs, byte for byte; the engine is closed afterwards): the journals still hold every command (no
// cut), apply.db and the payload log hold them too, and no graceful close has recorded how far the node applied, so a start replays.
func payloadNode(t *testing.T, n int) (dir string, store *control.Store, service *auth.Service) {
	t.Helper()
	store, service, cred, desc := fixture(t)
	live := t.TempDir()
	e := openPayloadEngine(t, live, store, service)
	if err := store.BindAdmissionOwner(e); err != nil {
		t.Fatal(err)
	}
	for i := range n {
		scope, batch := settleBatch(t, store, service, cred, desc, model.NewID(), 1, fmt.Sprintf("series_%d", i))
		if _, err := e.Append(context.Background(), scope, batch); err != nil {
			t.Fatal(err)
		}
	}
	dir = t.TempDir()
	copyTree(t, live, dir)
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, store, service
}

// startNode opens the node the way a start does (open, then EnableReplication) and reports what the engine did on the disk in the
// window between the two (the start's replay takes its time there): the full passes begun and the records of the payload log read.
// open is Open (the pass begins at once) or OpenReplicated (the product's start: it waits for EnableReplication).
func startNode(t *testing.T, dir string, store *control.Store, service Revalidator, open func(string, Revalidator) (*Engine, error), window time.Duration) (e *Engine, passes, reads int64, enableReads int64) {
	t.Helper()
	if err := activateTestControl(t, store); err != nil {
		t.Fatal(err)
	}
	e, err := open(dir, service)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	base := e.payload.nreads.Load()
	time.Sleep(window)
	passes, reads = e.ver.fullPasses.Load(), e.payload.nreads.Load()-base
	before := e.payload.nreads.Load()
	transport := replica.NewLoopback()
	t.Cleanup(func() { transport.Close() })
	groups, err := e.EnableReplication(replica.Config{ID: 1, Directory: filepath.Join(dir, "raft"), Transport: transport, Members: replica.Members{Revision: 1, Nodes: []replica.Member{{ID: 1, Address: "https://single.invalid", NodeIdentity: "single", FailureDomain: "local-disk"}}}}, nil, store)
	if err != nil {
		t.Fatal(err)
	}
	enableReads = e.payload.nreads.Load() - before
	for _, group := range groups {
		if err = transport.Register(group); err == nil {
			err = group.Campaign()
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return e, passes, reads, enableReads
}

// The old placement (Open: the pass begins when the engine opens) reads the node while its start replays; the product's start
// (OpenReplicated) does not read before EnableReplication returned, and then runs the pass after verifyStartDelay.
func TestFirstFullPassDoesNotCompeteWithTheStart(t *testing.T) {
	oldDelay := verifyStartDelay
	verifyStartDelay = 200 * time.Millisecond
	t.Cleanup(func() { verifyStartDelay = oldDelay })
	const window = 1500 * time.Millisecond

	dir, store, service := payloadNode(t, 40)
	_, passes, reads, _ := startNode(t, dir, store, service, Open, window)
	if passes != 1 {
		t.Fatalf("control: with Open the full pass began %d times in the first %v of the start; want it begun (it reads the node while the start replays)", passes, window)
	}
	t.Logf("Open: %d pass, %d records read before the start completed", passes, reads)

	dir, store, service = payloadNode(t, 40)
	e, passes, reads, _ := startNode(t, dir, store, service, OpenReplicated, window)
	if passes != 0 || reads != 0 {
		t.Fatalf("with OpenReplicated the full pass began %d times and read %d records of the log before the start completed", passes, reads)
	}
	deadline := time.Now().Add(20 * time.Second)
	for e.ver.fullPasses.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the full pass never began after the start")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A node that never enables replication (single-host mode without it, or a start that never ends) still gets its first full pass, within
// verifyStartMax.
func TestFirstFullPassOfAReplicatedOpenNeverWaitsForever(t *testing.T) {
	oldMax := verifyStartMax
	verifyStartMax = 300 * time.Millisecond
	t.Cleanup(func() { verifyStartMax = oldMax })
	store, service, _, _ := fixture(t)
	e, err := OpenReplicated(t.TempDir(), service)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	_ = store
	deadline := time.Now().Add(20 * time.Second)
	for e.ver.fullPasses.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the full pass of a node that never enabled replication did not begin")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A start replays the journals of its groups without reading the payload log: the command a journal entry carries is the command
// the store's reference names (length and CRC32C), which is all a replay of an applied entry compares.
func TestReplayOfAppliedCommandsReadsNoPayloadRecords(t *testing.T) {
	holdBackgroundVerification(t)
	const n = 30
	dir, store, service := payloadNode(t, n)
	e, _, _, enableReads := startNode(t, dir, store, service, OpenReplicated, 0)
	if enableReads != 0 {
		t.Fatalf("EnableReplication read %d records of the payload log: the replay of %d applied commands reads them back", enableReads, n)
	}
	if !e.payloadOn.Load() {
		t.Fatal("the reopened file lost the payload layout")
	}
	var applied uint64
	for slot := range uint16(64) {
		applied += e.indexes[slot]
	}
	if applied != n {
		t.Fatalf("the restarted node applied %d commands, want %d", applied, n)
	}
}

// What the replay no longer reads is still refused when the file is not what the reference names: a record the crash cut short.
func TestReplayStillRefusesAPayloadRecordTheCrashCutShort(t *testing.T) {
	holdBackgroundVerification(t)
	dir, store, service := payloadNode(t, 20)
	entries, err := os.ReadDir(filepath.Join(dir, payloadDirName))
	if err != nil || len(entries) == 0 {
		t.Fatalf("no payload files: %v", err)
	}
	last := filepath.Join(dir, payloadDirName, entries[len(entries)-1].Name())
	fi, err := os.Stat(last)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Truncate(last, fi.Size()-200); err != nil {
		t.Fatal(err)
	}
	if err = activateTestControl(t, store); err != nil {
		t.Fatal(err)
	}
	e, err := OpenReplicated(dir, service)
	if err == nil {
		defer e.Close()
		transport := replica.NewLoopback()
		defer transport.Close()
		_, err = e.EnableReplication(replica.Config{ID: 1, Directory: filepath.Join(dir, "raft"), Transport: transport, Members: replica.Members{Revision: 1, Nodes: []replica.Member{{ID: 1, Address: "https://single.invalid", NodeIdentity: "single", FailureDomain: "local-disk"}}}}, nil, store)
	}
	if err == nil {
		t.Fatal("a start over a payload file cut in the middle of its last record succeeded")
	}
}
