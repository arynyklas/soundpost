// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

var errInjectedFault = errors.New("injected fault")

// openFaulted reopens the control store of dir on its journal with a replication fault hook.
func openFaulted(t *testing.T, ctx context.Context, dir string, fault func(string) error) *control.Store {
	t.Helper()
	s, err := control.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = auth.NewService(auth.AuthDependencies{Control: s}); err != nil {
		t.Fatal(err)
	}
	var installation model.ID
	if err = s.View(ctx, func(st control.State) error { installation = st.Installation; return nil }); err != nil {
		t.Fatal(err)
	}
	local := replica.NewLoopback()
	t.Cleanup(func() { local.Close() })
	group, err := s.EnableReplication(replica.Config{ID: 1, Group: installation, Directory: filepath.Join(dir, "raft-control"), Transport: local, Fault: fault,
		Members: replica.Members{Revision: 1, Nodes: []replica.Member{{ID: 1, Address: "https://single.invalid", NodeIdentity: "single", FailureDomain: "local-disk"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = local.Register(group); err == nil {
		err = group.Campaign()
	}
	if err == nil {
		err = group.Ready(ctx)
	}
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The redaction driver is a sequence of steps (rewrite the retained commands, commit an empty
// revision, cut a snapshot, drop the superseded ones, compact the journal). A real fault between
// any two of them, at each hook the replication layer offers, leaves a node that a restart and a
// repeated call bring to the same end: no erased payload in any file, the receipt clean, the
// state the live state still was.
func TestRedactRetainedControlCommandsConvergesAfterAFaultAtEveryStep(t *testing.T) {
	hooks := []string{
		replica.HookRedactBegin, replica.HookRedactWrite, replica.HookRedactSync, replica.HookRedactSwitch, replica.HookRedactRenamed, replica.HookRedactMemory,
		replica.HookSnapshotCut, replica.HookSnapshotFileWrite, replica.HookSnapshotFileSync, replica.HookSnapshotManifestWrite, replica.HookSnapshotDirSync,
		replica.HookSnapshotSwitch, replica.HookSnapshotRenamed, replica.HookSnapshotCurrentWrite, replica.HookSnapshotCurrentSwitch, replica.HookSnapshotPublished,
		replica.HookCompactBegin, replica.HookCompactWrite, replica.HookCompactSync, replica.HookCompactSwitch, replica.HookCompactRenamed, replica.HookCompactMemory,
	}
	for _, hook := range hooks {
		t.Run(hook, func(t *testing.T) {
			f := newEraseFx(t)
			const gone, kept = "CANARYFAULTGONE0d2b86a7c41e9", "CANARYFAULTKEPT51f0aa93c7de1b"
			f.seedAll(f.newSeed(f.project, gone), 50)
			f.seedAll(f.newSeed(f.otherProject, kept), 50)
			f.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
			if err := f.store.Close(); err != nil {
				t.Fatal(err)
			}

			var mu sync.Mutex
			fired := false
			s := openFaulted(t, f.ctx, f.dir, func(at string) error {
				mu.Lock()
				defer mu.Unlock()
				if at == hook && !fired {
					fired = true
					return errInjectedFault
				}
				return nil
			})
			err := s.RedactRetainedControlCommands(f.ctx)
			mu.Lock()
			didFire := fired
			mu.Unlock()
			if !didFire {
				t.Fatalf("the hook %s never ran in the pass: the case proves nothing", hook)
			}
			if err == nil {
				t.Fatalf("a fault at %s was swallowed by the pass", hook)
			}
			if got := s.ResidualStores(); len(got) == 0 {
				t.Fatalf("a pass that failed at %s reported a clean receipt", hook)
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}

			s = openFaulted(t, f.ctx, f.dir, nil)
			defer s.Close()
			if err = s.RedactRetainedControlCommands(f.ctx); err != nil {
				t.Fatalf("the repeated pass after a fault at %s: %v", hook, err)
			}
			if got := s.ResidualStores(); len(got) != 0 {
				t.Fatalf("after a fault at %s, a restart and a second pass: %v", hook, got)
			}
			if hits := eraseFileHits(t, f.dir, gone); len(hits) != 0 {
				t.Fatalf("after a fault at %s, the erased payload is still held by %v", hook, hits)
			}
			if err = s.View(f.ctx, func(st control.State) error {
				raw, e := model.CanonicalJSON(st)
				if e == nil && (strings.Contains(string(raw), gone) || !strings.Contains(string(raw), kept)) {
					t.Errorf("the state after a fault at %s lost what it keeps or kept what it erased", hook)
				}
				return e
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
