// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// openDomainEngine is openTestEngine with every data group opened in one replica.FailDomain, the
// way appcore opens a node.
func openDomainEngine(t *testing.T, validator Revalidator, authority *control.Store, domain *replica.FailDomain) *Engine {
	t.Helper()
	if err := activateTestControl(t, authority); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	engine, err := Open(dir, validator)
	if err != nil {
		t.Fatal(err)
	}
	transport := replica.NewLoopback()
	groups, err := engine.EnableReplication(replica.Config{ID: 1, Directory: filepath.Join(dir, "raft"), Transport: transport, Domain: domain, Members: replica.Members{Revision: 1, Nodes: []replica.Member{{ID: 1, Address: "https://single.invalid", NodeIdentity: "single", FailureDomain: "local-disk"}}}}, nil, authority)
	if err != nil {
		engine.Close()
		transport.Close()
		t.Fatal(err)
	}
	for _, group := range groups {
		if err = transport.Register(group); err == nil {
			err = group.Campaign()
		}
		if err != nil {
			engine.Close()
			transport.Close()
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { engine.Close(); transport.Close() })
	return engine
}

// awaitFailedGroups waits for the domain to fail with one of the given reasons (the first failure
// wins, and an apply failure is reported both by the group that applied and by the engine) and for
// every data group of the node to be failed closed.
func awaitFailedGroups(t *testing.T, engine *Engine, domain *replica.FailDomain, want ...replica.FailReason) {
	t.Helper()
	select {
	case <-domain.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the node's storage failed and the replication domain did not fail with it")
	}
	if failure, ok := domain.Failure(); !ok || !slices.Contains(want, failure.Reason) {
		t.Fatalf("domain failure = %+v (%v), want one of %v", failure, ok, want)
	}
	deadline := time.Now().Add(5 * time.Second)
	for slot, group := range engine.repl.groups {
		for !group.Status().Failed {
			if time.Now().After(deadline) {
				t.Fatalf("data group %d of the failed node still serves (a node whose engine failed keeps leading groups it has not applied in yet)", slot)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// The engine behind all 64 data groups failing outside any command (a manifest commit whose fsync
// failed) must stop the node from leading or voting in every group, not only in the groups that
// happen to apply next.
func TestAnEngineFailureFailStopsEveryGroupOfTheNode(t *testing.T) {
	store, service, _, _ := fixture(t)
	domain := replica.NewFailDomain()
	engine := openDomainEngine(t, service, store, domain)
	engine.mu.Lock()
	engine.failLocked()
	engine.mu.Unlock()
	awaitFailedGroups(t, engine, domain, replica.FailEngine)
}

// An apply that fails after the command committed fails the engine; the node's other groups must
// stop with it.
func TestAnApplyFailureFailStopsEveryGroupOfTheNode(t *testing.T) {
	store, service, credential, descriptor := fixture(t)
	domain := replica.NewFailDomain()
	engine := openDomainEngine(t, service, store, domain)
	engine.fault = func(at string) error {
		if at == "before_apply" {
			return model.Fail(model.Unavailable)
		}
		return nil
	}
	scope, batch := normalized(t, store, service, credential, descriptor)
	if _, err := engine.Append(context.Background(), scope, batch); err == nil {
		t.Fatal("a batch whose apply failed was acknowledged")
	}
	awaitFailedGroups(t, engine, domain, replica.FailApply, replica.FailEngine)
}

// An engine opened without a fail domain has no node to stop: its failure marks the engine failed
// and leaves the replica groups to fail on their own when they next apply.
func TestAnEngineFailureWithoutAFailDomainLeavesItsGroupsAlone(t *testing.T) {
	store, service, _, _ := fixture(t)
	engine, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	engine.failLocked()
	failed := engine.failed
	engine.mu.Unlock()
	if !failed {
		t.Fatal("failLocked did not mark the engine failed")
	}
	time.Sleep(300 * time.Millisecond)
	for slot, group := range engine.repl.groups {
		if group.Status().Failed {
			t.Fatalf("data group %d failed although the engine has no fail domain", slot)
		}
	}
}
