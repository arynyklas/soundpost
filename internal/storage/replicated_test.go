// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"testing"

	bolt "go.etcd.io/bbolt"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/replica"
)

func activateTestControl(t *testing.T, authority *control.Store) error {
	t.Helper()
	if authority.ReplicaGroup() != nil {
		return nil
	}
	var id model.ID
	if err := authority.View(context.Background(), func(st control.State) error { id = st.Installation; return nil }); err != nil {
		return err
	}
	transport := replica.NewLoopback()
	group, err := authority.EnableReplication(replica.Config{ID: 1, Group: id, Directory: t.TempDir(), Transport: transport, Members: replica.Members{Revision: 1, Nodes: []replica.Member{{ID: 1, Address: "https://single.invalid", NodeIdentity: "single", FailureDomain: "local-disk"}}}})
	if err != nil {
		transport.Close()
		return err
	}
	if err = transport.Register(group); err == nil {
		err = group.Campaign()
	}
	if err != nil {
		group.Close()
		transport.Close()
		return err
	}
	t.Cleanup(func() { group.Close(); transport.Close() })
	return nil
}
func openTestEngine(t *testing.T, dir string, validator Revalidator, authority *control.Store) (*Engine, error) {
	t.Helper()
	if err := activateTestControl(t, authority); err != nil {
		return nil, err
	}
	engine, err := Open(dir, validator)
	if err != nil {
		return nil, err
	}
	transport := replica.NewLoopback()
	groups, err := engine.EnableReplication(replica.Config{ID: 1, Directory: filepath.Join(dir, "raft"), Transport: transport, Members: replica.Members{Revision: 1, Nodes: []replica.Member{{ID: 1, Address: "https://single.invalid", NodeIdentity: "single", FailureDomain: "local-disk"}}}}, nil, authority)
	if err != nil {
		engine.Close()
		transport.Close()
		return nil, err
	}
	for _, group := range groups {
		if err = transport.Register(group); err == nil {
			err = group.Campaign()
		}
		if err != nil {
			engine.Close()
			transport.Close()
			return nil, err
		}
	}
	t.Cleanup(func() { engine.Close(); transport.Close() })
	return engine, nil
}

// Returning a committed receipt before installed-owner apply, rewriting its
// original logical cursor on election, or losing typed rows breaks this test.
func TestReadYourReceiptUsesReplicatedOriginalApply(t *testing.T) {
	store, service, credential, descriptor := fixture(t)
	engine, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	scope, batch := normalized(t, store, service, credential, descriptor)
	original, err := engine.Append(context.Background(), scope, batch)
	if err != nil {
		t.Fatal(err)
	}
	group := engine.repl.groups[batch.RouteSlot]
	if group.Status().Applied <= uint64(original.Cursor.Index) {
		t.Fatal("physical no-op index was silently labeled application cursor")
	}
	if err = group.Campaign(); err != nil {
		t.Fatal(err)
	}
	retry, err := engine.Append(context.Background(), scope, batch)
	if err != nil {
		t.Fatal(err)
	}
	if string(mustJSON(t, original)) != string(mustJSON(t, retry)) {
		t.Fatal("original receipt changed")
	}
	if err = engine.db.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte("batches")).Get(batchKey(batch.Org, batch.Project, batch.Source, batch.Producer, batch.RouteSlot, batch.ID)) == nil {
			t.Fatal("ACK without actual typed data")
		}
		meta := tx.Bucket([]byte("replica_data"))
		if getUint(meta, metaKey(batch.RouteSlot, "physical")) < uint64(original.Cursor.Index) || getUint(meta, metaKey(batch.RouteSlot, "application")) != uint64(original.Cursor.Index) {
			t.Fatal("dual watermarks not installed with apply")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A dead credential must not strand a durable-but-unfinalized reservation, nor
// authorize a TTL refund. Only the installed owner's actual outcome may fix it.
func TestInstalledOwnerReconcilesConsumedAfterCredentialDeath(t *testing.T) {
	store, service, credential, descriptor := fixture(t)
	engine, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if err = store.BindAdmissionOwner(engine); err != nil {
		t.Fatal(err)
	}
	scope, batch := normalized(t, store, service, credential, descriptor)
	receipt, err := engine.Append(context.Background(), scope, batch)
	if err != nil {
		t.Fatal(err)
	}
	var bytesBefore model.Uint64
	if err = store.Update(context.Background(), func(st *control.State) error {
		r := st.Reservations[batch.Reservation.ID.String()]
		if r.State != "reserved" {
			t.Fatal("fixture finalized instead of exercising the mismatch")
		}
		source := st.Sources[descriptor.Source.String()]
		source.Revoked = true
		st.Sources[descriptor.Source.String()] = source
		bytesBefore = st.Quotas["project:"+batch.Org.String()+":"+batch.Project.String()].Bytes
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = store.ReconcileAdmissions(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = store.ReconcileAdmissions(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = store.View(context.Background(), func(st control.State) error {
		r := st.Reservations[batch.Reservation.ID.String()]
		if r.State != "consumed" || r.Cursor == nil || *r.Cursor != receipt.Cursor {
			t.Fatal("installed owner did not reconcile exact durable consumption")
		}
		if st.Quotas["project:"+batch.Org.String()+":"+batch.Project.String()].Bytes != bytesBefore {
			t.Fatal("reconciliation refunded or charged again")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = engine.Append(context.Background(), scope, batch); err == nil {
		t.Fatal("reconciliation revived the revoked source")
	}
}

func TestCancellationCarriesCommittedOwnerWatermark(t *testing.T) {
	store, service, credential, descriptor := fixture(t)
	engine, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if err = store.BindAdmissionOwner(engine); err != nil {
		t.Fatal(err)
	}
	scope, batch := normalized(t, store, service, credential, descriptor)
	proof, err := engine.Cancel(context.Background(), scope, batch.Reservation)
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		var watermark replica.CommitSetWatermark
		if json.Unmarshal(meta.Get(metaKey(batch.RouteSlot, "cancel-proof:"+batch.Reservation.ID.String())), &watermark) != nil || watermark.Reservation != batch.Reservation.ID || watermark.Group != proof.OwnerGroup || watermark.Term == 0 {
			t.Fatal("cancellation has receipt absence but no durable commit-set proof")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = store.CancelAdmission(context.Background(), scope, proof); err != nil {
		t.Fatal(err)
	}
	if _, err = engine.Append(context.Background(), scope, batch); err == nil {
		t.Fatal("cancelled reservation was consumed later")
	}
}

func testReadyWALPath(dir string, slot uint16) string {
	return filepath.Join(dir, "raft", "slot-"+strconv.Itoa(int(slot)), "ready.wal")
}
