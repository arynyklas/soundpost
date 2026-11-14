// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
)

// fakeCluster answers for itself with one list and for the cluster with another.
type fakeCluster struct{ local, cluster []string }

func (c fakeCluster) ResidualStores() []string        { return c.local }
func (c fakeCluster) ClusterResidualStores() []string { return c.cluster }

// A receipt carries the control group's view when the control source has one: the local list
// alone is not what the receipt says.
func TestResidualPlaneUsesTheClusterViewOfTheControlSource(t *testing.T) {
	f := newFx(t, options{})
	f.plane.residual = func() []string { return nil }
	src := fakeCluster{cluster: []string{control.ResidualControlJournal, control.ResidualControlState}}
	got := retention.NewResidualPlane(f.plane, src).ResidualStores()
	want := []string{control.ResidualControlJournal, control.ResidualControlState}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("a clean local list hid the cluster's residue: %v, want %v", got, want)
	}
	// A source without a cluster view answers for itself.
	if got = retention.NewResidualPlane(f.plane, fakeResiduals{control.ResidualControlJournal}).ResidualStores(); !reflect.DeepEqual(got, []string{control.ResidualControlJournal}) {
		t.Fatalf("a plain source: %v", got)
	}
}

// The retention worker is the voter's own path: its pass scrubs, redacts and then attests, and
// the receipt (which carries ClusterResidualStores) waits for that statement.
func TestWorkerPassAttestsSoTheReceiptCanBeClean(t *testing.T) {
	f := newFx(t, options{controlResiduals: true})
	if _, _, err := f.append(5, "requests"); err != nil {
		t.Fatal(err)
	}
	f.seedIncident(f.project, "CANARYWORKERATTEST7c41e90d2b86a")
	receipt, err := f.del(model.DeleteRetireProject, func(r *retention.DeleteRequest) { r.ProjectIDs = []model.ID{f.project} })
	if err != nil {
		t.Fatal(err)
	}
	if got := f.store.ClusterResidualStores(); !hasResidual(got, control.ResidualControlJournal) || !hasResidual(got, control.ResidualControlState) {
		t.Fatalf("an erasure committed and nobody attested: %v", got)
	}
	f.run()
	done := f.poll(receipt.OperationID)
	if done.Physical != retention.PhysicalDone || len(done.Residual) != 0 {
		t.Fatalf("the worker's pass scrubbed, redacted and must have attested: %+v", done)
	}
	if got := f.store.ClusterResidualStores(); len(got) != 0 {
		t.Fatalf("the cluster view after the worker's pass: %v", got)
	}
	var attested bool
	if err = f.store.View(f.ctx, func(st control.State) error { _, attested = st.OIDC["control_attest:1"]; return nil }); err != nil || !attested {
		t.Fatalf("the worker did not leave an attestation record: %v", err)
	}
}
