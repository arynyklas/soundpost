// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention

import (
	"context"
	"sort"

	"github.com/arynyklas/soundpost/internal/model"
)

// ResidualSource names the local stores that can still hold a copy of deleted
// bytes right now, in the vocabulary of storage.Engine.ResidualStores. The
// control store is one (control.Store.ResidualStores).
type ResidualSource interface {
	ResidualStores() []string
}

// ResidualPlane is the DataPlane the application hands the Service: the storage
// engine, whose residual stores it reports together with the control store's. A
// receipt names the residual stores of the whole installation, so a "physical:
// done" receipt can never hide a copy the control store still owes (the control
// Raft journal until this node's redaction pass is proven, and the free pages of
// control.db until they are scrubbed): the engine alone does not know about either.
type ResidualPlane struct {
	DataPlane
	control ResidualSource
}

// NewResidualPlane wraps data with the control residuals. control must not be nil
// (it is the *control.Store the Service is built on).
func NewResidualPlane(data DataPlane, control ResidualSource) ResidualPlane {
	return ResidualPlane{DataPlane: data, control: control}
}

// ClusterResidualSource is a ResidualSource that also knows the other nodes of the control
// group (control.Store.ClusterResidualStores): its list is what a receipt carries, because
// the control journal and control.db are rewritten and scrubbed per voter and a receipt must
// not call them clean while another voter has not attested its own copy. A source without it
// (a fake, a store without a replication group) answers for itself only.
type ClusterResidualSource interface {
	ResidualSource
	ClusterResidualStores() []string
}

func (p ResidualPlane) controlResiduals() []string {
	if c, ok := p.control.(ClusterResidualSource); ok {
		return c.ClusterResidualStores()
	}
	return p.control.ResidualStores()
}

// ResidualStores is the union of the engine's and the control store's residual
// stores, each name once, sorted; nil when neither owes anything.
func (p ResidualPlane) ResidualStores() []string {
	var out []string
	seen := map[string]bool{}
	for _, list := range [][]string{p.DataPlane.ResidualStores(), p.controlResiduals()} {
		for _, name := range list {
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ErasureTracker is the per-voter bookkeeping of physical erasure (storage.Engine implements
// it). PhysicalAt in the control state is one cluster-wide fact, so a voter that did not run the
// erasure itself must still run it (ErasedLocally false), and a receipt names the data store
// until every voter of the group acknowledged the operation (ErasureResidual). A DataPlane
// without it (a fake) is treated as having no per-voter state.
type ErasureTracker interface {
	ErasedLocally(op model.ID) bool
	MarkErased(ops []model.ID) error
	AckErasure(ctx context.Context) error
	ErasureResidual(op model.ID) []string
}

func (p ResidualPlane) tracker() ErasureTracker {
	t, _ := p.DataPlane.(ErasureTracker)
	return t
}

// ErasedLocally forwards to the data plane's tracker; without one nothing is owed per voter.
func (p ResidualPlane) ErasedLocally(op model.ID) bool {
	if t := p.tracker(); t != nil {
		return t.ErasedLocally(op)
	}
	return true
}

// MarkErased forwards to the data plane's tracker.
func (p ResidualPlane) MarkErased(ops []model.ID) error {
	if t := p.tracker(); t != nil {
		return t.MarkErased(ops)
	}
	return nil
}

// AckErasure forwards to the data plane's tracker.
func (p ResidualPlane) AckErasure(ctx context.Context) error {
	if t := p.tracker(); t != nil {
		return t.AckErasure(ctx)
	}
	return nil
}

// ErasureResidual forwards to the data plane's tracker.
func (p ResidualPlane) ErasureResidual(op model.ID) []string {
	if t := p.tracker(); t != nil {
		return t.ErasureResidual(op)
	}
	return nil
}

// mergeResidual is the union of two residual lists, each name once, sorted; nil when empty.
func mergeResidual(a, b []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, list := range [][]string{a, b} {
		for _, name := range list {
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}
