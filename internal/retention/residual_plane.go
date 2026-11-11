// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention

import "sort"

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

// ResidualStores is the union of the engine's and the control store's residual
// stores, each name once, sorted; nil when neither owes anything.
func (p ResidualPlane) ResidualStores() []string {
	var out []string
	seen := map[string]bool{}
	for _, list := range [][]string{p.DataPlane.ResidualStores(), p.control.ResidualStores()} {
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
