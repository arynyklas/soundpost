// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"github.com/arynyklas/soundpost/internal/artifacts/refledger"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replays"
)

// contractIndexes is the organization step of `soundpost upgrade contract-indexes` (D70): the artifact
// ledger index and the replay pins drop the per-project values the previous release reads, and the
// organization is marked contracted so no write keeps them. The organization is changed only when
// both succeed.
func contractIndexes(o *model.ControlOrg) (bool, error) {
	next := *o
	ledgers, err := refledger.Contract(&next)
	if err != nil {
		return false, err
	}
	pins, err := replays.ContractPins(&next)
	if err != nil {
		return false, err
	}
	*o = next
	return ledgers || pins, nil
}
