// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"crypto/sha256"
	"encoding/binary"
	"github.com/arynyklas/soundpost/internal/model"
)

const RouteSlots = 64

// SlotGroup preserves the already installed engine's length-delimited identity
// derivation. Placement and membership never alter this fixed slot namespace.
func SlotGroup(installation model.ID, slot uint16) (model.ID, error) {
	if installation == (model.ID{}) || slot >= RouteSlots {
		return model.ID{}, ErrInvalid
	}
	var input [18]byte
	copy(input[:16], installation[:])
	binary.BigEndian.PutUint16(input[16:], slot)
	hash := sha256.Sum256(input[:])
	var group model.ID
	copy(group[:], hash[:16])
	return group, nil
}
