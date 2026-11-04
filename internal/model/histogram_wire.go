// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
	"errors"
)

func (h *IntegerHistogram) UnmarshalJSON(raw []byte) error {
	type plain IntegerHistogram
	var value plain
	wire := struct {
		*plain
		Count     *Uint64 `json:"count"`
		ZeroCount *Uint64 `json:"zero_count"`
	}{plain: &value}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	if wire.Count == nil || wire.ZeroCount == nil {
		return errors.New("histogram counts required")
	}
	value.Count = *wire.Count
	value.ZeroCount = *wire.ZeroCount
	*h = IntegerHistogram(value)
	return nil
}
func (c *Cursor) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Group ID      `json:"group"`
		Index *Uint64 `json:"index"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	if wire.Index == nil {
		return errors.New("cursor index required")
	}
	c.Group = wire.Group
	c.Index = *wire.Index
	return nil
}
