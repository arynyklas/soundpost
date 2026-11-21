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

// cursorCanonical is the form Cursor marshals to: {"group":"<32 hex>","index":"<decimal>"}.
const (
	cursorHead = `{"group":`
	cursorMid  = `,"index":`
)

// UnmarshalJSON decodes the canonical form in place (no pooled decoder per cursor: a snapshot or a
// journal record carries one per entry) and hands every other input to the general decoder, so
// the answer for them is unchanged.
func (c *Cursor) UnmarshalJSON(raw []byte) error {
	if n := len(cursorHead) + 34 + len(cursorMid); len(raw) > n+2 && raw[len(raw)-1] == '}' &&
		string(raw[:len(cursorHead)]) == cursorHead && string(raw[len(cursorHead)+34:n]) == cursorMid {
		var group ID
		var index Uint64
		if group.UnmarshalJSON(raw[len(cursorHead):len(cursorHead)+34]) == nil && index.UnmarshalJSON(raw[n:len(raw)-1]) == nil {
			c.Group, c.Index = group, index
			return nil
		}
	}
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
