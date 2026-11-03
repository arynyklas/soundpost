// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
)

func (h *IntegerHistogram) UnmarshalJSON(raw []byte) error {
	type plain IntegerHistogram
	var decoded plain
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	var fields struct {
		Count     json.RawMessage `json:"count"`
		ZeroCount json.RawMessage `json:"zero_count"`
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if _, err := parseDecimal(fields.Count, false); err != nil {
		return err
	}
	if _, err := parseDecimal(fields.ZeroCount, false); err != nil {
		return err
	}
	*h = IntegerHistogram(decoded)
	return nil
}
func (c *Cursor) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Group ID              `json:"group"`
		Index json.RawMessage `json:"index"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	var index AbsoluteBucket
	if err := json.Unmarshal(wire.Index, &index); err != nil {
		return err
	}
	c.Group = wire.Group
	c.Index = uint64(index)
	return nil
}
