// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"bytes"
	"encoding/json"
)

// SDKs may use an empty object for their empty label set. Nonempty label maps
// are forbidden: a list is required so duplicate label names cannot disappear.
func (l *Labels) UnmarshalJSON(b []byte) error {
	if bytes.Equal(bytes.TrimSpace(b), []byte("{}")) {
		*l = Labels{}
		return nil
	}
	type list Labels
	var v list
	if json.Unmarshal(b, &v) != nil {
		return Fail(Invalid)
	}
	*l = Labels(v)
	return nil
}
func (l *LogRecord) UnmarshalJSON(b []byte) error {
	type plain LogRecord
	var value plain
	wire := struct {
		*plain
		Fields   map[string]json.RawMessage `json:"fields"`
		Metadata map[string]json.RawMessage `json:"structured_metadata"`
	}{plain: &value}
	if StrictJSON(b, &wire) != nil {
		return Fail(Invalid)
	}
	narrow := func(raw map[string]json.RawMessage) map[string]Scalar {
		out := map[string]Scalar{}
		for key, v := range raw {
			var scalar Scalar
			if json.Unmarshal(v, &scalar) == nil {
				out[key] = scalar
			}
		}
		return out
	}
	value.Fields = narrow(wire.Fields)
	value.Metadata = narrow(wire.Metadata)
	*l = LogRecord(value)
	return nil
}
