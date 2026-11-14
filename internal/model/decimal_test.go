// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model_test

import (
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/model"
	"strings"
	"testing"
)

func TestCanonicalWireIntegersDirectDecoders(t *testing.T) {
	unsigned := []struct {
		raw  string
		want model.Uint64
	}{{`"0"`, 0}, {`"18446744073709551615"`, ^model.Uint64(0)}, {`"9007199254740993"`, 9007199254740993}, {`"\u0031"`, 1}}
	for _, test := range unsigned {
		for _, stream := range []bool{false, true} {
			var got model.Uint64
			var err error
			if stream {
				err = json.NewDecoder(strings.NewReader(test.raw)).Decode(&got)
			} else {
				err = json.Unmarshal([]byte(test.raw), &got)
			}
			if err != nil || got != test.want {
				t.Fatal("canonical unsigned rejected")
			}
			out, err := json.Marshal(got)
			if err != nil || len(out) < 3 || out[0] != '"' {
				t.Fatal("counter not string encoded")
			}
		}
	}
	for _, raw := range []string{`"01"`, `"00"`, `"+1"`, `"-0"`, `"-1"`, `"18446744073709551616"`, `"1.0"`, `"1e0"`, `" 1"`, `"1 "`, `1`, `null`, `true`, `"\u0030\u0031"`} {
		var got model.Uint64
		if json.Unmarshal([]byte(raw), &got) == nil {
			t.Fatal("noncanonical unsigned accepted")
		}
	}
	signed := []struct {
		raw  string
		want model.Int64
	}{{`"0"`, 0}, {`"9223372036854775807"`, 9223372036854775807}, {`"-9223372036854775808"`, -9223372036854775808}, {`"-9007199254740993"`, -9007199254740993}, {`"\u002d1"`, -1}}
	for _, test := range signed {
		var got model.Int64
		if err := json.Unmarshal([]byte(test.raw), &got); err != nil || got != test.want {
			t.Fatal("canonical signed rejected")
		}
	}
	for _, raw := range []string{`"01"`, `"-01"`, `"-0"`, `"+1"`, `"9223372036854775808"`, `"-9223372036854775809"`, `"1.0"`, `1`, `null`} {
		var got model.Int64
		if json.NewDecoder(strings.NewReader(raw)).Decode(&got) == nil {
			t.Fatal("noncanonical signed accepted")
		}
	}
	var ordinary struct {
		Counter model.Uint64 `json:"counter"`
		Label   string       `json:"label"`
	}
	if err := json.Unmarshal([]byte(`{"counter":"1","label":"01"}`), &ordinary); err != nil || ordinary.Label != "01" {
		t.Fatal("ordinary strings changed")
	}
}
func TestCanonicalWireIntegerFastDecodeAllocations(t *testing.T) {
	raw := []byte(`"18446744073709551615"`)
	var value model.Uint64
	var err error
	allocations := testing.AllocsPerRun(1000, func() { err = value.UnmarshalJSON(raw) })
	if err != nil || value != ^model.Uint64(0) || allocations != 0 {
		t.Fatal("valid integer decoder allocates or changes value")
	}
}
