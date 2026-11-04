// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"encoding/json"
	"testing"
)

func TestNormalizationPreservesNanosecondTies(t *testing.T) {
	got, e := NormalizeSeconds(json.Number("1700000000.000000001"))
	if e != nil || got != "1700000000000000001" {
		t.Fatalf("%s %v", got, e)
	}
	if _, e = NormalizeSeconds(json.Number("0.0000000001")); e == nil {
		t.Fatal("sub-nanosecond timestamp accepted")
	}
	got, e = NormalizeFloat("-0")
	if e != nil || got != "8000000000000000" {
		t.Fatalf("%s %v", got, e)
	}
}
