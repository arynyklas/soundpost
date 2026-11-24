// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"testing"
)

func TestBlobJobBookFindsTheRecordWithoutDecodingTheBlob(t *testing.T) {
	cases := []struct {
		name, blob, key, want string
		found                 bool
	}{
		{"compact", `{"Orgs":{"a":{"x":"}"}},"JobBooks":{"k1":{"v":1},"k\"2":{"v":2}},"Sources":null}`, "k1", `{"v":1}`, true},
		{"escaped key", `{"JobBooks":{"k1":{"v":1},"k\"2":{"v":2}}}`, `k"2`, `{"v":2}`, true},
		{"absent key", `{"JobBooks":{"k1":{"v":1}}}`, "k3", "", false},
		{"null books", `{"JobBooks":null,"Orgs":{}}`, "k1", "", false},
		{"no books", `{"Orgs":{}}`, "k1", "", false},
		{"not compact", "{ \"JobBooks\" : { \"k1\" : { \"v\" : 1 } } }", "k1", `{ "v" : 1 }`, true},
	}
	for _, c := range cases {
		raw, found, err := blobJobBook([]byte(c.blob), c.key)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if found != c.found {
			t.Fatalf("%s: found %v, want %v", c.name, found, c.found)
		}
		if found && !json.Valid(raw) {
			t.Fatalf("%s: %q is not a JSON value", c.name, raw)
		}
		if found && !sameJSON(raw, []byte(c.want)) {
			t.Fatalf("%s: record %q, want %q", c.name, raw, c.want)
		}
	}
	if _, _, err := blobJobBook([]byte(`{"JobBooks":{"k1":`), "k1"); err == nil {
		t.Fatal("a truncated blob was read")
	}
}

func TestOnlyJobBooksDifferIsFalseForAnyOtherChange(t *testing.T) {
	members := func(blob string) map[string]json.RawMessage {
		m, err := decodeMembers([]byte(blob))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	old := `{"Orgs":{"a":1},"JobBooks":{"k":{"v":1}},"Audits":[1]}`
	for _, c := range []struct {
		name, next string
		want       bool
	}{
		{"job books only", `{"Orgs":{"a":1},"JobBooks":{"k":{"v":2}},"Audits":[1]}`, true},
		{"job books appear", `{"Orgs":{"a":1},"Audits":[1]}`, true},
		{"another member changes", `{"Orgs":{"a":2},"JobBooks":{"k":{"v":2}},"Audits":[1]}`, false},
		{"a member is added", `{"Orgs":{"a":1},"JobBooks":{"k":{"v":1}},"Audits":[1],"Sources":{}}`, false},
		{"a member goes away", `{"Orgs":{"a":1},"JobBooks":{"k":{"v":1}}}`, false},
		{"a member is replaced by another", `{"Orgs":{"a":1},"JobBooks":{"k":{"v":1}},"Sources":{}}`, false},
	} {
		if got := onlyJobBooksDiffer([]byte(old), members(c.next)); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	if onlyJobBooksDiffer(nil, members(old)) {
		t.Error("no committed blob: a change")
	}
}
