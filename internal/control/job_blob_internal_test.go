// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"slices"
	"sort"
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

// A write names exactly the members it changed, and the job books are one of them like any other: what a
// core reader does with that is decided by the members it reads (coreMembers), not here.
func TestChangedMembersNamesEveryMemberThatDiffers(t *testing.T) {
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
		want       []string
	}{
		{"identical", old, nil},
		{"job books only", `{"Orgs":{"a":1},"JobBooks":{"k":{"v":2}},"Audits":[1]}`, []string{"JobBooks"}},
		{"job books appear", `{"Orgs":{"a":1},"Audits":[1]}`, []string{"JobBooks"}},
		{"another member changes", `{"Orgs":{"a":2},"JobBooks":{"k":{"v":2}},"Audits":[1]}`, []string{"JobBooks", "Orgs"}},
		{"a member is added", `{"Orgs":{"a":1},"JobBooks":{"k":{"v":1}},"Audits":[1],"Sources":{}}`, []string{"Sources"}},
		{"a member goes away", `{"Orgs":{"a":1},"JobBooks":{"k":{"v":1}}}`, []string{"Audits"}},
		{"a member is replaced by another", `{"Orgs":{"a":1},"JobBooks":{"k":{"v":1}},"Sources":{}}`, []string{"Audits", "Sources"}},
	} {
		got, all := changedMembers([]byte(old), members(c.next))
		sort.Strings(got)
		if all || !slices.Equal(got, c.want) {
			t.Errorf("%s: %v (all %v), want %v", c.name, got, all, c.want)
		}
	}
	if _, all := changedMembers(nil, members(old)); !all {
		t.Error("no committed blob: every member is a change")
	}
	if _, all := changedMembers([]byte(`{"Orgs":`), members(old)); !all {
		t.Error("a committed blob that cannot be read: every member is a change")
	}
}
