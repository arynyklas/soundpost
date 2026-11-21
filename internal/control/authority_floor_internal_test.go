// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// installationFloor trusts the pair only while it names the AuthorityRevision it was written with;
// every doubt is the whole scalar.
func TestInstallationFloorTrustsThePairOnlyWhileItIsCurrent(t *testing.T) {
	pair := func(raw string) map[string]json.RawMessage {
		return map[string]json.RawMessage{model.ScopedAuthorityKey: json.RawMessage(raw)}
	}
	for _, c := range []struct {
		name string
		st   State
		want model.Revision
	}{
		{"no pair", State{Revision: 50, AuthorityRevision: 40}, 40},
		{"current pair", State{Revision: 50, AuthorityRevision: 40, OIDC: pair(`{"floor":"30","global":"40"}`)}, 30},
		{"void: a commit of another binary moved the scalar", State{Revision: 50, AuthorityRevision: 45, OIDC: pair(`{"floor":"30","global":"40"}`)}, 45},
		{"unreadable", State{Revision: 50, AuthorityRevision: 40, OIDC: pair(`"x"`)}, 40},
		{"unknown member", State{Revision: 50, AuthorityRevision: 40, OIDC: pair(`{"floor":"30","global":"40","x":1}`)}, 40},
		{"floor above the scalar", State{Revision: 50, AuthorityRevision: 40, OIDC: pair(`{"floor":"41","global":"40"}`)}, 40},
		{"bare numbers are not the encoding of a revision", State{Revision: 50, AuthorityRevision: 40, OIDC: pair(`{"floor":30,"global":40}`)}, 40},
	} {
		if got := installationFloor(&c.st); got != c.want {
			t.Errorf("%s: floor %d, want %d", c.name, got, c.want)
		}
	}
	legacy := State{Revision: 50}
	if got := installationFloor(&legacy); got != 50 {
		t.Errorf("legacy state without the scalar: floor %d, want the revision 50", got)
	}
}
