// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/query/profile"
)

// Every rejected expression of the PromQL syntax corpora must report the same
// start and end as the pinned parser's ParseErrors[0].PositionRange (02.02-W1).
func TestOwnedSyntaxRangesAgainstRecordedGoLevelObservations(t *testing.T) {
	raw, err := os.ReadFile("testdata/native-promql-syntax-ranges.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Rows []struct {
			Profile    string   `json:"profile"`
			Enabled    []string `json:"enabled"`
			ID         string   `json:"id"`
			Expression string   `json:"expression"`
			Accepted   bool     `json:"accepted"`
			Start, End int
		} `json:"rows"`
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Rows) < 498 {
		t.Fatalf("recorded range observations shrank to %d rows", len(f.Rows))
	}
	registry, err := profile.Load(os.DirFS("../../../profiles/query"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range f.Rows {
		var manifest profile.Profile
		if err = ReadJSON("../../../profiles/query/"+row.Profile+".json", &manifest); err != nil {
			t.Fatal(err)
		}
		want := append([]string(nil), row.Enabled...)
		sort.Strings(want)
		setID := ""
		for _, set := range manifest.FeatureSets {
			have := append([]string(nil), set.Enabled...)
			sort.Strings(have)
			if strings.Join(have, ",") == strings.Join(want, ",") {
				setID = set.ID
			}
		}
		p, err := registry.Resolve(row.Profile, setID)
		if err != nil {
			t.Fatal(err)
		}
		owned, err := observeOwnedSyntax(row.Expression, p)
		if err != nil {
			t.Errorf("%s %q: owned observation failed: %v", row.Profile, row.Expression, err)
			continue
		}
		if row.Accepted {
			if !owned.Accepted {
				t.Errorf("%s %q: the reference accepts it, the owned parser rejects it at %d..%d", row.Profile, row.Expression, owned.StartByte, owned.EndByte)
			}
			continue
		}
		if owned.Accepted {
			continue // acceptance of rejected rows is the HTTP differential's job
		}
		if owned.StartByte != row.Start {
			t.Errorf("%s %q: start %d, reference %d", row.Profile, row.Expression, owned.StartByte, row.Start)
			continue
		}
		if owned.EndByte != row.End {
			t.Errorf("%s %q: end %d, reference %d", row.Profile, row.Expression, owned.EndByte, row.End)
		}
	}
}
