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

// knownEndRangeDivergences are the rejected expressions whose owned error end
// still differs from the pinned parser's PositionRange.End (02.02-W1): the
// metric-name-twice check (whole selector incl. the closing brace), the
// experimental duration gate (the duration operand's own range) and the
// limitk() gate (the enclosing lastClosing). Lexer errors and the operator-part
// errors are fixed. Fixing a row removes it from this list: the test fails when
// a listed row starts to agree.
var knownEndRangeDivergences = map[string]bool{
	`1 + sum(limitk(2, rate(foo[5m])))`: true, `foo{__name__="bar"}`: true,
	`foo[5m + 1m]`: true, `foo[(5m)]`: true, `foo offset min_of(1h, 30m)`: true, `foo[10m:step()]`: true,
}

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
			Start, End int
		} `json:"rows"`
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Rows) < 394 {
		t.Fatalf("recorded range observations shrank to %d rows", len(f.Rows))
	}
	registry, err := profile.Load(os.DirFS("../../../profiles/query"))
	if err != nil {
		t.Fatal(err)
	}
	diverged := map[string]bool{}
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
		if err != nil || owned.Accepted {
			continue // acceptance is the HTTP differential's job
		}
		if owned.StartByte != row.Start {
			t.Errorf("%s %q: start %d, reference %d", row.Profile, row.Expression, owned.StartByte, row.Start)
			continue
		}
		if owned.EndByte != row.End {
			diverged[row.Expression] = true
			if !knownEndRangeDivergences[row.Expression] {
				t.Errorf("%s %q: end %d, reference %d", row.Profile, row.Expression, owned.EndByte, row.End)
			}
		}
	}
	for expression := range knownEndRangeDivergences {
		if !diverged[expression] {
			t.Errorf("%q: end now agrees under every profile; drop it from knownEndRangeDivergences", expression)
		}
	}
}
