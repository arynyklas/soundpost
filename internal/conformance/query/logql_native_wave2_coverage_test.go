// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestRecordedWave2ObservationsCoverEveryAuthoredRowAndTheFourOpenQuestions pins what
// TestOwnedMatchesRecordedNativeLogQLWave2Observations replays (07.05#11): the four
// questions lane 2 wave 1 left open (approx_topk(-1), group modifiers, bool on
// arithmetic, zero-length ranges) were each observed on the lock-pinned Loki 3.5.2
// oracle, and the owned engine is compared with every one of those observations.
// The replay test only has a floor on the number of recorded rows: this test says
// which rows those are. Every row of the content-locked authored file has a recorded
// observation, and each question has recorded accepted and rejected answers of the
// reference where the reference gives both, so an observation file that lost one
// question (or recorded it vacuously) fails here.
func TestRecordedWave2ObservationsCoverEveryAuthoredRowAndTheFourOpenQuestions(t *testing.T) {
	var lock SourceLock
	if err := ReadJSON("../../../conformance/query/source-lock.json", &lock); err != nil {
		t.Fatal(err)
	}
	raw, err := readLocked(lock, "cases/logql-wave2-divergences.json", "../../../conformance/query/cases/logql-wave2-divergences.json")
	if err != nil {
		t.Fatal(err)
	}
	var authored struct {
		Cases []struct {
			ID string `json:"id"`
		} `json:"cases"`
	}
	if err = json.Unmarshal(raw, &authored); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile("testdata/native-logql-wave2-observations.json")
	if err != nil {
		t.Fatal(err)
	}
	var recorded struct {
		Rows []struct {
			Case struct {
				ID    string `json:"id"`
				Query string `json:"query"`
				Input struct {
					Expression string `json:"expression"`
				} `json:"input"`
			} `json:"case"`
			Reference struct {
				Accepted bool `json:"accepted"`
				Error    *struct {
					Semantic string `json:"semantic"`
				} `json:"error"`
			} `json:"reference"`
		} `json:"rows"`
	}
	if err = json.Unmarshal(raw, &recorded); err != nil {
		t.Fatal(err)
	}
	observed := map[string]bool{}
	for _, r := range recorded.Rows {
		observed[r.Case.ID] = true
	}
	if len(authored.Cases) < 539 {
		t.Fatalf("the locked wave-2 case file shrank to %d rows", len(authored.Cases))
	}
	for _, c := range authored.Cases {
		if !observed[c.ID] {
			t.Errorf("authored row %s has no recorded observation of the reference", c.ID)
		}
	}
	type tally struct{ rows, accepted, rejected int }
	questions := []struct {
		name                     string
		pattern                  *regexp.Regexp
		rows, accepted, rejected int
	}{
		{"approx_topk(-1)", regexp.MustCompile(`approx_topk\(-1,`), 2, 0, 2},
		{"group modifiers", regexp.MustCompile(`group_(left|right)`), 120, 100, 14},
		{"bool on arithmetic", regexp.MustCompile(`\bbool\b`), 90, 80, 12},
		{"zero-length range", regexp.MustCompile(`\[0(s|m|ms|h|d|s0s)\]`), 150, 150, 6},
	}
	for _, q := range questions {
		var got tally
		for _, r := range recorded.Rows {
			if !q.pattern.MatchString(r.Case.Query + r.Case.Input.Expression) {
				continue
			}
			got.rows++
			if r.Reference.Accepted {
				got.accepted++
			} else {
				got.rejected++
			}
			if q.name == "approx_topk(-1)" && (r.Reference.Error == nil || !strings.HasPrefix(r.Reference.Error.Semantic, "syntax.")) {
				t.Errorf("%s: the reference did not reject it as a syntax error: %+v", r.Case.ID, r.Reference)
			}
		}
		if got.rows < q.rows || got.accepted < q.accepted || got.rejected < q.rejected {
			t.Errorf("%s: recorded %+v, floors rows %d accepted %d rejected %d", q.name, got, q.rows, q.accepted, q.rejected)
		}
	}
}
