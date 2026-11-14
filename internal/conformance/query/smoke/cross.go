// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smoke

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/arynyklas/soundpost/profiles"
)

type crossFile struct {
	Schema  string  `json:"schema"`
	Fixture fixture `json:"fixture"`
	Runner  struct {
		Stages []string `json:"stages"`
	} `json:"runner"`
	Cross []struct {
		ID         string                     `json:"id"`
		Expression string                     `json:"expression"`
		TimeNS     string                     `json:"time_ns"`
		Enabled    []string                   `json:"enabled"`
		Expect     map[string]json.RawMessage `json:"expect"`
	} `json:"cross_products"`
}

// featureSetFor resolves a registered feature set whose enabled gates are
// exactly the given ones.
func featureSetFor(profileID string, enabled []string) (string, error) {
	files, err := profiles.Query()
	if err != nil {
		return "", err
	}
	raw, err := fs.ReadFile(files, profileID+".json")
	if err != nil {
		return "", err
	}
	var m struct {
		FeatureSets []struct {
			ID      string   `json:"id"`
			Enabled []string `json:"enabled"`
		} `json:"feature_sets"`
	}
	if err = json.Unmarshal(raw, &m); err != nil {
		return "", err
	}
	want := append([]string(nil), enabled...)
	sort.Strings(want)
	for _, set := range m.FeatureSets {
		got := append([]string(nil), set.Enabled...)
		sort.Strings(got)
		if strings.Join(got, ",") == strings.Join(want, ",") {
			return set.ID, nil
		}
	}
	return "", fmt.Errorf("no registered feature set enables exactly %v in %s", enabled, profileID)
}

// RunCross executes profile-cross-products.json: every query under each exact
// profile with its own expectation, hot / flushed / compacted / restarted.
func RunCross(ctx context.Context, layout Layout, dir, path string) (steps []StepResult, err error) {
	defer recoverFailure(&err)
	var file crossFile
	check(readJSON(path, &file))
	checkf(file.Schema == "soundpost-profile-cross-products/1", "unknown schema %s", file.Schema)
	env, err := NewEnv(ctx, layout, dir)
	check(err)
	defer env.Close()
	file.Fixture.Load(env)
	stage := func(name string) {
		for _, c := range file.Cross {
			for profileID, raw := range c.Expect {
				result := StepResult{Name: name + "/" + profileID + "/" + c.ID}
				func() {
					defer func() {
						switch r := recover().(type) {
						case nil:
						case failure:
							result.Detail = r.err.Error()
						default:
							panic(r)
						}
					}()
					set, err := featureSetFor(profileID, c.Enabled)
					check(err)
					body := env.QueryBody("promql", profileID, c.Expression, mustInt(c.TimeNS), file.Fixture.Projects...)
					body["feature_set"] = set
					code, out := env.Post(env.People["reader"], "/api/v1/query", body)
					var want struct {
						Status  int      `json:"status"`
						Code    string   `json:"code"`
						Project []string `json:"project-a"`
					}
					check(json.Unmarshal(raw, &want))
					checkf(code == want.Status, "status %d want %d: %s", code, want.Status, trim(out))
					if want.Status != 200 {
						var f struct {
							Code string `json:"code"`
						}
						check(json.Unmarshal(out, &f))
						checkf(f.Code == want.Code, "code %q want %q", f.Code, want.Code)
						checkf(!strings.Contains(string(out), `"vector"`), "a language error carries a value")
					} else {
						got := env.projectVector(out)["project-a"]
						checkf(fmt.Sprint(got) == fmt.Sprint(want.Project), "got %v want %v", got, want.Project)
					}
					result.Passed = true
				}()
				steps = append(steps, result)
			}
		}
	}
	stage("hot")
	check(env.app.Storage.Flush(ctx))
	stage("flush")
	check(env.app.Storage.Compact(ctx))
	stage("compaction")
	check(env.Restart())
	stage("restart")
	return steps, nil
}
