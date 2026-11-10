// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smoke

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"

	"soundpost/internal/auth"
	q "soundpost/internal/conformance/query"
	"soundpost/internal/model"
	"soundpost/internal/storage"
)

type persistedFile struct {
	Schema string `json:"schema"`
	Runner struct {
		Stages   []string `json:"stages"`
		Modes    []string `json:"modes"`
		Profiles []string `json:"profiles"`
	} `json:"runner"`
	Fixture  fixture `json:"fixture"`
	Resends  []point `json:"resends"`
	Conflict point   `json:"conflict"`
	Queries  []struct {
		ID         string              `json:"id"`
		Expression string              `json:"expression"`
		TimeNS     string              `json:"time_ns"`
		Expect     map[string][]string `json:"expect"`
	} `json:"queries"`
}

type point struct {
	Source        string            `json:"source"`
	Name          string            `json:"name"`
	Labels        map[string]string `json:"labels"`
	TimeNS        string            `json:"time_ns"`
	ValueBits     string            `json:"value_bits"`
	ExemplarTrace string            `json:"exemplar_trace"`
}

// storedRow is what a raw storage scan returns for one metric sample.
type storedRow struct {
	Project string
	Name    string
	Labels  string
	Time    string
	Bits    string
}

func (e *Env) scanMetrics(project string) []storedRow {
	scope, err := e.app.Auth.Authorize(e.ctx, e.owner.Cred, e.org, []model.ID{e.Projects[project]}, auth.Read)
	check(err)
	rows, err := e.app.Storage.Scan(e.ctx, scope, storage.ScanRequest{Projects: []model.ID{e.Projects[project]}, Signal: model.Metric, Start: math.MinInt64, End: math.MaxInt64})
	check(err)
	defer rows.Close()
	var out []storedRow
	for {
		page, err := rows.Next(e.ctx)
		if err == io.EOF {
			return out
		}
		check(err)
		for i := range page.Len() {
			m := page.Values[i].Metric
			if m == nil || m.Value == nil {
				continue
			}
			var ls []string
			for _, l := range m.Labels {
				ls = append(ls, l.Name+"="+l.Value)
			}
			out = append(out, storedRow{Project: project, Name: m.Name, Labels: strings.Join(ls, ","), Time: decimal(int64(page.ObservedTimes[i])), Bits: fmt.Sprintf("%016x", uint64(*m.Value))})
		}
	}
}

func distinct(rows []storedRow) []storedRow {
	seen := map[storedRow]bool{}
	var out []storedRow
	for _, r := range rows {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return fmt.Sprint(out[i]) < fmt.Sprint(out[j]) })
	return out
}

// projectBits returns, per project name, the sorted float bits of the vector.
func (e *Env) projectVector(raw []byte) map[string][]string {
	var r struct {
		Projects []struct {
			ProjectID    string `json:"project_id"`
			Completeness string `json:"completeness"`
			Failure      any    `json:"failure"`
			Value        *struct {
				Vector []struct {
					Sample struct {
						Float string `json:"float"`
					} `json:"sample"`
				} `json:"vector"`
			} `json:"value"`
		} `json:"projects"`
	}
	check(json.Unmarshal(raw, &r))
	out := map[string][]string{}
	for _, p := range r.Projects {
		for name, id := range e.Projects {
			if id.String() != p.ProjectID {
				continue
			}
			checkf(p.Failure == nil && p.Completeness == "complete" && p.Value != nil, "project %s did not answer completely (%s)", name, p.Completeness)
			bits := []string{}
			for _, v := range p.Value.Vector {
				bits = append(bits, strings.ToLower(v.Sample.Float))
			}
			sort.Strings(bits)
			out[name] = bits
		}
	}
	return out
}

// PersistedResult is the outcome of persisted-path.json.
type PersistedResult struct {
	Steps         []StepResult
	Persistence   []q.ScenarioOutcome
	Normalization []q.NormalizationCheck
}

// RunPersisted executes persisted-path.json: the same authored answers must hold
// hot, after a flush, with several segments, after a compaction, after a
// restart and after a restart following compaction; admission receipts and
// the stored distinct samples must reconcile with what was sent at each stage.
func RunPersisted(ctx context.Context, dir, path string) (res PersistedResult, err error) {
	defer recoverFailure(&err)
	var file persistedFile
	check(readJSON(path, &file))
	checkf(file.Schema == "soundpost-persisted-path/1", "unknown schema %s", file.Schema)
	env, err := NewEnv(ctx, dir)
	check(err)
	defer env.Close()
	// The owner needs read on both projects to reconcile raw scans.
	for _, p := range file.Fixture.Projects {
		env.AddProject(p)
	}
	for _, s := range file.Fixture.Sources {
		var kinds []model.Kind
		for _, k := range s.Kinds {
			kinds = append(kinds, model.Kind(k))
		}
		env.AddSource(SourceSpec{Name: s.ID, Project: s.Project, Kinds: kinds, Labels: s.Labels})
	}
	for _, pr := range file.Fixture.Principals {
		env.AddPerson(pr.ID)
		for project, perms := range pr.Grants {
			env.Grant(pr.ID, project, true, perms...)
		}
	}
	send := func(p point) {
		s := env.Sources[p.Source]
		checkf(s != nil, "unknown source %s", p.Source)
		env.Ingest(s, env.MetricRecord(s, p.Name, p.Labels, mustInt(p.TimeNS), mustHex(p.ValueBits), nil))
	}
	var sent int
	expected := map[storedRow]bool{}
	var authored []q.InputRecord
	remember := func(p point) {
		project := env.Sources[p.Source].Project
		var ls []string
		keys := make([]string, 0, len(p.Labels))
		for k := range p.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			ls = append(ls, k+"="+p.Labels[k])
		}
		expected[storedRow{project, p.Name, strings.Join(ls, ","), p.TimeNS, p.ValueBits}] = true
	}
	for _, p := range file.Fixture.MetricPoints {
		send(p)
		sent++
		remember(p)
		authored = append(authored, inputOf(env, p))
	}
	// Exact duplicates re-sent as later batches: they must collapse, never double.
	resend := func() {
		for _, p := range file.Resends {
			send(p)
			sent++
			remember(p)
		}
	}
	record := func(name string, passed bool, detail string) {
		res.Steps = append(res.Steps, StepResult{Name: name, Passed: passed, Detail: detail})
	}
	stageCheck := func(stage string) {
		failures := 0
		for _, profileID := range file.Runner.Profiles {
			for _, qr := range file.Queries {
				body := env.QueryBody("promql", profileID, qr.Expression, mustInt(qr.TimeNS), file.Fixture.Projects...)
				code, out := env.Post(env.People["reader"], "/api/v1/query", body)
				name := stage + "/" + profileID + "/" + qr.ID
				if code != 200 {
					record(name, false, fmt.Sprintf("status %d %s", code, trim(out)))
					failures++
					continue
				}
				got := env.projectVector(out)
				ok := true
				for project, want := range qr.Expect {
					if fmt.Sprint(got[project]) != fmt.Sprint(want) {
						ok = false
						record(name, false, fmt.Sprintf("%s: got %v want %v", project, got[project], want))
					}
				}
				if ok {
					record(name, true, "")
				} else {
					failures++
				}
			}
		}
		// Manifest: receipts sent == batches admitted; stored distinct samples == sent distinct samples.
		var rows []storedRow
		for _, p := range file.Fixture.Projects {
			rows = append(rows, env.scanMetrics(p)...)
		}
		stored := distinct(rows)
		manifestOK := len(stored) == len(expected)
		for _, r := range stored {
			manifestOK = manifestOK && expected[r]
		}
		record(stage+"/manifest-reconciles", manifestOK, fmt.Sprintf("%d raw rows, %d distinct stored, %d distinct sent from %d batches", len(rows), len(stored), len(expected), sent))
		var normalized []q.InputRecord
		for _, r := range stored {
			if r.Project == "project-a" || r.Project == "project-b" {
				normalized = append(normalized, rowInput(r))
			}
		}
		sort.Slice(normalized, func(i, j int) bool { return canonicalKey(normalized[i]) < canonicalKey(normalized[j]) })
		src := append([]q.InputRecord(nil), authored...)
		sort.Slice(src, func(i, j int) bool { return canonicalKey(src[i]) < canonicalKey(src[j]) })
		res.Normalization = append(res.Normalization, q.NormalizationCheck{ID: "persisted-path/" + stage, Profile: "promql-prometheus-3.13.5", Source: src, Normalized: normalized})
		res.Persistence = append(res.Persistence, q.ScenarioOutcome{Name: stage + "-queries", Passed: failures == 0})
		res.Persistence = append(res.Persistence, q.ScenarioOutcome{Name: stage + "-manifest", Passed: manifestOK})
	}
	stageCheck("hot")
	check(env.app.Storage.Flush(ctx))
	stageCheck("flush")
	resend()
	check(env.app.Storage.Flush(ctx))
	stageCheck("multi-segment")
	check(env.app.Storage.Compact(ctx))
	stageCheck("compaction")
	check(env.Restart())
	stageCheck("restart")
	check(env.app.Storage.Compact(ctx))
	check(env.Restart())
	stageCheck("restart-after-compaction")
	// A conflicting duplicate (same series and time, different value) is not
	// admitted silently and changes no answer.
	conflict := file.Conflict
	s := env.Sources[conflict.Source]
	func() {
		defer func() {
			r := recover()
			if f, ok := r.(failure); ok {
				record("conflicting-duplicate-is-not-admitted", true, f.err.Error())
				return
			}
			if r != nil {
				panic(r)
			}
			record("conflicting-duplicate-is-not-admitted", false, "the conflicting duplicate was acknowledged")
		}()
		env.Ingest(s, env.MetricRecord(s, conflict.Name, conflict.Labels, mustInt(conflict.TimeNS), mustHex(conflict.ValueBits), nil))
	}()
	stageCheck("after-conflict")
	// Collate the named persistence scenarios from the stage outcomes.
	pass := func(names ...string) bool {
		for _, n := range names {
			ok := false
			for _, o := range res.Persistence {
				if o.Name == n && o.Passed {
					ok = true
				}
			}
			if !ok {
				return false
			}
		}
		return true
	}
	res.Persistence = append(res.Persistence,
		q.ScenarioOutcome{Name: "hot-read", Passed: pass("hot-queries")},
		q.ScenarioOutcome{Name: "flush", Passed: pass("flush-queries", "multi-segment-queries")},
		q.ScenarioOutcome{Name: "compaction", Passed: pass("compaction-queries")},
		q.ScenarioOutcome{Name: "restart", Passed: pass("restart-queries", "restart-after-compaction-queries")},
		q.ScenarioOutcome{Name: "receipt-manifest-reconciles", Passed: pass("hot-manifest", "flush-manifest", "multi-segment-manifest", "compaction-manifest", "restart-manifest", "restart-after-compaction-manifest", "after-conflict-manifest")},
	)
	return res, nil
}

func inputOf(e *Env, p point) q.InputRecord {
	var ls []string
	keys := make([]string, 0, len(p.Labels))
	for k := range p.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ls = append(ls, k+"="+p.Labels[k])
	}
	return q.InputRecord{Kind: "float", Timestamp: p.TimeNS, Name: e.Sources[p.Source].Project + "/" + p.Name + "{" + strings.Join(ls, ",") + "}", Bits: p.ValueBits}
}

func rowInput(r storedRow) q.InputRecord {
	return q.InputRecord{Kind: "float", Timestamp: r.Time, Name: r.Project + "/" + r.Name + "{" + r.Labels + "}", Bits: r.Bits}
}

func canonicalKey(r q.InputRecord) string { return r.Name + "\x00" + r.Timestamp + "\x00" + r.Bits }
