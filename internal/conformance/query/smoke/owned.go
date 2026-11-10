// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smoke

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"soundpost/internal/model"
	"soundpost/internal/query"
)

// ownedFile mirrors cases/owned-query-smoke.json.
type ownedFile struct {
	Schema string `json:"schema"`
	Runner struct {
		Profiles []string `json:"profiles"`
	} `json:"runner"`
	Fixture   fixture         `json:"fixture"`
	Steps     []ownedStepSpec `json:"steps"`
	Forbidden struct {
		GetQueryRoutes    []string `json:"get_query_routes"`
		UpstreamShaped    []string `json:"upstream_shaped_routes"`
		UpstreamEngineMsg string   `json:"upstream_engine_clients"`
	} `json:"forbidden"`
}

type ownedStepSpec struct {
	ID       string          `json:"id"`
	Route    string          `json:"route"`
	As       string          `json:"as"`
	HoldScan bool            `json:"hold_scan"`
	Then     string          `json:"then"`
	Body     json.RawMessage `json:"body"`
	Pages    *struct {
		Order []string `json:"expect_items_in_order"`
	} `json:"pages"`
	Expect map[string]json.RawMessage `json:"expect"`
}

type fixture struct {
	Projects []string `json:"projects"`
	Sources  []struct {
		ID      string              `json:"id"`
		Project string              `json:"project"`
		Kinds   []string            `json:"kinds"`
		Labels  map[string][]string `json:"labels"`
	} `json:"sources"`
	MetricPoints []point `json:"metric_points"`
	Principals   []struct {
		ID     string              `json:"id"`
		Grants map[string][]string `json:"grants"`
	} `json:"principals"`
}

// Load builds the fixture on the node: projects, sources, principals and the
// admitted metric points. It returns the receipts for manifest reconciliation.
func (f fixture) Load(e *Env) []model.Receipt {
	for _, p := range f.Projects {
		e.AddProject(p)
	}
	for _, s := range f.Sources {
		var kinds []model.Kind
		for _, k := range s.Kinds {
			kinds = append(kinds, model.Kind(k))
		}
		e.AddSource(SourceSpec{Name: s.ID, Project: s.Project, Kinds: kinds, Labels: s.Labels})
	}
	for _, p := range f.Principals {
		e.AddPerson(p.ID)
		for project, perms := range p.Grants {
			e.Grant(p.ID, project, true, perms...)
		}
	}
	var receipts []model.Receipt
	for _, pt := range f.MetricPoints {
		s := e.Sources[pt.Source]
		checkf(s != nil, "unknown source %s", pt.Source)
		var exemplar *model.ID
		if pt.ExemplarTrace != "" {
			id := e.Name(pt.ExemplarTrace)
			exemplar = &id
		}
		receipts = append(receipts, e.Ingest(s, e.MetricRecord(s, pt.Name, pt.Labels, mustInt(pt.TimeNS), mustHex(pt.ValueBits), exemplar)))
	}
	return receipts
}

func mustInt(s string) int64 {
	var v int64
	_, err := fmt.Sscan(s, &v)
	check(err)
	return v
}
func mustHex(s string) uint64 {
	var v uint64
	_, err := fmt.Sscanf(s, "%x", &v)
	check(err)
	return v
}

// substitute rewrites project names and the org into a case body.
func (e *Env) body(raw json.RawMessage, language, profileID string) map[string]any {
	var m map[string]any
	check(json.Unmarshal(raw, &m))
	m["org"] = e.org.String()
	if ps, ok := m["projects"].([]any); ok {
		for i, p := range ps {
			name, _ := p.(string)
			if id, ok := e.Projects[name]; ok {
				ps[i] = id.String()
			}
		}
	}
	if _, ok := m["profile"]; !ok && profileID != "" {
		m["profile"] = profileID
		m["feature_set"] = e.Features[profileID]
	}
	if ev, ok := m["evaluation"].(map[string]any); ok {
		for _, k := range []string{"start", "end", "step"} {
			if _, has := ev[k]; !has {
				ev[k] = "0"
			}
		}
		if _, has := m["budget"]; !has {
			m["budget"] = map[string]any{"timeout_ns": "0", "memory_bytes": "0", "max_returned": "0"}
		}
	}
	if b, ok := m["budget"].(map[string]any); ok {
		for _, k := range []string{"timeout_ns", "memory_bytes", "max_returned"} {
			if _, has := b[k]; !has {
				b[k] = "0"
			}
		}
	}
	if _, ok := m["allow_partial"]; !ok && language != "" {
		if _, isQuery := m["evaluation"]; isQuery {
			m["allow_partial"] = false
		}
	}
	return m
}

// stripVolatile removes the per-request identifier so two denials compare.
func stripVolatile(raw []byte) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return string(raw)
	}
	delete(m, "request_id")
	out, _ := json.Marshal(m)
	return string(out)
}

func jsonField[T any](m map[string]json.RawMessage, key string) (T, bool) {
	var zero T
	raw, ok := m[key]
	if !ok {
		return zero, false
	}
	var v T
	check(json.Unmarshal(raw, &v))
	return v, true
}

// perProjectBits returns each project's single float result bits, by project name.
func (e *Env) perProjectBits(raw []byte) map[string]string {
	var r struct {
		Projects []struct {
			ProjectID    string `json:"project_id"`
			Completeness string `json:"completeness"`
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
	out := map[string]string{}
	for _, p := range r.Projects {
		for name, id := range e.Projects {
			if id.String() == p.ProjectID && p.Value != nil && len(p.Value.Vector) == 1 {
				checkf(p.Completeness == "complete", "project %s completeness %s", name, p.Completeness)
				out[name] = strings.ToLower(p.Value.Vector[0].Sample.Float)
			}
		}
	}
	return out
}

// RunOwned executes owned-query-smoke.json on a fresh node. Language steps run
// once per applicable pinned PromQL profile; steps are expectations authored
// from the fixture (never from an upstream engine).
func RunOwned(ctx context.Context, dir, path string) (steps []StepResult, err error) {
	defer recoverFailure(&err)
	var file ownedFile
	check(readJSON(path, &file))
	checkf(file.Schema == "soundpost-owned-query-smoke/1", "unknown schema %s", file.Schema)
	env, err := NewEnv(ctx, dir)
	check(err)
	defer env.Close()
	receipts := file.Fixture.Load(env)
	steps = append(steps, StepResult{Name: "fixture-admitted", Passed: len(receipts) == len(file.Fixture.MetricPoints), Detail: fmt.Sprintf("%d receipts for %d points", len(receipts), len(file.Fixture.MetricPoints))})
	for _, profileID := range file.Runner.Profiles {
		if !strings.HasPrefix(profileID, "promql-") {
			continue // the authored steps are PromQL and discovery steps only
		}
		for _, st := range file.Steps {
			name := profileID + "/" + st.ID
			result := StepResult{Name: name}
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
				env.ownedStep(ctx, &file, st, profileID)
				result.Passed = true
			}()
			steps = append(steps, result)
		}
	}
	// Forbidden routes: GET query routes and upstream-shaped routes are absent.
	forbidden := StepResult{Name: "forbidden-routes-absent", Passed: true}
	for _, route := range file.Forbidden.GetQueryRoutes {
		if code := env.Do("GET", route); code != 405 && code != 404 {
			forbidden.Passed, forbidden.Detail = false, fmt.Sprintf("GET %s answered %d", route, code)
		}
	}
	for _, route := range file.Forbidden.UpstreamShaped {
		for _, method := range []string{"GET", "POST"} {
			if code := env.Do(method, route); code != 404 && code != 405 {
				forbidden.Passed, forbidden.Detail = false, fmt.Sprintf("%s %s answered %d", method, route, code)
			}
		}
	}
	steps = append(steps, forbidden)
	return steps, nil
}

func (e *Env) ownedStep(ctx context.Context, file *ownedFile, st ownedStepSpec, profileID string) {
	who := e.People[st.As]
	checkf(who != nil, "unknown principal %s", st.As)
	language := "promql"
	body := e.body(st.Body, language, profileID)
	if st.Route == "/api/v1/query/format" {
		body["projects"] = []string{e.Projects["project-a"].String()}
		body["profile"], body["feature_set"] = profileID, e.Features[profileID]
	}
	switch {
	case st.HoldScan && strings.HasPrefix(st.Then, "revoke"):
		e.revocationDuringCompute(st.Route, who, body)
		return
	case st.HoldScan:
		e.cancellationReleasesEverything(st.Route, who, body, st.Expect)
		return
	}
	code, out := e.Post(who, st.Route, body)
	if want, ok := jsonField[int](st.Expect, "status"); ok {
		checkf(code == want, "status %d want %d: %s", code, want, trim(out))
	}
	if want, ok := jsonField[string](st.Expect, "code"); ok {
		var f struct {
			Code string `json:"code"`
		}
		check(json.Unmarshal(out, &f))
		checkf(f.Code == want, "code %q want %q", f.Code, want)
	}
	if st.Pages != nil {
		e.pagedItems(st.Route, who, body, st.Pages.Order)
		return
	}
	if want, ok := jsonField[[]string](st.Expect, "items"); ok {
		var d query.DiscoveryResult
		check(json.Unmarshal(out, &d))
		checkf(fmt.Sprint(d.Items) == fmt.Sprint(want), "items %v want %v", d.Items, want)
		if more, ok := jsonField[bool](st.Expect, "more"); ok {
			checkf(d.More == more, "more=%v", d.More)
		}
		if c, ok := jsonField[string](st.Expect, "completeness"); ok {
			checkf(d.Freshness.Completeness == c, "completeness %q want %q", d.Freshness.Completeness, c)
		}
	}
	if traces, ok := jsonField[[]string](st.Expect, "exemplar_traces"); ok {
		var r query.ExemplarResult
		check(json.Unmarshal(out, &r))
		projects, _ := jsonField[[]string](st.Expect, "exemplar_projects")
		checkf(len(r.Exemplars) == len(traces), "%d exemplars want %d", len(r.Exemplars), len(traces))
		for i, ex := range r.Exemplars {
			checkf(ex.Trace == e.Name(traces[i]), "exemplar trace is not %s", traces[i])
			checkf(ex.Project == e.Projects[projects[i]], "exemplar project is not %s", projects[i])
		}
	}
	if formatted, ok := jsonField[string](st.Expect, "formatted"); ok {
		var r query.FormatResult
		check(json.Unmarshal(out, &r))
		checkf(r.Formatted == formatted, "formatted %q want %q", r.Formatted, formatted)
	}
	if want, ok := jsonField[map[string]string](st.Expect, "per_project_float_bits"); ok {
		got := e.perProjectBits(out)
		checkf(fmt.Sprint(got) == fmt.Sprint(want), "per-project bits %v want %v", got, want)
		if merged, ok := jsonField[string](st.Expect, "never_merged_value_bits"); ok {
			checkf(!bytes.Contains(bytes.ToLower(out), []byte(merged)), "a merged cross-project value %s appeared", merged)
		}
	}
	if same, _ := jsonField[bool](st.Expect, "same_body_as_nonexistent_project"); same {
		ghost := e.body(st.Body, language, profileID)
		ghost["projects"] = []string{model.NewID().String()}
		gcode, gout := e.Post(who, st.Route, ghost)
		checkf(gcode == code && stripVolatile(gout) == stripVolatile(out), "a foreign project is distinguishable from a nonexistent one: %d %s vs %d %s", code, trim(out), gcode, trim(gout))
	}
	if none, _ := jsonField[bool](st.Expect, "no_value_in_body"); none {
		checkf(!bytes.Contains(out, []byte(`"vector"`)) && !bytes.Contains(out, []byte(`"float"`)), "an error response carries a value: %s", trim(out))
	}
}

func trim(b []byte) string {
	if len(b) > 200 {
		b = b[:200]
	}
	return string(b)
}

func (e *Env) pagedItems(route string, who *Person, body map[string]any, order []string) {
	var items []string
	for page := 0; page < 20; page++ {
		code, out := e.Post(who, route, body)
		checkf(code == 200, "page status %d", code)
		var d query.DiscoveryResult
		check(json.Unmarshal(out, &d))
		items = append(items, d.Items...)
		checkf(d.More == (d.NextCursor != ""), "more=%v with cursor %q", d.More, d.NextCursor)
		if d.NextCursor == "" {
			checkf(fmt.Sprint(items) == fmt.Sprint(order), "paged items %v want %v", items, order)
			return
		}
		body["cursor"] = d.NextCursor
	}
	checkf(false, "paging did not terminate")
}

// revocationDuringCompute holds the scan, revokes the grant, and requires the
// request to finish as a denial WITHOUT the scan being released.
func (e *Env) revocationDuringCompute(route string, who *Person, body map[string]any) {
	release := e.gate.arm()
	defer func() { e.gate.disarm() }()
	done := make(chan struct {
		code int
		out  []byte
	}, 1)
	raw, _ := json.Marshal(body)
	go func() {
		c, o := e.PostRaw(who, route, raw, nil)
		done <- struct {
			code int
			out  []byte
		}{c, o}
	}()
	waitFor(func() bool { return e.gate.heldCount() > 0 }, "the scan was never reached")
	principal := strings.TrimSuffix(who.Email, "@example.test")
	e.Grant(principal, "project-a", false, "telemetry.read")
	select {
	case r := <-done:
		checkf(r.code == 404, "revoked request answered %d, want 404: %s", r.code, trim(r.out))
		checkf(!bytes.Contains(r.out, []byte(`"vector"`)) && !bytes.Contains(r.out, []byte(`"float"`)), "a revoked request returned a value")
	case <-time.After(10 * time.Second):
		close(release)
		<-done
		checkf(false, "the request did not finish after revocation without the scan being released")
	}
	close(release)
	// Re-grant so later steps are unaffected.
	e.Grant(principal, "project-a", true, "telemetry.read")
	waitFor(func() bool { return e.gate.openCount() == 0 }, "iterators left open")
}

func (e *Env) cancellationReleasesEverything(route string, who *Person, body map[string]any, expect map[string]json.RawMessage) {
	release := e.gate.arm()
	defer e.gate.disarm()
	ctx, cancel := context.WithCancel(context.Background())
	raw, _ := json.Marshal(body)
	finished := make(chan struct{})
	go func() { e.PostRaw(who, route, raw, ctx); close(finished) }()
	waitFor(func() bool { return e.gate.heldCount() > 0 }, "the scan was never reached")
	cancel()
	<-finished
	close(release)
	waitFor(func() bool {
		u := e.engine.Usage()
		return e.gate.openCount() == 0 && e.gate.heldCount() == 0 && u.OpenIterators == 0 && u.MemoryUsed == 0 && u.ActiveQueries == 0 && u.QueuedQueries == 0
	}, "resources remained after cancellation")
	u := e.engine.Usage()
	checkf(u.LeakedBytes == 0 && u.OverReleasedBytes == 0, "accounting violation leaked=%d over=%d", u.LeakedBytes, u.OverReleasedBytes)
}

func waitFor(cond func() bool, what string) {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	checkf(false, "timed out: %s", what)
}
