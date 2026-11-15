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

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
	"github.com/arynyklas/soundpost/internal/storage"
)

// faultMode is an injected failure of the scan seam.
type faultMode int

const (
	faultNone faultMode = iota
	// faultCorruptAtOnce makes the first page read fail as corrupt storage.
	faultCorruptAtOnce
	// faultCorruptAfterFirstPage lets one page through and then reports corrupt
	// storage where the stream would have ended: a scan that is cut short must
	// never read as a complete, shorter answer.
	faultCorruptAfterFirstPage
)

// faultyRows is the iterator the gate hands out under an injected fault.
type faultyRows struct {
	storage.RowIterator
	mode  faultMode
	pages int
}

func (f *faultyRows) Next(ctx context.Context) (storage.Page, error) {
	switch f.mode {
	case faultCorruptAtOnce:
		return storage.Page{}, model.Fail(model.Corrupt)
	case faultCorruptAfterFirstPage:
		if f.pages == 0 {
			f.pages++
			return f.RowIterator.Next(ctx)
		}
		return storage.Page{}, model.Fail(model.Corrupt)
	}
	return f.RowIterator.Next(ctx)
}

// cacheSection is the "cache" part of persisted-path.json: one authored
// query that the cache stages and the fault rows run under many cache keys
// (the "{k}" of the expression is a number added and subtracted again, so every
// k is a different cache key with the same authored answer).
type cacheSection struct {
	Expression string              `json:"expression"`
	TimeNS     string              `json:"time_ns"`
	Profile    string              `json:"profile"`
	Projects   []string            `json:"projects"`
	Expect     map[string][]string `json:"expect"`
}

type asked struct {
	code int
	raw  []byte
}

func (c cacheSection) expression(k int) string {
	return strings.ReplaceAll(c.Expression, "{k}", fmt.Sprint(k))
}

func (e *Env) askCache(c cacheSection, k int, allowPartial bool) asked {
	body := e.QueryBody("promql", c.Profile, c.expression(k), mustInt(c.TimeNS), c.Projects...)
	body["allow_partial"] = allowPartial
	code, raw := e.Post(e.People["reader"], "/api/v1/query", body)
	return asked{code, raw}
}

// result parses a 200 answer.
func (a asked) result() query.Result {
	checkf(a.code == 200, "status %d %s", a.code, trim(a.raw))
	var res query.Result
	check(json.Unmarshal(a.raw, &res))
	return res
}

// cachedFlags reports how many projects of a 200 answer were served from the
// cache and how many were computed.
func (a asked) cachedFlags() (cached, computed int) {
	for _, p := range a.result().Projects {
		if p.Stats.Cached {
			cached++
		} else {
			computed++
		}
	}
	return
}

// answers checks a 200 answer carries exactly the authored per-project values.
func (e *Env) answers(a asked, want map[string][]string) string {
	if a.code != 200 {
		return fmt.Sprintf("status %d %s", a.code, trim(a.raw))
	}
	got := e.projectVector(a.raw)
	for project, bits := range want {
		if fmt.Sprint(got[project]) != fmt.Sprint(bits) {
			return fmt.Sprintf("%s: got %v want %v", project, got[project], bits)
		}
	}
	return ""
}

// typedFailure checks an answer is an error with a closed fault code and no
// value anywhere in the body: never a 200, never an empty success.
func typedFailure(a asked, codes ...string) string {
	if a.code == 200 {
		return "a failure was answered 200: " + trim(a.raw)
	}
	var f struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(a.raw, &f) != nil || f.Code == "" {
		return fmt.Sprintf("status %d without a typed code: %s", a.code, trim(a.raw))
	}
	ok := false
	for _, c := range codes {
		ok = ok || f.Code == c
	}
	if !ok {
		return fmt.Sprintf("status %d code %q, want one of %v: %s", a.code, f.Code, codes, trim(a.raw))
	}
	for _, v := range []string{`"vector"`, `"float"`, `"streams"`, `"matrix"`} {
		if bytes.Contains(a.raw, []byte(v)) {
			return "an error body carries a value: " + trim(a.raw)
		}
	}
	return ""
}

// stepOf runs fn as one named step, turning a failed check into a failing step.
func stepOf(name string, fn func() string) StepResult {
	st := StepResult{Name: name}
	func() {
		defer func() {
			switch r := recover().(type) {
			case nil:
			case failure:
				st.Detail = r.err.Error()
			default:
				panic(r)
			}
		}()
		if d := fn(); d != "" {
			st.Detail = d
			return
		}
		st.Passed = true
	}()
	return st
}

// cacheHook runs the warm/cold authorized-cache stages at every persisted stage
// and, at the end, the injected scan faults. A result computed for a request is
// served warm only while nothing it depends on moved: flushing and compacting
// move bytes, never the data, so they keep an entry; a restart empties the
// in-memory cache; a delete generation advance, a revoked grant, a missing
// shard or a corrupt scan never produce a cached or an empty success.
func cacheHook(env *Env, c cacheSection) persistedHook {
	stage := 0
	prev := 0
	return persistedHook{
		name: "cache-and-faults",
		check: func(name string) []StepResult {
			stage++
			k := stage
			var steps []StepResult
			prefix := name + "/cache/"
			steps = append(steps, stepOf(prefix+"cold", func() string {
				a := env.askCache(c, k, false)
				if d := env.answers(a, c.Expect); d != "" {
					return d
				}
				if cached, _ := a.cachedFlags(); cached != 0 {
					return fmt.Sprintf("a never-asked query was served from the cache for %d projects", cached)
				}
				return ""
			}))
			steps = append(steps, stepOf(prefix+"warm", func() string {
				a := env.askCache(c, k, false)
				if d := env.answers(a, c.Expect); d != "" {
					return d
				}
				if _, computed := a.cachedFlags(); computed != 0 {
					return fmt.Sprintf("the identical query was recomputed for %d projects", computed)
				}
				return ""
			}))
			if prev != 0 {
				restarted := strings.HasPrefix(name, "restart")
				steps = append(steps, stepOf(prefix+"previous-stage-entry", func() string {
					a := env.askCache(c, prev, false)
					if d := env.answers(a, c.Expect); d != "" {
						return d
					}
					cached, computed := a.cachedFlags()
					if restarted && cached != 0 {
						return fmt.Sprintf("an entry computed before the restart was served from the cache for %d projects", cached)
					}
					if !restarted && computed != 0 {
						return fmt.Sprintf("a flush or compaction dropped the entry: %d projects were recomputed", computed)
					}
					return ""
				}))
			}
			prev = k
			return steps
		},
		final: func() []StepResult { return faultRows(env, c) },
	}
}

// faultRows are the rows that run once the persisted stages are done.
func faultRows(env *Env, c cacheSection) []StepResult {
	var steps []StepResult
	add := func(name string, fn func() string) { steps = append(steps, stepOf("faults/"+name, fn)) }
	next := 100
	key := func() int { next++; return next }
	partialFailure := func(a asked, code string) string {
		res := a.result()
		if len(res.Projects) != len(c.Projects) {
			return fmt.Sprintf("%d project results for %d projects", len(res.Projects), len(c.Projects))
		}
		for _, p := range res.Projects {
			if p.Completeness == query.CompletenessComplete || p.Value != nil || p.Failure == nil || p.Failure.Code != code {
				return fmt.Sprintf("project %s: completeness %q value %v failure %+v, want a partial result carrying only the typed failure %q", p.ProjectID, p.Completeness, p.Value != nil, p.Failure, code)
			}
		}
		return ""
	}

	add("revoked-reader-is-never-served-a-warm-entry", func() string {
		k := key()
		env.askCache(c, k, false)
		if cached, _ := env.askCache(c, k, false).cachedFlags(); cached != len(c.Projects) {
			return "the entry never became warm"
		}
		for _, p := range c.Projects {
			env.Grant("reader", p, false, "telemetry.read")
		}
		a := env.askCache(c, k, false)
		d := typedFailure(a, "not_found", "forbidden")
		for _, p := range c.Projects {
			env.Grant("reader", p, true, "telemetry.read")
		}
		if d != "" {
			return d
		}
		return env.answers(env.askCache(c, k, false), c.Expect)
	})

	add("missing-shard-is-unavailable-never-empty", func() string {
		env.gate.setDown(true)
		defer env.gate.setDown(false)
		if d := typedFailure(env.askCache(c, key(), false), "unavailable"); d != "" {
			return "strict: " + d
		}
		if d := partialFailure(env.askCache(c, key(), true), "unavailable"); d != "" {
			return "partial: " + d
		}
		return ""
	})
	add("missing-shard-leaves-no-cached-failure", func() string {
		k := key()
		mark := env.stores.mark()
		env.gate.setDown(true)
		env.askCache(c, k, true)
		if d := env.stores.failedSince(mark); d != "" {
			env.gate.setDown(false)
			return d
		}
		env.gate.setDown(false)
		a := env.askCache(c, k, false)
		if d := env.answers(a, c.Expect); d != "" {
			return d
		}
		if cached, _ := a.cachedFlags(); cached != 0 {
			return "a failed answer was served from the cache afterwards"
		}
		return ""
	})

	for _, tc := range []struct {
		name string
		mode faultMode
	}{{"corrupt-first-page", faultCorruptAtOnce}, {"scan-cut-short-by-corruption", faultCorruptAfterFirstPage}} {
		tc := tc
		add(tc.name+"-is-corrupt-never-empty", func() string {
			env.gate.setFault(tc.mode)
			defer env.gate.setFault(faultNone)
			if d := typedFailure(env.askCache(c, key(), false), "corrupt"); d != "" {
				return "strict: " + d
			}
			if d := partialFailure(env.askCache(c, key(), true), "corrupt"); d != "" {
				return "partial: " + d
			}
			return ""
		})
		add(tc.name+"-leaves-no-cached-failure", func() string {
			k := key()
			mark := env.stores.mark()
			env.gate.setFault(tc.mode)
			env.askCache(c, k, true)
			if d := env.stores.failedSince(mark); d != "" {
				env.gate.setFault(faultNone)
				return d
			}
			env.gate.setFault(faultNone)
			a := env.askCache(c, k, false)
			if d := env.answers(a, c.Expect); d != "" {
				return d
			}
			if cached, _ := a.cachedFlags(); cached != 0 {
				return "a failed answer was served from the cache afterwards"
			}
			return ""
		})
	}

	add("warm-entry-dies-with-the-delete-generation", func() string {
		k := key()
		if d := env.answers(env.askCache(c, k, false), c.Expect); d != "" {
			return d
		}
		if cached, _ := env.askCache(c, k, false).cachedFlags(); cached != len(c.Projects) {
			return "the entry never became warm"
		}
		env.advanceDeleteGeneration()
		a := env.askCache(c, k, false)
		if d := env.answers(a, c.Expect); d != "" {
			return d
		}
		if cached, _ := a.cachedFlags(); cached != 0 {
			return fmt.Sprintf("a warm entry survived a delete generation advance for %d projects", cached)
		}
		if cached, _ := env.askCache(c, k, false).cachedFlags(); cached != len(c.Projects) {
			return "the recomputed answer was not cached again"
		}
		return ""
	})

	for _, partial := range []bool{false, true} {
		partial := partial
		add(fmt.Sprintf("deletion-during-compute-is-stale-never-success/allow-partial=%v", partial), func() string {
			k := key()
			release := env.gate.arm()
			defer env.gate.disarm()
			done := make(chan asked, 1)
			body := env.QueryBody("promql", c.Profile, c.expression(k), mustInt(c.TimeNS), c.Projects...)
			body["allow_partial"] = partial
			raw, _ := json.Marshal(body)
			go func() {
				code, out := env.PostRaw(env.People["reader"], "/api/v1/query", raw, nil)
				done <- asked{code, out}
			}()
			waitFor(func() bool { return env.gate.heldCount() > 0 }, "the scan was never reached")
			env.advanceDeleteGeneration()
			close(release)
			var a asked
			select {
			case a = <-done:
			case <-time.After(10 * time.Second):
				return "the request did not finish after the deletion"
			}
			waitFor(func() bool { return env.gate.openCount() == 0 }, "iterators left open")
			if d := typedFailure(a, "stale"); d != "" {
				return d
			}
			// The request is retryable: the same query now answers completely.
			return env.answers(env.askCache(c, k, false), c.Expect)
		})
	}
	return steps
}

// advanceDeleteGeneration commits one deletion generation advance and waits
// until the generation the engine reads has stopped moving, so the next row
// starts from a settled state.
func (e *Env) advanceDeleteGeneration() {
	_, err := e.app.Control.AdvanceDeleteGeneration(e.ctx, e.org)
	check(err)
	read := func() uint64 {
		g, err := e.app.Retention.DeleteGeneration(e.ctx, e.org, []model.ID{e.Projects["project-a"]})
		check(err)
		return g
	}
	last, since := read(), time.Now()
	for time.Since(since) < time.Second {
		time.Sleep(50 * time.Millisecond)
		if g := read(); g != last {
			last, since = g, time.Now()
		}
	}
}
