// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"runtime"
	"soundpost/internal/model"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/scan"
	"soundpost/internal/query/value"
	"strconv"
	"strings"
	"testing"
	"time"
)

func hostileRun(t *testing.T, q string, e LogEntry, limit int64) (PipelineResult, error, *value.BoundedAccount) {
	t.Helper()
	account := value.NewBoundedAccount(limit)
	r, err := RunPipeline(context.Background(), testPlan(t, q), e, account)
	return r, err, account
}

// The vendored scanner indexes the first byte of an empty quoted key; the
// reference treats an empty key as a real key, so the row is an ordinary miss.
func TestJSONEmptyQuotedKeyDoesNotPanic(t *testing.T) {
	for _, c := range []struct{ expr, line, want string }{
		{`a[""]`, `{"a":[1,2]}`, ""},
		{`a[""]`, `{"a":{"":1}}`, "1"},
		{`[""]`, `{"a":[1,2],"":0}`, "0"},
		{`a[""][0]`, `{"a":{"":[5,6]}}`, "5"},
		{`a[0][""]`, `{"a":[1,2]}`, ""},
	} {
		r, err, account := hostileRun(t, `{app="api"}|json x="`+strings.ReplaceAll(c.expr, `"`, `\"`)+`"`, entry(c.line), 16<<20)
		if err != nil {
			t.Fatalf("%s on %s: %v", c.expr, c.line, err)
		}
		if got := lookup(r.Labels, "x"); got != c.want || lookup(r.Labels, "__error__") != "" {
			t.Fatalf("%s on %s: x=%q error=%q want %q", c.expr, c.line, got, lookup(r.Labels, "__error__"), c.want)
		}
		account.Release(r.Bytes)
		if account.Used() != 0 {
			t.Fatal("account leaked")
		}
	}
}

// OWNED (not native): the reference itself panics on `a[0][""]` over nested
// arrays. Ours reports the stage's ordinary scanner error for the row.
func TestJSONScannerPanicBecomesStageError(t *testing.T) {
	r, err, account := hostileRun(t, `{app="api"}|json x="a[0][\"\"]", y="a[0][0]"`, entry(`{"a":[[1],[2]]}`), 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	if lookup(r.Labels, "__error__") != "JSONParserErr" || lookup(r.Labels, "__error_details__") != "Malformed JSON error" {
		t.Fatalf("labels=%v", r.Labels)
	}
	account.Release(r.Bytes)
	if account.Used() != 0 {
		t.Fatal("account leaked")
	}
}

// No generated hostile combination of paths and bytes may panic out of RunPipeline.
func TestJSONAndUnpackNeverPanic(t *testing.T) {
	paths := []string{`a[""]`, `[""]`, `a[0][""]`, `a[""][0]`, `a[""][""]`, `a.b[""]`, `[0]`, `a[0]`, `a[0][0][""]`, `a[""].b`}
	alphabet := []string{`{`, `}`, `[`, `]`, `"a"`, `""`, `:`, `,`, `1`, `"`, `\`, ` `, `null`, `"_entry"`, `"b"`}
	var plans []PipelinePlan
	for _, p := range paths {
		plans = append(plans, testPlan(t, `{app="api"}|json x="`+strings.ReplaceAll(p, `"`, `\"`)+`"`))
	}
	plans = append(plans, testPlan(t, `{app="api"}|json`), testPlan(t, `{app="api"}|unpack`))
	rng := rand.New(rand.NewPCG(7, 7))
	for range 4000 {
		var b strings.Builder
		for n := rng.IntN(14) + 1; n > 0; n-- {
			b.WriteString(alphabet[rng.IntN(len(alphabet))])
		}
		line := b.String()
		for _, plan := range plans {
			func() {
				defer func() {
					if p := recover(); p != nil {
						t.Fatalf("panic for %q: %v", line, p)
					}
				}()
				_, _ = RunPipeline(context.Background(), plan, entry(line), value.NewBoundedAccount(16<<20))
			}()
		}
	}
}

func allocSince(before uint64) uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.TotalAlloc - before
}
func totalAlloc() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.TotalAlloc
}

func TestJSONDeepNestingIsLinearInAllocation(t *testing.T) {
	const depth = 5000
	line := strings.Repeat(`{"abcdefgh":`, depth) + `1` + strings.Repeat(`}`, depth)
	before := totalAlloc()
	start := time.Now()
	r, err, account := hostileRun(t, `{app="api"}|json`, entry(line), 64<<20)
	elapsed := time.Since(start)
	alloc := allocSince(before)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Repeat("abcdefgh_", depth-1) + "abcdefgh"; lookup(r.Labels, want) != "1" {
		t.Fatalf("deep leaf missing, labels=%d", len(r.Labels))
	}
	if limit := uint64(100 * len(line)); alloc > limit {
		t.Fatalf("TotalAlloc grew %d bytes for a %d byte line (limit %d)", alloc, len(line), limit)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("deep nesting took %s", elapsed)
	}
	account.Release(r.Bytes)
	if account.Used() != 0 {
		t.Fatal("account leaked")
	}
}

// Every level carries a leaf, so the composed keys are legitimately quadratic
// output; the stage must refuse before allocating them, not after.
func TestJSONDeepNestingWithLeavesIsChargedBeforeAllocation(t *testing.T) {
	const depth = 5000
	line := strings.Repeat(`{"k":1,"n":`, depth) + `1` + strings.Repeat(`}`, depth)
	before := totalAlloc()
	_, err, account := hostileRun(t, `{app="api"}|json`, entry(line), 4<<20)
	alloc := allocSince(before)
	if err == nil {
		t.Fatal("expected a quota failure")
	}
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.Quota {
		t.Fatalf("err=%v", err)
	}
	if alloc > 48<<20 {
		t.Fatalf("TotalAlloc %d for a 4 MiB account", alloc)
	}
	if account.Used() != 0 {
		t.Fatalf("account leaked %d", account.Used())
	}
}

func manyKeyLines(n int) (jsonLine, logfmtLine, unpackLine string) {
	var j, l, u strings.Builder
	j.WriteByte('{')
	u.WriteString(`{"_entry":"x"`)
	for i := range n {
		k := "k" + strconv.Itoa(i)
		if i > 0 {
			j.WriteByte(',')
			l.WriteByte(' ')
		}
		fmt.Fprintf(&j, `"%s":"v"`, k)
		fmt.Fprintf(&l, `%s=v`, k)
		fmt.Fprintf(&u, `,"%s":"v"`, k)
	}
	j.WriteByte('}')
	u.WriteByte('}')
	return j.String(), l.String(), u.String()
}

func TestManyLabelsAreBuiltInBoundedTime(t *testing.T) {
	const n = 100000
	jl, ll, ul := manyKeyLines(n)
	for _, c := range []struct{ q, line string }{
		{`{app="api"}|json`, jl},
		{`{app="api"}|logfmt`, ll},
		{`{app="api"}|unpack`, ul},
		{`{app="api"}|logfmt|keep k1, k2`, ll},
		{`{app="api"}|logfmt|drop k1, k2`, ll},
		{`{app="api"}|logfmt|drop k1=~"k.*"`, ll},
	} {
		start := time.Now()
		r, err, account := hostileRun(t, c.q, entry(c.line), 1<<30)
		if err != nil {
			t.Fatalf("%s: %v", c.q, err)
		}
		if d := time.Since(start); d > 6*time.Second {
			t.Fatalf("%s took %s for %d keys", c.q, d, n)
		}
		account.Release(r.Bytes)
		if account.Used() != 0 {
			t.Fatalf("%s leaked %d", c.q, account.Used())
		}
	}
}

func TestManyLabelResultsAreCorrect(t *testing.T) {
	jl, ll, _ := manyKeyLines(300)
	for _, q := range []string{`{app="api"}|json|drop k1`, `{app="api"}|logfmt|drop k1`} {
		line := jl
		if strings.Contains(q, "logfmt") {
			line = ll
		}
		r, err, _ := hostileRun(t, q, entry(line), 64<<20)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Labels) != 1+299 || lookup(r.Labels, "k0") != "v" || lookup(r.Labels, "k299") != "v" {
			t.Fatalf("%s: %d labels", q, len(r.Labels))
		}
		for i := 1; i < len(r.Labels); i++ {
			if r.Labels[i-1].Name >= r.Labels[i].Name {
				t.Fatalf("%s: labels not strictly sorted at %d", q, i)
			}
		}
	}
}

// cancelAccount cancels the context when its Check has been called cancelAt
// times (never when cancelAt < 0) and records the instant.
type cancelAccount struct {
	*value.BoundedAccount
	cancel      context.CancelFunc
	cancelAt    int
	calls       int
	cancelledAt time.Time
}

func (a *cancelAccount) Check(ctx context.Context) error {
	a.calls++
	if a.calls == a.cancelAt {
		a.cancelledAt = time.Now()
		a.cancel()
	}
	return ctx.Err()
}

// Cancellation is observed inside the label-building loops, not only per key:
// the context is cancelled at a call count taken from an uncancelled run, in
// the middle of the stage and in its last loop.
func TestManyLabelParsingCancelsPromptly(t *testing.T) {
	const n = 100000
	jl, ll, ul := manyKeyLines(n)
	for _, c := range []struct{ q, line string }{
		{`{app="api"}|json`, jl}, {`{app="api"}|logfmt`, ll}, {`{app="api"}|unpack`, ul},
		{`{app="api"}|logfmt|keep nothing`, ll}, {`{app="api"}|logfmt|drop k1=~"k.*"`, ll},
	} {
		plan := testPlan(t, c.q)
		total := &cancelAccount{BoundedAccount: value.NewBoundedAccount(1 << 30), cancelAt: -1, cancel: func() {}}
		r, err := RunPipeline(context.Background(), plan, entry(c.line), total)
		if err != nil {
			t.Fatalf("%s: %v", c.q, err)
		}
		total.Release(r.Bytes)
		for _, at := range []int{total.calls / 2, total.calls - 3} {
			ctx, cancel := context.WithCancel(context.Background())
			account := &cancelAccount{BoundedAccount: value.NewBoundedAccount(1 << 30), cancel: cancel, cancelAt: at}
			_, err := RunPipeline(ctx, plan, entry(c.line), account)
			returned := time.Now()
			cancel()
			var fault *model.Fault
			if !errors.Is(err, context.Canceled) || !errors.As(err, &fault) || fault.Code != model.Cancelled {
				t.Fatalf("%s cancel at %d/%d: %v", c.q, at, total.calls, err)
			}
			if lag := returned.Sub(account.cancelledAt); lag > time.Second {
				t.Fatalf("%s cancel at %d/%d: returned %s after the cancel", c.q, at, total.calls, lag)
			}
			if account.Used() != 0 {
				t.Fatalf("%s cancel at %d/%d: leaked %d", c.q, at, total.calls, account.Used())
			}
		}
	}
}

func TestManyCapturesAreBuiltInBoundedTime(t *testing.T) {
	const n = 3000
	var pat, line, re, reLine strings.Builder
	for i := range n {
		fmt.Fprintf(&pat, "<c%d>;", i)
		fmt.Fprintf(&line, "v%d;", i)
		fmt.Fprintf(&re, "(?P<c%d>v%d);", i, i)
	}
	reLine.WriteString(line.String())
	for _, q := range []string{
		`{app="api"}|pattern "` + pat.String() + `"`,
		`{app="api"}|regexp "` + re.String() + `"`,
	} {
		start := time.Now()
		r, err, account := hostileRun(t, q, entry(line.String()), 1<<30)
		if err != nil {
			t.Fatal(err)
		}
		if d := time.Since(start); d > 6*time.Second {
			t.Fatalf("%.30s took %s", q, d)
		}
		if lookup(r.Labels, "c2999") != "v2999" {
			t.Fatalf("%.30s: capture missing", q)
		}
		account.Release(r.Bytes)
	}
}

// Typed-field binding reserved a flat 32 KiB per field; admission caps field
// size, not field count.
func TestTemplateBindsManyTypedFields(t *testing.T) {
	var fields []TypedField
	for i := range 5000 {
		var s model.Scalar
		if err := s.UnmarshalJSON([]byte(strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
		fields = append(fields, TypedField{Name: "f" + strconv.Itoa(i), Value: s})
	}
	got, err := templateRender(t, `{{.f4999}}/{{.f0}}`, TemplateInput{Fields: fields})
	if err != nil || got != "4999/0" {
		t.Fatalf("got %q err=%v", got, err)
	}
	e := entry("line")
	e.Fields = fields
	r, err, _ := hostileRun(t, `{app="api"}|line_format "{{.f4999}}"|label_format z="{{.f7}}"`, e, 256<<20)
	if err != nil || r.Entry.Line != "4999" || lookup(r.Labels, "z") != "7" {
		t.Fatalf("pipeline: %v line=%q z=%q", err, r.Entry.Line, lookup(r.Labels, "z"))
	}
}

func TestTemplateTrimCostIsMetered(t *testing.T) {
	cutset := make([]rune, 60000)
	for i := range cutset {
		cutset[i] = rune(0x4e00 + i)
	}
	last := string(cutset[len(cutset)-1])
	for _, source := range []string{`{{ Trim .l .c | len }}`, `{{ TrimLeft .l .c | len }}`, `{{ TrimRight .l .c | len }}`, `{{ trimAll .c .l | len }}`} {
		start := time.Now()
		_, err := templateRender(t, source, TemplateInput{Labels: model.Labels{{Name: "c", Value: string(cutset)}, {Name: "l", Value: strings.Repeat(last, 200000)}}})
		var limit *TemplateLimitError
		if !errors.As(err, &limit) {
			t.Fatalf("%s: err=%v", source, err)
		}
		if d := time.Since(start); d > time.Second {
			t.Fatalf("%s took %s", source, d)
		}
	}
}

func TestTemplateComparisonCostIsMetered(t *testing.T) {
	big := strings.Repeat("x", 4<<20)
	other := strings.Repeat("x", 4<<20-1) + "y"
	start := time.Now()
	_, err := templateRender(t, strings.Repeat(`{{eq .a .b}}`, 8000), TemplateInput{Labels: model.Labels{{Name: "a", Value: big}, {Name: "b", Value: other}}})
	var limit *TemplateLimitError
	if !errors.As(err, &limit) {
		t.Fatalf("err=%v", err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("took %s", d)
	}
}

// keep/drop regex matchers compile with the plan, so a budget failure is a
// plan error and does not depend on whether a row carries the label.
func TestKeepDropRegexCompiledAtPlanTime(t *testing.T) {
	for _, kind := range []string{"drop", "keep"} {
		var matchers []string
		var labels model.Labels
		for _, c := range "abcdefgh" {
			matchers = append(matchers, string(c)+`=~"`+strings.Repeat(string(c)+"{1000}", 1500)+`"`)
			labels = append(labels, model.Label{Name: string(c), Value: "z"})
		}
		_, err := tryTestPlan(`{app="api"}|` + kind + " " + strings.Join(matchers, ","))
		var fault *model.Fault
		if err == nil || strings.Contains(err.Error(), "syntax") || errors.As(err, &fault) && fault.Code == model.Invalid {
			t.Fatalf("%s: the regex budget failure must surface when the plan is built, got %v", kind, err)
		}
	}
}

func tryTestPlan(source string) (PipelinePlan, error) {
	p, err := loadTestProfile()
	if err != nil {
		return PipelinePlan{}, err
	}
	e, err := Parse(source, p)
	if err != nil {
		return PipelinePlan{}, err
	}
	typed, _, err := Check(e, p)
	if err != nil {
		return PipelinePlan{}, err
	}
	plan, err := BuildPlan(typed, value.Evaluation{}, p)
	if err != nil {
		return PipelinePlan{}, err
	}
	if plan.Pipeline == nil {
		return PipelinePlan{}, errors.New("expected one log pipeline")
	}
	return *plan.Pipeline, nil
}
func loadTestProfile() (profile.Profile, error) {
	r, err := profile.Load(os.DirFS("../../../profiles/query"))
	if err != nil {
		return profile.Profile{}, err
	}
	return r.Resolve("logql-loki-3.5.2", "features-ef306c4e3aff8e4e9f5fb90595bb4f4b13f3de438c78ba73db83d9eb088e79eb")
}

// The lookback may be written as a JSON string or as a JSON number.
func TestInstantLogLookbackAcceptsStringAndNumber(t *testing.T) {
	for _, c := range []struct {
		raw  string
		want bool
	}{{`"2000000000"`, true}, {`2000000000`, true}, {`"0"`, false}, {`0`, false}, {`-5`, false}, {`1.5`, false}, {`"x"`, false}, {`true`, false}} {
		plan := metricPlan(t, `{app="api"}`, value.Evaluation{Instant: true, Time: 2e9})
		config := map[string]json.RawMessage{}
		for k, v := range plan.Profile.Configuration {
			config[k] = v
		}
		config["instant_log_lookback_ns"] = json.RawMessage(c.raw)
		plan.Profile.Configuration = config
		src := &metricSource{rows: []scan.LogRow{metricRow(1, 1e9, "one")}}
		a := value.NewBoundedAccount(32 << 20)
		r, err := EvaluateLogs(context.Background(), plan, src, Forward, 10, a)
		if c.want {
			if err != nil || len(r.Logs) != 1 {
				t.Fatalf("%s: err=%v logs=%d", c.raw, err, len(r.Logs))
			}
			a.Release(value.ResultBytes(r))
		} else if err == nil {
			t.Fatalf("%s accepted", c.raw)
		}
		if a.Used() != 0 {
			t.Fatalf("%s leaked %d", c.raw, a.Used())
		}
	}
}
