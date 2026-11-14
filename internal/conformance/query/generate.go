// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/arynyklas/soundpost/internal/query/profile"
)

// GenerationSpec is conformance/query/generation.json: the declared feature
// axes, the combinations excluded as inapplicable (each rejected before
// execution, never silently dropped), the targeted higher-order tuples,
// negative forms, gate probes and signature-directed profiles.
type GenerationSpec struct {
	Schema        string              `json:"schema"`
	Languages     []LanguageSpec      `json:"languages"`
	Excluded      []ExcludedCombo     `json:"excluded_combinations"`
	HigherOrder   []TupleSpec         `json:"higher_order"`
	NegativeForms []NegativeForm      `json:"negative_forms"`
	GateProbes    []GateProbe         `json:"gate_probes"`
	SemanticGates map[string]string   `json:"semantic_only_gates"`
	SpecialArgs   map[string][]string `json:"special_arguments"`
}
type LanguageSpec struct {
	Language string     `json:"language"`
	Profiles []string   `json:"profiles"`
	Axes     []AxisSpec `json:"axes"`
}
type AxisSpec struct {
	ID     string   `json:"id"`
	Values []string `json:"values"`
}
type ExcludedCombo struct {
	Language string   `json:"language"`
	Pair     []string `json:"pair"` // "axis=value" x2
	Reason   string   `json:"reason"`
}
type TupleSpec struct {
	Language string   `json:"language"`
	Tuple    []string `json:"tuple"`
}
type NegativeForm struct {
	ID       string `json:"id"`
	Language string `json:"language"`
	Wrap     string `json:"wrap"` // %s is replaced by the valid feature-bearing expression
	Category string `json:"category"`
}
type GateProbe struct {
	Profile    string `json:"profile"`
	Gate       string `json:"gate"`
	Expression string `json:"expression"`
	Category   string `json:"category"`
}

// GenerationBudget bounds one Generate call. Exceeding MaxCases is an error,
// never a silent truncation.
type GenerationBudget struct {
	MaxCases int
	Random   int // additional seed-drawn tuples beyond the exhaustive set
	Spec     GenerationSpec
	Domains  []GateDomain
}

type Case struct {
	ID         string            `json:"id"`
	Kind       string            `json:"kind"` // valid, negative, gate, signature, signature-negative
	Language   string            `json:"language"`
	Profile    string            `json:"profile"`
	FeatureSet string            `json:"feature_set,omitempty"` // empty: valid in every registered feature set
	Expression string            `json:"expression"`
	Coordinate map[string]string `json:"coordinate,omitempty"`
	Input      []InputRecord     `json:"input,omitempty"`
	Reject     string            `json:"reject_category,omitempty"` // negative: expected error category
	Gate       string            `json:"gate,omitempty"`
	Enabled    bool              `json:"gate_enabled,omitempty"`
	Obligation string            `json:"obligation,omitempty"`
	Seed       uint64            `json:"seed"`
}

// CaseMismatch is a mismatch bound to the case that produced it.
type CaseMismatch struct {
	Mismatch
	Case Case
}

func LoadGenerationSpec(path string) (GenerationSpec, error) {
	var spec GenerationSpec
	if err := ReadJSON(path, &spec); err != nil {
		return spec, err
	}
	return spec, spec.Validate()
}

func (s GenerationSpec) Validate() error {
	if s.Schema != "soundpost-query-generation/1" || len(s.Languages) == 0 {
		return fmt.Errorf("invalid generation spec")
	}
	for _, l := range s.Languages {
		seen := map[string]bool{}
		for _, a := range l.Axes {
			if a.ID == "" || seen[a.ID] || len(a.Values) < 2 {
				return fmt.Errorf("axis %s of %s needs two or more distinct values", a.ID, l.Language)
			}
			seen[a.ID] = true
			vs := map[string]bool{}
			for _, v := range a.Values {
				if v == "" || vs[v] {
					return fmt.Errorf("duplicate axis value %s.%s", a.ID, v)
				}
				vs[v] = true
			}
		}
	}
	return nil
}

func (s GenerationSpec) language(name string) (LanguageSpec, bool) {
	for _, l := range s.Languages {
		if l.Language == name {
			return l, true
		}
	}
	return LanguageSpec{}, false
}

func coord(axis, value string) string { return axis + "=" + value }

// ValidateCombination rejects an invalid feature combination BEFORE anything is
// executed: an undeclared axis or value, or a combination the spec excludes.
func (s GenerationSpec) ValidateCombination(language string, c map[string]string) error {
	l, ok := s.language(language)
	if !ok {
		return fmt.Errorf("unknown language %s", language)
	}
	if len(c) != len(l.Axes) {
		return fmt.Errorf("combination must assign every axis of %s", language)
	}
	for _, a := range l.Axes {
		v, ok := c[a.ID]
		if !ok {
			return fmt.Errorf("axis %s unassigned", a.ID)
		}
		found := false
		for _, allowed := range a.Values {
			found = found || allowed == v
		}
		if !found {
			return fmt.Errorf("value %s is not declared for axis %s of %s", v, a.ID, language)
		}
	}
	for _, e := range s.Excluded {
		if e.Language == language && len(e.Pair) == 2 && has(c, e.Pair[0]) && has(c, e.Pair[1]) {
			return fmt.Errorf("excluded combination %v: %s", e.Pair, e.Reason)
		}
	}
	return nil
}

func has(c map[string]string, kv string) bool {
	k, v, _ := strings.Cut(kv, "=")
	return c[k] == v
}

// splitmix64 gives deterministic, dependency-free pseudo-randomness.
type splitmix struct{ s uint64 }

func (r *splitmix) next() uint64 {
	r.s += 0x9e3779b97f4a7c15
	z := r.s
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}
func (r *splitmix) pick(options ...string) string { return options[r.next()%uint64(len(options))] }

// tuples enumerates every assignment of the language's axes in a fixed order.
func tuples(l LanguageSpec) []map[string]string {
	out := []map[string]string{{}}
	for _, a := range l.Axes {
		var next []map[string]string
		for _, base := range out {
			for _, v := range a.Values {
				m := make(map[string]string, len(base)+1)
				for k, bv := range base {
					m[k] = bv
				}
				m[a.ID] = v
				next = append(next, m)
			}
		}
		out = next
	}
	return out
}

func tupleKey(l LanguageSpec, c map[string]string) string {
	parts := make([]string, 0, len(l.Axes))
	for _, a := range l.Axes {
		parts = append(parts, coord(a.ID, c[a.ID]))
	}
	return strings.Join(parts, ",")
}

const nanBits = "7ff8000000000001"

func floatBits(f float64) string {
	s, _ := NormalizeFloat(strconv.FormatFloat(f, 'g', -1, 64))
	return s
}

func promInput(c map[string]string) []InputRecord {
	sample := func(t int, bits string, labels map[string]string) InputRecord {
		return InputRecord{Kind: "float", Timestamp: strconv.Itoa(t) + "000000000", Name: "m", Labels: labels, Bits: bits}
	}
	l := map[string]string{"job": "api"}
	var in []InputRecord
	switch c["sample_kind"] {
	case "native_histogram":
		h := func(count, zero, sum string, d []string) *Histogram {
			return &Histogram{Kind: "integer", Schema: 0, ResetHint: "unknown", Count: count, ZeroCount: zero, ZeroThresholdBits: floatBits(0.001), SumBits: sum, PositiveSpans: []HistogramSpan{{Offset: 0, Length: uint32(len(d))}}, NegativeSpans: []HistogramSpan{}, PositiveDeltas: d}
		}
		in = []InputRecord{
			{Kind: "histogram", Timestamp: "10000000000", Name: "h", Labels: l, Histogram: h("9", "1", floatBits(12), []string{"3", "1", "-1"})},
			// A counter reset: the second observation has a lower count.
			{Kind: "histogram", Timestamp: "20000000000", Name: "h", Labels: l, Histogram: h("4", "0", floatBits(5), []string{"2", "0", "0"})},
		}
	case "stale":
		in = []InputRecord{sample(10, floatBits(1), l), sample(20, StaleBits, l), sample(30, floatBits(3), l)}
	case "nan":
		in = []InputRecord{sample(10, floatBits(1), l), sample(20, nanBits, l), sample(30, floatBits(3), l)}
	default:
		in = []InputRecord{sample(10, floatBits(1), l), sample(20, floatBits(2), l), sample(30, floatBits(3), l)}
	}
	name := "m"
	if c["sample_kind"] == "native_histogram" {
		name = "h"
	}
	switch c["order_duplicates"] {
	case "duplicate_timestamp":
		// A legitimate exact duplicate (same timestamp, type and value).
		in = append(in, in[len(in)-1])
	case "tie_limit":
		other := map[string]string{"job": "worker"}
		in = append(in, InputRecord{Kind: "float", Timestamp: in[0].Timestamp, Name: name, Labels: other, Bits: in[0].Bits})
	}
	return in
}

func logInput(c map[string]string) []InputRecord {
	line := func(t int, text string, labels map[string]string) InputRecord {
		return InputRecord{Kind: "log", Timestamp: strconv.Itoa(t) + "000000000", Labels: labels, Line: text}
	}
	labels := map[string]string{"app": "web"}
	switch c["sample_kind"] {
	case "structured_metadata":
		labels["trace_id"] = "abc"
	case "newline_label":
		labels["nl"] = "a\nb"
	}
	in := []InputRecord{line(10, "{\"app\":\"web\",\"ok\":1} x", labels), line(20, "plain x line", labels)}
	if c["order_duplicates"] == "duplicate_timestamp" {
		in = append(in, line(20, "plain x line", labels))
	}
	return in
}

func promExpression(c map[string]string, r *splitmix) string {
	sel := "m"
	if c["sample_kind"] == "native_histogram" {
		sel = "h"
	}
	window := r.pick("1m", "5m", "10m")
	var e string
	switch c["time_window"] {
	case "offset":
		e = sel + " offset " + r.pick("1m", "5m")
	case "at_modifier":
		e = sel + " @ " + r.pick("20", "30")
	case "range_window":
		e = "rate(" + sel + "[" + window + "])"
	case "subquery":
		e = "last_over_time(" + sel + "[10m:" + r.pick("1m", "30s") + "])"
	default:
		e = sel
	}
	if c["metadata_mutation"] == "metadata" {
		e = `label_replace(` + e + `, "dst", "$1", "job", "(.*)")`
	}
	switch c["order_duplicates"] {
	case "tie_limit":
		e = "topk(1, " + e + ")"
	case "ordering":
		e = "sort(" + e + ")"
	}
	return e
}

func logExpression(c map[string]string, r *splitmix) string {
	stages := ""
	switch c["sample_kind"] {
	case "structured_metadata":
		stages += ` | trace_id="abc"`
	case "newline_label":
		stages += ` | nl=~"(?s)a.+b"`
	}
	switch c["metadata_mutation"] {
	case "metadata":
		stages += " | json"
	case "mutation":
		stages += " | label_format ctx=app"
	}
	if c["template_parse"] == "template" {
		stages += ` | line_format "{{ .app }}: {{ __line__ }}"`
	}
	if c["order_duplicates"] == "stage_order" {
		stages += ` |= "x"`
	}
	q := `{app="web"}` + stages
	switch c["time_window"] {
	case "offset":
		return "count_over_time(" + q + " [" + r.pick("1m", "5m") + "] offset " + r.pick("1m", "2m") + ")"
	case "range_window":
		return "count_over_time(" + q + " [" + r.pick("1m", "5m") + "])"
	}
	return q
}

// Generate deterministically builds valid, negative, gate-probe and
// signature-directed cases. The same seed yields byte-identical output. The
// valid set is the EXHAUSTIVE cross product of the declared axes minus declared
// exclusions, which contains every pairwise interaction and every higher-order
// tuple; seed-drawn extras supplement it, never replace it. Valid and negative
// generation are separate passes and every combination is validated before a
// case is emitted.
func Generate(ctx context.Context, registry profile.Registry, ledger Ledger, seed uint64, budget GenerationBudget) ([]Case, error) {
	if err := budget.Spec.Validate(); err != nil {
		return nil, err
	}
	rng := &splitmix{s: seed}
	var out []Case
	push := func(c Case) error {
		if budget.MaxCases > 0 && len(out) >= budget.MaxCases {
			return fmt.Errorf("generation budget %d exceeded: the required set is larger, nothing is truncated silently", budget.MaxCases)
		}
		c.Seed = seed
		out = append(out, c)
		return nil
	}
	for _, l := range budget.Spec.Languages {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		all := tuples(l)
		var valid []map[string]string
		for _, t := range all {
			if budget.Spec.ValidateCombination(l.Language, t) == nil {
				valid = append(valid, t)
			}
		}
		// Seed-drawn supplements: extra surface variants of random valid tuples.
		extras := make([]map[string]string, 0, budget.Random)
		for i := 0; i < budget.Random && len(valid) > 0; i++ {
			extras = append(extras, valid[rng.next()%uint64(len(valid))])
		}
		for _, id := range l.Profiles {
			for n, t := range append(append([]map[string]string{}, valid...), extras...) {
				r := &splitmix{s: seed ^ uint64(n)*0x2545f4914f6cdd1d ^ hash64(id)}
				var expr string
				var in []InputRecord
				if l.Language == "promql" {
					expr, in = promExpression(t, r), promInput(t)
				} else {
					expr, in = logExpression(t, r), logInput(t)
				}
				key := tupleKey(l, t)
				kind := "valid"
				cid := "gen/" + id + "/" + key
				if n >= len(valid) {
					cid += "#extra" + strconv.Itoa(n-len(valid))
				}
				if err := push(Case{ID: cid, Kind: kind, Language: l.Language, Profile: id, Expression: expr, Coordinate: t, Input: in}); err != nil {
					return nil, err
				}
				// Negative pass: each declared negative form wrapped around
				// this feature-bearing expression, rejected before execution.
				if n >= len(valid) {
					continue
				}
				for _, f := range budget.Spec.NegativeForms {
					if f.Language != l.Language {
						continue
					}
					if err := push(Case{ID: "neg/" + id + "/" + f.ID + "/" + key, Kind: "negative", Language: l.Language, Profile: id, Expression: strings.Replace(f.Wrap, "%s", expr, 1), Coordinate: t, Reject: f.Category}); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	// Gate probes against every registered feature set of the profile.
	for _, d := range budget.Domains {
		for _, p := range budget.Spec.GateProbes {
			if p.Profile != d.Profile {
				continue
			}
			for _, set := range d.FeatureSets {
				enabled := false
				for _, g := range set.Enabled {
					enabled = enabled || g == p.Gate
				}
				if err := push(Case{ID: "gate/" + set.ID + "/" + p.Gate, Kind: "gate", Language: languageOf(p.Profile), Profile: p.Profile, FeatureSet: set.ID, Expression: p.Expression, Gate: p.Gate, Enabled: enabled, Reject: p.Category}); err != nil {
					return nil, err
				}
			}
		}
	}
	// Signature-directed cases from the obligation ledger.
	sigs, err := signatureCases(budget.Spec, ledger)
	if err != nil {
		return nil, err
	}
	for _, c := range sigs {
		if err := push(c); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func languageOf(profileID string) string {
	if strings.HasPrefix(profileID, "logql-") {
		return "logql"
	}
	return "promql"
}

func hash64(s string) uint64 {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(s); i++ {
		h = (h ^ uint64(s[i])) * 1099511628211
	}
	return h
}

var signaturePattern = regexp.MustCompile(`^([a-z_0-9A-Z]+)\(([^)]*)\)->([a-z]+); variadic=(-?\d+)$`)

// signatureCases derives a valid call and two negative calls (extra argument,
// swapped argument type) for every PromQL function-signature obligation, from
// the signature text alone: type-directed argument synthesis.
func signatureCases(spec GenerationSpec, ledger Ledger) ([]Case, error) {
	arg := map[string]string{"vector": "m", "matrix": "m[5m]", "scalar": "1", "string": `"x"`}
	swapped := map[string]string{"vector": "m[5m]", "matrix": "m", "scalar": `"x"`, "string": "1"}
	var out []Case
	for _, o := range ledger.Obligations {
		if o.Kind != "function-signature" || !strings.HasPrefix(o.Profile, "promql-") {
			continue
		}
		m := signaturePattern.FindStringSubmatch(o.Signature)
		if m == nil {
			return nil, fmt.Errorf("unparseable function signature %q", o.Signature)
		}
		var types []string
		if strings.TrimSpace(m[2]) != "" {
			types = strings.Split(m[2], ",")
		}
		build := func(override int, extra bool) (string, bool) {
			parts := make([]string, 0, len(types)+1)
			for i, t := range types {
				t = strings.TrimSpace(t)
				text, ok := arg[t]
				if !ok {
					return "", false
				}
				if i == override {
					text = swapped[t]
				}
				parts = append(parts, text)
			}
			if extra {
				parts = append(parts, "1")
			}
			return m[1] + "(" + strings.Join(parts, ", ") + ")", true
		}
		valid, ok := build(-1, false)
		if special, found := spec.SpecialArgs[m[1]]; found {
			out = append(out, Case{ID: "sig/" + o.ID, Kind: "signature", Language: "promql", Profile: o.Profile, Expression: m[1] + "(" + strings.Join(special, ", ") + ")", Obligation: o.ID})
			continue
		}
		if !ok {
			continue // argument type outside vector/matrix/scalar/string: not synthesizable
		}
		out = append(out, Case{ID: "sig/" + o.ID, Kind: "signature", Language: "promql", Profile: o.Profile, Expression: valid, Obligation: o.ID})
		if extra, ok := build(-1, true); ok && m[4] == "0" {
			out = append(out, Case{ID: "sig-arity/" + o.ID, Kind: "signature-negative", Language: "promql", Profile: o.Profile, Expression: extra, Obligation: o.ID, Reject: "type"})
		}
		if len(types) > 0 {
			if swap, ok := build(0, false); ok && swap != valid {
				out = append(out, Case{ID: "sig-type/" + o.ID, Kind: "signature-negative", Language: "promql", Profile: o.Profile, Expression: swap, Obligation: o.ID, Reject: "type"})
			}
		}
	}
	return out, nil
}

// ResolveEnabled returns the profile resolved with exactly the given enabled
// gates, which must be a registered feature set.
func ResolveEnabled(files fs.FS, registry profile.Registry, id string, enabled []string) (profile.Profile, error) {
	raw, err := fs.ReadFile(files, id+".json")
	if err != nil {
		return profile.Profile{}, err
	}
	var manifest profile.Profile
	if err = json.Unmarshal(raw, &manifest); err != nil {
		return profile.Profile{}, err
	}
	want := append([]string(nil), enabled...)
	sort.Strings(want)
	for _, set := range manifest.FeatureSets {
		got := append([]string(nil), set.Enabled...)
		sort.Strings(got)
		if strings.Join(got, "\x00") == strings.Join(want, "\x00") {
			return registry.Resolve(id, set.ID)
		}
	}
	return profile.Profile{}, fmt.Errorf("unregistered feature combination for %s", id)
}

// Coverage reports required versus covered interactions over the VALID cases:
// every applicable pair of axis values (minus declared exclusions) and every
// declared higher-order tuple.
func Coverage(spec GenerationSpec, cases []Case) InteractionCoverage {
	var result InteractionCoverage
	for _, l := range spec.Languages {
		present := map[string]bool{}
		for _, c := range cases {
			if c.Kind != "valid" || c.Language != l.Language || c.Profile != l.Profiles[0] {
				continue
			}
			var coords []string
			for _, a := range l.Axes {
				coords = append(coords, coord(a.ID, c.Coordinate[a.ID]))
			}
			for i := range coords {
				for j := i + 1; j < len(coords); j++ {
					present[coords[i]+"|"+coords[j]] = true
				}
			}
			present[strings.Join(coords, "|")] = true
			for _, h := range spec.HigherOrder {
				if h.Language == l.Language && containsAll(coords, h.Tuple) {
					present["H:"+strings.Join(h.Tuple, "|")] = true
				}
			}
		}
		for i, a := range l.Axes {
			for _, b := range l.Axes[i+1:] {
				for _, av := range a.Values {
					for _, bv := range b.Values {
						if excludedPair(spec, l.Language, coord(a.ID, av), coord(b.ID, bv)) {
							continue
						}
						result.Required++
						key := coord(a.ID, av) + "|" + coord(b.ID, bv)
						if present[key] {
							result.Covered++
						} else {
							result.Missing = append(result.Missing, l.Language+":"+key)
						}
					}
				}
			}
		}
		for _, h := range spec.HigherOrder {
			if h.Language != l.Language {
				continue
			}
			result.Required++
			if present["H:"+strings.Join(h.Tuple, "|")] {
				result.Covered++
			} else {
				result.Missing = append(result.Missing, l.Language+":"+strings.Join(h.Tuple, "|"))
			}
		}
	}
	return result
}

func excludedPair(spec GenerationSpec, language, a, b string) bool {
	for _, e := range spec.Excluded {
		if e.Language == language && len(e.Pair) == 2 && ((e.Pair[0] == a && e.Pair[1] == b) || (e.Pair[0] == b && e.Pair[1] == a)) {
			return true
		}
	}
	return false
}

func containsAll(have, want []string) bool {
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

// Minimize shrinks a mismatching case while predicate keeps reporting that the
// mismatch persists. Candidates only remove input records or peel trailing
// characters from the expression at token-ish boundaries; the result is never
// larger and always still satisfies the predicate. The predicate decides what
// counts as the same mismatch, so a candidate that merely fails differently is
// refused by it.
func Minimize(ctx context.Context, mismatch CaseMismatch, predicate func(Case) (bool, error)) (Case, error) {
	best := mismatch.Case
	if ok, err := predicate(best); err != nil {
		return best, err
	} else if !ok {
		return best, fmt.Errorf("mismatch does not reproduce on the original case")
	}
	for progress := true; progress; {
		progress = false
		for _, candidate := range shrinks(best) {
			if err := ctx.Err(); err != nil {
				return best, err
			}
			ok, err := predicate(candidate)
			if err != nil {
				return best, err
			}
			if ok {
				best, progress = candidate, true
				break
			}
		}
	}
	return best, nil
}

func shrinks(c Case) []Case {
	var out []Case
	for i := range c.Input {
		d := c
		d.Input = append(append([]InputRecord(nil), c.Input[:i]...), c.Input[i+1:]...)
		out = append(out, d)
	}
	runes := []rune(c.Expression)
	for n := len(runes) - 1; n >= 1; n-- {
		if n == len(runes)-1 || runes[n-1] == ' ' || runes[n-1] == ')' || runes[n-1] == '(' || runes[n-1] == ',' {
			d := c
			d.Expression = string(runes[:n])
			out = append(out, d)
		}
	}
	for i := range runes {
		if runes[i] == ' ' {
			d := c
			d.Expression = strings.TrimSpace(string(runes[:i])) + string(runes[i+1:])
			out = append(out, d)
		}
	}
	return out
}
