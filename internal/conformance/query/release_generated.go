// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/logql"
)

// ErrNotObserved marks a row that a differential phase run never observed on
// one side. The gate counts it as unrun, never as a match and never as a
// mismatch of the engines.
var ErrNotObserved = errors.New("not observed")

// GeneratedRow is one concrete row of a generated case in one registered
// feature set. It is executed by the same differential phase runner as the
// authored case files (evaluation, syntax, pipeline, logql-metric), never by a
// second comparator.
type GeneratedRow struct {
	Row     ReleaseCase `json:"row"`
	Phase   string      `json:"phase"` // runner tag, e.g. promql:evaluation
	Source  Case        `json:"source"`
	Enabled []string    `json:"enabled"`
	payload any
}

// GeneratedRun is every row of one seed plus the observations of the phase
// runs. A nil Oracle or Own means that side was never run: every row is unrun.
type GeneratedRun struct {
	Seed   uint64
	Rows   []GeneratedRow
	Oracle OracleFunc
	Own    OwnFunc
}

// GeneratedMismatch is one failing generated case handed to the minimizer.
type GeneratedMismatch struct {
	Seed     uint64
	Row      GeneratedRow
	Problems []string
}

// Regression is a minimized genuine mismatch, written to conformance/query/regressions.
type Regression struct {
	ID         string   `json:"id"`
	Seed       uint64   `json:"seed"`
	Profile    string   `json:"profile"`
	Phase      string   `json:"phase"`
	FeatureSet string   `json:"feature_set"`
	Enabled    []string `json:"enabled_features"`
	Problems   []string `json:"problems"`
	Original   string   `json:"original_expression"`
	Case       Case     `json:"case"`
}

// GeneratedCounts is the generated/executed/matched/mismatched/unrun accounting.
// Executed + Unrun == Generated and Matched + Mismatched == Executed.
type GeneratedCounts struct {
	Generated  int `json:"generated"`
	Executed   int `json:"executed"`
	Matched    int `json:"matched"`
	Mismatched int `json:"mismatched"`
	Unrun      int `json:"unrun"`
}

// GeneratedSeedReport is the gate's evidence for one generator seed.
type GeneratedSeedReport struct {
	Seed uint64 `json:"seed"`
	GeneratedCounts
	ByPhase        map[string]GeneratedCounts `json:"by_phase"`
	MismatchedRows []string                   `json:"mismatched_rows"` // first 50
	UnrunRows      []string                   `json:"unrun_rows"`      // first 50
	Regressions    []Regression               `json:"regressions"`
}

const generatedSampleLimit = 50

const (
	tagPromEvaluation = "promql:evaluation"
	tagPromSyntax     = "promql:syntax"
	tagLogSyntax      = "logql:syntax"
	tagLogPipeline    = "logql:pipeline"
	tagLogMetric      = "logql:logql-metric"
)

var (
	offsetPattern = regexp.MustCompile(`offset (\d+)([smh])`)
	promProfiles  = []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"}
)

func offsetNS(expr string) int64 {
	m := offsetPattern.FindStringSubmatch(expr)
	if m == nil {
		return 0
	}
	n, _ := strconv.ParseInt(m[1], 10, 64)
	unit := map[string]int64{"s": 1e9, "m": 60e9, "h": 3600e9}[m[2]]
	return n * unit
}

func setTag(id string) string {
	h := sha256.Sum256([]byte(id))
	return "@fs" + hex.EncodeToString(h[:4])
}

func parseNS(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) }

func parseBits(s string) (model.FloatBits, error) {
	n, err := strconv.ParseUint(s, 16, 64)
	if err != nil || len(s) != 16 {
		return 0, fmt.Errorf("invalid float bits %q", s)
	}
	return model.FloatBits(n), nil
}

func evalHistogram(h Histogram) (*model.NativeHistogram, error) {
	zt, err := parseBits(h.ZeroThresholdBits)
	if err != nil {
		return nil, err
	}
	sum, err := parseBits(h.SumBits)
	if err != nil {
		return nil, err
	}
	count, err := strconv.ParseUint(h.Count, 10, 64)
	if err != nil {
		return nil, err
	}
	zero, err := strconv.ParseUint(h.ZeroCount, 10, 64)
	if err != nil {
		return nil, err
	}
	spans := func(in []HistogramSpan) []model.HistogramSpan {
		out := make([]model.HistogramSpan, 0, len(in))
		for _, s := range in {
			out = append(out, model.HistogramSpan{Offset: s.Offset, Length: s.Length})
		}
		return out
	}
	buckets := make([]model.DeltaBucket, 0, len(h.PositiveDeltas))
	for _, d := range h.PositiveDeltas {
		n, err := strconv.ParseInt(d, 10, 64)
		if err != nil {
			return nil, err
		}
		buckets = append(buckets, model.DeltaBucket(n))
	}
	return &model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", Schema: h.Schema, ZeroThreshold: zt, Sum: sum, Count: model.Uint64(count), ZeroCount: model.Uint64(zero), PositiveSpans: spans(h.PositiveSpans), NegativeSpans: spans(h.NegativeSpans), PositiveBuckets: buckets, NegativeBuckets: []model.DeltaBucket{}, ResetHint: h.ResetHint}}, nil
}

// evaluationSeries turns the generator's post-ingest records into fixture
// series. Records of one (name, labels) form one series; an exact duplicate
// sample (same time, same value) collapses to one, as ingestion does, and a
// conflicting duplicate is a generator bug reported as an error.
func evaluationSeries(in []InputRecord) ([]EvaluationSeries, error) {
	index := map[string]int{}
	var out []EvaluationSeries
	for _, r := range in {
		labels := map[string]string{"__name__": r.Name}
		for k, v := range r.Labels {
			labels[k] = v
		}
		names := make([]string, 0, len(labels))
		for k := range labels {
			names = append(names, k)
		}
		sort.Strings(names)
		ls := make(model.Labels, 0, len(names))
		for _, k := range names {
			ls = append(ls, model.Label{Name: k, Value: labels[k]})
		}
		key, _ := json.Marshal(ls)
		i, ok := index[string(key)]
		if !ok {
			i = len(out)
			index[string(key)] = i
			out = append(out, EvaluationSeries{Labels: ls, Samples: []EvaluationSample{}})
		}
		ts, err := parseNS(r.Timestamp)
		if err != nil {
			return nil, err
		}
		s := EvaluationSample{Time: model.UnixNano(ts)}
		switch r.Kind {
		case "float":
			bits, err := parseBits(r.Bits)
			if err != nil {
				return nil, err
			}
			s.Float = &bits
		case "histogram":
			if r.Histogram == nil {
				return nil, fmt.Errorf("histogram record without histogram")
			}
			if s.Histogram, err = evalHistogram(*r.Histogram); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupported sample record kind %q", r.Kind)
		}
		prev := out[i].Samples
		if n := len(prev); n > 0 && prev[n-1].Time == s.Time {
			a, _ := json.Marshal(prev[n-1])
			b, _ := json.Marshal(s)
			if string(a) != string(b) {
				return nil, fmt.Errorf("conflicting duplicate sample at %d", ts)
			}
			continue
		}
		out[i].Samples = append(prev, s)
	}
	return out, nil
}

func logEntries(in []InputRecord) ([]LogQLEntry, error) {
	out := make([]LogQLEntry, 0, len(in))
	for i, r := range in {
		if r.Kind != "log" {
			return nil, fmt.Errorf("unsupported log record kind %q", r.Kind)
		}
		ts, err := parseNS(r.Timestamp)
		if err != nil {
			return nil, err
		}
		var stream, meta model.Labels
		names := make([]string, 0, len(r.Labels))
		for k := range r.Labels {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			if k == "trace_id" {
				meta = append(meta, model.Label{Name: k, Value: r.Labels[k]})
			} else {
				stream = append(stream, model.Label{Name: k, Value: r.Labels[k]})
			}
		}
		if stream == nil {
			stream = model.Labels{}
		}
		if meta == nil {
			meta = model.Labels{}
		}
		out = append(out, LogQLEntry{Timestamp: model.UnixNano(ts), ID: model.ID{0: byte(i + 1)}, Multiplicity: 1, Line: r.Line, StreamLabels: stream, Metadata: meta, Fields: []logql.TypedField{}})
	}
	return out, nil
}

func domainSets(domains []GateDomain) map[string][]FeatureSet {
	out := map[string][]FeatureSet{}
	for _, d := range domains {
		out[d.Profile] = d.FeatureSets
	}
	return out
}

func enabledOf(set FeatureSet) []string {
	out := append([]string{}, set.Enabled...)
	sort.Strings(out)
	return out
}

func newRow(c Case, set FeatureSet, id, profile, tag string, payload any) GeneratedRow {
	raw, _ := json.Marshal(struct {
		File  string `json:"file"`
		Phase string `json:"phase"`
	}{"generated", tag})
	src := c
	src.FeatureSet = set.ID
	return GeneratedRow{Row: ReleaseCase{ID: id, Profile: profile, Input: raw, Expected: SemanticResult{Kind: "phase-case", Type: tag}}, Phase: tag, Source: src, Enabled: enabledOf(set), payload: payload}
}

// rowsFor expands one generated case into its concrete rows. A case without a
// feature set is valid in every registered feature set of its profile and is
// run in each of them.
func rowsFor(c Case, sets map[string][]FeatureSet) ([]GeneratedRow, error) {
	profileSets := sets[c.Profile]
	if len(profileSets) == 0 {
		return nil, fmt.Errorf("no registered feature sets for %s", c.Profile)
	}
	var chosen []FeatureSet
	for _, s := range profileSets {
		if c.FeatureSet == "" || s.ID == c.FeatureSet {
			chosen = append(chosen, s)
		}
	}
	if len(chosen) == 0 {
		return nil, fmt.Errorf("case %s names an unregistered feature set", c.ID)
	}
	var rows []GeneratedRow
	var series []EvaluationSeries // shared by every feature set of this case
	for _, set := range chosen {
		id := c.ID + setTag(set.ID)
		if c.Kind == "gate" {
			id = c.ID
		}
		switch {
		case c.Language == "promql" && (c.Kind == "valid" || c.Kind == "signature" || c.Kind == "signature-negative"):
			if series == nil {
				in := c.Input
				if c.Kind != "valid" {
					in = promInput(map[string]string{})
				}
				var err error
				if series, err = evaluationSeries(in); err != nil {
					return nil, fmt.Errorf("%s: %w", c.ID, err)
				}
			}
			ev := EvaluationCase{ID: id, Profiles: []string{c.Profile}, Enabled: enabledOf(set), Query: c.Expression, Kind: "instant", Time: model.UnixNano(40e9 + offsetNS(c.Expression)), Series: series}
			if err := validateEvaluationCase(ev); err != nil {
				return nil, err
			}
			rows = append(rows, newRow(c, set, id, c.Profile, tagPromEvaluation, ev))
		case c.Language == "promql" && (c.Kind == "negative" || c.Kind == "gate"):
			sc := SyntaxCase{ID: id, Profiles: []string{c.Profile}, Enabled: enabledOf(set)}
			sc.Input.Expression = c.Expression
			if c.Kind == "negative" || !c.Enabled {
				sc.Expected.Category = c.Reject
			} else {
				sc.Expected.Accepted = true
			}
			rows = append(rows, newRow(c, set, id, c.Profile, tagPromSyntax, sc))
		case c.Language == "logql" && c.Kind == "negative":
			lc := LogQLCase{ID: id, Phase: "syntax", Profiles: []string{logQLProfile}, Enabled: enabledOf(set)}
			lc.Input.Expression = c.Expression
			no := false
			lc.Expected.Accepted = &no
			lc.Expected.Category = c.Reject
			rows = append(rows, newRow(c, set, id, logQLProfile, tagLogSyntax, lc))
		case c.Language == "logql" && c.Kind == "valid":
			entries, err := logEntries(c.Input)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", c.ID, err)
			}
			if strings.HasPrefix(c.Expression, "count_over_time(") {
				lc := LogQLCase{ID: id, Phase: "logql-metric", Profiles: []string{logQLProfile}, Enabled: enabledOf(set), Query: c.Expression, Kind: "instant", Time: model.UnixNano(30e9 + offsetNS(c.Expression)), Direction: "forward", Entries: entries}
				if err = validateLogQLCase(lc); err != nil {
					return nil, err
				}
				rows = append(rows, newRow(c, set, id, logQLProfile, tagLogMetric, lc))
				continue
			}
			for i := range entries {
				e := entries[i]
				pid := id + "#e" + strconv.Itoa(i)
				lc := LogQLCase{ID: pid, Phase: "pipeline", Profiles: []string{logQLProfile}, Enabled: enabledOf(set)}
				lc.Input.Expression = c.Expression
				lc.Input.Entry = &e
				if err = validateLogQLCase(lc); err != nil {
					return nil, err
				}
				rows = append(rows, newRow(c, set, pid, logQLProfile, tagLogPipeline, lc))
			}
		default:
			return nil, fmt.Errorf("generated case %s (%s/%s) has no differential phase", c.ID, c.Language, c.Kind)
		}
	}
	return rows, nil
}

// PlanGenerated generates the cases of one seed and expands them into rows,
// deterministically: the same inputs and seed yield byte-identical rows.
func PlanGenerated(spec GenerationSpec, ledger Ledger, domains []GateDomain, seed uint64) ([]GeneratedRow, error) {
	cases, err := generateForRelease(spec, ledger, domains, seed)
	if err != nil {
		return nil, err
	}
	sets := domainSets(domains)
	var rows []GeneratedRow
	seen := map[string]bool{}
	for _, c := range cases {
		r, err := rowsFor(c, sets)
		if err != nil {
			return nil, err
		}
		for _, row := range r {
			k := PhaseKey(row.Row.Profile, row.Row.ID)
			if seen[k] {
				return nil, fmt.Errorf("duplicate generated row %s", row.Row.ID)
			}
			seen[k] = true
			rows = append(rows, row)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Phase != rows[j].Phase {
			return rows[i].Phase < rows[j].Phase
		}
		if rows[i].Row.Profile != rows[j].Row.Profile {
			return rows[i].Row.Profile < rows[j].Row.Profile
		}
		return rows[i].Row.ID < rows[j].Row.ID
	})
	return rows, nil
}

// RowsOfPhase keeps the rows of one phase tag (diagnostic partial runs only).
func RowsOfPhase(rows []GeneratedRow, tag string) []GeneratedRow {
	var out []GeneratedRow
	for _, r := range rows {
		if r.Phase == tag {
			out = append(out, r)
		}
	}
	return out
}

// GeneratedEnv is what running generated rows needs: the locked source
// identities, the query directory the lock was written for, the profile
// manifests and the OCI runtime.
type GeneratedEnv struct {
	Lock        SourceLock
	QueryDir    string
	ProfilesDir string
	Runtime     string
}

// phaseFile renders the case file of one phase. The strict case readers decode
// it exactly as they decode an authored file.
func phaseFile(tag string, rows []GeneratedRow) (name string, raw []byte, err error) {
	var cases []any
	for _, r := range rows {
		cases = append(cases, r.payload)
	}
	lang, phase, _ := strings.Cut(tag, ":")
	name = "generated-" + lang + "-" + strings.ReplaceAll(phase, ",", "-") + ".json"
	var doc any
	switch {
	case lang == "promql":
		doc = struct {
			Phase string `json:"phase"`
			Cases []any  `json:"cases"`
		}{phase, cases}
	case phase == "logql-metric":
		doc = struct {
			Schema string `json:"schema"`
			Phase  string `json:"phase"`
			Cases  []any  `json:"cases"`
		}{"soundpost-authored-logql-metric-cases-v1", phase, cases}
	default:
		doc = struct {
			Schema string `json:"schema"`
			Phase  string `json:"phase"`
			Cases  []any  `json:"cases"`
		}{"soundpost-authored-logql-cases-v1", phase, cases}
	}
	raw, err = json.MarshalIndent(doc, "", " ")
	return name, raw, err
}

// anchorRows complete a phase file that holds rows for one PromQL profile only:
// the runners refuse a comparison that does not cover both exact profiles.
// Anchors are never reported.
func anchorRows(tag string, rows []GeneratedRow) []GeneratedRow {
	if tag != tagPromEvaluation && tag != tagPromSyntax {
		return nil
	}
	have := map[string]bool{}
	for _, r := range rows {
		have[r.Row.Profile] = true
	}
	var out []GeneratedRow
	for _, p := range promProfiles {
		if have[p] {
			continue
		}
		id := "anchor/" + p
		var payload any
		if tag == tagPromEvaluation {
			payload = EvaluationCase{ID: id, Profiles: []string{p}, Enabled: []string{}, Query: "1", Kind: "instant", Time: model.UnixNano(40e9), Series: []EvaluationSeries{}}
		} else {
			sc := SyntaxCase{ID: id, Profiles: []string{p}, Enabled: []string{}}
			sc.Input.Expression = "1"
			sc.Expected.Accepted, sc.Expected.Type = true, "scalar"
			payload = sc
		}
		out = append(out, GeneratedRow{Row: ReleaseCase{ID: id, Profile: p}, Phase: tag, payload: payload})
	}
	return out
}

// prepare writes the rows as content-locked case files into a private mirror of
// the query directory. The lock copy differs from the repository lock only by
// dropping the other case files (not needed here) and adding the digests of the
// files just written, so every runner still verifies the bytes it consumes.
func (e GeneratedEnv) prepare(rows []GeneratedRow) (lock SourceLock, qdir string, manifest ReleaseCaseManifest, cleanup func(), err error) {
	byTag := map[string][]GeneratedRow{}
	for _, r := range rows {
		byTag[r.Phase] = append(byTag[r.Phase], r)
	}
	tags := make([]string, 0, len(byTag))
	for t := range byTag {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	tmp, err := os.MkdirTemp("", "soundpost-generated-")
	if err != nil {
		return lock, "", manifest, nil, err
	}
	cleanup = func() { _ = os.RemoveAll(tmp) }
	defer func() {
		if err != nil {
			cleanup()
		}
	}()
	qdir = filepath.Join(tmp, "conformance", "query")
	copyFile := func(from, to string) error {
		raw, err := os.ReadFile(from)
		if err != nil {
			return err
		}
		if err = os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
			return err
		}
		return os.WriteFile(to, raw, 0o644)
	}
	if err = copyFile(e.Lock.LedgerPath, filepath.Join(qdir, "obligations.json")); err != nil {
		return lock, "", manifest, nil, err
	}
	lock = e.Lock
	lock.LedgerPath = filepath.Join(qdir, "obligations.json")
	lock.InventoryFiles = map[string]string{}
	for name, sum := range e.Lock.InventoryFiles {
		if strings.HasPrefix(name, "cases/") {
			continue
		}
		if err = copyFile(filepath.Join(e.QueryDir, filepath.FromSlash(name)), filepath.Join(qdir, filepath.FromSlash(name))); err != nil {
			return lock, "", manifest, nil, err
		}
		lock.InventoryFiles[name] = sum
	}
	for name := range e.Lock.ProfileFiles {
		if err = copyFile(filepath.Join(e.QueryDir, "..", "..", filepath.FromSlash(name)), filepath.Join(tmp, filepath.FromSlash(name))); err != nil {
			return lock, "", manifest, nil, err
		}
	}
	manifest = ReleaseCaseManifest{Schema: "soundpost-query-release-cases/1"}
	for _, tag := range tags {
		all := append(append([]GeneratedRow(nil), byTag[tag]...), anchorRows(tag, byTag[tag])...)
		name, raw, werr := phaseFile(tag, all)
		if werr != nil {
			err = werr
			return lock, "", manifest, nil, err
		}
		if err = os.MkdirAll(filepath.Join(qdir, "cases"), 0o755); err != nil {
			return lock, "", manifest, nil, err
		}
		if err = os.WriteFile(filepath.Join(qdir, "cases", name), raw, 0o644); err != nil {
			return lock, "", manifest, nil, err
		}
		sum := sha256.Sum256(raw)
		lock.InventoryFiles["cases/"+name] = hex.EncodeToString(sum[:])
		lang, phase, _ := strings.Cut(tag, ":")
		manifest.Files = append(manifest.Files, ReleasePhaseFile{Path: "cases/" + name, Language: lang, Phase: phase})
	}
	return lock, qdir, manifest, cleanup, nil
}

// Run executes the rows through RunReleasePhases, the same function that runs
// the authored files.
func (e GeneratedEnv) Run(ctx context.Context, rows []GeneratedRow) (PhaseResults, error) {
	lock, qdir, manifest, cleanup, err := e.prepare(rows)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	return RunReleasePhases(ctx, lock, qdir, e.ProfilesDir, e.Runtime, manifest)
}

// Execute runs every row of one seed and returns the run the gate judges. A
// runner failure that observed nothing leaves the affected rows unobserved,
// which the gate counts as unrun.
func (e GeneratedEnv) Execute(ctx context.Context, seed uint64, rows []GeneratedRow) (GeneratedRun, error) {
	results, err := e.Run(ctx, rows)
	run := GeneratedRun{Seed: seed, Rows: rows}
	if results != nil {
		run.Oracle, run.Own = results.PhaseOracle(), results.PhaseOwn()
	}
	return run, err
}

// GeneratedMinimizer re-runs shrunken candidates of a mismatching case through
// the same phase runners and keeps a candidate only while a row of it still
// disagrees.
type GeneratedMinimizer struct {
	Domains []GateDomain
	RunRows func(ctx context.Context, rows []GeneratedRow) (PhaseResults, error)
}

var digits = regexp.MustCompile(`[0-9]+`)

// problemShape reduces a mismatch text to what identifies the disagreement:
// shrinking an expression moves byte positions, which must not make the same
// mismatch look different, while a candidate that merely fails some other way
// (a parse error instead of the original execution error) must.
func problemShape(p string) string { return digits.ReplaceAllString(p, "#") }

func sameProblem(want, got []string) bool {
	have := map[string]bool{}
	for _, g := range got {
		have[problemShape(g)] = true
	}
	for _, w := range want {
		if have[problemShape(w)] {
			return true
		}
	}
	return false
}

func (m GeneratedMinimizer) Minimize(ctx context.Context, gm GeneratedMismatch) (Regression, error) {
	sets := domainSets(m.Domains)
	predicate := func(c Case) (bool, error) {
		rows, err := rowsFor(c, sets)
		if err != nil || len(rows) == 0 {
			return false, nil // an invalid candidate is not the same mismatch
		}
		res, err := m.RunRows(ctx, rows)
		if cerr := ctx.Err(); cerr != nil {
			return false, cerr
		}
		if err != nil && len(res) == 0 {
			return false, nil
		}
		for _, r := range rows {
			if o, ok := res[PhaseKey(r.Row.Profile, r.Row.ID)]; ok && o.Identity != nil && sameProblem(gm.Problems, o.Problems) {
				return true, nil
			}
		}
		return false, nil
	}
	min, err := Minimize(ctx, CaseMismatch{Case: gm.Row.Source}, predicate)
	if err != nil {
		return Regression{}, err
	}
	probs := gm.Problems
	if rows, e := rowsFor(min, sets); e == nil {
		if res, e := m.RunRows(ctx, rows); e == nil || len(res) > 0 {
			for _, r := range rows {
				if o, ok := res[PhaseKey(r.Row.Profile, r.Row.ID)]; ok && len(o.Problems) > 0 {
					probs = o.Problems
					break
				}
			}
		}
	}
	return Regression{ID: fmt.Sprintf("%s/seed-%d", gm.Row.Source.ID, gm.Seed), Seed: gm.Seed, Profile: gm.Row.Row.Profile, Phase: gm.Row.Phase, FeatureSet: gm.Row.Source.FeatureSet, Enabled: gm.Row.Enabled, Problems: probs, Original: gm.Row.Source.Expression, Case: min}, nil
}

// Minimizer is the production minimizer for this environment.
func (e GeneratedEnv) Minimizer(domains []GateDomain) GeneratedMinimizer {
	return GeneratedMinimizer{Domains: domains, RunRows: e.Run}
}

type regressionIndex struct {
	Schema      string           `json:"schema"`
	Description string           `json:"description"`
	Regressions []map[string]any `json:"regressions"`
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// WriteRegressions writes one case file per minimized regression into dir and
// merges them into dir/index.json (by id). index.json is a content-locked
// inventory file: after a real mismatch it must be relocked and reviewed.
func WriteRegressions(dir string, regs []Regression) error {
	if len(regs) == 0 {
		return nil
	}
	path := filepath.Join(dir, "index.json")
	idx := regressionIndex{Schema: "soundpost-query-regressions/1"}
	if raw, err := os.ReadFile(path); err == nil {
		if err = json.Unmarshal(raw, &idx); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	idx.Description = "Minimized genuine mismatches observed by the release gate, with source seed and profile. Each entry names the minimized case file."
	byID := map[string]int{}
	for i, r := range idx.Regressions {
		id, _ := r["id"].(string)
		byID[id] = i
	}
	for _, r := range regs {
		file := unsafeName.ReplaceAllString(r.ID, "_") + ".json"
		raw, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(dir, file), append(raw, '\n'), 0o644); err != nil {
			return err
		}
		entry := map[string]any{"id": r.ID, "seed": r.Seed, "profile": r.Profile, "phase": r.Phase, "feature_set": r.FeatureSet, "file": file, "problems": r.Problems, "original_expression": r.Original, "minimized_expression": r.Case.Expression}
		if i, ok := byID[r.ID]; ok {
			idx.Regressions[i] = entry
		} else {
			byID[r.ID] = len(idx.Regressions)
			idx.Regressions = append(idx.Regressions, entry)
		}
	}
	raw, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

// gateGenerated judges every generated run. A row is executed only when the
// pinned oracle was observed with a verified identity AND the owned engine was
// observed; anything else is unrun. Executed rows are matched or mismatched by
// the phase runner's own comparison. It never short-circuits.
func gateGenerated(ctx context.Context, cfg ReleaseConfig, sources map[string]SourceProfile, rep *Report, fail func(string, ...any)) error {
	if len(cfg.Generated) == 0 {
		fail("no generated case runs: the generated cases were never executed")
		return nil
	}
	seenSeed := map[uint64]bool{}
	for _, run := range cfg.Generated {
		if seenSeed[run.Seed] {
			fail("duplicate generated run for seed %d", run.Seed)
		}
		seenSeed[run.Seed] = true
		sr := GeneratedSeedReport{Seed: run.Seed, ByPhase: map[string]GeneratedCounts{}, MismatchedRows: []string{}, UnrunRows: []string{}, Regressions: []Regression{}}
		minimized := map[string]bool{}
		for _, row := range run.Rows {
			if err := ctx.Err(); err != nil {
				return err
			}
			counts := sr.ByPhase[row.Phase]
			counts.Generated++
			sr.Generated++
			executed, problems := false, []string(nil)
			src, known := sources[row.Row.Profile]
			if run.Oracle != nil && run.Own != nil && known {
				ref, oerr := run.Oracle(ctx, src, row.Row)
				switch {
				case oerr != nil || !oracleIdentityOK(src, ref):
				default:
					got, gerr := run.Own(ctx, row.Row)
					switch {
					case errors.Is(gerr, ErrNotObserved):
					case gerr != nil:
						executed, problems = true, []string{gerr.Error()}
					default:
						executed = true
						for _, m := range Compare(row.Row.Expected, ref, row.Row.Ordering) {
							problems = append(problems, "oracle: "+m.Field)
						}
						for _, m := range Compare(row.Row.Expected, got, row.Row.Ordering) {
							problems = append(problems, "owned: "+m.Field)
						}
					}
				}
			}
			switch {
			case !executed:
				counts.Unrun++
				sr.Unrun++
				if len(sr.UnrunRows) < generatedSampleLimit {
					sr.UnrunRows = append(sr.UnrunRows, row.Row.ID)
				}
			case len(problems) > 0:
				counts.Executed++
				sr.Executed++
				counts.Mismatched++
				sr.Mismatched++
				if len(sr.MismatchedRows) < generatedSampleLimit {
					sr.MismatchedRows = append(sr.MismatchedRows, row.Row.ID)
				}
				key := row.Source.ID
				if cfg.Minimize != nil && !minimized[key] {
					minimized[key] = true
					reg, err := cfg.Minimize(ctx, GeneratedMismatch{Seed: run.Seed, Row: row, Problems: problems})
					if err != nil {
						fail("seed %d: minimizing %s: %v", run.Seed, row.Row.ID, err)
					} else {
						sr.Regressions = append(sr.Regressions, reg)
					}
				}
			default:
				counts.Executed++
				sr.Executed++
				counts.Matched++
				sr.Matched++
			}
			sr.ByPhase[row.Phase] = counts
		}
		if sr.Generated == 0 {
			fail("seed %d: no generated cases", run.Seed)
		} else if sr.Executed == 0 {
			fail("seed %d: zero generated cases executed (%d generated)", run.Seed, sr.Generated)
		}
		rep.Generated = append(rep.Generated, sr)
	}
	return nil
}
