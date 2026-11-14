// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Suite names one qualification suite.
type Suite string

// The suites of tools/qualify.
const (
	SuiteRuntime  Suite = "runtime"
	SuitePrivacy  Suite = "privacy"
	SuiteOverhead Suite = "overhead"
)

// State is the single outcome class of one matrix row.
type State string

// A row carries exactly one of these.
const (
	StateExercised    State = "exercised"
	StateNotExercised State = "not_exercised"
	StateUnsupported  State = "unsupported"
	StateDenied       State = "denied"
)

// Outcome is the verdict of an exercised row.
type Outcome string

// Exercised rows either held their checks and budgets or failed them.
const (
	OutcomePassed Outcome = "passed"
	OutcomeFailed Outcome = "failed"
)

// Availability is the state of one capability reading. Unavailable states never
// carry a number: zero is a measurement, not an absence.
type Availability string

// Availability values.
const (
	AvailAvailable    Availability = "available"
	AvailUnsupported  Availability = "unsupported"
	AvailDenied       Availability = "denied"
	AvailNotExercised Availability = "not_exercised"
)

// Errors returned by ValidateRow.
var (
	ErrUnavailableAsZero = errors.New("unavailable capability reported a numeric value")
	ErrExtrapolated      = errors.New("observed build does not match the row's own subject")
	ErrBudgetMismatch    = errors.New("budget verdict does not follow from its observed value")
	ErrRowInvalid        = errors.New("invalid qualification row")
)

// Subject is what a row claims to qualify.
type Subject struct {
	Family  string `json:"family"`
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

// Build is the exact build observed by an exercised row.
type Build struct {
	Family  string `json:"family"`
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	ID      string `json:"build_id"`
	SHA256  string `json:"sha256,omitempty"`
	Host    string `json:"host_class,omitempty"`
}

// CommandRun records one executed harness command and its own exit code.
type CommandRun struct {
	Command    string `json:"command"`
	ExitCode   int    `json:"exit_code"`
	DurationMS int64  `json:"duration_ms"`
}

// Reading is one capability reading. Value is nil unless Availability is
// available, so an absent capability can never serialize as zero.
type Reading struct {
	Name         string       `json:"name"`
	Unit         string       `json:"unit,omitempty"`
	Availability Availability `json:"availability"`
	Value        *float64     `json:"value,omitempty"`
	Reason       string       `json:"reason,omitempty"`
}

// Series is one raw safe measurement series (numbers only, never telemetry content).
type Series struct {
	Name   string    `json:"name"`
	Unit   string    `json:"unit"`
	Mode   string    `json:"mode,omitempty"`
	Values []float64 `json:"values"`
}

// BudgetResult compares one observed number with a design section 13 limit.
type BudgetResult struct {
	Name     string  `json:"name"`
	Source   string  `json:"source"`
	Unit     string  `json:"unit"`
	Limit    float64 `json:"limit"`
	Observed float64 `json:"observed"`
	Within   bool    `json:"within"`
	Method   string  `json:"method,omitempty"`
}

// IntervalReport carries requested and observed sampling intervals.
type IntervalReport struct {
	RequestedUS *float64 `json:"requested_us,omitempty"`
	ObservedUS  *float64 `json:"observed_us,omitempty"`
	Note        string   `json:"note,omitempty"`
}

// Row is one matrix row.
type Row struct {
	ID       string          `json:"id"`
	Suite    Suite           `json:"suite"`
	Required bool            `json:"required"`
	Subject  Subject         `json:"subject"`
	State    State           `json:"state"`
	Reason   string          `json:"reason,omitempty"`
	Outcome  Outcome         `json:"outcome,omitempty"`
	Failures []string        `json:"failures,omitempty"`
	Build    *Build          `json:"build,omitempty"`
	Command  *CommandRun     `json:"command,omitempty"`
	Readings []Reading       `json:"readings,omitempty"`
	Series   []Series        `json:"series,omitempty"`
	Budgets  []BudgetResult  `json:"budgets,omitempty"`
	Interval *IntervalReport `json:"interval,omitempty"`
	Loss     string          `json:"loss_and_coverage,omitempty"`
	Limits   []string        `json:"limits,omitempty"`
	Evidence []string        `json:"evidence,omitempty"`
}

// matches reports whether an observed build is the subject's own build. Only a
// subject that says "any" for os/arch (an in-process check with no platform)
// matches every platform; no row can borrow another row's build.
func (b Build) matches(s Subject) bool {
	return b.Family != "" && b.Family == s.Family && (s.OS == "any" || b.OS == s.OS) && (s.Arch == "any" || b.Arch == s.Arch) && versionMatches(b.Version, s.Version)
}

// versionMatches reports whether an observed version is the wanted one or one of
// its patch builds: "3.12.3" matches "3.12" but "3.120.1" does not.
func versionMatches(observed, want string) bool {
	observed, want = strings.TrimPrefix(observed, "v"), strings.TrimPrefix(want, "v")
	return want != "" && (observed == want || strings.HasPrefix(observed, want+"."))
}

// ValidateRow enforces the state rules of one row. It never repairs a row: an
// unavailable capability with a number, an observed build that is not the row's
// own build, a budget verdict that does not follow from its numbers and an
// exercised row without evidence are all rejected.
func ValidateRow(r Row) error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s: %s", ErrRowInvalid, r.ID, fmt.Sprintf(format, args...))
	}
	if r.ID == "" || r.Subject.Family == "" || r.Subject.Version == "" && r.Subject.OS == "" && r.Subject.Arch == "" {
		return bad("row needs an id and a subject")
	}
	// The capability invariant holds in every state.
	for _, rd := range r.Readings {
		switch rd.Availability {
		case AvailAvailable:
			if rd.Value == nil {
				return bad("reading %s is available but has no value", rd.Name)
			}
			if math.IsNaN(*rd.Value) || math.IsInf(*rd.Value, 0) {
				return bad("reading %s is not a finite number", rd.Name)
			}
		case AvailUnsupported, AvailDenied, AvailNotExercised:
			if rd.Value != nil {
				return fmt.Errorf("%w: %s: reading %s is %s but carries %v", ErrUnavailableAsZero, r.ID, rd.Name, rd.Availability, *rd.Value)
			}
			if rd.Reason == "" {
				return bad("reading %s is %s without a reason", rd.Name, rd.Availability)
			}
		default:
			return bad("reading %s has unknown availability %q", rd.Name, rd.Availability)
		}
	}
	switch r.State {
	case StateNotExercised:
		if r.Reason == "" {
			return bad("not_exercised without a reason")
		}
		if r.Build != nil || r.Command != nil || len(r.Series) > 0 || len(r.Budgets) > 0 || r.Interval != nil || r.Outcome != "" || len(r.Failures) > 0 {
			return bad("not_exercised carries measurement data")
		}
		for _, rd := range r.Readings {
			if rd.Availability == AvailAvailable {
				return bad("not_exercised carries an available reading %s", rd.Name)
			}
		}
	case StateUnsupported, StateDenied:
		if r.Reason == "" {
			return bad("%s without a reason", r.State)
		}
		if len(r.Evidence) == 0 {
			return bad("%s without the observation that established it", r.State)
		}
		if len(r.Series) > 0 || len(r.Budgets) > 0 || r.Outcome != "" || len(r.Failures) > 0 {
			return bad("%s carries measurement data", r.State)
		}
		for _, rd := range r.Readings {
			if rd.Availability == AvailAvailable {
				return bad("%s row carries an available reading %s", r.State, rd.Name)
			}
		}
		if r.Build != nil && !r.Build.matches(r.Subject) {
			return fmt.Errorf("%w: %s: observed %s %s %s/%s", ErrExtrapolated, r.ID, r.Build.Family, r.Build.Version, r.Build.OS, r.Build.Arch)
		}
	case StateExercised:
		if r.Build == nil || r.Build.ID == "" {
			return bad("exercised without the observed build id")
		}
		if !r.Build.matches(r.Subject) {
			return fmt.Errorf("%w: %s: row is %s %s %s/%s, observed %s %s %s/%s", ErrExtrapolated, r.ID,
				r.Subject.Family, r.Subject.Version, r.Subject.OS, r.Subject.Arch, r.Build.Family, r.Build.Version, r.Build.OS, r.Build.Arch)
		}
		if len(r.Evidence) == 0 || r.Command == nil && len(r.Series) == 0 {
			return bad("exercised without evidence or the command that produced it")
		}
		for _, s := range r.Series {
			if len(s.Values) == 0 {
				return bad("series %s is empty", s.Name)
			}
			for _, v := range s.Values {
				if math.IsNaN(v) || math.IsInf(v, 0) {
					return bad("series %s holds a non-finite value", s.Name)
				}
			}
		}
		failedBudget := false
		for _, b := range r.Budgets {
			if b.Within != (b.Observed <= b.Limit) {
				return fmt.Errorf("%w: %s: %s observed %v limit %v within=%v", ErrBudgetMismatch, r.ID, b.Name, b.Observed, b.Limit, b.Within)
			}
			failedBudget = failedBudget || !b.Within
		}
		switch r.Outcome {
		case OutcomePassed:
			if failedBudget || len(r.Failures) > 0 {
				return bad("passed with a failed budget or failure")
			}
		case OutcomeFailed:
			if len(r.Failures) == 0 && !failedBudget {
				return bad("failed without a reason")
			}
		default:
			return bad("exercised without a passed/failed outcome")
		}
	default:
		return bad("unknown state %q", r.State)
	}
	return nil
}

// SuiteReport is the machine report of one suite run.
type SuiteReport struct {
	Suite       Suite    `json:"suite"`
	Matrix      string   `json:"matrix"`
	MatrixSHA   string   `json:"matrix_sha256"`
	RecordedAt  string   `json:"recorded_at"`
	Host        HostInfo `json:"host"`
	Rows        []Row    `json:"rows"`
	Unqualified []string `json:"unqualified_required_rows"`
	Failed      []string `json:"measured_failures"`
	ExitCode    int      `json:"exit_code"`
}

// HostInfo identifies the machine that produced a report.
type HostInfo struct {
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Kernel  string `json:"kernel,omitempty"`
	Class   string `json:"class"`
	NumCPU  int    `json:"logical_cpus"`
	MemMiB  int    `json:"memory_mib,omitempty"`
	GoBuild string `json:"go,omitempty"`
}

// ParseSuiteReport decodes a report strictly and validates every row, so a
// tampered report cannot launder an unavailable capability into a number.
func ParseSuiteReport(raw []byte) (SuiteReport, error) {
	var r SuiteReport
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return SuiteReport{}, fmt.Errorf("%w: %v", ErrRowInvalid, err)
	}
	ids := map[string]bool{}
	for _, row := range r.Rows {
		if ids[row.ID] {
			return SuiteReport{}, fmt.Errorf("%w: duplicate row %s", ErrRowInvalid, row.ID)
		}
		ids[row.ID] = true
		if err := ValidateRow(row); err != nil {
			return SuiteReport{}, err
		}
	}
	return r, nil
}

// Process exit codes of the qualify command.
const (
	ExitOK          = 0
	ExitFail        = 1  // a measured failure, an invalid report, a broken control
	ExitUsage       = 2  // unusable arguments or matrix
	ExitUnqualified = 10 // required rows were not exercised: NOT a pass
)

// Verdict fills the unqualified/measured-failure lists and the exit code. A
// required row that is not exercised (including unsupported and denied) blocks
// the claim, every exercised row that missed a check or budget blocks it, and a
// matrix without any required row cannot pass vacuously.
func (r *SuiteReport) Verdict() {
	r.Unqualified, r.Failed = nil, nil
	required := 0
	for _, row := range r.Rows {
		if row.Required {
			required++
			if row.State != StateExercised {
				r.Unqualified = append(r.Unqualified, fmt.Sprintf("%s: %s (%s)", row.ID, row.State, row.Reason))
			}
		}
		if row.State == StateExercised && row.Outcome == OutcomeFailed {
			why := append([]string(nil), row.Failures...)
			for _, b := range row.Budgets {
				if !b.Within {
					why = append(why, fmt.Sprintf("%s observed %.4g %s > limit %.4g", b.Name, b.Observed, b.Unit, b.Limit))
				}
			}
			r.Failed = append(r.Failed, fmt.Sprintf("%s: %s", row.ID, strings.Join(why, "; ")))
		}
	}
	switch {
	case required == 0:
		r.Failed = append(r.Failed, "matrix has no required row for this suite: a vacuous pass is refused")
		r.ExitCode = ExitFail
	case len(r.Failed) > 0:
		r.ExitCode = ExitFail
	case len(r.Unqualified) > 0:
		r.ExitCode = ExitUnqualified
	default:
		r.ExitCode = ExitOK
	}
}

// Summary is the human text of the verdict: every unqualified required row and
// every measured failure, one per line.
func (r SuiteReport) Summary() string {
	var b strings.Builder
	counts := map[State]int{}
	for _, row := range r.Rows {
		counts[row.State]++
	}
	fmt.Fprintf(&b, "suite %s: %d rows (exercised %d, not_exercised %d, unsupported %d, denied %d), exit %d\n", r.Suite, len(r.Rows),
		counts[StateExercised], counts[StateNotExercised], counts[StateUnsupported], counts[StateDenied], r.ExitCode)
	for _, line := range r.Failed {
		fmt.Fprintf(&b, "MEASURED FAILURE %s\n", line)
	}
	for _, line := range r.Unqualified {
		fmt.Fprintf(&b, "UNQUALIFIED %s\n", line)
	}
	return b.String()
}

// BuildSpec describes one build a row needs, so that its absence is a stated
// fact and a different build can never stand in for it.
type BuildSpec struct {
	Family       string   `yaml:"family"`
	Version      string   `yaml:"version"`
	OS           string   `yaml:"os"`
	Arch         string   `yaml:"arch"`
	Env          string   `yaml:"env,omitempty"`
	Candidates   []string `yaml:"candidates,omitempty"`
	VersionArgs  []string `yaml:"version_args,omitempty"`
	VersionRegex string   `yaml:"version_regex,omitempty"`
	Absent       string   `yaml:"absent"`
}

// RowSpec is one matrix row before it is run.
type RowSpec struct {
	ID       string            `yaml:"id"`
	Suite    Suite             `yaml:"suite"`
	Required bool              `yaml:"required"`
	Runner   string            `yaml:"runner"`
	Build    string            `yaml:"build,omitempty"`
	Subject  *Subject          `yaml:"subject,omitempty"`
	Needs    []string          `yaml:"needs,omitempty"`
	Params   map[string]string `yaml:"params,omitempty"`
}

// NativeSpec expands to one required row per kernel series, architecture and capability.
type NativeSpec struct {
	Suite        Suite    `yaml:"suite"`
	Kernels      []string `yaml:"kernels"`
	Arches       []string `yaml:"arches"`
	Capabilities []string `yaml:"capabilities"`
	Runner       string   `yaml:"runner"`
}

// Matrix is the decoded matrix.yaml.
type Matrix struct {
	Schema    string               `yaml:"schema"`
	Root      string               `yaml:"root"`
	Workloads string               `yaml:"workloads"`
	Builds    map[string]BuildSpec `yaml:"builds"`
	Rows      []RowSpec            `yaml:"rows"`
	Native    []NativeSpec         `yaml:"native"`
}

// MatrixSchema is the schema identifier of matrix.yaml.
const MatrixSchema = "soundpost-qualification-matrix/1"

// LoadMatrix decodes matrix.yaml strictly and expands the native section.
func LoadMatrix(path string) (Matrix, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Matrix{}, err
	}
	var m Matrix
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return Matrix{}, fmt.Errorf("matrix %s: %w", path, err)
	}
	if m.Schema != MatrixSchema {
		return Matrix{}, fmt.Errorf("matrix %s: schema %q, want %q", path, m.Schema, MatrixSchema)
	}
	for _, n := range m.Native {
		for _, k := range n.Kernels {
			for _, a := range n.Arches {
				for _, c := range n.Capabilities {
					m.Rows = append(m.Rows, RowSpec{
						ID: fmt.Sprintf("%s.native.linux-%s.%s.%s", n.Suite, k, a, c), Suite: n.Suite, Required: true, Runner: n.Runner,
						Subject: &Subject{Family: "linux-kernel", Version: k, OS: "linux", Arch: a},
						Params:  map[string]string{"capability": c},
					})
				}
			}
		}
	}
	seen := map[string]bool{}
	for _, row := range m.Rows {
		switch {
		case row.ID == "" || row.Runner == "":
			return Matrix{}, fmt.Errorf("matrix %s: a row needs an id and a runner", path)
		case seen[row.ID]:
			return Matrix{}, fmt.Errorf("matrix %s: duplicate row %s", path, row.ID)
		case row.Suite != SuiteRuntime && row.Suite != SuitePrivacy && row.Suite != SuiteOverhead:
			return Matrix{}, fmt.Errorf("matrix %s: row %s has unknown suite %q", path, row.ID, row.Suite)
		case row.Build == "" && row.Subject == nil:
			return Matrix{}, fmt.Errorf("matrix %s: row %s has neither a build nor a subject", path, row.ID)
		}
		if row.Build != "" {
			if _, ok := m.Builds[row.Build]; !ok {
				return Matrix{}, fmt.Errorf("matrix %s: row %s names unknown build %q", path, row.ID, row.Build)
			}
		}
		for _, need := range row.Needs {
			if _, ok := m.Builds[need]; !ok {
				return Matrix{}, fmt.Errorf("matrix %s: row %s needs unknown build %q", path, row.ID, need)
			}
		}
		seen[row.ID] = true
	}
	for key, b := range m.Builds {
		if b.Family == "" || b.Version == "" || b.OS == "" || b.Arch == "" || b.Absent == "" {
			return Matrix{}, fmt.Errorf("matrix %s: build %s needs family, version, os, arch and an absent reason", path, key)
		}
	}
	return m, nil
}

func hostInfo() HostInfo {
	h := HostInfo{OS: runtime.GOOS, Arch: runtime.GOARCH, Class: runtime.GOOS, NumCPU: runtime.NumCPU(), GoBuild: runtime.Version()}
	if runtime.GOOS == "linux" {
		if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
			h.Kernel = strings.TrimSpace(string(b))
		}
		if v, err := os.ReadFile("/proc/version"); err == nil && strings.Contains(strings.ToLower(string(v)), "microsoft") {
			h.Class = "wsl2"
		}
		if b, err := os.ReadFile("/proc/meminfo"); err == nil {
			var kb int
			if _, err := fmt.Sscanf(string(b), "MemTotal: %d kB", &kb); err == nil {
				h.MemMiB = kb / 1024
			}
		}
	}
	return h
}

// runner produces the row for one spec. It never validates: RunSuite does.
type runner func(rc *runCtx, spec RowSpec) Row

// RunSuite runs every matrix row of one suite against the builds actually
// installed on this host, validates every row, writes <suite>-report.json and
// the raw evidence under reportDir, and returns the report with its verdict.
// An error is returned for an unusable matrix, an invalid row (a bug in a
// runner) or a cancelled context; a failed budget is NOT an error but a
// non-zero ExitCode with the row marked failed.
func RunSuite(ctx context.Context, suite Suite, matrixPath, reportDir string) (SuiteReport, error) {
	m, err := LoadMatrix(matrixPath)
	if err != nil {
		return SuiteReport{}, err
	}
	rawMatrix, _ := os.ReadFile(matrixPath)
	sum := sha256.Sum256(rawMatrix)
	absMatrix, _ := filepath.Abs(matrixPath)
	root := filepath.Clean(filepath.Join(filepath.Dir(absMatrix), m.Root))
	wl, err := LoadWorkloads(filepath.Join(root, m.Workloads))
	if err != nil {
		return SuiteReport{}, err
	}
	if err := os.MkdirAll(filepath.Join(reportDir, "evidence"), 0o755); err != nil {
		return SuiteReport{}, err
	}
	work, err := os.MkdirTemp("", "soundpost-qualify-")
	if err != nil {
		return SuiteReport{}, err
	}
	defer os.RemoveAll(work)
	// The unprivileged-helper permission cases (uid 65534) must be able to exec the built workloads.
	// The directory holds only binaries built from this repository.
	if err := os.Chmod(work, 0o755); err != nil {
		return SuiteReport{}, err
	}
	rc := &runCtx{ctx: ctx, root: root, reportDir: reportDir, work: work, matrix: m, workloads: wl, host: hostInfo(), probes: map[string]*probeResult{}, cache: map[string]any{}}
	rep := SuiteReport{
		Suite: suite, Matrix: filepath.ToSlash(matrixPath), MatrixSHA: hex.EncodeToString(sum[:]),
		RecordedAt: time.Now().UTC().Format(time.RFC3339), Host: rc.host, Rows: []Row{},
	}
	var invalid []error
	for _, spec := range m.Rows {
		if spec.Suite != suite {
			continue
		}
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		run, ok := runners[spec.Runner]
		if !ok {
			return rep, fmt.Errorf("row %s: unknown runner %q", spec.ID, spec.Runner)
		}
		row := run(rc, spec)
		row.ID, row.Suite, row.Required = spec.ID, spec.Suite, spec.Required
		row.Subject = rc.subject(spec)
		if err := ValidateRow(row); err != nil {
			invalid = append(invalid, err)
			row = Row{ID: spec.ID, Suite: spec.Suite, Required: spec.Required, Subject: rc.subject(spec), State: StateExercised, Outcome: OutcomeFailed,
				Failures: []string{"runner produced an invalid row: " + err.Error()}, Build: &Build{Family: row.Subject.Family, Version: row.Subject.Version, OS: row.Subject.OS, Arch: row.Subject.Arch, ID: "invalid"},
				Evidence: []string{"invalid row"}, Command: &CommandRun{Command: spec.Runner}}
		}
		rep.Rows = append(rep.Rows, row)
	}
	rep.Verdict()
	if len(invalid) > 0 {
		rep.ExitCode = ExitFail
	}
	out, err := json.MarshalIndent(rep, "", " ")
	if err != nil {
		return rep, err
	}
	if err := os.WriteFile(filepath.Join(reportDir, string(suite)+"-report.json"), append(out, '\n'), 0o644); err != nil {
		return rep, err
	}
	if err := os.WriteFile(filepath.Join(reportDir, string(suite)+"-summary.txt"), []byte(rep.Summary()), 0o644); err != nil {
		return rep, err
	}
	return rep, errors.Join(invalid...)
}
