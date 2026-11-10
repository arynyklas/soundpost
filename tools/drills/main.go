// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Command drills runs the Soundpost failure drills against ISOLATED targets only:
//
//	go run ./tools/drills --scenario <name|all> --target isolated --report <dir> [--binary PATH]
//
// `--target` accepts only the literal `isolated`; a drill refuses any data directory that is not
// under an allowlisted isolated root, the production/default data directories and any address that
// is not a loopback literal. Production execution is a separate owner action and is not built here.
//
// Exit codes: 0 every selected scenario passed; 1 a scenario failed; 2 usage or a safety refusal;
// 10 no scenario failed but at least one was recorded not_run (a not_run row is never a pass).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	f := flag.NewFlagSet("drills", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	scenario := f.String("scenario", "", "scenario name or `all`")
	target := f.String("target", "", "must be the literal `isolated`")
	reportDir := f.String("report", "", "directory for the JSON reports")
	binary := f.String("binary", "", "produced static soundpost binary (scenarios that run real nodes)")
	root := f.String("root", ".", "repository root")
	manifest := f.String("scenarios", "drills/scenarios.yaml", "scenario manifest with the isolated-target allowlist")
	if err := f.Parse(args); err != nil {
		fmt.Fprintln(stderr, "usage:", err)
		return 2
	}
	if *scenario == "" || *reportDir == "" {
		fmt.Fprintln(stderr, "usage: drills --scenario NAME|all --target isolated --report DIR [--binary PATH]")
		return 2
	}
	m, err := LoadManifest(*manifest)
	if err != nil {
		fmt.Fprintln(stderr, "manifest:", err)
		return 2
	}
	if *target != TargetName {
		fmt.Fprintf(stderr, "%v\n", refuse("--target accepts only the literal %q", TargetName))
		return 2
	}
	// The data root itself must be safe before anything is created under it.
	if err := CheckTarget(m.Allowlist, Target{Name: *target, DataDirs: []string{filepath.Join(m.Allowlist.DataRoots[0], "probe")}, Addresses: []string{"127.0.0.1:1"}}); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	names, err := m.Select(*scenario)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := os.MkdirAll(*reportDir, 0o700); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	absRoot, _ := filepath.Abs(*root)
	code := 0
	for _, name := range names {
		rep, err := Execute(context.Background(), m, name, *target, absRoot, *binary, *reportDir)
		switch {
		case errors.Is(err, ErrRefused):
			fmt.Fprintf(stderr, "%s: %v\n", name, err)
			return 2
		case err != nil:
			fmt.Fprintf(stderr, "%s: report: %v\n", name, err)
			return 2
		}
		fmt.Fprintf(stdout, "%s: %s %s\n", name, rep.Status, rep.Reason)
		switch rep.Status {
		case StatusFailed:
			code = 1
		case StatusNotRun:
			if code == 0 {
				code = 10
			}
		}
	}
	return code
}

// ---- manifest ----

// ScenarioSpec is one row of drills/scenarios.yaml.
type ScenarioSpec struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	// NotRun, when set, is the exact reason this drill cannot be executed on an unprivileged
	// isolated host. The row is reported not_run; it is never simulated as passed.
	NotRun string `yaml:"not_run"`
	// NeedsBinary marks drills that start real processes of the produced static binary.
	NeedsBinary bool `yaml:"needs_binary"`
}

// Manifest is drills/scenarios.yaml.
type Manifest struct {
	Version   int            `yaml:"version"`
	Allowlist Allowlist      `yaml:"allowlist"`
	Scenarios []ScenarioSpec `yaml:"scenarios"`
}

// LoadManifest reads the manifest strictly (unknown fields are errors).
func LoadManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseManifest(raw)
}

// ParseManifest decodes and validates a manifest.
func ParseManifest(raw []byte) (*Manifest, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if m.Version != 1 {
		return nil, fmt.Errorf("unsupported manifest version %d", m.Version)
	}
	if len(m.Allowlist.DataRoots) == 0 || len(m.Allowlist.Hosts) == 0 || len(m.Allowlist.Forbidden) == 0 {
		return nil, errors.New("the allowlist must name data_roots, hosts and forbidden_data_dirs explicitly")
	}
	seen := map[string]bool{}
	for _, s := range m.Scenarios {
		if s.Name == "" || seen[s.Name] {
			return nil, fmt.Errorf("scenario %q is empty or duplicated", s.Name)
		}
		seen[s.Name] = true
		if s.NotRun == "" && s.Description == "" {
			return nil, fmt.Errorf("scenario %q has no description", s.Name)
		}
	}
	return &m, nil
}

// Select resolves `all` or one name.
func (m *Manifest) Select(name string) ([]string, error) {
	var names []string
	for _, s := range m.Scenarios {
		if name == "all" || s.Name == name {
			names = append(names, s.Name)
		}
	}
	if len(names) == 0 {
		var have []string
		for _, s := range m.Scenarios {
			have = append(have, s.Name)
		}
		sort.Strings(have)
		return nil, fmt.Errorf("unknown scenario %q (have %v)", name, have)
	}
	return names, nil
}

func (m *Manifest) spec(name string) ScenarioSpec {
	for _, s := range m.Scenarios {
		if s.Name == name {
			return s
		}
	}
	return ScenarioSpec{}
}

// ---- execution and reports ----

// Status of one scenario run.
type Status string

const (
	StatusPassed Status = "passed"
	StatusFailed Status = "failed"
	StatusNotRun Status = "not_run"
)

// Report is the JSON written for one scenario: the ACK ledger, the reconciliation, cursors,
// fences, policy and notification timelines, and every named check with its result.
type Report struct {
	Scenario       string           `json:"scenario"`
	Target         string           `json:"target"`
	Status         Status           `json:"status"`
	Reason         string           `json:"reason,omitempty"`
	StartedAt      string           `json:"started_at"`
	ElapsedMS      int64            `json:"elapsed_ms"`
	AckLedger      []Ack            `json:"ack_ledger"`
	FailedAttempts []Attempt        `json:"failed_attempts"`
	Reconciliation *Reconciliation  `json:"reconciliation,omitempty"`
	Cursors        map[string]any   `json:"cursors,omitempty"`
	Fences         []map[string]any `json:"fences,omitempty"`
	PolicyTimeline []map[string]any `json:"policy_timeline,omitempty"`
	Notifications  []Event          `json:"notification_timeline,omitempty"`
	Checks         []Check          `json:"checks"`
	Facts          map[string]any   `json:"facts,omitempty"`
	NotRunItems    []NotRunItem     `json:"not_run_items,omitempty"`

	ledger   *Ledger
	timeline *Timeline
}

// Check is one named assertion of a drill.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// NotRunItem is one part of a scenario that could not be exercised, with the exact reason.
type NotRunItem struct {
	Item   string `json:"item"`
	Reason string `json:"reason"`
}

// Ledger returns the scenario's ACK ledger (created on first use).
func (r *Report) Ledger() *Ledger {
	if r.ledger == nil {
		r.ledger = &Ledger{}
	}
	return r.ledger
}

// Timeline returns the scenario's notification/outage timeline (created on first use).
func (r *Report) Timeline() *Timeline {
	if r.timeline == nil {
		r.timeline = NewTimeline(nil)
	}
	return r.timeline
}

// Fact records a JSON-serialisable observation (no secrets, no raw telemetry content).
func (r *Report) Fact(key string, v any) {
	if r.Facts == nil {
		r.Facts = map[string]any{}
	}
	r.Facts[key] = v
}

// Cursor records a cursor observation.
func (r *Report) Cursor(key string, v any) {
	if r.Cursors == nil {
		r.Cursors = map[string]any{}
	}
	r.Cursors[key] = v
}

// Require records a check and returns an error when it does not hold. A drill returns the first
// error; the failing check stays in the report.
func (r *Report) Require(name string, ok bool, detail string) error {
	r.Checks = append(r.Checks, Check{Name: name, OK: ok, Detail: detail})
	if !ok {
		return fmt.Errorf("check %s failed: %s", name, detail)
	}
	return nil
}

// Reconcile compares the ledger with the retained data and records the outcome as a check.
func (r *Report) Reconcile(retained map[string]string) error {
	rec, err := Reconcile(r.Ledger(), retained)
	if err != nil {
		r.Checks = append(r.Checks, Check{Name: "exact_reconciliation", OK: false, Detail: err.Error()})
		return err
	}
	r.Reconciliation = &rec
	r.Checks = append(r.Checks, Check{Name: "exact_reconciliation", OK: true, Detail: fmt.Sprintf("%d acknowledged ids retained with identical semantic data", rec.ExactMatches)})
	return nil
}

// NotRun marks part of the scenario as not exercised.
func (r *Report) NotRun(item, reason string) {
	r.NotRunItems = append(r.NotRunItems, NotRunItem{Item: item, Reason: reason})
}

// Env is what a scenario receives. Work is a fresh directory under an allowlisted isolated data
// root; every data directory and address a scenario uses MUST go through Allow(Target).
type Env struct {
	Ctx       context.Context
	Allowlist Allowlist
	Root      string // repository root
	Binary    string // produced static binary ("" when the scenario does not need one)
	Work      string
	Spec      ScenarioSpec
	Logf      func(format string, args ...any)
}

// Approve checks a concrete target (directories and loopback addresses) against the allowlist.
func (e *Env) Approve(dirs []string, addrs []string) error {
	return CheckTarget(e.Allowlist, Target{Name: TargetName, DataDirs: dirs, Addresses: addrs})
}

var registry = map[string]func(*Env, *Report) error{}

func register(name string, fn func(*Env, *Report) error) { registry[name] = fn }

// Execute runs one scenario and writes <report>/<scenario>.json. A safety refusal is returned as
// an ErrRefused error before anything is created.
func Execute(ctx context.Context, m *Manifest, name, target, root, binary, reportDir string) (*Report, error) {
	spec := m.spec(name)
	rep := &Report{Scenario: name, Target: target, StartedAt: time.Now().UTC().Format(time.RFC3339), Checks: []Check{}}
	begin := time.Now()
	finish := func() (*Report, error) {
		rep.ElapsedMS = time.Since(begin).Milliseconds()
		rep.AckLedger, rep.FailedAttempts = []Ack{}, []Attempt{}
		if rep.ledger != nil {
			rep.AckLedger, rep.FailedAttempts = rep.ledger.Acks(), rep.ledger.Attempts()
		}
		if rep.timeline != nil {
			rep.Notifications = rep.timeline.Events()
		}
		encoded, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return rep, err
		}
		return rep, os.WriteFile(filepath.Join(reportDir, name+".json"), append(encoded, '\n'), 0o600)
	}
	if err := CheckTarget(m.Allowlist, Target{Name: target}); err != nil {
		return nil, err
	}
	if spec.Name == "" {
		return nil, fmt.Errorf("unknown scenario %q", name)
	}
	if spec.NotRun != "" {
		rep.Status, rep.Reason = StatusNotRun, spec.NotRun
		return finish()
	}
	if registry[name] == nil {
		rep.Status, rep.Reason = StatusFailed, "scenario has no implementation and no not_run reason"
		return finish()
	}
	if spec.NeedsBinary && binary == "" {
		rep.Status, rep.Reason = StatusFailed, "this scenario needs --binary (the produced static soundpost binary)"
		return finish()
	}
	if err := os.MkdirAll(m.Allowlist.DataRoots[0], 0o700); err != nil {
		return nil, err
	}
	work, err := os.MkdirTemp(m.Allowlist.DataRoots[0], name+"-")
	if err != nil {
		return nil, err
	}
	if err := CheckTarget(m.Allowlist, Target{Name: target, DataDirs: []string{work}}); err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	env := &Env{Ctx: ctx, Allowlist: m.Allowlist, Root: root, Binary: binary, Work: work, Spec: spec,
		Logf: func(f string, a ...any) { fmt.Fprintf(os.Stderr, "["+name+"] "+f+"\n", a...) }}
	runErr := func() (err error) {
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("scenario panicked: %v", p)
			}
		}()
		return registry[name](env, rep)
	}()
	switch {
	case errors.Is(runErr, ErrRefused):
		return nil, runErr
	case runErr != nil:
		rep.Status, rep.Reason = StatusFailed, runErr.Error()
	default:
		rep.Status = StatusPassed
		for _, c := range rep.Checks {
			if !c.OK {
				rep.Status, rep.Reason = StatusFailed, "check "+c.Name+" failed"
			}
		}
		if rep.Status == StatusPassed && len(rep.NotRunItems) > 0 {
			rep.Reason = fmt.Sprintf("%d part(s) not run; see not_run_items", len(rep.NotRunItems))
		}
	}
	return finish()
}
