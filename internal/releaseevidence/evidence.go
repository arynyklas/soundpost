// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package releaseevidence defines the soundpost-release-evidence/1 envelope that
// the release gate (go run ./build gate) reads, and the one way producers write
// it. The envelope carries rows only: there is no producer-side "passed" flag
// and the gate recomputes the verdict from the rows. An exporter maps each
// producer result row to exactly one envelope row and never decides a verdict.
package releaseevidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Schema is the envelope identifier.
const Schema = "soundpost-release-evidence/1"

// The five report kinds the gate consumes, with their producers:
// language = the 07.05 query campaign, runtime = the 07.06 runtime and overhead
// qualification suites, privacy = the 07.06 privacy canary suite, node_loss =
// the 07.07 node-loss drills and browser = the real-Chrome end-to-end specs and
// the journeys and evidence smokes.
const (
	KindLanguage = "language"
	KindRuntime  = "runtime"
	KindPrivacy  = "privacy"
	KindNodeLoss = "node_loss"
	KindBrowser  = "browser"
)

// Kinds lists every kind in gate order.
var Kinds = []string{KindLanguage, KindRuntime, KindPrivacy, KindNodeLoss, KindBrowser}

// StatusPassed is the only passing status. Everything else (failed, not_run,
// not_exercised, unsupported, denied, skipped, flaky, ...) blocks the gate.
const StatusPassed = "passed"

// Statuses an exporter emits besides StatusPassed.
const (
	StatusFailed = "failed"
	StatusNotRun = "not_run"
)

// Report is the envelope. Its JSON form is read by the gate with unknown fields rejected.
type Report struct {
	Schema   string   `json:"schema"`
	Kind     string   `json:"kind"`
	Commit   string   `json:"commit"`
	Expected []string `json:"expected_rows"`
	Rows     []Row    `json:"rows"`
}

// Row is one measured row of a producer.
type Row struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// CheckCommit requires a full lowercase 40-hex source commit, the form the gate compares by equality.
func CheckCommit(commit string) error {
	if !commitPattern.MatchString(commit) {
		return fmt.Errorf("commit %q is not a full 40-hex lowercase source commit", commit)
	}
	return nil
}

// New builds a report. expected must be the ids the producer is REQUIRED to
// deliver, taken from a source independent of the rows themselves (a matrix,
// a manifest, a fixed list), so a producer that drops a row cannot also drop
// the expectation.
func New(kind, commit string, expected []string, rows []Row) (Report, error) {
	r := Report{Schema: Schema, Kind: kind, Commit: commit, Expected: append([]string{}, expected...), Rows: append([]Row{}, rows...)}
	sort.Strings(r.Expected)
	return r, r.Validate()
}

// Validate checks the envelope shape. It never inspects a verdict: failing rows are valid.
func (r Report) Validate() error {
	if r.Schema != Schema {
		return fmt.Errorf("schema %q, want %q", r.Schema, Schema)
	}
	known := false
	for _, k := range Kinds {
		known = known || k == r.Kind
	}
	if !known {
		return fmt.Errorf("kind %q is not one of %s", r.Kind, strings.Join(Kinds, ", "))
	}
	if err := CheckCommit(r.Commit); err != nil {
		return err
	}
	if len(r.Expected) == 0 {
		return errors.New("a report with no expected rows is refused: it would pass vacuously")
	}
	seen := map[string]bool{}
	for _, id := range r.Expected {
		if id == "" || seen[id] {
			return fmt.Errorf("expected row id %q is empty or duplicated", id)
		}
		seen[id] = true
	}
	rows := map[string]bool{}
	for _, row := range r.Rows {
		if row.ID == "" || row.Status == "" {
			return fmt.Errorf("row %q has an empty id or status", row.ID)
		}
		if rows[row.ID] {
			return fmt.Errorf("duplicate row %s", row.ID)
		}
		rows[row.ID] = true
	}
	return nil
}

// Missing lists expected ids that have no row, so an exporter can say so; the gate reports them too.
func (r Report) Missing() []string {
	have := map[string]bool{}
	for _, row := range r.Rows {
		have[row.ID] = true
	}
	var out []string
	for _, id := range r.Expected {
		if !have[id] {
			out = append(out, id)
		}
	}
	return out
}

// Summary is one line stating how many rows passed, did not pass and are missing, plus every non-passing id.
func (r Report) Summary() string {
	passed := 0
	var bad []string
	for _, row := range r.Rows {
		if row.Status == StatusPassed {
			passed++
		} else {
			bad = append(bad, row.ID+"="+row.Status)
		}
	}
	missing := r.Missing()
	var b strings.Builder
	fmt.Fprintf(&b, "%s evidence for %s: %d expected, %d rows, %d passed, %d not passed, %d missing", r.Kind, r.Commit, len(r.Expected), len(r.Rows), passed, len(bad), len(missing))
	for _, s := range bad {
		fmt.Fprintf(&b, "\n  NOT PASSED %s", s)
	}
	for _, s := range missing {
		fmt.Fprintf(&b, "\n  MISSING %s", s)
	}
	return b.String()
}

// Marshal is the canonical encoding written to disk.
func (r Report) Marshal() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	if err := e.Encode(r); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Write validates and writes the report atomically (temp file, then rename).
func (r Report) Write(path string) error {
	raw, err := r.Marshal()
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".evidence-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err = tmp.Write(raw); err == nil {
		err = tmp.Close()
	} else {
		tmp.Close()
	}
	if err == nil {
		err = os.Chmod(name, 0o644)
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		os.Remove(name)
	}
	return err
}

// Detail joins non-empty parts with "; " and bounds the length so a row never carries a log.
func Detail(parts ...string) string {
	var keep []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			keep = append(keep, p)
		}
	}
	s := strings.Join(keep, "; ")
	const limit = 1200
	if len(s) > limit {
		s = s[:limit] + "..."
	}
	return s
}
