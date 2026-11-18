// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// goTestEvidenceFile is the `go test -json` stream that
// conformance/query/author/observe-go-tests.sh records, relative to the query
// directory. Every observation in acceptance.json is hashed over it.
const goTestEvidenceFile = "evidence/release-go-tests.jsonl"

// loadGoTestEvidence reads the go test stream the observations of acceptance.json
// were hashed over. A stream that was never recorded is nil: every observation then
// stays unobserved and the gate says so. Any other failure to read it is an error.
func loadGoTestEvidence(queryDir string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(queryDir, filepath.FromSlash(goTestEvidenceFile)))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return raw, err
}

// goTestEvent is the part of one `go test -json` event the gate reads.
type goTestEvent struct {
	Action string `json:"Action"`
	Test   string `json:"Test"`
}

// goTestOutcomes reads the stream and returns the tests that have a pass event
// and the tests that have a fail or skip event, by test name. A subtest is a name
// of its own: its pass does not observe its parent. A line that is not a go test
// event makes the whole stream untrustworthy.
func goTestOutcomes(evidence []byte) (passed, notPassed map[string]bool, err error) {
	passed, notPassed = map[string]bool{}, map[string]bool{}
	for i, line := range bytes.Split(evidence, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var ev goTestEvent
		if jerr := json.Unmarshal(line, &ev); jerr != nil || ev.Action == "" {
			return nil, nil, fmt.Errorf("go test evidence line %d is not a go test event", i+1)
		}
		if ev.Test == "" {
			continue // a package-level event
		}
		switch ev.Action {
		case "pass":
			passed[ev.Test] = true
		case "fail", "skip":
			notPassed[ev.Test] = true
		}
	}
	return passed, notPassed, nil
}

// observedTests returns the names of the observations that count as passed, and
// the problems with the evidence they rest on. An observation counts only if it
// is well formed, its digest is the digest of the go test stream, and that
// stream holds a pass event for the test and no failed or skipped one: a
// hand-written entry with a well-formed digest observes nothing.
func observedTests(obs []TestObservation, evidence []byte) (map[string]bool, []string) {
	observed := map[string]bool{}
	if len(evidence) == 0 {
		return observed, []string{"go test evidence is absent"}
	}
	passed, notPassed, err := goTestOutcomes(evidence)
	if err != nil {
		return observed, []string{err.Error()}
	}
	sum := sha256.Sum256(evidence)
	var problems []string
	for _, t := range obs {
		digest, derr := hex.DecodeString(t.EvidenceSHA256)
		if t.Name == "" || !t.Passed || t.Command == "" || derr != nil || len(digest) != len(sum) {
			continue
		}
		if !bytes.Equal(digest, sum[:]) {
			problems = append(problems, fmt.Sprintf("go test observation %s does not match the go test stream", t.Name))
			continue
		}
		if !passed[t.Name] || notPassed[t.Name] {
			problems = append(problems, fmt.Sprintf("go test observation %s is not backed by a pass event", t.Name))
			continue
		}
		observed[t.Name] = true
	}
	return observed, problems
}
