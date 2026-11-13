// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"soundpost/internal/releaseevidence"
)

// EvidenceNodeLoss is the manifest value (`evidence: node_loss`) that puts a scenario into the
// release gate's node_loss report.
const EvidenceNodeLoss = "node_loss"

// NodeLossScenarios lists the scenarios the manifest tags for the node_loss report, in manifest order.
func (m *Manifest) NodeLossScenarios() []string {
	var names []string
	for _, s := range m.Scenarios {
		if s.Evidence == EvidenceNodeLoss {
			names = append(names, s.Name)
		}
	}
	return names
}

// ReadReport decodes <dir>/<scenario>.json strictly.
func ReadReport(dir, scenario string) (Report, error) {
	var rep Report
	raw, err := os.ReadFile(filepath.Join(dir, scenario+".json"))
	if err != nil {
		return rep, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&rep); err != nil {
		return Report{}, fmt.Errorf("%s: %w", scenario, err)
	}
	return rep, nil
}

// NodeLossEvidence exports the drill reports of the manifest's node_loss scenarios as the
// "node_loss" release evidence. The expected rows are the manifest's tagged scenarios, so a drill
// whose report is absent stays visible as a missing row. A scenario row keeps the drill's own
// status: passed stays passed (including its recorded not-run parts, named in the detail),
// failed and not_run keep their names. A report whose status says passed while one of its checks
// is not ok contradicts itself and is exported as failed.
func NodeLossEvidence(m *Manifest, reportDir, commit string) (releaseevidence.Report, error) {
	expected := m.NodeLossScenarios()
	if len(expected) == 0 {
		return releaseevidence.Report{}, errors.New("the manifest tags no scenario for the node_loss report")
	}
	var rows []releaseevidence.Row
	for _, name := range expected {
		rep, err := ReadReport(reportDir, name)
		if errors.Is(err, os.ErrNotExist) {
			continue // no report: the gate names the expected row as having no result
		}
		if err != nil {
			return releaseevidence.Report{}, err
		}
		if rep.Scenario != name || rep.Target != TargetName {
			return releaseevidence.Report{}, fmt.Errorf("%s.json is the report of scenario %q on target %q", name, rep.Scenario, rep.Target)
		}
		rows = append(rows, drillRow(name, rep))
	}
	return releaseevidence.New(releaseevidence.KindNodeLoss, commit, expected, rows)
}

func drillRow(name string, rep Report) releaseevidence.Row {
	row := releaseevidence.Row{ID: name}
	var badChecks []string
	for _, c := range rep.Checks {
		if !c.OK {
			badChecks = append(badChecks, "check "+c.Name+" failed: "+c.Detail)
		}
	}
	switch rep.Status {
	case StatusPassed:
		if len(badChecks) > 0 {
			row.Status = releaseevidence.StatusFailed
			row.Detail = releaseevidence.Detail(append([]string{"report says passed but contradicts itself"}, badChecks...)...)
			return row
		}
		row.Status = releaseevidence.StatusPassed
		var notRun []string
		for _, n := range rep.NotRunItems {
			notRun = append(notRun, n.Item)
		}
		detail := fmt.Sprintf("%d checks ok", len(rep.Checks))
		if len(notRun) > 0 {
			detail += "; not run parts: " + strings.Join(notRun, ", ")
		}
		row.Detail = releaseevidence.Detail(detail)
	case StatusFailed:
		row.Status = releaseevidence.StatusFailed
		row.Detail = releaseevidence.Detail(append([]string{rep.Reason}, badChecks...)...)
	case StatusNotRun:
		row.Status = releaseevidence.StatusNotRun
		row.Detail = releaseevidence.Detail(rep.Reason)
	default:
		row.Status = releaseevidence.StatusFailed
		row.Detail = fmt.Sprintf("unrecognised report status %q", rep.Status)
	}
	return row
}

// runEvidence is `drills evidence --scenarios FILE --reports DIR --commit SHA --out FILE`. It exits 0
// when the envelope was written, whatever the rows say: the release gate decides.
func runEvidence(args []string, stdout, stderr io.Writer) int {
	f := flag.NewFlagSet("drills evidence", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	manifest := f.String("scenarios", "drills/scenarios.yaml", "scenario manifest that tags the node_loss scenarios")
	reports := f.String("reports", "", "directory of the per-scenario JSON reports")
	commit := f.String("commit", "", "full 40-hex source commit the drills ran against")
	out := f.String("out", "", "envelope file to write")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || *reports == "" || *out == "" {
		fmt.Fprintln(stderr, "usage: drills evidence --scenarios FILE --reports DIR --commit SHA --out FILE")
		return 2
	}
	if err := releaseevidence.CheckCommit(*commit); err != nil {
		fmt.Fprintln(stderr, "drills evidence:", err)
		return 2
	}
	m, err := LoadManifest(*manifest)
	if err == nil {
		var env releaseevidence.Report
		if env, err = NodeLossEvidence(m, *reports, *commit); err == nil {
			if err = env.Write(*out); err == nil {
				fmt.Fprintln(stdout, env.Summary())
				return 0
			}
		}
	}
	fmt.Fprintln(stderr, "drills evidence:", err)
	return 1
}
