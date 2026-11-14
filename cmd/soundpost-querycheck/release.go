// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	q "github.com/arynyklas/soundpost/internal/conformance/query"
)

// runRelease is the persisted-path release gate. Every --require flag is
// mandatory: the command refuses to run with a weaker gate than the policy.
func runRelease(args []string) error {
	f := flag.NewFlagSet("release", flag.ContinueOnError)
	policyPath := f.String("policy", "conformance/query/release-policy.json", "release policy")
	smokePath := f.String("smoke-report", "", "report written by `soundpost-querycheck smoke --report`")
	reportPath := f.String("report", "", "write the machine-readable report here as well as stdout")
	runtime := f.String("runtime", "", "absolute OCI runtime executable; without it no oracle is available")
	seed := f.Uint64("seed", 20261110, "generator seed")
	all := f.Bool("all-profiles", false, "require all pinned profiles")
	sets := f.Bool("all-feature-sets", false, "require every registered feature set")
	locked := f.Bool("require-locked", false, "require digest locks")
	unbound := f.Bool("require-zero-unbound", false, "require zero unbound obligations")
	skips := f.Bool("require-zero-skips", false, "require zero skips")
	mismatches := f.Bool("require-zero-mismatches", false, "require zero mismatches")
	if err := f.Parse(args); err != nil {
		return err
	}
	if !(*all && *sets && *locked && *unbound && *skips && *mismatches) {
		return fmt.Errorf("release requires --all-profiles --all-feature-sets --require-locked --require-zero-unbound --require-zero-skips --require-zero-mismatches")
	}
	var smoke *q.SmokeReport
	if *smokePath != "" {
		smoke = new(q.SmokeReport)
		if err := q.ReadJSON(*smokePath, smoke); err != nil {
			return err
		}
	}
	cfg, err := q.LoadReleaseConfig(filepath.Dir(*policyPath), *policyPath, smoke, *seed)
	if err != nil {
		return err
	}
	if *runtime != "" {
		cfg.Oracle = func(ctx context.Context, p q.SourceProfile, c q.ReleaseCase) (q.SemanticResult, error) {
			configuration, err := os.ReadFile(p.ConfigurationPath)
			if err != nil {
				return q.SemanticResult{}, err
			}
			return q.RunOracle(ctx, q.OracleRun{Profile: p, Input: c.Input, Configuration: configuration, Runtime: *runtime})
		}
	}
	report, gateErr := q.ReleaseGate(context.Background(), cfg)
	raw, err := q.MarshalReport(report)
	if err != nil {
		return err
	}
	if *reportPath != "" {
		if err = os.WriteFile(*reportPath, raw, 0o644); err != nil {
			return err
		}
	}
	if _, err = os.Stdout.Write(raw); err != nil {
		return err
	}
	if gateErr != nil {
		return gateErr
	}
	return nil
}
