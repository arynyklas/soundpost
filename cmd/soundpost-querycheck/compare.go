// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	q "github.com/arynyklas/soundpost/internal/conformance/query"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func runCompare(args []string) error {
	flags := flag.NewFlagSet("compare", flag.ContinueOnError)
	phase := flags.String("phase", "", "required comparison phase")
	cases := flags.String("cases", "conformance/query/cases/promql-syntax.json", "comma-separated authored case files")
	profiles := flags.String("profiles", "promql-prometheus-3.1.0,promql-prometheus-3.13.5", "exact required profiles")
	directory := flags.String("profile-dir", "profiles/query", "factual profile manifest directory")
	lockPath := flags.String("lock", "conformance/query/source-lock.json", "source/artifact lock")
	locked := flags.Bool("require-locked", false, "require exact oracle locks")
	runtime := flags.String("runtime", os.Getenv("SOUNDPOST_ORACLE_RUNTIME"), "absolute OCI runtime path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*locked {
		return fmt.Errorf("compare requires --require-locked")
	}
	ids := strings.Split(*profiles, ",")
	sort.Strings(ids)
	isLogQL := strings.Join(ids, ",") == "logql-loki-3.5.2"
	if !isLogQL && strings.Join(ids, ",") != "promql-prometheus-3.1.0,promql-prometheus-3.13.5" {
		return fmt.Errorf("comparison requires exact Loki or both exact PromQL profiles; no omitted profile may pass")
	}
	if isLogQL {
		if *phase != "syntax" && *phase != "pipeline" && *phase != "syntax,pipeline" && *phase != "pipeline,syntax" && *phase != "logql-template" && *phase != "logql-metric" {
			return fmt.Errorf("Loki comparison requires --phase syntax,pipeline|logql-template|logql-metric")
		}
	} else if *phase != "syntax" && *phase != "evaluation" {
		return fmt.Errorf("PromQL comparison requires --phase syntax|evaluation")
	}
	var lock q.SourceLock
	if err := q.ReadJSON(*lockPath, &lock); err != nil {
		return err
	}
	lock.LedgerPath = filepath.Join(filepath.Dir(*lockPath), "obligations.json")
	if isLogQL {
		report, err := q.RunLogQLPhase(context.Background(), lock, *cases, *directory, *runtime, *phase)
		if encodeErr := json.NewEncoder(os.Stdout).Encode(report); encodeErr != nil {
			return encodeErr
		}
		return err
	}
	if *phase == "evaluation" {
		report, err := q.RunEvaluationPhase(context.Background(), lock, strings.Split(*cases, ","), *directory, *runtime)
		if encodeErr := json.NewEncoder(os.Stdout).Encode(report); encodeErr != nil {
			return encodeErr
		}
		return err
	}
	report, err := q.RunSyntaxPhase(context.Background(), lock, *cases, *directory, *runtime)
	if encodeErr := json.NewEncoder(os.Stdout).Encode(report); encodeErr != nil {
		return encodeErr
	}
	return err
}
