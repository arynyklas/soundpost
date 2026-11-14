// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// soundpost-querycheck is development tooling, never linked into query execution.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	q "github.com/arynyklas/soundpost/internal/conformance/query"
	"os"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("expected inventory or oracle")
	}
	if os.Args[1] == "release" {
		return runRelease(os.Args[2:])
	}
	if os.Args[1] == "smoke" {
		return runSmoke(os.Args[2:])
	}
	if os.Args[1] == "compare" {
		return runCompare(os.Args[2:])
	}
	if os.Args[1] == "adapter" {
		if len(os.Args) != 3 {
			return fmt.Errorf("adapter requires exact profile ID")
		}
		return q.ServeAdapter(context.Background(), os.Args[2], os.Stdin, os.Stdout)
	}
	if os.Args[1] == "source-audit" {
		flags := flag.NewFlagSet("source-audit", flag.ContinueOnError)
		lockPath := flags.String("lock", "conformance/query/source-lock.json", "source lock")
		profileID := flags.String("profile", "", "exact profile identity")
		archive := flags.String("archive", "", "locally acquired exact source tar.gz")
		if err := flags.Parse(os.Args[2:]); err != nil {
			return err
		}
		var lock q.SourceLock
		if err := q.ReadJSON(*lockPath, &lock); err != nil {
			return err
		}
		if err := q.ValidateSourceLock(lock); err != nil {
			return err
		}
		for _, p := range lock.Profiles {
			if p.ID == *profileID {
				file, err := os.Open(*archive)
				if err != nil {
					return err
				}
				defer file.Close()
				audit, err := q.AuditSource(context.Background(), p, file)
				if err != nil {
					return err
				}
				return json.NewEncoder(os.Stdout).Encode(audit)
			}
		}
		return fmt.Errorf("unknown source audit profile")
	}
	f := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	lockPath := f.String("lock", "conformance/query/source-lock.json", "source lock")
	ledgerPath := f.String("ledger", "conformance/query/obligations.json", "obligation ledger")
	check := f.Bool("check", false, "require accepted complete inventory")
	casesPath := f.String("cases", "conformance/query/cases/oracle-sanity.json", "authored cases")
	all := f.Bool("all-profiles", false, "require all locked profiles")
	locked := f.Bool("require-locked", false, "require digest locks")
	runtime := f.String("runtime", "", "absolute OCI runtime executable")
	if err := f.Parse(os.Args[2:]); err != nil {
		return err
	}
	var lock q.SourceLock
	if err := q.ReadJSON(*lockPath, &lock); err != nil {
		return err
	}
	if err := q.ValidateSourceLock(lock); err != nil {
		return err
	}
	switch os.Args[1] {
	case "inventory":
		lock.LedgerPath = *ledgerPath
		l, err := q.Inventory(context.Background(), lock)
		if err != nil {
			return err
		}
		if *check {
			return json.NewEncoder(os.Stdout).Encode(l)
		}
		return json.NewEncoder(os.Stdout).Encode(l)
	case "oracle":
		if !*all || !*locked {
			return fmt.Errorf("oracle requires --all-profiles --require-locked")
		}
		lock.LedgerPath = *ledgerPath
		if _, err := q.Inventory(context.Background(), lock); err != nil {
			return err
		}
		var cases struct {
			Cases []struct {
				ID       string           `json:"id"`
				Profiles []string         `json:"profiles"`
				Input    json.RawMessage  `json:"input"`
				Expected q.SemanticResult `json:"expected"`
			}
		}
		if err := q.ReadLockedJSON(lock, "cases/oracle-sanity.json", *casesPath, &cases); err != nil {
			return err
		}
		if len(cases.Cases) == 0 {
			return fmt.Errorf("no oracle cases")
		}
		for _, p := range lock.Profiles {
			configuration, err := os.ReadFile(p.ConfigurationPath)
			if err != nil {
				return err
			}
			applicable := 0
			for _, c := range cases.Cases {
				for _, id := range c.Profiles {
					if id != p.ID {
						continue
					}
					applicable++
					got, err := q.RunOracle(context.Background(), q.OracleRun{Profile: p, Input: c.Input, Configuration: configuration, Runtime: *runtime})
					if err != nil {
						return fmt.Errorf("%s/%s: %w", p.ID, c.ID, err)
					}
					if differences := q.Compare(c.Expected, got, q.OrderingFreedom{}); len(differences) > 0 {
						return fmt.Errorf("%s/%s: semantic mismatch: %v", p.ID, c.ID, differences)
					}
					if err = json.NewEncoder(os.Stdout).Encode(got); err != nil {
						return err
					}
				}
			}
			if applicable == 0 {
				return fmt.Errorf("profile %s has no applicable oracle case", p.ID)
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown command")
	}
}
