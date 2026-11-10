//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Command acceptance is the task 04.09 native CPU/off-CPU acceptance runner. It
// launches the real workloads, acquires REAL CPU samples through the committed
// signed-grant helper (its own process, the real nativeperf.Helper), resolves
// frames with the verifier-side ELF lookup and asserts the workload's hot
// function appears in genuine native callchains. It never accepts a staged
// acquisition_pending path, an empty successful session, synthetic samples or a
// no-op sampler (those are exercised as negative controls before the real path),
// and it exits ExitUnexercised (10) when required rows could not be exercised on
// this host (scheduler path, other kernels/architectures): that is NOT a pass.
//
//	cc -O2 -pthread -fno-omit-frame-pointer -g -o fixtures/nativeperf/acceptance/workloads fixtures/nativeperf/acceptance/workloads.c
//	go run ./fixtures/nativeperf/acceptance --manifest fixtures/nativeperf/qualification.json \
//	    --workload fixtures/nativeperf/acceptance/workloads --duration 60s --seed 451 --endpoint-env SOUNDPOST_FIXTURE_API
//
// Exit codes: 0 every required row supported; 1 an exercised row failed; 2 usage;
// 4 a contaminated capture was ACCEPTED (the gate itself is broken); 10 required
// rows unexercised.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"strings"
	"time"

	"soundpost/fixtures/nativeperf/qual"
	"soundpost/internal/nativeperf"
)

type options struct {
	manifest    string
	workload    string
	duration    time.Duration
	seed        int64
	endpointEnv string
	out         string
	runtimeDir  string
	runtimes    string
	commandLine string
}

func main() {
	if handled, code := qual.HelperRole(os.Args[1:]); handled {
		os.Exit(code)
	}
	var o options
	flag.StringVar(&o.manifest, "manifest", "fixtures/nativeperf/qualification.json", "qualification manifest")
	flag.StringVar(&o.workload, "workload", "fixtures/nativeperf/acceptance/workloads", "compiled workloads binary")
	flag.DurationVar(&o.duration, "duration", 30*time.Second, "total CPU-capture time across the CPU scenarios (>= 10s)")
	flag.Int64Var(&o.seed, "seed", 451, "seed for the privacy nonce and the scenario order")
	flag.StringVar(&o.endpointEnv, "endpoint-env", "SOUNDPOST_FIXTURE_API", "environment variable that would name an external node endpoint (not used: this runner exports nothing)")
	flag.StringVar(&o.out, "out", "", "write the machine report here instead of stdout")
	flag.StringVar(&o.runtimeDir, "runtime-dir", "fixtures/nativeperf/runtime", "runtime fixtures directory")
	flag.StringVar(&o.runtimes, "runtimes", "python,node,bun", "runtime columns to run (comma separated, empty for none)")
	flag.Parse()
	if o.duration < 10*time.Second || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: --duration must be at least 10s and no positional arguments are accepted")
		os.Exit(qual.ExitUsage)
	}
	o.commandLine = "acceptance " + strings.Join(os.Args[1:], " ")
	res, code := run(o)
	if res != nil {
		raw, _ := json.MarshalIndent(res, "", "  ")
		raw = append(raw, '\n')
		if o.out != "" {
			if err := os.WriteFile(o.out, raw, 0o644); err != nil {
				fmt.Fprintln(os.Stderr, "write report:", err)
				os.Exit(qual.ExitFail)
			}
		} else {
			os.Stdout.Write(raw)
		}
		if unq := res.UnqualifiedRequired(); len(unq) > 0 {
			fmt.Fprintln(os.Stderr, "acceptance: required rows not supported:")
			for _, u := range unq {
				fmt.Fprintln(os.Stderr, "  "+u)
			}
		}
	}
	os.Exit(code)
}

func run(o options) (*qual.QualificationResult, int) {
	res := &qual.QualificationResult{
		KernelBuild: qual.KernelRelease(), KernelConfig: qual.ReadKernelConfig(), Arch: qual.GOARCHName(), PolicyRevision: 1,
		RuntimeBuild: map[string]qual.RuntimeBuild{},
		Commands:     []qual.Command{{Command: o.commandLine, Ran: true}},
		Evidence:     []qual.EvidenceRef{},
	}
	for _, row := range res.Rows() {
		*row = qual.Row{State: qual.StateNotRun, Reason: "not reached"}
	}
	// 1. contaminated captures must be rejected BEFORE the real path runs.
	res.NegativeControls = qual.RunNegativeControls()
	for _, nc := range res.NegativeControls {
		if !nc.Behaved {
			fmt.Fprintln(os.Stderr, "acceptance: the capture checker ACCEPTED a contaminated capture:", nc.Name)
			return res, qual.ExitContaminated
		}
	}
	if _, err := os.Stat(o.workload); err != nil {
		fmt.Fprintln(os.Stderr, "acceptance: workload binary missing; compile it first (see the command in this file's header)")
		return nil, qual.ExitUsage
	}
	if raw, err := os.ReadFile(o.manifest); err != nil || !json.Valid(raw) {
		fmt.Fprintln(os.Stderr, "acceptance: manifest unreadable or not JSON")
		return nil, qual.ExitUsage
	} else {
		sum := sha256.Sum256(raw)
		res.Evidence = append(res.Evidence, qual.EvidenceRef{Name: "manifest " + o.manifest, SHA256: hex.EncodeToString(sum[:]), Bytes: len(raw)})
	}
	if v := os.Getenv(o.endpointEnv); v != "" {
		res.NotRun = append(res.NotRun, qual.NotRunItem{Item: "export to " + o.endpointEnv, Reason: "an external endpoint was named but this runner exports nothing; export, storage and read privacy are covered by the 04.08 verify fixture, not re-run here"})
	}
	if sum, n, err := qual.FileSHA256(o.workload); err == nil {
		bid, _ := qual.BuildIDOf(o.workload)
		res.TargetBuild = qual.TargetBuild{Compiler: ccVersion(), Flags: "cc -O2 -pthread -fno-omit-frame-pointer -g", BuildID: bid, SHA256: sum}
		res.Evidence = append(res.Evidence, qual.EvidenceRef{Name: "workload " + o.workload, SHA256: sum, Bytes: n})
	}
	scratch, err := os.MkdirTemp("", "soundpost-accept-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "acceptance:", err)
		return nil, qual.ExitFail
	}
	defer os.RemoveAll(scratch)
	ctx, cancel := context.WithTimeout(context.Background(), o.duration*4+10*time.Minute)
	defer cancel()
	a := &accept{o: o, res: res, scratch: scratch, ctx: ctx}
	a.nonce = seededNonce(o.seed)
	a.rng = rand.New(rand.NewPCG(uint64(o.seed), 0x9e3779b97f4a7c15))
	a.runAll()
	return res, res.ExitCode()
}

func seededNonce(seed int64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("soundpost-04.09-nonce-%d", seed)))
	return hex.EncodeToString(sum[:8])
}

func ccVersion() string {
	out, err := exec.Command("cc", "--version").Output()
	if err != nil {
		return "unknown"
	}
	return strings.SplitN(string(out), "\n", 2)[0]
}

var _ = nativeperf.DefaultConfig
