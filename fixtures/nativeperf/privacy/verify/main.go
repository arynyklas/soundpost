//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Command verify is the task 04.08 privacy fixture verifier. It runs the real
// native acquisition (signed grant, private helper socket, real perf events)
// against the privacy canary workload, exports through the real C03 batch route
// of an in-process real node (verified-TLS HTTP, gzip), reads the profile back
// through the real C05 scoped reader, and audits every owned boundary for the
// workload's sentinels, which only this verifier knows:
//
//	go run ./fixtures/nativeperf/privacy/verify --workload fixtures/nativeperf/privacy/canary \
//	    --endpoint-env SOUNDPOST_FIXTURE_API --audit-syscalls --inject-peer-death
//
// Exit codes: 0 every required row passed; 1 failure; 2 usage; 4 a canary crossed
// a boundary (also the expected result of --negative-control); 10 privacy, CPU
// evidence, resource cleanup and the other requested rows passed, but scheduler
// evidence could not be acquired on this kernel (unqualified, NOT a pass).
//
// The kernel ring's fixed ABI transiently carries command names (and scheduler
// tracepoint prev/next comm bytes); this verifier proves they never leave the
// helper's borrowed ring view, not that they never existed.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
)

const (
	exitOK            = 0
	exitFail          = 1
	exitUsage         = 2
	exitCanary        = 4
	exitNoScheduler   = 10
	defaultPolicyPath = "fixtures/nativeperf/privacy/policy.json"
)

type options struct {
	workload        string
	endpointEnv     string
	policyPath      string
	seconds         int
	auditSyscalls   bool
	injectPeerDeath bool
	injectHelperEnd bool
	negativeControl bool
	role            string
	resultFile      string
	socket          string
	requestFile     string
	policyBlob      string
}

func main() {
	var o options
	flag.StringVar(&o.workload, "workload", "fixtures/nativeperf/privacy/canary", "compiled canary workload")
	flag.StringVar(&o.endpointEnv, "endpoint-env", "SOUNDPOST_FIXTURE_API", "environment variable that selects/receives the real node endpoint")
	flag.StringVar(&o.policyPath, "policy", defaultPolicyPath, "privacy policy file")
	flag.IntVar(&o.seconds, "seconds", 4, "real capture seconds (1..30)")
	flag.BoolVar(&o.auditSyscalls, "audit-syscalls", false, "re-run the whole fixture under strace -f -v and audit forbidden syscalls/configuration")
	flag.BoolVar(&o.injectPeerDeath, "inject-peer-death", false, "SIGKILL a real socket peer mid-capture and require exact resource release")
	flag.BoolVar(&o.injectHelperEnd, "inject-helper-crash", false, "SIGKILL a real helper process mid-capture and require a failure (never a success) and no dump files")
	flag.BoolVar(&o.negativeControl, "negative-control", false, "run a deliberately contaminated sanitizer (copies comm); the run MUST exit 4")
	flag.StringVar(&o.role, "role", "", "internal: child|peer|helper")
	flag.StringVar(&o.resultFile, "result-file", "", "internal: write the JSON report here instead of stdout")
	flag.StringVar(&o.socket, "socket", "", "internal: helper socket")
	flag.StringVar(&o.requestFile, "request-file", "", "internal: signed capture request")
	flag.StringVar(&o.policyBlob, "operator-file", "", "internal: helper operator policy")
	flag.Parse()
	if o.seconds < 1 || o.seconds > 30 || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage error: --seconds must be 1..30 and no positional arguments are accepted")
		os.Exit(exitUsage)
	}
	code, e := dispatch(o)
	if e != nil {
		// Only closed fixture error text: never workload content.
		fmt.Fprintln(os.Stderr, "verify:", e)
	}
	os.Exit(code)
}

func dispatch(o options) (int, error) {
	switch o.role {
	case "peer":
		return runPeer(o)
	case "helper":
		return runHelperProcess(o)
	case "", "child":
	default:
		return exitUsage, errors.New("unknown role")
	}
	if o.auditSyscalls && o.role == "" {
		return runUnderStrace(o)
	}
	rep, code, e := runFixture(o)
	if rep != nil {
		out := os.Stdout
		if o.resultFile != "" {
			f, err := os.OpenFile(o.resultFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
			if err != nil {
				return exitFail, err
			}
			defer f.Close()
			out = f
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return exitFail, err
		}
	}
	return code, e
}
